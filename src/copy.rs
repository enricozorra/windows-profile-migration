//! Builds the working copy of a profile and verifies it against the source.
//!
//! Every entry is copied through backup semantics, so data, alternate data
//! streams, extended attributes, security descriptors, attributes and
//! timestamps arrive as they were. The walk never enters reparse points: a
//! junction or symlink is recreated as a link (retargeted when it points
//! into the source profile, see `reparse`). Online-only cloud files are not
//! copied, because reading them would download them; the cloud service
//! still holds them.
//!
//! The verification walks the finished copy independently and compares it
//! entry by entry with what the copy recorded, then checks that the source
//! did not change while it was being copied.

use std::collections::BTreeMap;
use std::error::Error;
use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

use crate::journal::{self, FOLDER_MARKER_FILE};
use crate::model::EntryFacts;
use crate::platform;
use crate::reparse;
use crate::scan::{
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_OFFLINE, FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS,
    FILE_ATTRIBUTE_RECALL_ON_OPEN, FILE_ATTRIBUTE_REPARSE_POINT,
};
use crate::timefmt;

/// Attributes that are copied and compared: read-only, hidden, system,
/// archive, temporary and not-content-indexed. The others describe how a
/// file is stored (reparse point, sparse, compressed, cloud state) rather
/// than something the copy sets directly.
pub const COPIED_ATTRIBUTES: u32 = 0x0001 | 0x0002 | 0x0004 | 0x0020 | 0x0100 | 0x2000;

/// The copy manifest in the migration folder: one record per entry.
pub const MANIFEST_FILE: &str = "copy-manifest.log";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyClass {
    Directory,
    File,
    /// Junction, symlink or other reparse point: recreated, never entered.
    Link,
    /// A cloud file or folder whose data is not on this machine.
    CloudOnly,
}

impl CopyClass {
    pub fn name(self) -> &'static str {
        match self {
            CopyClass::Directory => "directory",
            CopyClass::File => "file",
            CopyClass::Link => "link",
            CopyClass::CloudOnly => "cloud-only",
        }
    }
}

/// How an entry of the source is copied. A cloud placeholder whose data is
/// local (a hydrated OneDrive file, or a populated OneDrive folder) is
/// copied as a plain file or folder: the placeholder state belongs to the
/// sync client, which is not running for the copy.
pub fn classify(attributes: u32, reparse_tag: Option<u32>) -> CopyClass {
    let not_local = FILE_ATTRIBUTE_RECALL_ON_OPEN
        | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
        | FILE_ATTRIBUTE_OFFLINE;
    let is_dir = attributes & FILE_ATTRIBUTE_DIRECTORY != 0;
    if attributes & not_local != 0 {
        CopyClass::CloudOnly
    } else if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        && !reparse_tag.is_some_and(reparse::is_cloud_tag)
    {
        CopyClass::Link
    } else if is_dir {
        CopyClass::Directory
    } else {
        CopyClass::File
    }
}

/// What one entry of the copy must look like.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryRecord {
    /// Path below the profile folder; empty for the folder itself.
    pub relative: String,
    pub class: CopyClass,
    pub size: u64,
    pub sha256: Option<[u8; 32]>,
    /// Masked with `COPIED_ATTRIBUTES`.
    pub attributes: u32,
    pub created: i64,
    pub written: i64,
    pub reparse: Option<Vec<u8>>,
    pub security: String,
    pub streams: Vec<String>,
}

impl EntryRecord {
    fn new(relative: &str, class: CopyClass, facts: &EntryFacts) -> EntryRecord {
        EntryRecord {
            relative: relative.to_string(),
            class,
            size: if class == CopyClass::File {
                facts.size
            } else {
                0
            },
            sha256: None,
            attributes: facts.attributes & COPIED_ATTRIBUTES,
            created: facts.created,
            written: facts.written,
            reparse: if class == CopyClass::Link {
                facts.reparse.clone()
            } else {
                None
            },
            security: facts.security.clone(),
            streams: facts.streams.clone(),
        }
    }

    fn shown(&self) -> &str {
        if self.relative.is_empty() {
            "(profile folder)"
        } else {
            &self.relative
        }
    }
}

/// Where to copy from and to. Links that point at `retarget_from` or below
/// are rewritten to point below `retarget_to`, the folder the copy will
/// finally be renamed to.
pub struct CopyPaths<'a> {
    pub source: &'a Path,
    pub staging: &'a Path,
    pub retarget_from: &'a str,
    pub retarget_to: &'a str,
}

#[derive(Debug, Default)]
pub struct CopyOutcome {
    pub entries: Vec<EntryRecord>,
    /// Relative paths of online-only cloud entries that were not copied.
    pub cloud_only: Vec<String>,
    /// Relative paths of links that were retargeted.
    pub retargeted: Vec<String>,
    pub bytes: u64,
}

impl CopyOutcome {
    pub fn count(&self, class: CopyClass) -> usize {
        self.entries.iter().filter(|e| e.class == class).count()
    }
}

/// The per-entry record of what was copied or skipped, for later analysis.
/// Unlike the journal it is not synced line by line: it documents the copy,
/// it is not needed to undo it.
pub struct Manifest {
    out: BufWriter<File>,
}

impl Manifest {
    pub fn create(path: &Path) -> io::Result<Manifest> {
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        Ok(Manifest {
            out: BufWriter::new(file),
        })
    }

    fn record(&mut self, event: &str, fields: &[(&str, &str)]) -> io::Result<()> {
        let line = journal::render(event, &timefmt::now().rfc3339(), fields);
        writeln!(self.out, "{line}")
    }

    pub fn finish(mut self) -> io::Result<()> {
        self.out.flush()?;
        self.out.get_ref().sync_data()
    }
}

/// Creates the copy's root folder with the source folder's security, then
/// writes the marker that identifies it as this migration's.
pub fn create_root(paths: &CopyPaths, migration_id: &str) -> Result<EntryRecord, Box<dyn Error>> {
    // The marker must be the only file of that name in the copy, or the
    // copy could not be told apart from the source's own content.
    match fs::symlink_metadata(paths.source.join(FOLDER_MARKER_FILE)) {
        Ok(_) => {
            return Err(format!(
                "the source profile already contains {FOLDER_MARKER_FILE}; was it migrated before?"
            )
            .into())
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(context(paths.source, err)),
    }
    let copied = platform::copy_entry(paths.source, paths.staging, true, None)
        .map_err(|err| context(paths.staging, err))?;
    fs::write(paths.staging.join(FOLDER_MARKER_FILE), migration_id)
        .map_err(|err| context(paths.staging, err))?;
    Ok(EntryRecord::new("", CopyClass::Directory, &copied.source))
}

/// Copies everything below the root. Stops at the first error: a copy with
/// a hole in it is never verified or used.
pub fn copy_tree(
    paths: &CopyPaths,
    root: EntryRecord,
    manifest: &mut Manifest,
) -> Result<CopyOutcome, Box<dyn Error>> {
    let mut outcome = CopyOutcome {
        entries: vec![root],
        ..CopyOutcome::default()
    };
    // Iterative, like the scan: profile trees can be deep.
    let mut pending = vec![String::new()];
    while let Some(dir) = pending.pop() {
        let source_dir = join(paths.source, &dir);
        // Listed with backup semantics, so folders whose DACL keeps even
        // administrators out are copied too.
        let entries = platform::list_dir(&source_dir).map_err(|err| context(&source_dir, err))?;
        for (name, attributes) in entries {
            let relative = if dir.is_empty() {
                name
            } else {
                format!("{dir}\\{name}")
            };
            let source = join(paths.source, &relative);
            let dest = join(paths.staging, &relative);

            let link_data = if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
                && classify(attributes, None) != CopyClass::CloudOnly
            {
                platform::read_entry(&source)
                    .map_err(|err| context(&source, err))?
                    .reparse
            } else {
                None
            };
            let class = classify(attributes, link_data.as_deref().and_then(reparse::tag));
            let is_dir = attributes & FILE_ATTRIBUTE_DIRECTORY != 0;
            match class {
                CopyClass::CloudOnly => {
                    manifest.record(
                        "skipped",
                        &[("path", &relative), ("reason", "online-only cloud file")],
                    )?;
                    outcome.cloud_only.push(relative);
                }
                CopyClass::Directory | CopyClass::File => {
                    let copied = platform::copy_entry(&source, &dest, is_dir, None)
                        .map_err(|err| context(&source, err))?;
                    let mut record = EntryRecord::new(&relative, class, &copied.source);
                    record.sha256 = copied.sha256;
                    let hash = copied.sha256.map(|h| reparse::hex(&h)).unwrap_or_default();
                    let size = record.size.to_string();
                    manifest.record(
                        "copied",
                        &[
                            ("path", &relative),
                            ("kind", class.name()),
                            ("size", &size),
                            ("sha256", &hash),
                        ],
                    )?;
                    outcome.bytes += record.size;
                    if class == CopyClass::Directory {
                        pending.push(relative);
                    }
                    outcome.entries.push(record);
                }
                CopyClass::Link => {
                    let original = link_data.ok_or_else(|| {
                        format!("{}: reparse point without reparse data", source.display())
                    })?;
                    let rewritten =
                        reparse::retarget(&original, paths.retarget_from, paths.retarget_to)
                            .map_err(|err| format!("{}: {err}", source.display()))?;
                    let data = rewritten.as_deref().unwrap_or(&original);
                    let copied = platform::copy_entry(&source, &dest, is_dir, Some(data))
                        .map_err(|err| context(&source, err))?;
                    let mut record = EntryRecord::new(&relative, class, &copied.source);
                    record.reparse = Some(data.to_vec());
                    let target = reparse::link_target(data)
                        .ok()
                        .flatten()
                        .map(|t| t.print)
                        .unwrap_or_default();
                    let retargeted = if rewritten.is_some() { "yes" } else { "no" };
                    manifest.record(
                        "copied",
                        &[
                            ("path", &relative),
                            ("kind", class.name()),
                            ("target", &target),
                            ("retargeted", retargeted),
                        ],
                    )?;
                    if rewritten.is_some() {
                        outcome.retargeted.push(relative);
                    }
                    outcome.entries.push(record);
                }
            }
            if outcome.entries.len() % 5000 == 0 {
                eprintln!(
                    "    copied {} entries, {}",
                    outcome.entries.len(),
                    crate::preflight::format_bytes(outcome.bytes)
                );
            }
        }
    }

    // Creating entries changed the copied folders' timestamps, so they are
    // set again once nothing more is added, innermost first.
    for record in outcome.entries.iter().rev() {
        if record.class == CopyClass::Directory {
            let dest = join(paths.staging, &record.relative);
            platform::set_times(&dest, record.created, record.written)
                .map_err(|err| context(&dest, err))?;
        }
    }
    Ok(outcome)
}

/// Re-reads the copy and the source and lists every difference. An empty
/// list means the copy is complete and faithful.
pub fn verify(paths: &CopyPaths, outcome: &CopyOutcome) -> Result<Vec<String>, Box<dyn Error>> {
    let mut problems = Vec::new();

    let mut expected = outcome.entries.clone();
    for record in &mut expected {
        // Sparse files were copied without a running hash; hash the source.
        if record.class == CopyClass::File && record.sha256.is_none() {
            let source = join(paths.source, &record.relative);
            record.sha256 =
                Some(platform::hash_data(&source).map_err(|err| context(&source, err))?);
        }
    }
    let observed = observe_copy(paths.staging)?;
    problems.extend(compare(&expected, &observed));

    for record in &outcome.entries {
        let source = join(paths.source, &record.relative);
        match platform::read_entry(&source) {
            Ok(now) => problems.extend(source_change(record, &now)),
            Err(err) => problems.push(format!(
                "{}: source no longer readable: {err}",
                record.shown()
            )),
        }
    }
    Ok(problems)
}

/// Walks the finished copy the same way the copy walked the source.
fn observe_copy(staging: &Path) -> Result<Vec<EntryRecord>, Box<dyn Error>> {
    let facts = platform::read_entry(staging).map_err(|err| context(staging, err))?;
    let mut observed = vec![EntryRecord::new("", CopyClass::Directory, &facts)];
    let mut pending = vec![String::new()];
    while let Some(dir) = pending.pop() {
        let dir_path = join(staging, &dir);
        for (name, _) in platform::list_dir(&dir_path).map_err(|err| context(&dir_path, err))? {
            if dir.is_empty() && name == FOLDER_MARKER_FILE {
                continue;
            }
            let relative = if dir.is_empty() {
                name
            } else {
                format!("{dir}\\{name}")
            };
            let path = join(staging, &relative);
            let facts = platform::read_entry(&path).map_err(|err| context(&path, err))?;
            let class = if facts.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                CopyClass::Link
            } else if facts.attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
                CopyClass::Directory
            } else {
                CopyClass::File
            };
            let mut record = EntryRecord::new(&relative, class, &facts);
            match class {
                CopyClass::File => {
                    record.sha256 =
                        Some(platform::hash_data(&path).map_err(|err| context(&path, err))?)
                }
                CopyClass::Directory => pending.push(relative),
                CopyClass::Link | CopyClass::CloudOnly => {}
            }
            observed.push(record);
        }
    }
    Ok(observed)
}

/// Differences between what the copy should contain and what it contains.
pub fn compare(expected: &[EntryRecord], observed: &[EntryRecord]) -> Vec<String> {
    let mut found: BTreeMap<&str, &EntryRecord> = observed
        .iter()
        .map(|record| (record.relative.as_str(), record))
        .collect();
    let mut problems = Vec::new();
    for want in expected {
        let Some(have) = found.remove(want.relative.as_str()) else {
            problems.push(format!("{}: missing from the copy", want.shown()));
            continue;
        };
        let name = want.shown();
        if want.class != have.class {
            problems.push(format!(
                "{name}: is a {} in the copy, a {} in the source",
                have.class.name(),
                want.class.name()
            ));
            continue;
        }
        if want.size != have.size {
            problems.push(format!(
                "{name}: size {} in the copy, {} in the source",
                have.size, want.size
            ));
        }
        if want.sha256 != have.sha256 {
            problems.push(format!("{name}: content differs (SHA-256)"));
        }
        if want.attributes != have.attributes {
            problems.push(format!(
                "{name}: attributes {:#x} in the copy, {:#x} in the source",
                have.attributes, want.attributes
            ));
        }
        if want.created != have.created || want.written != have.written {
            problems.push(format!("{name}: timestamps differ"));
        }
        if want.reparse != have.reparse {
            problems.push(format!("{name}: link target differs"));
        }
        if want.security != have.security {
            problems.push(format!(
                "{name}: security differs (copy {}, source {})",
                have.security, want.security
            ));
        }
        if want.streams != have.streams {
            problems.push(format!(
                "{name}: alternate data streams differ (copy [{}], source [{}])",
                have.streams.join(", "),
                want.streams.join(", ")
            ));
        }
    }
    for extra in found.values() {
        problems.push(format!(
            "{}: in the copy but not in the source",
            extra.shown()
        ));
    }
    problems
}

/// Whether the source entry changed after it was copied, which would make
/// the copy stale.
pub fn source_change(copied: &EntryRecord, now: &EntryFacts) -> Option<String> {
    let size = if copied.class == CopyClass::File {
        now.size
    } else {
        0
    };
    if now.written != copied.written || size != copied.size {
        Some(format!(
            "{}: the source changed while it was being copied",
            copied.shown()
        ))
    } else {
        None
    }
}

fn join(root: &Path, relative: &str) -> PathBuf {
    if relative.is_empty() {
        root.to_path_buf()
    } else {
        root.join(relative)
    }
}

fn context(path: &Path, err: io::Error) -> Box<dyn Error> {
    format!("{}: {err}", path.display()).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reparse::IO_REPARSE_TAG_MOUNT_POINT;

    const CLOUD_TAG: u32 = 0x9000_001A;

    fn record(relative: &str, class: CopyClass) -> EntryRecord {
        EntryRecord {
            relative: relative.into(),
            class,
            size: 3,
            sha256: Some([7; 32]),
            attributes: 0x20,
            created: 1,
            written: 2,
            reparse: None,
            security: "O:S-1-5-21-1".into(),
            streams: vec![],
        }
    }

    #[test]
    fn plain_entries_are_classified_by_the_directory_bit() {
        assert_eq!(
            classify(FILE_ATTRIBUTE_DIRECTORY, None),
            CopyClass::Directory
        );
        assert_eq!(classify(0x20, None), CopyClass::File);
    }

    #[test]
    fn junctions_are_links_and_never_entered() {
        let attributes = FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT;
        assert_eq!(
            classify(attributes, Some(IO_REPARSE_TAG_MOUNT_POINT)),
            CopyClass::Link
        );
    }

    #[test]
    fn local_cloud_entries_are_copied_as_plain_files_and_folders() {
        assert_eq!(
            classify(FILE_ATTRIBUTE_REPARSE_POINT, Some(CLOUD_TAG)),
            CopyClass::File
        );
        assert_eq!(
            classify(
                FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT,
                Some(CLOUD_TAG)
            ),
            CopyClass::Directory
        );
    }

    #[test]
    fn online_only_cloud_entries_are_not_copied() {
        let attributes = FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS;
        assert_eq!(classify(attributes, Some(CLOUD_TAG)), CopyClass::CloudOnly);
        assert_eq!(
            classify(
                FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_RECALL_ON_OPEN,
                None
            ),
            CopyClass::CloudOnly
        );
    }

    #[test]
    fn identical_trees_have_no_differences() {
        let tree = vec![
            record("", CopyClass::Directory),
            record("a.txt", CopyClass::File),
        ];
        assert!(compare(&tree, &tree).is_empty());
    }

    #[test]
    fn missing_and_extra_entries_are_reported() {
        let expected = vec![record("a.txt", CopyClass::File)];
        let observed = vec![record("b.txt", CopyClass::File)];
        let problems = compare(&expected, &observed);
        assert_eq!(problems.len(), 2);
        assert!(problems[0].contains("a.txt: missing"));
        assert!(problems[1].contains("b.txt: in the copy but not in the source"));
    }

    #[test]
    fn every_differing_property_is_reported() {
        let expected = vec![record("a.txt", CopyClass::File)];
        let mut changed = record("a.txt", CopyClass::File);
        changed.size = 4;
        changed.sha256 = Some([8; 32]);
        changed.attributes = 0x21;
        changed.written = 9;
        changed.security = "O:S-1-5-18".into();
        changed.streams = vec!["Zone.Identifier=26".into()];
        let problems = compare(&expected, &[changed]);
        for needle in [
            "size",
            "content",
            "attributes",
            "timestamps",
            "security",
            "streams",
        ] {
            assert!(
                problems.iter().any(|p| p.contains(needle)),
                "{needle} not in {problems:?}"
            );
        }
    }

    #[test]
    fn a_folder_replaced_by_a_link_is_reported_once() {
        let expected = vec![record("Docs", CopyClass::Directory)];
        let mut link = record("Docs", CopyClass::Link);
        link.written = 99;
        let problems = compare(&expected, &[link]);
        assert_eq!(problems.len(), 1);
        assert!(problems[0].contains("is a link in the copy"));
    }

    #[test]
    fn source_changes_after_the_copy_are_detected() {
        let copied = record("a.txt", CopyClass::File);
        let mut now = EntryFacts {
            size: 3,
            written: 2,
            ..EntryFacts::default()
        };
        assert_eq!(source_change(&copied, &now), None);
        now.written = 3;
        assert!(source_change(&copied, &now).is_some());
        now.written = 2;
        now.size = 5;
        assert!(source_change(&copied, &now).is_some());
    }

    #[test]
    fn the_root_is_named_in_messages() {
        let expected = vec![record("", CopyClass::Directory)];
        assert!(compare(&expected, &[])[0].contains("(profile folder)"));
    }
}
