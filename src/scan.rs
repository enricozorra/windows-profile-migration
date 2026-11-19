//! Read-only walk of a profile directory.
//!
//! The walk never follows reparse points: profiles contain legacy junctions
//! (`Application Data`, `My Documents`, ...) that point back into the tree
//! or at denied locations, and following them loops or double-counts. Cloud
//! placeholders are not opened either, so the scan cannot trigger a download.

use std::fs;
use std::io;
use std::path::Path;

use crate::model::{KnownPaths, ProfileScan, SkipReason, SkippedEntry};
use crate::platform;
use crate::sddl;

pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0010;
pub const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
pub const FILE_ATTRIBUTE_OFFLINE: u32 = 0x1000;
pub const FILE_ATTRIBUTE_ENCRYPTED: u32 = 0x4000;
pub const FILE_ATTRIBUTE_RECALL_ON_OPEN: u32 = 0x0004_0000;
pub const FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS: u32 = 0x0040_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    Directory,
    File,
    /// Junction, symlink or other reparse point: recorded, never entered.
    ReparsePoint,
    /// OneDrive/cloud-files placeholder: recorded, never opened.
    CloudPlaceholder,
}

/// Classifies an entry from its Win32 attributes. Cloud placeholders are
/// also reparse points, so they are checked first.
pub fn classify(attributes: u32) -> EntryKind {
    let recall = FILE_ATTRIBUTE_RECALL_ON_OPEN
        | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
        | FILE_ATTRIBUTE_OFFLINE;
    if attributes & recall != 0 {
        EntryKind::CloudPlaceholder
    } else if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        EntryKind::ReparsePoint
    } else if attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
        EntryKind::Directory
    } else {
        EntryKind::File
    }
}

/// Walks `root` and tallies everything the migration will have to touch or
/// skip. `read_sddl` returns the owner+DACL SDDL for a path.
pub fn scan_profile(
    root: &Path,
    source_sid: &str,
    read_sddl: &mut dyn FnMut(&Path) -> io::Result<String>,
) -> ProfileScan {
    let mut scan = ProfileScan::default();
    // The caller has already verified the root is a real directory.
    scan.directories += 1;
    analyze_security(root, source_sid, read_sddl, &mut scan);

    // Iterative DFS: profile trees can be deep enough to make recursion
    // a stack-overflow risk.
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(err) => {
                record_inaccessible(&mut scan, &dir, err);
                continue;
            }
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(err) => {
                    record_inaccessible(&mut scan, &dir, err);
                    continue;
                }
            };
            let path = entry.path();
            // DirEntry::metadata does not traverse links on any platform.
            let metadata = match entry.metadata() {
                Ok(m) => m,
                Err(err) => {
                    record_inaccessible(&mut scan, &path, err);
                    continue;
                }
            };
            let attributes = platform::file_attributes(&metadata);
            match classify(attributes) {
                EntryKind::CloudPlaceholder => {
                    let shown = path.display().to_string();
                    scan.cloud_placeholders.add(shown.clone());
                    scan.skipped.push(SkippedEntry {
                        path: shown,
                        reason: SkipReason::CloudPlaceholder,
                    });
                }
                EntryKind::ReparsePoint => {
                    let shown = path.display().to_string();
                    scan.reparse_points.add(shown.clone());
                    scan.skipped.push(SkippedEntry {
                        path: shown,
                        reason: SkipReason::ReparsePoint,
                    });
                }
                kind @ (EntryKind::Directory | EntryKind::File) => {
                    if attributes & FILE_ATTRIBUTE_ENCRYPTED != 0 {
                        scan.encrypted.add(path.display().to_string());
                    }
                    analyze_security(&path, source_sid, read_sddl, &mut scan);
                    if kind == EntryKind::Directory {
                        scan.directories += 1;
                        pending.push(path);
                    } else {
                        scan.files += 1;
                    }
                }
            }
        }
    }
    scan
}

fn analyze_security(
    path: &Path,
    source_sid: &str,
    read_sddl: &mut dyn FnMut(&Path) -> io::Result<String>,
    scan: &mut ProfileScan,
) {
    let text = match read_sddl(path) {
        Ok(text) => text,
        Err(err) => {
            record_inaccessible(scan, path, err);
            return;
        }
    };
    let descriptor = match sddl::parse(&text) {
        Ok(sd) => sd,
        Err(err) => {
            scan.unparsable_sddl
                .add(format!("{}: {err}", path.display()));
            scan.skipped.push(SkippedEntry {
                path: path.display().to_string(),
                reason: SkipReason::UnparsableSddl(err.to_string()),
            });
            return;
        }
    };
    let refs = sddl::references(&descriptor, source_sid);
    let shown = path.display().to_string();
    if refs.is_owner {
        scan.owned_by_source.add(shown.clone());
    }
    if refs.explicit_aces > 0 {
        scan.explicit_source_aces.add(shown.clone());
        if descriptor.dacl_is_protected() {
            scan.protected_dacls_with_source.add(shown);
        }
    }
}

fn record_inaccessible(scan: &mut ProfileScan, path: &Path, err: io::Error) {
    scan.inaccessible.add(format!("{}: {err}", path.display()));
    scan.skipped.push(SkippedEntry {
        path: path.display().to_string(),
        reason: SkipReason::Inaccessible(err.to_string()),
    });
}

/// Checks fixed locations with known migration caveats.
pub fn inspect_known_paths(root: &Path, source_sid: &str) -> KnownPaths {
    let mut known = KnownPaths::default();
    let roaming_ms = root.join("AppData").join("Roaming").join("Microsoft");
    let local_ms = root.join("AppData").join("Local").join("Microsoft");

    known.dpapi_master_keys = is_real_dir(&roaming_ms.join("Protect").join(source_sid));
    for dir in [local_ms.join("Credentials"), roaming_ms.join("Credentials")] {
        match count_children(&dir, |_| true) {
            Ok(n) => known.credential_files += n,
            Err(err) => known.errors.push(format!("{}: {err}", dir.display())),
        }
    }
    known.onedrive_client_state = is_real_dir(&local_ms.join("OneDrive"));

    match fs::read_dir(root) {
        Ok(entries) => {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.to_ascii_lowercase().starts_with("onedrive") {
                    known.onedrive_folders.push(name);
                }
            }
            known.onedrive_folders.sort();
        }
        Err(err) => known.errors.push(format!("{}: {err}", root.display())),
    }

    let packages = root.join("AppData").join("Local").join("Packages");
    match count_children(&packages, |m| m.is_dir()) {
        Ok(n) => known.appx_package_dirs = n,
        Err(err) => known.errors.push(format!("{}: {err}", packages.display())),
    }
    known
}

fn is_real_dir(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| m.is_dir())
}

/// Counts children matching `filter`. A missing directory counts as zero;
/// any other error is returned so it can be reported.
fn count_children(dir: &Path, filter: impl Fn(&fs::Metadata) -> bool) -> io::Result<usize> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(err) => return Err(err),
    };
    let mut count = 0;
    for entry in entries {
        if filter(&entry?.metadata()?) {
            count += 1;
        }
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const SRC: &str = "S-1-5-21-100-200-300-1001";

    /// A unique scratch directory under the system temp dir, removed on drop.
    struct TempTree(PathBuf);

    impl TempTree {
        fn new(name: &str) -> TempTree {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let dir = std::env::temp_dir().join(format!(
                "windows-profile-migration-test-{name}-{}-{nanos}",
                std::process::id()
            ));
            fs::create_dir_all(&dir).unwrap();
            TempTree(dir)
        }
    }

    impl Drop for TempTree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn owner_sddl(_: &Path) -> io::Result<String> {
        Ok(format!(
            "O:{SRC}G:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;{SRC})"
        ))
    }

    #[test]
    fn classify_prefers_cloud_over_reparse() {
        let cloud = FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS;
        assert_eq!(classify(cloud), EntryKind::CloudPlaceholder);
        assert_eq!(
            classify(FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY),
            EntryKind::ReparsePoint
        );
        assert_eq!(classify(FILE_ATTRIBUTE_DIRECTORY), EntryKind::Directory);
        assert_eq!(classify(0x20), EntryKind::File);
    }

    #[test]
    fn scan_counts_entries_and_acl_footprint() {
        let tree = TempTree::new("counts");
        fs::create_dir_all(tree.0.join("Documents/Sub")).unwrap();
        fs::write(tree.0.join("Documents/a.txt"), b"a").unwrap();
        fs::write(tree.0.join("Documents/Sub/b.txt"), b"b").unwrap();

        let scan = scan_profile(&tree.0, SRC, &mut owner_sddl);
        assert_eq!(scan.directories, 3);
        assert_eq!(scan.files, 2);
        assert_eq!(scan.owned_by_source.count, 5);
        assert_eq!(scan.explicit_source_aces.count, 5);
        assert_eq!(scan.protected_dacls_with_source.count, 5);
        assert_eq!(scan.inaccessible.count, 0);
    }

    #[cfg(unix)]
    #[test]
    fn scan_does_not_follow_a_link_loop() {
        let tree = TempTree::new("loop");
        fs::create_dir_all(tree.0.join("AppData")).unwrap();
        // Mirrors the legacy "Application Data" junction that points back
        // into the profile.
        std::os::unix::fs::symlink(&tree.0, tree.0.join("AppData/Application Data")).unwrap();

        let scan = scan_profile(&tree.0, SRC, &mut owner_sddl);
        assert_eq!(scan.reparse_points.count, 1);
        assert_eq!(scan.directories, 2);
        assert_eq!(scan.skipped.len(), 1);
        assert_eq!(scan.skipped[0].reason, SkipReason::ReparsePoint);
    }

    #[test]
    fn security_read_failures_are_recorded_not_fatal() {
        let tree = TempTree::new("denied");
        fs::write(tree.0.join("x.txt"), b"x").unwrap();
        let mut deny = |_: &Path| -> io::Result<String> {
            Err(io::Error::new(io::ErrorKind::PermissionDenied, "denied"))
        };
        let scan = scan_profile(&tree.0, SRC, &mut deny);
        assert_eq!(scan.files, 1);
        assert_eq!(scan.inaccessible.count, 2);
    }

    #[test]
    fn unparsable_sddl_is_recorded() {
        let tree = TempTree::new("garbage");
        let mut garbage = |_: &Path| -> io::Result<String> { Ok("garbage".into()) };
        let scan = scan_profile(&tree.0, SRC, &mut garbage);
        assert_eq!(scan.unparsable_sddl.count, 1);
    }

    #[test]
    fn known_paths_are_detected() {
        let tree = TempTree::new("known");
        let root = &tree.0;
        fs::create_dir_all(root.join(format!("AppData/Roaming/Microsoft/Protect/{SRC}"))).unwrap();
        fs::create_dir_all(root.join("AppData/Roaming/Microsoft/Credentials")).unwrap();
        fs::write(root.join("AppData/Roaming/Microsoft/Credentials/ABC"), b"x").unwrap();
        fs::create_dir_all(root.join("AppData/Local/Microsoft/OneDrive")).unwrap();
        fs::create_dir_all(root.join("OneDrive - Contoso")).unwrap();
        fs::create_dir_all(
            root.join("AppData/Local/Packages/Microsoft.WindowsCalculator_8wekyb3d8bbwe"),
        )
        .unwrap();

        let known = inspect_known_paths(root, SRC);
        assert!(known.dpapi_master_keys);
        assert_eq!(known.credential_files, 1);
        assert!(known.onedrive_client_state);
        assert_eq!(
            known.onedrive_folders,
            vec!["OneDrive - Contoso".to_string()]
        );
        assert_eq!(known.appx_package_dirs, 1);
        assert!(known.errors.is_empty());
    }

    #[test]
    fn known_paths_on_empty_profile_are_clean() {
        let tree = TempTree::new("empty");
        let known = inspect_known_paths(&tree.0, SRC);
        assert_eq!(known, KnownPaths::default());
    }
}
