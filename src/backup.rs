//! Snapshot taken before any mutation: ProfileList export, hive file copies
//! and an ACL manifest of critical paths. Writes only into a new, private
//! backup folder; never touches the profile or the registry.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use crate::facts::{ntuser_path, usrclass_path};
use crate::json::Json;
use crate::log::{Level, Logger};
use crate::model::{SystemFacts, PROFILE_GUID_KEY, PROFILE_LIST_KEY};
use crate::platform;
use crate::scan::{classify, EntryKind};
use crate::timefmt;

const PHASE: &str = "backup";

/// UTF-16LE BOM followed by the header reg.exe writes for version 5 files.
const REG_HEADER: &str = "Windows Registry Editor Version 5.00";

/// Fixed paths, relative to the profile root, whose ACLs matter most for a
/// working logon. Top-level children are added at runtime.
const CRITICAL_RELATIVE_PATHS: &[&str] = &[
    "AppData",
    r"AppData\Local",
    r"AppData\Local\Microsoft",
    r"AppData\Local\Microsoft\Windows",
    r"AppData\Local\Packages",
    r"AppData\LocalLow",
    r"AppData\Roaming",
    r"AppData\Roaming\Microsoft",
    r"AppData\Roaming\Microsoft\Protect",
    r"AppData\Roaming\Microsoft\Credentials",
];

pub struct BackupOutcome {
    pub dir: PathBuf,
    pub files: Vec<(String, u64)>,
}

pub fn create(
    backup_root: &Path,
    facts: &SystemFacts,
    log: &mut Logger,
) -> Result<BackupOutcome, Box<dyn Error>> {
    let source_sid = facts.source.sid().ok_or("source SID is unknown")?;
    let target_sid = facts.target.sid().ok_or("target SID is unknown")?;
    let profile = facts
        .source_entry()
        .and_then(|e| e.profile_image_path_expanded.clone())
        .map(PathBuf::from)
        .ok_or("source profile path is unknown")?;

    fs::create_dir_all(backup_root)?;
    let dir = backup_root.join(format!("{}_{source_sid}", timefmt::now().compact()));
    platform::create_private_dir(&dir)?;
    log.event(
        Level::Info,
        PHASE,
        "backup_dir_created",
        "created private backup folder (SYSTEM + Administrators only)",
        vec![("path", dir.display().to_string().into())],
    )?;

    let mut files = Vec::new();

    let reg_file = dir.join("ProfileList.reg");
    export_and_verify(PROFILE_LIST_KEY, &reg_file, log)?;
    files.push(file_record(&dir, &reg_file)?);

    if platform::hklm_key_exists(PROFILE_GUID_KEY)? {
        let guid_file = dir.join("ProfileGuid.reg");
        export_and_verify(PROFILE_GUID_KEY, &guid_file, log)?;
        files.push(file_record(&dir, &guid_file)?);
    }

    let hive_dir = dir.join("hives");
    fs::create_dir(&hive_dir)?;
    for hive in [ntuser_path(&profile), usrclass_path(&profile)] {
        for copied in copy_hive_family(&hive, &hive_dir, log)? {
            files.push(file_record(&dir, &copied)?);
        }
    }

    let acl_file = dir.join("acl-manifest.json");
    let acl_entries = acl_manifest(&profile, log)?;
    fs::write(&acl_file, Json::Arr(acl_entries).render())?;
    files.push(file_record(&dir, &acl_file)?);
    log.event(
        Level::Info,
        PHASE,
        "acl_manifest_written",
        "saved owner/DACL of critical paths",
        vec![("path", acl_file.display().to_string().into())],
    )?;

    let manifest = Json::obj(vec![
        ("tool", "windows-profile-migration".into()),
        ("version", env!("CARGO_PKG_VERSION").into()),
        ("run", log.run_id().into()),
        ("created", timefmt::now().rfc3339().into()),
        ("computer", facts.computer_name.as_str().into()),
        ("source_sid", source_sid.into()),
        (
            "source_account",
            facts.source.account().map(|a| a.qualified_name()).into(),
        ),
        ("target_sid", target_sid.into()),
        (
            "target_account",
            facts.target.account().map(|a| a.qualified_name()).into(),
        ),
        ("profile_path", profile.display().to_string().into()),
        (
            "os_build",
            facts
                .os
                .as_ref()
                .ok()
                .map(|o| format!("{}.{}", o.build, o.ubr))
                .into(),
        ),
        (
            "files",
            Json::Arr(
                files
                    .iter()
                    .map(|(name, size)| {
                        Json::obj(vec![
                            ("name", name.as_str().into()),
                            ("bytes", (*size).into()),
                        ])
                    })
                    .collect(),
            ),
        ),
    ]);
    fs::write(dir.join("manifest.json"), manifest.render())?;
    log.event(
        Level::Info,
        PHASE,
        "backup_complete",
        "backup written",
        vec![
            ("path", dir.display().to_string().into()),
            ("files", files.len().into()),
        ],
    )?;
    Ok(BackupOutcome { dir, files })
}

fn export_and_verify(subkey: &str, dest: &Path, log: &mut Logger) -> Result<(), Box<dyn Error>> {
    platform::export_registry_key(subkey, dest)?;
    let bytes = fs::read(dest)?;
    if !is_reg_export(&bytes) {
        return Err(format!(
            "{} does not look like a reg.exe export (missing UTF-16 header)",
            dest.display()
        )
        .into());
    }
    log.event(
        Level::Info,
        PHASE,
        "registry_exported",
        &format!("exported HKLM\\{subkey}"),
        vec![
            ("path", dest.display().to_string().into()),
            ("bytes", bytes.len().into()),
        ],
    )?;
    Ok(())
}

/// True if `bytes` start with a UTF-16LE BOM and the regedit v5 header.
pub fn is_reg_export(bytes: &[u8]) -> bool {
    if bytes.len() < 2 || bytes[0] != 0xFF || bytes[1] != 0xFE {
        return false;
    }
    let header: Vec<u16> = REG_HEADER.encode_utf16().collect();
    let body = &bytes[2..];
    if body.len() < header.len() * 2 {
        return false;
    }
    header
        .iter()
        .enumerate()
        .all(|(i, &unit)| u16::from_le_bytes([body[2 * i], body[2 * i + 1]]) == unit)
}

/// Copies a hive and its sibling transaction logs (`.LOG1`, `.LOG2`,
/// `{guid}.TM.blf`, `.regtrans-ms`). A hive copied without its logs can be
/// missing the most recent writes.
fn copy_hive_family(
    hive: &Path,
    dest_dir: &Path,
    log: &mut Logger,
) -> Result<Vec<PathBuf>, Box<dyn Error>> {
    let (Some(parent), Some(name)) = (hive.parent(), hive.file_name()) else {
        return Err(format!("invalid hive path {}", hive.display()).into());
    };
    let prefix = name.to_string_lossy().to_ascii_lowercase();
    let mut copied = Vec::new();
    let entries = match fs::read_dir(parent) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            log.event(
                Level::Warn,
                PHASE,
                "hive_missing",
                "hive folder not found; nothing to copy",
                vec![("path", parent.display().to_string().into())],
            )?;
            return Ok(copied);
        }
        Err(err) => return Err(err.into()),
    };
    for entry in entries {
        let entry = entry?;
        let file_name = entry.file_name().to_string_lossy().into_owned();
        if !is_hive_family_member(&file_name, &prefix) || !entry.metadata()?.is_file() {
            continue;
        }
        let dest = dest_dir.join(&file_name);
        let written = fs::copy(entry.path(), &dest)?;
        let original = entry.metadata()?.len();
        if written != original {
            return Err(format!(
                "copy of {} is {written} bytes, expected {original}",
                entry.path().display()
            )
            .into());
        }
        log.event(
            Level::Info,
            PHASE,
            "hive_file_copied",
            "copied hive file",
            vec![
                ("from", entry.path().display().to_string().into()),
                ("to", dest.display().to_string().into()),
                ("bytes", written.into()),
            ],
        )?;
        copied.push(dest);
    }
    Ok(copied)
}

/// `ntuser.dat`, `ntuser.dat.LOG1`, `NTUSER.DAT{guid}.TM.blf`, ... but not
/// `ntuser.ini` or `ntuser.pol`.
pub fn is_hive_family_member(file_name: &str, hive_name_lower: &str) -> bool {
    file_name.to_ascii_lowercase().starts_with(hive_name_lower)
}

fn acl_manifest(profile: &Path, log: &mut Logger) -> Result<Vec<Json>, Box<dyn Error>> {
    let mut paths = vec![profile.to_path_buf()];
    for entry in fs::read_dir(profile)? {
        let entry = entry?;
        let metadata = entry.metadata()?;
        match classify(platform::file_attributes(&metadata)) {
            EntryKind::Directory | EntryKind::File => paths.push(entry.path()),
            EntryKind::ReparsePoint | EntryKind::CloudPlaceholder => {}
        }
    }
    for relative in CRITICAL_RELATIVE_PATHS {
        let path = profile.join(relative);
        if !paths.contains(&path) && fs::symlink_metadata(&path).is_ok() {
            paths.push(path);
        }
    }

    let mut entries = Vec::new();
    for path in paths {
        let shown = path.display().to_string();
        match platform::read_sddl(&path) {
            Ok(sddl) => entries.push(Json::obj(vec![
                ("path", shown.into()),
                ("sddl", sddl.into()),
            ])),
            Err(err) => {
                log.event(
                    Level::Warn,
                    PHASE,
                    "acl_unreadable",
                    "could not read security descriptor for manifest",
                    vec![
                        ("path", shown.clone().into()),
                        ("error", err.to_string().into()),
                    ],
                )?;
                entries.push(Json::obj(vec![
                    ("path", shown.into()),
                    ("error", err.to_string().into()),
                ]));
            }
        }
    }
    Ok(entries)
}

fn file_record(dir: &Path, path: &Path) -> Result<(String, u64), Box<dyn Error>> {
    let name = path.strip_prefix(dir).unwrap_or(path).display().to_string();
    Ok((name, fs::metadata(path)?.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16le_with_bom(text: &str) -> Vec<u8> {
        let mut bytes = vec![0xFF, 0xFE];
        for unit in text.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn reg_export_header_is_recognized() {
        let file = utf16le_with_bom(
            "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\x]\r\n",
        );
        assert!(is_reg_export(&file));
    }

    #[test]
    fn non_reg_content_is_rejected() {
        assert!(!is_reg_export(b""));
        assert!(!is_reg_export(b"Windows Registry Editor Version 5.00"));
        assert!(!is_reg_export(&utf16le_with_bom("REGEDIT4")));
        assert!(!is_reg_export(&utf16le_with_bom("Windows Registry")));
    }

    #[test]
    fn hive_family_includes_transaction_logs_only() {
        let hive = "ntuser.dat";
        for name in [
            "NTUSER.DAT",
            "ntuser.dat.LOG1",
            "NTUSER.DAT.LOG2",
            "NTUSER.DAT{016888bd-6c6f-11de-8d1d-001e0bcde3ec}.TM.blf",
            "NTUSER.DAT{016888bd-6c6f-11de-8d1d-001e0bcde3ec}.TMContainer00000000000000000001.regtrans-ms",
        ] {
            assert!(is_hive_family_member(name, hive), "{name}");
        }
        for name in ["ntuser.ini", "ntuser.pol", "UsrClass.dat"] {
            assert!(!is_hive_family_member(name, hive), "{name}");
        }
    }
}
