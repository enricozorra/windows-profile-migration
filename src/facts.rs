//! Gathers `SystemFacts` through the platform layer. Read-only.
//!
//! Failures that make the whole run meaningless (cannot read the token or
//! the ProfileList) are returned as errors. Failures of a single probe are
//! recorded in the facts so preflight reports them as findings.

use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::account;
use crate::apps::{self, AppContext};
use crate::hive_scan::Inspector;
use crate::model::{
    AccountInfo, AccountInput, AccountReferences, AccountResolution, HiveFileProbe, LocalGroups,
    LookupOutcome, ProfileDirFacts, RegData, RegistryInspection, SystemFacts, TargetDirFacts,
    APPX_USER_STORE_KEY, STAGING_SUFFIX,
};
use crate::platform;
use crate::references::{self, AccountNames};
use crate::scan::{self, FILE_ATTRIBUTE_REPARSE_POINT};

pub struct Request {
    pub source: String,
    pub target: String,
    /// Parent of the private scratch folder used to read a copy of the
    /// source hives. The scratch folder is removed before `gather` returns.
    pub work_dir: PathBuf,
}

pub fn gather(request: &Request) -> Result<SystemFacts, Box<dyn Error>> {
    let token = platform::current_token()?;
    let computer_name = platform::computer_name()?;
    let os = platform::os_version().map_err(|e| e.to_string());
    let domain = platform::domain_membership();
    let source = resolve(&request.source, &computer_name);
    let target = resolve(&request.target, &computer_name);
    let profile_list = platform::read_profile_list()?;
    let loaded_hives = platform::loaded_user_hives()?;

    let mut facts = SystemFacts {
        token,
        os,
        computer_name,
        domain,
        source,
        target,
        profile_list,
        loaded_hives,
        hive_files: Vec::new(),
        appx_store_present: false,
        profile_dir: None,
        known_paths: None,
        scan: None,
        target_dir: None,
        free_bytes: None,
        registry: None,
        local_groups: None,
        account_references: None,
        apps: Vec::new(),
    };

    if let Some(sid) = facts.source.sid().map(str::to_string) {
        facts.appx_store_present =
            platform::hklm_key_exists(&format!("{APPX_USER_STORE_KEY}\\{sid}"))?;
    }

    let profile_path = facts
        .source_entry()
        .and_then(|e| e.profile_image_path_expanded.clone())
        .map(PathBuf::from);
    if let Some(path) = profile_path {
        facts.hive_files = probe_hive_files(&path);
        let dir = profile_dir_facts(&path);
        let scannable = dir.exists && !dir.is_reparse_point;
        facts.profile_dir = Some(dir);
        if let (true, Some(sid)) = (scannable, facts.source.sid().map(str::to_string)) {
            facts.known_paths = Some(scan::inspect_known_paths(&path, &sid));
            let mut read_sddl = |p: &Path| platform::read_sddl(p);
            facts.scan = Some(scan::scan_profile(&path, &sid, &mut read_sddl));
            facts.registry = Some(inspect_registry(&facts, &path, &sid, &request.work_dir));
        }
    }

    if let (Some(root), Some(target)) = (
        facts.profile_list.profiles_directory.clone(),
        facts.target.account().cloned(),
    ) {
        let root = PathBuf::from(root);
        facts.target_dir = Some(target_dir_facts(&root, &target.name));
        facts.free_bytes = Some(platform::free_bytes(&root).map_err(|e| e.to_string()));
    }
    if let (Some(source), Some(target)) = (facts.source.account(), facts.target.account()) {
        facts.local_groups = Some(LocalGroups {
            source: platform::local_groups(&source.qualified_name()).map_err(|e| e.to_string()),
            target: platform::local_groups(&target.qualified_name()).map_err(|e| e.to_string()),
        });
    }
    if let Some(source) = facts.source.account().cloned() {
        facts.account_references = Some(account_references(&source));
    }
    if let (Some(dir), Some(known), Some(sid)) = (
        facts.profile_dir.as_ref(),
        facts.known_paths.as_ref(),
        facts.source.sid(),
    ) {
        facts.apps = apps::detect_all(&AppContext {
            profile: &dir.path,
            source_sid: sid,
            known,
            registry: facts.registry.as_ref().and_then(|r| r.as_ref().ok()),
            target_profile: facts.target_dir.as_ref().map(|d| d.path.as_path()),
        });
    }
    Ok(facts)
}

/// The new folder takes the target account's name, as the profile service
/// would name it at a first logon.
fn target_dir_facts(profiles_root: &Path, account_name: &str) -> TargetDirFacts {
    let path = profiles_root.join(account_name);
    let staging_path = profiles_root.join(format!("{account_name}{STAGING_SUFFIX}"));
    TargetDirFacts {
        folder_name: account_name.to_string(),
        exists: fs::symlink_metadata(&path).is_ok(),
        staging_exists: fs::symlink_metadata(&staging_path).is_ok(),
        path,
        staging_path,
    }
}

/// Reads every value of the source user's hives without ever loading the
/// original files: a logged-on user's hive is read where it is already
/// mounted; otherwise a copy in a private folder is mounted briefly, so log
/// replay and any other write can only touch the copy.
fn inspect_registry(
    facts: &SystemFacts,
    profile: &Path,
    sid: &str,
    work_dir: &Path,
) -> Result<RegistryInspection, String> {
    let classes = format!("{sid}_Classes");
    let is_loaded = |name: &str| {
        facts
            .loaded_hives
            .iter()
            .any(|h| h.eq_ignore_ascii_case(name))
    };
    let profile_text = profile.display().to_string();

    if is_loaded(sid) {
        let mut inspector = Inspector::new(&profile_text, "live, user logged on");
        for (label, key) in [("HKCU", sid), ("HKCU\\Classes", classes.as_str())] {
            if !is_loaded(key) {
                continue;
            }
            let mut visit = |k: &str, v: &str, d: &RegData| inspector.visit(label, k, v, d);
            let errors = platform::walk_loaded_hive(key, &mut visit).map_err(|e| e.to_string())?;
            errors.into_iter().for_each(|e| inspector.record_error(e));
        }
        return Ok(inspector.finish());
    }

    let mut inspector = Inspector::new(&profile_text, "private copy");
    let scratch = scratch_dir(work_dir).map_err(|e| e.to_string())?;
    let walked = (|| -> io::Result<()> {
        for (label, hive) in [
            ("HKCU", ntuser_path(profile)),
            ("HKCU\\Classes", usrclass_path(profile)),
        ] {
            if !hive.is_file() {
                continue;
            }
            let copy_dir = scratch.join(if label == "HKCU" {
                "ntuser"
            } else {
                "usrclass"
            });
            fs::create_dir(&copy_dir)?;
            let copy = copy_hive_family(&hive, &copy_dir)?;
            let mut visit = |k: &str, v: &str, d: &RegData| inspector.visit(label, k, v, d);
            let errors = platform::walk_hive_file(&copy, &mut visit)?;
            errors.into_iter().for_each(|e| inspector.record_error(e));
        }
        Ok(())
    })();
    // The copy holds the user's secrets; a failed cleanup is reported,
    // never ignored.
    if let Err(err) = fs::remove_dir_all(&scratch) {
        inspector.record_error(format!(
            "could not remove the scratch copy {}: {err}",
            scratch.display()
        ));
    }
    walked.map_err(|e| e.to_string())?;
    Ok(inspector.finish())
}

/// A new, uniquely named folder that only SYSTEM and Administrators can open.
fn scratch_dir(work_dir: &Path) -> io::Result<PathBuf> {
    fs::create_dir_all(work_dir)?;
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let dir = work_dir.join(format!("registry-{}-{nanos}", std::process::id()));
    platform::create_private_dir(&dir)?;
    Ok(dir)
}

/// Copies a hive with its transaction logs (.LOG1/.LOG2), which the load
/// needs to replay anything not yet flushed into the hive file.
fn copy_hive_family(hive: &Path, dest_dir: &Path) -> io::Result<PathBuf> {
    let name = hive
        .file_name()
        .ok_or_else(|| io::Error::other(format!("{} has no file name", hive.display())))?
        .to_string_lossy()
        .to_ascii_lowercase();
    let parent = hive
        .parent()
        .ok_or_else(|| io::Error::other(format!("{} has no parent", hive.display())))?;
    let wanted = [name.clone(), format!("{name}.log1"), format!("{name}.log2")];
    let mut copied = None;
    for entry in fs::read_dir(parent)? {
        let entry = entry?;
        let file_name = entry.file_name().to_string_lossy().into_owned();
        let lower = file_name.to_ascii_lowercase();
        if !wanted.contains(&lower) {
            continue;
        }
        let dest = dest_dir.join(&file_name);
        fs::copy(entry.path(), &dest)?;
        if lower == name {
            copied = Some(dest);
        }
    }
    copied
        .ok_or_else(|| io::Error::other(format!("{} disappeared during the copy", hive.display())))
}

fn account_references(source: &AccountInfo) -> AccountReferences {
    let names = AccountNames {
        sid: &source.sid,
        domain: &source.domain,
        name: &source.name,
    };
    let mut refs = AccountReferences::default();
    match platform::service_accounts() {
        Ok(services) => {
            refs.services = services
                .into_iter()
                .filter(|(_, account)| references::names_account(account, &names))
                .map(|(service, account)| format!("{service} (runs as {account})"))
                .collect();
        }
        Err(err) => refs.errors.push(format!("services: {err}")),
    }
    match std::env::var_os("SystemRoot") {
        Some(root) => {
            let tasks = PathBuf::from(root).join("System32").join("Tasks");
            collect_tasks(&tasks, &tasks, &names, &mut refs);
        }
        None => refs
            .errors
            .push("scheduled tasks: SystemRoot is not set".into()),
    }
    refs
}

/// Walks the task store. Task definitions are small XML files; a folder or
/// file that cannot be read is recorded, and the walk continues.
fn collect_tasks(root: &Path, dir: &Path, names: &AccountNames, refs: &mut AccountReferences) {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) => {
            refs.errors.push(format!("{}: {err}", dir.display()));
            return;
        }
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                refs.errors.push(format!("{}: {err}", dir.display()));
                continue;
            }
        };
        let path = entry.path();
        match entry.file_type() {
            Ok(kind) if kind.is_dir() => collect_tasks(root, &path, names, refs),
            Ok(kind) if kind.is_file() => match fs::read(&path) {
                Ok(bytes) => {
                    let xml = references::decode_text_file(&bytes);
                    if references::task_user_ids(&xml)
                        .iter()
                        .any(|id| references::names_account(id, names))
                    {
                        let relative = path.strip_prefix(root).unwrap_or(&path);
                        refs.scheduled_tasks
                            .push(format!("\\{}", relative.display()));
                    }
                }
                Err(err) => refs.errors.push(format!("{}: {err}", path.display())),
            },
            Ok(_) => {}
            Err(err) => refs.errors.push(format!("{}: {err}", path.display())),
        }
    }
}

fn resolve(input: &str, computer_name: &str) -> AccountResolution {
    let (input_kind, lookup) = match account::classify(input) {
        Err(reason) => (AccountInput::Malformed, LookupOutcome::Invalid(reason)),
        Ok(AccountInput::Sid(sid)) => {
            let lookup = platform::lookup_account_sid(&sid);
            (AccountInput::Sid(sid), lookup)
        }
        // Not looked up: preflight rejects bare names as ambiguous, and a
        // lookup would only show which of the candidates LSA picked first.
        Ok(AccountInput::Bare) => (
            AccountInput::Bare,
            LookupOutcome::Invalid(format!("'{input}' is ambiguous")),
        ),
        Ok(kind) => {
            let name = account::expand_local_shorthand(input, computer_name);
            (kind, platform::lookup_account_name(&name))
        }
    };
    AccountResolution {
        input: input.trim().to_string(),
        input_kind,
        lookup,
    }
}

pub fn ntuser_path(profile: &Path) -> PathBuf {
    profile.join("NTUSER.DAT")
}

pub fn usrclass_path(profile: &Path) -> PathBuf {
    profile
        .join("AppData")
        .join("Local")
        .join("Microsoft")
        .join("Windows")
        .join("UsrClass.dat")
}

fn probe_hive_files(profile: &Path) -> Vec<HiveFileProbe> {
    [
        ("NTUSER.DAT", ntuser_path(profile)),
        ("UsrClass.dat", usrclass_path(profile)),
    ]
    .into_iter()
    .map(|(label, path)| HiveFileProbe {
        label,
        state: platform::probe_exclusive(&path),
        path,
    })
    .collect()
}

fn profile_dir_facts(path: &Path) -> ProfileDirFacts {
    match fs::symlink_metadata(path) {
        Ok(metadata) => ProfileDirFacts {
            path: path.to_path_buf(),
            exists: metadata.is_dir() || metadata.file_type().is_symlink(),
            is_reparse_point: platform::file_attributes(&metadata) & FILE_ATTRIBUTE_REPARSE_POINT
                != 0,
        },
        Err(_) => ProfileDirFacts {
            path: path.to_path_buf(),
            exists: false,
            is_reparse_point: false,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hive_paths_are_where_windows_keeps_them() {
        let root = Path::new("profile");
        assert_eq!(ntuser_path(root), root.join("NTUSER.DAT"));
        assert!(
            usrclass_path(root).ends_with("AppData/Local/Microsoft/Windows/UsrClass.dat")
                || usrclass_path(root).ends_with(r"AppData\Local\Microsoft\Windows\UsrClass.dat")
        );
    }

    #[test]
    fn target_dir_uses_the_account_name_and_detects_leftovers() {
        let root = std::env::temp_dir().join(format!(
            "windows-profile-migration-facts-{}",
            std::process::id()
        ));
        fs::create_dir_all(root.join(format!("jdoe{STAGING_SUFFIX}"))).unwrap();
        let dir = target_dir_facts(&root, "jdoe");
        fs::remove_dir_all(&root).unwrap();
        assert_eq!(dir.path, root.join("jdoe"));
        assert!(!dir.exists);
        assert!(dir.staging_exists);
    }

    #[test]
    fn hive_copy_takes_the_logs_but_not_the_transaction_files() {
        let base = std::env::temp_dir().join(format!(
            "windows-profile-migration-hivecopy-{}",
            std::process::id()
        ));
        let profile = base.join("profile");
        let dest = base.join("dest");
        fs::create_dir_all(&profile).unwrap();
        fs::create_dir_all(&dest).unwrap();
        for name in [
            "NTUSER.DAT",
            "ntuser.dat.LOG1",
            "ntuser.dat.LOG2",
            "NTUSER.DAT{guid}.TM.blf",
            "Other.txt",
        ] {
            fs::write(profile.join(name), name).unwrap();
        }
        let copy = copy_hive_family(&profile.join("NTUSER.DAT"), &dest).unwrap();
        let mut copied: Vec<String> = fs::read_dir(&dest)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        copied.sort();
        fs::remove_dir_all(&base).unwrap();
        assert_eq!(copy, dest.join("NTUSER.DAT"));
        assert_eq!(
            copied,
            vec!["NTUSER.DAT", "ntuser.dat.LOG1", "ntuser.dat.LOG2"]
        );
    }

    #[test]
    fn malformed_input_is_classified_without_lookup() {
        let resolution = resolve("S-1-5-21-x", "PC01");
        assert_eq!(resolution.input_kind, AccountInput::Malformed);
        assert!(matches!(resolution.lookup, LookupOutcome::Invalid(_)));
    }

    #[test]
    fn bare_name_is_not_looked_up() {
        let resolution = resolve("jdoe", "PC01");
        assert_eq!(resolution.input_kind, AccountInput::Bare);
        assert!(matches!(resolution.lookup, LookupOutcome::Invalid(_)));
    }
}
