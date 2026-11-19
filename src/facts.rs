//! Gathers `SystemFacts` through the platform layer. Read-only.
//!
//! Failures that make the whole run meaningless (cannot read the token or
//! the ProfileList) are returned as errors. Failures of a single probe are
//! recorded in the facts so preflight reports them as findings.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use crate::account;
use crate::model::{
    AccountInput, AccountResolution, HiveFileProbe, LookupOutcome, ProfileDirFacts, SystemFacts,
    APPX_USER_STORE_KEY,
};
use crate::platform;
use crate::scan::{self, FILE_ATTRIBUTE_REPARSE_POINT};

pub struct Request {
    pub source: String,
    pub target: String,
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
        }
    }
    Ok(facts)
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
