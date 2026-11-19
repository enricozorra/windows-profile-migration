//! Plain data gathered from the system. `facts` fills these in through the
//! platform layer; `preflight` and `plan` only read them, which keeps every
//! decision testable without Windows.

use std::path::PathBuf;

/// Registry path of the profile list, relative to HKLM.
pub const PROFILE_LIST_KEY: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";
/// Domain profiles map the user's AD objectGUID to a SID here.
pub const PROFILE_GUID_KEY: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileGuid";
/// Per-user AppX registration state, relative to HKLM.
pub const APPX_USER_STORE_KEY: &str =
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore";

/// Value the execution phase writes into ProfileList\<TargetSID> before any
/// other change. Its presence anywhere means a previous run did not finish.
pub const MIGRATION_MARKER_VALUE: &str = "WindowsProfileMigrationSourceSid";
/// Prefix of the temporary HKU mount names the execution phase will use.
pub const HIVE_MOUNT_PREFIX: &str = "windows-profile-migration_";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenInfo {
    pub user_sid: String,
    pub is_elevated: bool,
    pub is_admin_member: bool,
    /// Privilege names present in the token (enabled or not), e.g.
    /// `SeBackupPrivilege`.
    pub privileges: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsVersion {
    pub product_name: String,
    pub display_version: String,
    pub installation_type: String,
    pub build: u32,
    pub ubr: u32,
}

// Some variants are only constructed by the Windows platform layer.
#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainMembership {
    Domain(String),
    Workgroup(String),
    Unjoined,
    /// NetGetJoinInformation failed; carries the reason.
    Unknown(String),
}

/// SID_NAME_USE, reduced to what the checks distinguish.
// Some variants are only constructed by the Windows platform layer.
#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountKind {
    User,
    Group,
    Domain,
    Alias,
    WellKnownGroup,
    DeletedAccount,
    Computer,
    Other(i32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountInfo {
    pub sid: String,
    pub domain: String,
    pub name: String,
    pub kind: AccountKind,
}

impl AccountInfo {
    pub fn qualified_name(&self) -> String {
        format!("{}\\{}", self.domain, self.name)
    }
}

/// How the operator wrote an account on the command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountInput {
    Sid(String),
    /// `DOMAIN\user` or `.\user`.
    Qualified,
    /// `user@domain.tld`.
    Upn,
    /// `user`: ambiguous between a local and a domain account.
    Bare,
    /// Could not be classified at all (see the lookup's `Invalid` reason).
    Malformed,
}

// Some variants are only constructed by the Windows platform layer.
#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupOutcome {
    Found(AccountInfo),
    /// ERROR_NONE_MAPPED: no account by that name/SID.
    NotFound,
    /// Any other failure (DC unreachable, broken trust, ...). Kept apart from
    /// NotFound so an outage is never mistaken for a missing account.
    Failed(String),
    /// The input could not be parsed (e.g. a malformed SID).
    Invalid(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountResolution {
    pub input: String,
    pub input_kind: AccountInput,
    pub lookup: LookupOutcome,
}

impl AccountResolution {
    /// The SID to operate on: the resolved one, or the literal SID input.
    pub fn sid(&self) -> Option<&str> {
        match (&self.lookup, &self.input_kind) {
            (LookupOutcome::Found(info), _) => Some(&info.sid),
            (_, AccountInput::Sid(sid)) => Some(sid),
            _ => None,
        }
    }

    pub fn account(&self) -> Option<&AccountInfo> {
        match &self.lookup {
            LookupOutcome::Found(info) => Some(info),
            _ => None,
        }
    }
}

// Some variants are only constructed by the Windows platform layer.
#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SidValue {
    Missing,
    Valid(String),
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileListEntry {
    /// Subkey name: a SID, possibly suffixed with `.bak`.
    pub key_name: String,
    pub profile_image_path: Option<String>,
    pub profile_image_path_expanded: Option<String>,
    pub flags: Option<u32>,
    pub state: Option<u32>,
    pub ref_count: Option<u32>,
    pub sid_value: SidValue,
    pub guid: Option<String>,
    pub migration_marker: Option<String>,
}

impl ProfileListEntry {
    pub fn is_bak(&self) -> bool {
        self.key_name.to_ascii_lowercase().ends_with(".bak")
    }

    /// The key name without any `.bak` suffix.
    pub fn base_sid(&self) -> &str {
        if self.is_bak() {
            &self.key_name[..self.key_name.len() - 4]
        } else {
            &self.key_name
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProfileListSnapshot {
    pub profiles_directory: Option<String>,
    pub entries: Vec<ProfileListEntry>,
}

// Some variants are only constructed by the Windows platform layer.
#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockState {
    Missing,
    Unlocked,
    /// Opened by another process (ERROR_SHARING_VIOLATION).
    Locked,
    Error(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HiveFileProbe {
    pub label: &'static str,
    pub path: PathBuf,
    pub state: LockState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileDirFacts {
    pub path: PathBuf,
    pub exists: bool,
    pub is_reparse_point: bool,
}

/// A counter that keeps the first few examples for the report.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Tally {
    pub count: usize,
    pub samples: Vec<String>,
}

impl Tally {
    pub const MAX_SAMPLES: usize = 15;

    pub fn add(&mut self, sample: impl Into<String>) {
        self.count += 1;
        if self.samples.len() < Self::MAX_SAMPLES {
            self.samples.push(sample.into());
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipReason {
    ReparsePoint,
    CloudPlaceholder,
    Inaccessible(String),
    UnparsableSddl(String),
}

/// One entry the scan did not analyze. Unlike the tallies, this list is
/// complete, so every skipped item can be logged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedEntry {
    pub path: String,
    pub reason: SkipReason,
}

/// Result of a read-only walk of the profile directory.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProfileScan {
    pub directories: usize,
    pub files: usize,
    pub reparse_points: Tally,
    pub cloud_placeholders: Tally,
    pub encrypted: Tally,
    pub inaccessible: Tally,
    pub owned_by_source: Tally,
    pub explicit_source_aces: Tally,
    pub protected_dacls_with_source: Tally,
    pub unparsable_sddl: Tally,
    pub skipped: Vec<SkippedEntry>,
}

/// Locations with known migration caveats, checked by name.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KnownPaths {
    /// AppData\Roaming\Microsoft\Protect\<SourceSID> exists (DPAPI master keys).
    pub dpapi_master_keys: bool,
    /// Files under AppData\{Local,Roaming}\Microsoft\Credentials.
    pub credential_files: usize,
    /// Top-level `OneDrive*` folders and the OneDrive client's local state.
    pub onedrive_folders: Vec<String>,
    pub onedrive_client_state: bool,
    /// Subfolders of AppData\Local\Packages (AppX/UWP per-user state).
    pub appx_package_dirs: usize,
    /// Locations that exist but could not be read.
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemFacts {
    pub token: TokenInfo,
    /// Err carries why the version could not be read.
    pub os: Result<OsVersion, String>,
    pub computer_name: String,
    pub domain: DomainMembership,
    pub source: AccountResolution,
    pub target: AccountResolution,
    pub profile_list: ProfileListSnapshot,
    pub loaded_hives: Vec<String>,
    pub hive_files: Vec<HiveFileProbe>,
    pub appx_store_present: bool,
    pub profile_dir: Option<ProfileDirFacts>,
    pub known_paths: Option<KnownPaths>,
    pub scan: Option<ProfileScan>,
}

impl SystemFacts {
    pub fn source_entry(&self) -> Option<&ProfileListEntry> {
        let sid = self.source.sid()?;
        self.profile_list
            .entries
            .iter()
            .find(|e| !e.is_bak() && crate::sid::sid_eq(&e.key_name, sid))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tally_keeps_count_beyond_sample_cap() {
        let mut tally = Tally::default();
        for i in 0..(Tally::MAX_SAMPLES + 5) {
            tally.add(format!("item{i}"));
        }
        assert_eq!(tally.count, Tally::MAX_SAMPLES + 5);
        assert_eq!(tally.samples.len(), Tally::MAX_SAMPLES);
    }

    #[test]
    fn bak_suffix_is_case_insensitive() {
        let entry = ProfileListEntry {
            key_name: "S-1-5-21-1-2-3-1001.BAK".into(),
            profile_image_path: None,
            profile_image_path_expanded: None,
            flags: None,
            state: None,
            ref_count: None,
            sid_value: SidValue::Missing,
            guid: None,
            migration_marker: None,
        };
        assert!(entry.is_bak());
        assert_eq!(entry.base_sid(), "S-1-5-21-1-2-3-1001");
    }

    #[test]
    fn literal_sid_input_is_used_when_lookup_fails() {
        let resolution = AccountResolution {
            input: "S-1-5-21-1-2-3-1001".into(),
            input_kind: AccountInput::Sid("S-1-5-21-1-2-3-1001".into()),
            lookup: LookupOutcome::NotFound,
        };
        assert_eq!(resolution.sid(), Some("S-1-5-21-1-2-3-1001"));
        assert!(resolution.account().is_none());
    }
}
