//! The single seam between platform-neutral logic and the operating system.
//!
//! On Windows every function forwards to `win::`. Elsewhere they fail with
//! `Unsupported`, which lets the whole crate build, lint and unit-test on a
//! non-Windows development machine without `cfg` noise in callers.

#[cfg(windows)]
pub use crate::win::{
    computer_name, create_private_dir, current_token, domain_membership, export_registry_key,
    file_attributes, hklm_key_exists, loaded_user_hives, lookup_account_name, lookup_account_sid,
    os_version, probe_exclusive, read_profile_list, read_sddl,
};

#[cfg(not(windows))]
pub use unsupported::*;

#[cfg(not(windows))]
mod unsupported {
    use std::fs::Metadata;
    use std::io;
    use std::path::Path;

    use crate::model::{
        DomainMembership, LockState, LookupOutcome, OsVersion, ProfileListSnapshot, TokenInfo,
    };
    use crate::scan::{FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT};

    const MESSAGE: &str = "windows-profile-migration only runs on Windows";

    fn unsupported() -> io::Error {
        io::Error::new(io::ErrorKind::Unsupported, MESSAGE)
    }

    pub fn current_token() -> io::Result<TokenInfo> {
        Err(unsupported())
    }

    pub fn computer_name() -> io::Result<String> {
        Err(unsupported())
    }

    pub fn domain_membership() -> DomainMembership {
        DomainMembership::Unknown(MESSAGE.into())
    }

    pub fn os_version() -> io::Result<OsVersion> {
        Err(unsupported())
    }

    pub fn lookup_account_name(_name: &str) -> LookupOutcome {
        LookupOutcome::Failed(MESSAGE.into())
    }

    pub fn lookup_account_sid(_sid: &str) -> LookupOutcome {
        LookupOutcome::Failed(MESSAGE.into())
    }

    pub fn read_profile_list() -> io::Result<ProfileListSnapshot> {
        Err(unsupported())
    }

    pub fn loaded_user_hives() -> io::Result<Vec<String>> {
        Err(unsupported())
    }

    pub fn hklm_key_exists(_subkey: &str) -> io::Result<bool> {
        Err(unsupported())
    }

    pub fn probe_exclusive(_path: &Path) -> LockState {
        LockState::Error(MESSAGE.into())
    }

    pub fn read_sddl(_path: &Path) -> io::Result<String> {
        Err(unsupported())
    }

    pub fn export_registry_key(_hklm_subkey: &str, _dest: &Path) -> io::Result<()> {
        Err(unsupported())
    }

    pub fn create_private_dir(_path: &Path) -> io::Result<()> {
        Err(unsupported())
    }

    /// Synthesizes the Win32 attribute bits the scanner looks at, so the
    /// walker's link-skipping logic is exercised by tests on Unix too.
    pub fn file_attributes(metadata: &Metadata) -> u32 {
        if metadata.file_type().is_symlink() {
            FILE_ATTRIBUTE_REPARSE_POINT
        } else if metadata.is_dir() {
            FILE_ATTRIBUTE_DIRECTORY
        } else {
            0
        }
    }
}
