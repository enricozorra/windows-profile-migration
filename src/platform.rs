//! The single seam between platform-neutral logic and the operating system.
//!
//! On Windows every function forwards to `win::`. Elsewhere they fail with
//! `Unsupported`, which lets the whole crate build, lint and unit-test on a
//! non-Windows development machine without `cfg` noise in callers.

#[cfg(windows)]
pub use crate::win::{
    computer_name, copy_entry, create_private_dir, current_token, delete_profile_list_entry,
    delete_tree, domain_membership, enable_copy_privileges, export_registry_key, file_attributes,
    free_bytes, hash_data, hklm_key_exists, list_dir, loaded_user_hives, local_groups, lock_file,
    lookup_account_name, lookup_account_sid, mount_hive, os_version, probe_exclusive, read_entry,
    read_profile_list, read_sddl, rewrite_hive, service_accounts, set_times, unload_hive,
    walk_hive_file, walk_loaded_hive,
};

#[cfg(not(windows))]
pub use unsupported::*;

#[cfg(not(windows))]
mod unsupported {
    use std::fs::Metadata;
    use std::io;
    use std::path::Path;

    use crate::model::{
        CopiedEntry, DomainMembership, EntryFacts, HiveSkips, LockState, LookupOutcome, OsVersion,
        ProfileListSnapshot, RegData, TokenInfo,
    };
    use crate::scan::{FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT};
    use crate::secdesc::Edited;

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

    pub fn lock_file(_path: &Path) -> io::Result<std::fs::File> {
        Err(unsupported())
    }

    pub fn unload_hive(_mount: &str) -> io::Result<()> {
        Err(unsupported())
    }

    pub fn delete_profile_list_entry(_sid: &str) -> io::Result<()> {
        Err(unsupported())
    }

    pub fn enable_copy_privileges() -> io::Result<()> {
        Err(unsupported())
    }

    pub fn copy_entry(
        _source: &Path,
        _dest: &Path,
        _is_dir: bool,
        _reparse: Option<&[u8]>,
        _edit_security: &dyn Fn(&[u8]) -> Edited,
    ) -> io::Result<CopiedEntry> {
        Err(unsupported())
    }

    pub fn read_entry(_path: &Path) -> io::Result<EntryFacts> {
        Err(unsupported())
    }

    pub fn hash_data(_path: &Path) -> io::Result<[u8; 32]> {
        Err(unsupported())
    }

    pub fn set_times(_path: &Path, _created: i64, _written: i64) -> io::Result<()> {
        Err(unsupported())
    }

    pub fn mount_hive(_path: &Path, _mount: &str) -> io::Result<()> {
        Err(unsupported())
    }

    pub fn rewrite_hive(
        _mount: &str,
        _security: &mut dyn FnMut(&str, &[u8]) -> Edited,
        _value: &mut dyn FnMut(&str, &str, &RegData) -> Option<RegData>,
    ) -> io::Result<HiveSkips> {
        Err(unsupported())
    }

    pub fn list_dir(_dir: &Path) -> io::Result<Vec<(String, u32)>> {
        Err(unsupported())
    }

    pub fn delete_tree(_root: &Path, _last: &str) -> io::Result<()> {
        Err(unsupported())
    }

    pub fn free_bytes(_path: &Path) -> io::Result<u64> {
        Err(unsupported())
    }

    pub fn local_groups(_account: &str) -> io::Result<Vec<String>> {
        Err(unsupported())
    }

    pub fn service_accounts() -> io::Result<Vec<(String, String)>> {
        Err(unsupported())
    }

    pub fn walk_loaded_hive(
        _hku_subkey: &str,
        _visit: &mut dyn FnMut(&str, &str, &RegData),
    ) -> io::Result<Vec<String>> {
        Err(unsupported())
    }

    pub fn walk_hive_file(
        _path: &Path,
        _visit: &mut dyn FnMut(&str, &str, &RegData),
    ) -> io::Result<Vec<String>> {
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
