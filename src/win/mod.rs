//! Win32 FFI wrappers. This is the only module allowed to use `unsafe`.
//!
//! Every function here is read-only with respect to system state except
//! `create_private_dir` (creates the backup or scratch folder),
//! `export_registry_key` (writes a .reg file), `lock_file`, and the two
//! rollback primitives `unload_hive` and `delete_profile_list_entry`. `walk_hive_file` mounts a
//! hive file under a temporary HKU name, so it is only ever given a copy
//! made by the caller. Each `unsafe` block carries a
//! SAFETY comment stating the invariant it relies on.
#![allow(unsafe_code)]

mod account;
mod files;
mod registry;
mod security;
mod system;
mod token;
mod wide;

pub use account::{lookup_account_name, lookup_account_sid};
pub use files::{export_registry_key, file_attributes, free_bytes, lock_file, probe_exclusive};
pub use registry::{
    delete_profile_list_entry, hklm_key_exists, loaded_user_hives, read_profile_list,
    service_accounts, unload_hive, walk_hive_file, walk_loaded_hive,
};
pub use security::{create_private_dir, read_sddl};
pub use system::{computer_name, domain_membership, local_groups, os_version};
pub use token::current_token;
