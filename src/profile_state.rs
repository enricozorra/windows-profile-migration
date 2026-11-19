//! Decoding of the ProfileList `State` value.
//!
//! Microsoft does not document these bits. The values below are the ones
//! the User Profile Service is widely observed to use (and that profile
//! tooling such as Helge Klein's research relies on). They are only used to
//! refuse or warn, never to compute a value to write, so an unknown bit
//! cannot cause a bad write.

pub const MANDATORY: u32 = 0x0001;
pub const NEW_CENTRAL: u32 = 0x0008;
pub const UPDATE_CENTRAL: u32 = 0x0010;
pub const DELETE_CACHE: u32 = 0x0020;
pub const TEMP_ASSIGNED: u32 = 0x0800;
pub const PARTLY_LOADED: u32 = 0x2000;
pub const BACKUP_EXISTS: u32 = 0x4000;
pub const THIS_IS_BAK: u32 = 0x8000;

/// Bits that mean the profile is mid-load, temporary, scheduled for
/// deletion, or entangled with a `.bak` copy.
const BLOCKING: &[(u32, &str)] = &[
    (TEMP_ASSIGNED, "a temporary profile was assigned"),
    (PARTLY_LOADED, "the profile is partly loaded"),
    (BACKUP_EXISTS, "a .bak copy of this profile exists"),
    (THIS_IS_BAK, "this entry is itself a .bak copy"),
    (DELETE_CACHE, "the local copy is scheduled for deletion"),
];

/// Bits that are legal but change how the profile behaves after migration.
const WARNING: &[(u32, &str)] = &[
    (
        MANDATORY,
        "mandatory profile: changes are discarded at logoff",
    ),
    (
        NEW_CENTRAL | UPDATE_CENTRAL,
        "roaming profile: the server copy may overwrite the migrated local copy",
    ),
];

pub fn blocking_reasons(state: u32) -> Vec<&'static str> {
    BLOCKING
        .iter()
        .filter(|(bit, _)| state & bit != 0)
        .map(|(_, reason)| *reason)
        .collect()
}

pub fn warning_reasons(state: u32) -> Vec<&'static str> {
    WARNING
        .iter()
        .filter(|(bits, _)| state & bits != 0)
        .map(|(_, reason)| *reason)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_state_has_no_reasons() {
        assert!(blocking_reasons(0).is_empty());
        assert!(warning_reasons(0).is_empty());
        // 0x0100 (admin user) and 0x0004 (new local) are informational.
        assert!(blocking_reasons(0x0104).is_empty());
    }

    #[test]
    fn temp_and_bak_bits_block() {
        assert_eq!(blocking_reasons(TEMP_ASSIGNED).len(), 1);
        assert_eq!(blocking_reasons(BACKUP_EXISTS | THIS_IS_BAK).len(), 2);
    }

    #[test]
    fn roaming_bits_warn_once() {
        assert_eq!(warning_reasons(NEW_CENTRAL | UPDATE_CENTRAL).len(), 1);
        assert_eq!(warning_reasons(MANDATORY | UPDATE_CENTRAL).len(), 2);
    }
}
