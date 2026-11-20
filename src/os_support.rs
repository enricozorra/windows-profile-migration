//! Which Windows builds the tool has been validated on.
//!
//! Supporting a new release means adding a row here after running the VM
//! validation script on it; nothing else in the code keys off the build.

use crate::model::OsVersion;

struct ValidatedBuild {
    build: u32,
    name: &'static str,
}

/// Client builds validated end-to-end. Build numbers are stable per feature
/// update; the UBR (patch level) is reported but not gated on.
const VALIDATED_BUILDS: &[ValidatedBuild] = &[
    ValidatedBuild {
        build: 19045,
        name: "Windows 10 22H2",
    },
    ValidatedBuild {
        build: 22631,
        name: "Windows 11 23H2",
    },
    ValidatedBuild {
        build: 26100,
        name: "Windows 11 24H2",
    },
    ValidatedBuild {
        build: 26200,
        name: "Windows 11 25H2",
    },
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OsSupport {
    Validated(&'static str),
    /// Newer than anything validated: probably fine, but untested.
    NewerThanValidated,
    Unsupported(String),
}

pub fn classify(os: &OsVersion) -> OsSupport {
    if !os.installation_type.eq_ignore_ascii_case("Client") {
        return OsSupport::Unsupported(format!(
            "installation type '{}' (only Windows client editions are supported)",
            os.installation_type
        ));
    }
    if let Some(known) = VALIDATED_BUILDS.iter().find(|b| b.build == os.build) {
        return OsSupport::Validated(known.name);
    }
    let newest = VALIDATED_BUILDS.iter().map(|b| b.build).max().unwrap_or(0);
    if os.build > newest {
        OsSupport::NewerThanValidated
    } else {
        OsSupport::Unsupported(format!(
            "build {} is older than or between validated builds",
            os.build
        ))
    }
}

/// Windows 11 still reports "Windows 10 ..." in the registry ProductName,
/// so the first Windows 11 build decides which name is shown.
#[cfg_attr(not(windows), allow(dead_code))]
const FIRST_WINDOWS_11_BUILD: u32 = 22000;

#[cfg_attr(not(windows), allow(dead_code))]
pub fn product_name_for_build(registry_product_name: &str, build: u32) -> String {
    match registry_product_name.strip_prefix("Windows 10") {
        Some(edition) if build >= FIRST_WINDOWS_11_BUILD => format!("Windows 11{edition}"),
        _ => registry_product_name.to_string(),
    }
}

pub fn validated_build_list() -> String {
    VALIDATED_BUILDS
        .iter()
        .map(|b| format!("{} ({})", b.name, b.build))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(build: u32, installation_type: &str) -> OsVersion {
        OsVersion {
            product_name: "Windows 10 Pro".into(),
            display_version: "x".into(),
            installation_type: installation_type.into(),
            build,
            ubr: 1,
        }
    }

    #[test]
    fn validated_builds_are_recognized() {
        assert_eq!(
            classify(&os(19045, "Client")),
            OsSupport::Validated("Windows 10 22H2")
        );
        assert_eq!(
            classify(&os(26100, "client")),
            OsSupport::Validated("Windows 11 24H2")
        );
    }

    #[test]
    fn newer_build_is_flagged_not_rejected() {
        assert_eq!(
            classify(&os(27000, "Client")),
            OsSupport::NewerThanValidated
        );
    }

    #[test]
    fn older_or_unlisted_build_is_unsupported() {
        assert!(matches!(
            classify(&os(19044, "Client")),
            OsSupport::Unsupported(_)
        ));
        assert!(matches!(
            classify(&os(22621, "Client")),
            OsSupport::Unsupported(_)
        ));
    }

    #[test]
    fn product_name_is_corrected_on_windows_11_builds() {
        assert_eq!(
            product_name_for_build("Windows 10 Pro", 26100),
            "Windows 11 Pro"
        );
        assert_eq!(
            product_name_for_build("Windows 10 Enterprise", 22000),
            "Windows 11 Enterprise"
        );
    }

    #[test]
    fn product_name_is_kept_on_windows_10_and_other_names() {
        assert_eq!(
            product_name_for_build("Windows 10 Pro", 19045),
            "Windows 10 Pro"
        );
        assert_eq!(
            product_name_for_build("Windows 11 Pro", 26100),
            "Windows 11 Pro"
        );
    }

    #[test]
    fn server_is_unsupported_even_on_validated_build() {
        assert!(matches!(
            classify(&os(26100, "Server")),
            OsSupport::Unsupported(_)
        ));
    }
}
