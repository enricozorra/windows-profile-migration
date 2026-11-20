//! Read-only preflight evaluation.
//!
//! `evaluate` turns gathered `SystemFacts` into one `Finding` per check.
//! Every check reports, including passes, so the summary shows what was
//! verified and not only what failed. Nothing here touches the system.

use crate::apps::AppReport;
use crate::model::{
    AccountInput, AccountKind, DomainMembership, LockState, LookupOutcome, ProfileListEntry,
    SidValue, SystemFacts, HIVE_MOUNT_PREFIX,
};
use crate::os_support::{self, OsSupport};
use crate::profile_state;
use crate::sid::{sid_eq, SidString};

pub const LOCAL_SYSTEM_SID: &str = "S-1-5-18";

/// Privileges the execution phase needs: backup/restore to load hives and
/// read/write files regardless of DACLs, take-ownership to fix owners.
pub const REQUIRED_PRIVILEGES: &[&str] = &[
    "SeBackupPrivilege",
    "SeRestorePrivilege",
    "SeTakeOwnershipPrivilege",
];

/// Checks an operator may downgrade from Blocking to Warning with
/// `--accept <ID>`. Everything else is a hard stop.
pub const OVERRIDABLE_CHECKS: &[&str] = &[ids::OS_SUPPORTED, ids::SOURCE_ACCOUNT, ids::EFS_FILES];

pub mod ids {
    pub const ELEVATION: &str = "ELEVATION";
    pub const PRIVILEGES: &str = "PRIVILEGES";
    pub const OS_SUPPORTED: &str = "OS_SUPPORTED";
    pub const DOMAIN_JOINED: &str = "DOMAIN_JOINED";
    pub const SOURCE_ACCOUNT: &str = "SOURCE_ACCOUNT";
    pub const TARGET_ACCOUNT: &str = "TARGET_ACCOUNT";
    pub const SCENARIO: &str = "SCENARIO";
    pub const PROFILE_SOURCE_ENTRY: &str = "PROFILE_SOURCE_ENTRY";
    pub const PROFILE_TARGET_ENTRY: &str = "PROFILE_TARGET_ENTRY";
    pub const PROFILE_LIST_BAK: &str = "PROFILE_LIST_BAK";
    pub const PROFILE_PATH_UNIQUE: &str = "PROFILE_PATH_UNIQUE";
    pub const MIGRATION_MARKER: &str = "MIGRATION_MARKER";
    pub const PROFILE_DIRECTORY: &str = "PROFILE_DIRECTORY";
    pub const HIVES_UNLOADED: &str = "HIVES_UNLOADED";
    pub const HIVE_FILES: &str = "HIVE_FILES";
    pub const ACL_FOOTPRINT: &str = "ACL_FOOTPRINT";
    pub const EFS_FILES: &str = "EFS_FILES";
    pub const INACCESSIBLE_ENTRIES: &str = "INACCESSIBLE_ENTRIES";
    pub const REPARSE_POINTS: &str = "REPARSE_POINTS";
    pub const CLOUD_PLACEHOLDERS: &str = "CLOUD_PLACEHOLDERS";
    pub const DPAPI_SECRETS: &str = "DPAPI_SECRETS";
    pub const APPX_STATE: &str = "APPX_STATE";
    pub const KNOWN_PATHS: &str = "KNOWN_PATHS";
    pub const TARGET_FOLDER: &str = "TARGET_FOLDER";
    pub const DISK_SPACE: &str = "DISK_SPACE";
    pub const REGISTRY_PATHS: &str = "REGISTRY_PATHS";
    pub const LOCAL_GROUPS: &str = "LOCAL_GROUPS";
    pub const ACCOUNT_REFERENCES: &str = "ACCOUNT_REFERENCES";
}

/// Headroom on top of the profile size: NTFS metadata for the copied tree,
/// the hive copies and anything the user writes while the copy runs.
pub const COPY_MARGIN_BYTES: u64 = 1 << 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Pass,
    Info,
    Warning,
    Blocking,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Pass => "PASS",
            Severity::Info => "INFO",
            Severity::Warning => "WARN",
            Severity::Blocking => "BLOCK",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub id: &'static str,
    pub severity: Severity,
    pub summary: String,
    pub details: Vec<String>,
    /// Whether `--accept <id>` may downgrade this particular finding. Set
    /// per finding, not per check: e.g. an unresolvable source SID can be
    /// accepted, a source that is a group cannot.
    pub overridable: bool,
    /// Set when an overridable blocking finding was downgraded by `--accept`.
    pub accepted: bool,
}

impl Finding {
    fn new(id: &'static str, severity: Severity, summary: impl Into<String>) -> Finding {
        Finding {
            id,
            severity,
            summary: summary.into(),
            details: Vec::new(),
            overridable: false,
            accepted: false,
        }
    }

    fn overridable(mut self) -> Finding {
        self.overridable = true;
        self
    }

    fn with_details(mut self, details: Vec<String>) -> Finding {
        self.details = details;
        self
    }
}

#[derive(Debug, Clone, Default)]
pub struct Options {
    /// Optional operator assertion of where the profile lives.
    pub expected_profile_path: Option<std::path::PathBuf>,
    /// Check IDs from `--accept`, already validated against
    /// `OVERRIDABLE_CHECKS`.
    pub accepted: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Report {
    pub findings: Vec<Finding>,
}

impl Report {
    pub fn is_blocked(&self) -> bool {
        self.findings
            .iter()
            .any(|f| f.severity == Severity::Blocking)
    }

    pub fn count(&self, severity: Severity) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == severity)
            .count()
    }
}

pub fn evaluate(facts: &SystemFacts, options: &Options) -> Report {
    let mut findings = vec![
        check_elevation(facts),
        check_privileges(facts),
        check_os(facts),
        check_domain(facts),
        check_source_account(facts),
        check_target_account(facts),
        check_scenario(facts),
        check_source_entry(facts, options),
        check_target_entry(facts),
        check_bak_entries(facts),
        check_unique_profile_path(facts),
        check_migration_marker(facts),
        check_profile_directory(facts),
        check_loaded_hives(facts),
        check_hive_files(facts),
        check_target_folder(facts),
        check_disk_space(facts),
    ];
    findings.extend(check_scan(facts));
    findings.push(check_registry(facts));
    findings.push(check_local_groups(facts));
    findings.push(check_account_references(facts));
    findings.extend(check_known_paths(facts));
    findings.extend(facts.apps.iter().map(app_finding));

    for finding in &mut findings {
        if finding.severity == Severity::Blocking
            && finding.overridable
            && options.accepted.iter().any(|a| a == finding.id)
        {
            finding.severity = Severity::Warning;
            finding.accepted = true;
        }
    }
    Report { findings }
}

fn check_elevation(facts: &SystemFacts) -> Finding {
    let token = &facts.token;
    if sid_eq(&token.user_sid, LOCAL_SYSTEM_SID) {
        return Finding::new(ids::ELEVATION, Severity::Pass, "running as LocalSystem");
    }
    if token.is_admin_member && token.is_elevated {
        return Finding::new(
            ids::ELEVATION,
            Severity::Pass,
            format!("running elevated as an administrator ({})", token.user_sid),
        );
    }
    let reason = if token.is_admin_member {
        "the token is not elevated; run from an elevated terminal"
    } else {
        "the account is not an active member of BUILTIN\\Administrators (UAC-filtered token or non-admin)"
    };
    Finding::new(ids::ELEVATION, Severity::Blocking, reason)
}

fn check_privileges(facts: &SystemFacts) -> Finding {
    let missing: Vec<String> = REQUIRED_PRIVILEGES
        .iter()
        .filter(|p| !facts.token.privileges.iter().any(|have| have == *p))
        .map(|p| p.to_string())
        .collect();
    if missing.is_empty() {
        Finding::new(
            ids::PRIVILEGES,
            Severity::Pass,
            "backup, restore and take-ownership privileges are available",
        )
    } else {
        Finding::new(
            ids::PRIVILEGES,
            Severity::Blocking,
            "required privileges are not held by this token",
        )
        .with_details(missing)
    }
}

fn check_os(facts: &SystemFacts) -> Finding {
    let os = match &facts.os {
        Ok(os) => os,
        Err(reason) => {
            return Finding::new(
                ids::OS_SUPPORTED,
                Severity::Blocking,
                format!("could not read the OS version: {reason}"),
            )
        }
    };
    let description = format!(
        "{} {} (build {}.{}, {})",
        os.product_name, os.display_version, os.build, os.ubr, os.installation_type
    );
    match os_support::classify(os) {
        OsSupport::Validated(name) => Finding::new(
            ids::OS_SUPPORTED,
            Severity::Pass,
            format!("{name}: {description}"),
        ),
        OsSupport::NewerThanValidated => Finding::new(
            ids::OS_SUPPORTED,
            Severity::Warning,
            format!("{description} is newer than any validated build"),
        )
        .with_details(vec![format!(
            "validated: {}",
            os_support::validated_build_list()
        )]),
        OsSupport::Unsupported(reason) => Finding::new(
            ids::OS_SUPPORTED,
            Severity::Blocking,
            format!("unsupported OS: {reason}"),
        )
        .overridable()
        .with_details(vec![
            description,
            format!("validated: {}", os_support::validated_build_list()),
        ]),
    }
}

fn check_domain(facts: &SystemFacts) -> Finding {
    match &facts.domain {
        DomainMembership::Domain(joined) => {
            let target_domain = facts.target.account().map(|a| a.domain.as_str());
            match target_domain {
                Some(td) if !td.eq_ignore_ascii_case(joined) => Finding::new(
                    ids::DOMAIN_JOINED,
                    Severity::Warning,
                    format!("joined to {joined}, but the target account is in {td}"),
                )
                .with_details(vec![
                    "the target can only log on if a trust exists between the domains".into(),
                ]),
                _ => Finding::new(
                    ids::DOMAIN_JOINED,
                    Severity::Pass,
                    format!("machine is joined to domain {joined}"),
                ),
            }
        }
        DomainMembership::Workgroup(name) => Finding::new(
            ids::DOMAIN_JOINED,
            Severity::Blocking,
            format!("machine is in workgroup {name}; a domain target account cannot log on"),
        ),
        DomainMembership::Unjoined => Finding::new(
            ids::DOMAIN_JOINED,
            Severity::Blocking,
            "machine is not joined to a domain",
        ),
        DomainMembership::Unknown(reason) => Finding::new(
            ids::DOMAIN_JOINED,
            Severity::Blocking,
            format!("could not determine domain membership: {reason}"),
        ),
    }
}

fn check_source_account(facts: &SystemFacts) -> Finding {
    let source = &facts.source;
    if source.input_kind == AccountInput::Bare {
        return Finding::new(
            ids::SOURCE_ACCOUNT,
            Severity::Blocking,
            format!(
                "'{}' is ambiguous; write COMPUTER\\user, .\\user, DOMAIN\\user or a SID",
                source.input
            ),
        );
    }
    let unresolved_reason = match &source.lookup {
        LookupOutcome::Invalid(reason) => {
            return Finding::new(ids::SOURCE_ACCOUNT, Severity::Blocking, reason.clone())
        }
        LookupOutcome::Found(info) if info.kind != AccountKind::DeletedAccount => {
            if let Some(problem) = account_problem(&info.sid, info.kind, "source") {
                return Finding::new(ids::SOURCE_ACCOUNT, Severity::Blocking, problem);
            }
            return Finding::new(
                ids::SOURCE_ACCOUNT,
                Severity::Pass,
                format!("source {} = {}", info.qualified_name(), info.sid),
            );
        }
        LookupOutcome::Found(_) => "the account was deleted".to_string(),
        LookupOutcome::NotFound => "no account has this name or SID".to_string(),
        LookupOutcome::Failed(reason) => format!("lookup failed: {reason}"),
    };
    let finding = Finding::new(
        ids::SOURCE_ACCOUNT,
        Severity::Blocking,
        format!(
            "source '{}' does not resolve: {unresolved_reason}",
            source.input
        ),
    );
    // Domain A -> B after the old domain or its trust is gone: the SID no
    // longer resolves, but the profile is still on disk. The operator may
    // proceed only when naming the SID explicitly and a profile exists.
    let explicit_sid = matches!(source.input_kind, AccountInput::Sid(_));
    let sid_is_user_shaped = source
        .sid()
        .and_then(SidString::parse)
        .is_some_and(|s| s.is_account_domain_sid() && !s.is_builtin_admin_or_guest());
    if explicit_sid && sid_is_user_shaped && facts.source_entry().is_some() {
        finding.overridable().with_details(vec![
            "a ProfileList entry exists for this SID; if the source domain is gone, \
             re-run with --accept SOURCE_ACCOUNT"
                .into(),
        ])
    } else {
        finding
    }
}

fn check_target_account(facts: &SystemFacts) -> Finding {
    let target = &facts.target;
    if target.input_kind == AccountInput::Bare {
        // In Local -> AD the same user name usually exists both locally and
        // in the domain; a bare name resolves to the local one first.
        return Finding::new(
            ids::TARGET_ACCOUNT,
            Severity::Blocking,
            format!(
                "'{}' is ambiguous; write DOMAIN\\user, user@domain or a SID",
                target.input
            ),
        );
    }
    let info = match &target.lookup {
        LookupOutcome::Found(info) => info,
        LookupOutcome::Invalid(reason) => {
            return Finding::new(ids::TARGET_ACCOUNT, Severity::Blocking, reason.clone())
        }
        LookupOutcome::Failed(reason) => {
            return Finding::new(
                ids::TARGET_ACCOUNT,
                Severity::Blocking,
                format!("account lookup failed for '{}': {reason}", target.input),
            )
        }
        LookupOutcome::NotFound => {
            return Finding::new(
                ids::TARGET_ACCOUNT,
                Severity::Blocking,
                format!("target '{}' does not resolve to an account", target.input),
            )
        }
    };
    if let Some(problem) = account_problem(&info.sid, info.kind, "target") {
        return Finding::new(ids::TARGET_ACCOUNT, Severity::Blocking, problem);
    }
    if info.domain.eq_ignore_ascii_case(&facts.computer_name) {
        return Finding::new(
            ids::TARGET_ACCOUNT,
            Severity::Blocking,
            format!(
                "target {} is a local account; supported scenarios need a domain target",
                info.qualified_name()
            ),
        );
    }
    if let Some(source_sid) = facts.source.sid() {
        if sid_eq(source_sid, &info.sid) {
            return Finding::new(
                ids::TARGET_ACCOUNT,
                Severity::Blocking,
                "source and target are the same SID",
            );
        }
    }
    Finding::new(
        ids::TARGET_ACCOUNT,
        Severity::Pass,
        format!("target {} = {}", info.qualified_name(), info.sid),
    )
}

/// Shared validity rules for both accounts.
fn account_problem(sid: &str, kind: AccountKind, role: &str) -> Option<String> {
    let Some(parsed) = SidString::parse(sid) else {
        return Some(format!("{role} SID '{sid}' is malformed"));
    };
    if kind != AccountKind::User {
        return Some(format!("{role} {sid} is a {kind:?}, not a user account"));
    }
    if parsed.is_service_account() || !parsed.is_account_domain_sid() {
        return Some(format!(
            "{role} {sid} is not a local or domain user SID (S-1-5-21-...)"
        ));
    }
    if parsed.is_builtin_admin_or_guest() {
        return Some(format!(
            "{role} {sid} is a built-in Administrator/Guest account (RID {}), which is not supported",
            parsed.rid()
        ));
    }
    None
}

fn check_scenario(facts: &SystemFacts) -> Finding {
    let (Some(source_sid), Some(target)) = (facts.source.sid(), facts.target.account()) else {
        return Finding::new(
            ids::SCENARIO,
            Severity::Info,
            "not evaluated: source or target unresolved",
        );
    };
    let (Some(src), Some(tgt)) = (SidString::parse(source_sid), SidString::parse(&target.sid))
    else {
        return Finding::new(
            ids::SCENARIO,
            Severity::Info,
            "not evaluated: malformed SID",
        );
    };
    let source_is_local = facts
        .source
        .account()
        .map(|a| a.domain.eq_ignore_ascii_case(&facts.computer_name))
        .unwrap_or(false);
    let scenario = if source_is_local {
        "Local -> Domain"
    } else {
        "Domain -> Domain"
    };
    let mut finding = Finding::new(
        ids::SCENARIO,
        Severity::Info,
        format!("{scenario}: {source_sid} -> {}", target.sid),
    );
    if sid_eq(src.domain_part(), tgt.domain_part()) {
        finding.severity = Severity::Warning;
        finding
            .details
            .push("source and target are in the same account domain (re-created account?)".into());
    }
    // When the old SID resolves to the new account, the target carries it
    // in sIDHistory. Access then keeps working through SID history and
    // silently breaks the day SID history is cleaned up.
    if let Some(source_info) = facts.source.account() {
        if source_info
            .qualified_name()
            .eq_ignore_ascii_case(&target.qualified_name())
            && !sid_eq(&source_info.sid, &target.sid)
        {
            finding.severity = Severity::Warning;
            finding.details.push(format!(
                "{source_sid} resolves to {} via SID history; ACLs still need rewriting before SID history is removed",
                target.qualified_name()
            ));
        }
    }
    finding
}

fn check_source_entry(facts: &SystemFacts, options: &Options) -> Finding {
    let Some(source_sid) = facts.source.sid() else {
        return Finding::new(
            ids::PROFILE_SOURCE_ENTRY,
            Severity::Info,
            "not evaluated: source SID unknown",
        );
    };
    let Some(entry) = facts.source_entry() else {
        return Finding::new(
            ids::PROFILE_SOURCE_ENTRY,
            Severity::Blocking,
            format!("no ProfileList entry for {source_sid}"),
        );
    };
    let mut blocking = Vec::new();
    let mut warnings = Vec::new();

    match &entry.sid_value {
        SidValue::Valid(value) if !sid_eq(value, source_sid) => blocking.push(format!(
            "Sid value {value} does not match the key name {}",
            entry.key_name
        )),
        SidValue::Invalid => blocking.push("Sid value is not a valid binary SID".into()),
        SidValue::Missing => warnings.push("Sid value is missing".into()),
        SidValue::Valid(_) => {}
    }
    if let Some(ref_count) = entry.ref_count.filter(|&c| c > 0) {
        blocking.push(format!(
            "RefCount is {ref_count}: the User Profile Service considers the profile in use"
        ));
    }
    if let Some(state) = entry.state {
        blocking.extend(
            profile_state::blocking_reasons(state)
                .into_iter()
                .map(|r| format!("State 0x{state:04X}: {r}")),
        );
        warnings.extend(
            profile_state::warning_reasons(state)
                .into_iter()
                .map(|r| format!("State 0x{state:04X}: {r}")),
        );
    }
    match &entry.profile_image_path_expanded {
        None => blocking.push("ProfileImagePath is missing".into()),
        Some(path) => {
            if let Some(expected) = &options.expected_profile_path {
                if !same_path(path, &expected.to_string_lossy()) {
                    blocking.push(format!(
                        "ProfileImagePath {path} does not match --profile-path {}",
                        expected.display()
                    ));
                }
            }
            if let Some(root) = &facts.profile_list.profiles_directory {
                if !is_direct_child(path, root) {
                    warnings.push(format!("{path} is not directly under {root}"));
                }
            }
        }
    }
    if entry.guid.is_some() {
        warnings.push(
            "Guid value present (domain profile); the old objectGUID mapping must not be carried over"
                .into(),
        );
    }

    let path = entry
        .profile_image_path_expanded
        .clone()
        .unwrap_or_else(|| "<no path>".into());
    if !blocking.is_empty() {
        blocking.extend(warnings);
        Finding::new(
            ids::PROFILE_SOURCE_ENTRY,
            Severity::Blocking,
            format!("source ProfileList entry is not in a clean state ({path})"),
        )
        .with_details(blocking)
    } else if !warnings.is_empty() {
        Finding::new(
            ids::PROFILE_SOURCE_ENTRY,
            Severity::Warning,
            format!("source ProfileList entry: {path}"),
        )
        .with_details(warnings)
    } else {
        Finding::new(
            ids::PROFILE_SOURCE_ENTRY,
            Severity::Pass,
            format!("source ProfileList entry is clean: {path}"),
        )
    }
}

fn check_target_entry(facts: &SystemFacts) -> Finding {
    let Some(target_sid) = facts.target.sid() else {
        return Finding::new(
            ids::PROFILE_TARGET_ENTRY,
            Severity::Info,
            "not evaluated: target SID unknown",
        );
    };
    let existing = facts
        .profile_list
        .entries
        .iter()
        .find(|e| !e.is_bak() && sid_eq(&e.key_name, target_sid));
    match existing {
        // Typically the domain user already logged on once and got a fresh
        // C:\Users\user.DOMAIN profile. Overwriting that entry would orphan
        // it; merging profiles is out of scope.
        Some(entry) => Finding::new(
            ids::PROFILE_TARGET_ENTRY,
            Severity::Blocking,
            format!("target {target_sid} already has a profile"),
        )
        .with_details(vec![
            format!(
                "ProfileImagePath: {}",
                entry
                    .profile_image_path_expanded
                    .as_deref()
                    .unwrap_or("<missing>")
            ),
            "remove that profile (System Properties > User Profiles, or Remove-CimInstance Win32_UserProfile) first"
                .into(),
        ]),
        None => Finding::new(
            ids::PROFILE_TARGET_ENTRY,
            Severity::Pass,
            "target has no existing profile",
        ),
    }
}

fn check_bak_entries(facts: &SystemFacts) -> Finding {
    let involved: Vec<&str> = [facts.source.sid(), facts.target.sid()]
        .into_iter()
        .flatten()
        .collect();
    let mut blocking = Vec::new();
    let mut unrelated = Vec::new();
    for entry in facts.profile_list.entries.iter().filter(|e| e.is_bak()) {
        if involved.iter().any(|sid| sid_eq(entry.base_sid(), sid)) {
            blocking.push(entry.key_name.clone());
        } else {
            unrelated.push(entry.key_name.clone());
        }
    }
    if !blocking.is_empty() {
        // Winlogon prefers or trips over the .bak twin and assigns a
        // temporary profile.
        blocking.extend(unrelated.into_iter().map(|k| format!("(unrelated) {k}")));
        Finding::new(
            ids::PROFILE_LIST_BAK,
            Severity::Blocking,
            "a .bak ProfileList entry exists for the source or target SID",
        )
        .with_details(blocking)
    } else if !unrelated.is_empty() {
        Finding::new(
            ids::PROFILE_LIST_BAK,
            Severity::Warning,
            "other accounts have .bak ProfileList entries (not touched)",
        )
        .with_details(unrelated)
    } else {
        Finding::new(
            ids::PROFILE_LIST_BAK,
            Severity::Pass,
            "no .bak ProfileList entries",
        )
    }
}

fn check_unique_profile_path(facts: &SystemFacts) -> Finding {
    let Some(source) = facts.source_entry() else {
        return Finding::new(
            ids::PROFILE_PATH_UNIQUE,
            Severity::Info,
            "not evaluated: no source entry",
        );
    };
    let Some(path) = &source.profile_image_path_expanded else {
        return Finding::new(
            ids::PROFILE_PATH_UNIQUE,
            Severity::Info,
            "not evaluated: no ProfileImagePath",
        );
    };
    let others: Vec<String> = facts
        .profile_list
        .entries
        .iter()
        .filter(|e| e.key_name != source.key_name)
        .filter(|e| {
            e.profile_image_path_expanded
                .as_deref()
                .is_some_and(|p| same_path(p, path))
        })
        .map(|e| e.key_name.clone())
        .collect();
    if others.is_empty() {
        Finding::new(
            ids::PROFILE_PATH_UNIQUE,
            Severity::Pass,
            format!("{path} is referenced by one ProfileList entry"),
        )
    } else {
        Finding::new(
            ids::PROFILE_PATH_UNIQUE,
            Severity::Blocking,
            format!("{path} is also referenced by other ProfileList entries"),
        )
        .with_details(others)
    }
}

fn check_migration_marker(facts: &SystemFacts) -> Finding {
    let marked: Vec<String> = facts
        .profile_list
        .entries
        .iter()
        .filter_map(|e: &ProfileListEntry| {
            e.migration_marker
                .as_ref()
                .map(|from| format!("{} (from {from})", e.key_name))
        })
        .collect();
    if marked.is_empty() {
        Finding::new(
            ids::MIGRATION_MARKER,
            Severity::Pass,
            "no interrupted windows-profile-migration migration found",
        )
    } else {
        Finding::new(
            ids::MIGRATION_MARKER,
            Severity::Blocking,
            "a previous windows-profile-migration migration did not complete; roll back before retrying",
        )
        .with_details(marked)
    }
}

fn check_profile_directory(facts: &SystemFacts) -> Finding {
    match &facts.profile_dir {
        None => Finding::new(
            ids::PROFILE_DIRECTORY,
            Severity::Info,
            "not evaluated: profile path unknown",
        ),
        Some(dir) if !dir.exists => Finding::new(
            ids::PROFILE_DIRECTORY,
            Severity::Blocking,
            format!("{} does not exist", dir.path.display()),
        ),
        Some(dir) if dir.is_reparse_point => Finding::new(
            ids::PROFILE_DIRECTORY,
            Severity::Blocking,
            format!(
                "{} is itself a junction/symlink; resolve it manually first",
                dir.path.display()
            ),
        ),
        Some(dir) => Finding::new(
            ids::PROFILE_DIRECTORY,
            Severity::Pass,
            format!("{} exists and is a real directory", dir.path.display()),
        ),
    }
}

fn check_loaded_hives(facts: &SystemFacts) -> Finding {
    let mut loaded = Vec::new();
    for (role, sid) in [
        ("source", facts.source.sid()),
        ("target", facts.target.sid()),
    ] {
        let Some(sid) = sid else { continue };
        let classes = format!("{sid}_Classes");
        for key in &facts.loaded_hives {
            if sid_eq(key, sid) || sid_eq(key, &classes) {
                loaded.push(format!("HKU\\{key} ({role})"));
            }
        }
    }
    for key in &facts.loaded_hives {
        if key.to_ascii_lowercase().starts_with(HIVE_MOUNT_PREFIX) {
            loaded.push(format!(
                "HKU\\{key} (left over by an earlier windows-profile-migration run)"
            ));
        }
    }
    if loaded.is_empty() {
        Finding::new(
            ids::HIVES_UNLOADED,
            Severity::Pass,
            "no source/target hives are mounted under HKU",
        )
    } else {
        Finding::new(
            ids::HIVES_UNLOADED,
            Severity::Blocking,
            "hives are still mounted: the user is logged on, or a process/service holds the hive",
        )
        .with_details(loaded)
    }
}

fn check_hive_files(facts: &SystemFacts) -> Finding {
    if facts.hive_files.is_empty() {
        return Finding::new(
            ids::HIVE_FILES,
            Severity::Info,
            "not evaluated: profile path unknown",
        );
    }
    let mut severity = Severity::Pass;
    let mut details = Vec::new();
    for probe in &facts.hive_files {
        let path = probe.path.display();
        let (sev, text) = match &probe.state {
            LockState::Unlocked => (Severity::Pass, format!("{path}: unlocked")),
            LockState::Locked => (
                Severity::Blocking,
                format!("{path}: open in another process (sharing violation)"),
            ),
            // A user who never started a UWP/Explorer session can lack
            // UsrClass.dat; Windows recreates it at logon.
            LockState::Missing if probe.label == "UsrClass.dat" => {
                (Severity::Warning, format!("{path}: missing"))
            }
            LockState::Missing => (Severity::Blocking, format!("{path}: missing")),
            LockState::Error(e) => (Severity::Blocking, format!("{path}: {e}")),
        };
        severity = severity.max(sev);
        details.push(text);
    }
    let summary = match severity {
        Severity::Pass => "hive files exist and are not locked",
        Severity::Blocking => "hive files are missing or locked",
        _ => "hive files need attention",
    };
    Finding::new(ids::HIVE_FILES, severity, summary).with_details(details)
}

fn check_scan(facts: &SystemFacts) -> Vec<Finding> {
    let Some(scan) = &facts.scan else {
        return vec![Finding::new(
            ids::ACL_FOOTPRINT,
            Severity::Info,
            "profile tree not scanned (profile directory unavailable)",
        )];
    };
    let mut findings = Vec::new();

    let footprint = scan.owned_by_source.count + scan.explicit_source_aces.count;
    findings.push(if footprint == 0 {
        // Every real profile has the user as owner or in explicit ACEs; none
        // at all usually means the wrong source account was given.
        Finding::new(
            ids::ACL_FOOTPRINT,
            Severity::Warning,
            format!(
                "the source SID does not appear in any owner or explicit ACE across {} entries; is this the right source?",
                scan.directories + scan.files
            ),
        )
    } else {
        Finding::new(
            ids::ACL_FOOTPRINT,
            Severity::Info,
            format!(
                "scanned {} directories / {} files: {} owned by source, {} with explicit source ACEs, {} protected DACLs",
                scan.directories,
                scan.files,
                scan.owned_by_source.count,
                scan.explicit_source_aces.count,
                scan.protected_dacls_with_source.count
            ),
        )
    });

    if scan.encrypted.count > 0 {
        findings.push(
            Finding::new(
                ids::EFS_FILES,
                Severity::Blocking,
                format!(
                    "{} EFS-encrypted entries: their keys are DPAPI-protected by the source account and will be unreadable by the target",
                    scan.encrypted.count
                ),
            )
            .overridable()
            .with_details(with_more(&scan.encrypted.samples, scan.encrypted.count)),
        );
    } else {
        findings.push(Finding::new(
            ids::EFS_FILES,
            Severity::Pass,
            "no EFS-encrypted files",
        ));
    }

    let inaccessible = scan.inaccessible.count + scan.unparsable_sddl.count;
    if inaccessible > 0 {
        let mut details = with_more(&scan.inaccessible.samples, scan.inaccessible.count);
        details.extend(with_more(
            &scan.unparsable_sddl.samples,
            scan.unparsable_sddl.count,
        ));
        findings.push(
            Finding::new(
                ids::INACCESSIBLE_ENTRIES,
                Severity::Warning,
                format!("{inaccessible} entries could not be read or analyzed"),
            )
            .with_details(details),
        );
    }

    findings.push(
        Finding::new(
            ids::REPARSE_POINTS,
            Severity::Info,
            format!(
                "{} junctions/symlinks are not traversed; the copy recreates them pointing into the new folder",
                scan.reparse_points.count
            ),
        )
        .with_details(with_more(
            &scan.reparse_points.samples,
            scan.reparse_points.count,
        )),
    );

    if scan.cloud_placeholders.count > 0 {
        findings.push(
            Finding::new(
                ids::CLOUD_PLACEHOLDERS,
                Severity::Warning,
                format!(
                    "{} cloud placeholders (online-only files) are not copied, which would download them; they reappear after OneDrive sign-in",
                    scan.cloud_placeholders.count
                ),
            )
            .with_details(with_more(
                &scan.cloud_placeholders.samples,
                scan.cloud_placeholders.count,
            )),
        );
    }
    findings
}

fn check_known_paths(facts: &SystemFacts) -> Vec<Finding> {
    let Some(known) = &facts.known_paths else {
        return Vec::new();
    };
    let mut findings = Vec::new();

    if !known.errors.is_empty() {
        findings.push(
            Finding::new(
                ids::KNOWN_PATHS,
                Severity::Warning,
                "some caveat locations could not be read; the DPAPI/AppX/application checks may be incomplete",
            )
            .with_details(known.errors.clone()),
        );
    }

    if known.dpapi_master_keys || known.credential_files > 0 {
        findings.push(
            Finding::new(
                ids::DPAPI_SECRETS,
                Severity::Warning,
                "DPAPI-protected secrets will not decrypt for the target account",
            )
            .with_details(vec![
                format!(
                    "DPAPI master keys for the source SID: {}",
                    if known.dpapi_master_keys { "present" } else { "absent" }
                ),
                format!("Credential Manager files: {}", known.credential_files),
                "affected: saved Windows credentials, browser passwords, Wi-Fi/VPN user credentials, Outlook/Teams tokens".into(),
                "master keys are bound to the source SID and password; export what is needed before migrating".into(),
            ]),
        );
    }

    if facts.appx_store_present || known.appx_package_dirs > 0 {
        findings.push(
            Finding::new(
                ids::APPX_STATE,
                Severity::Warning,
                "AppX/UWP registrations are per-SID and do not follow a SID remap",
            )
            .with_details(vec![
                format!(
                    "AppxAllUserStore entry for source SID: {}",
                    if facts.appx_store_present { "present" } else { "absent" }
                ),
                format!("package state folders: {}", known.appx_package_dirs),
                "Start menu, Settings and Store apps may need re-registration after the target's first logon".into(),
            ]),
        );
    }
    findings
}

fn check_target_folder(facts: &SystemFacts) -> Finding {
    let Some(dir) = &facts.target_dir else {
        return Finding::new(
            ids::TARGET_FOLDER,
            Severity::Info,
            "not evaluated: target account or profiles directory unknown",
        );
    };
    let path = dir.path.display().to_string();
    if dir.staging_exists {
        return Finding::new(
            ids::TARGET_FOLDER,
            Severity::Blocking,
            format!(
                "a working copy from an earlier run exists: {}",
                dir.staging_path.display()
            ),
        )
        .with_details(vec![
            "an earlier migration stopped before its commit; roll it back before retrying".into(),
        ]);
    }
    let claimed_by: Vec<String> = facts
        .profile_list
        .entries
        .iter()
        .filter(|e| {
            e.profile_image_path_expanded
                .as_deref()
                .is_some_and(|p| same_path(p, &path))
        })
        .map(|e| e.key_name.clone())
        .collect();
    if dir.exists || !claimed_by.is_empty() {
        let mut details = claimed_by
            .into_iter()
            .map(|k| format!("used by ProfileList entry {k}"))
            .collect::<Vec<_>>();
        details.push(
            "remove or rename it first; the migration never merges into an existing folder".into(),
        );
        return Finding::new(
            ids::TARGET_FOLDER,
            Severity::Blocking,
            format!("{path} is already taken"),
        )
        .with_details(details);
    }
    Finding::new(
        ids::TARGET_FOLDER,
        Severity::Pass,
        format!("the migrated profile will be created at {path}"),
    )
}

fn check_disk_space(facts: &SystemFacts) -> Finding {
    let (Some(free), Some(scan)) = (&facts.free_bytes, &facts.scan) else {
        return Finding::new(
            ids::DISK_SPACE,
            Severity::Info,
            "not evaluated: profile not scanned",
        );
    };
    let free = match free {
        Ok(free) => *free,
        Err(reason) => {
            return Finding::new(
                ids::DISK_SPACE,
                Severity::Blocking,
                format!("could not read the free disk space: {reason}"),
            )
        }
    };
    let required = scan.file_bytes + scan.file_bytes / 10 + COPY_MARGIN_BYTES;
    let summary = format!(
        "{} free, the copy needs {} ({} of files + 10% + {})",
        format_bytes(free),
        format_bytes(required),
        format_bytes(scan.file_bytes),
        format_bytes(COPY_MARGIN_BYTES)
    );
    if free < required {
        Finding::new(ids::DISK_SPACE, Severity::Blocking, summary).with_details(vec![
            "the source profile is kept until the migration is finalized, so both must fit".into(),
        ])
    } else {
        Finding::new(ids::DISK_SPACE, Severity::Pass, summary)
    }
}

fn check_registry(facts: &SystemFacts) -> Finding {
    let inspection = match &facts.registry {
        None => {
            return Finding::new(
                ids::REGISTRY_PATHS,
                Severity::Info,
                "not evaluated: source profile path unknown",
            )
        }
        Some(Err(reason)) => {
            return Finding::new(
                ids::REGISTRY_PATHS,
                Severity::Warning,
                format!("the source registry could not be inspected: {reason}"),
            )
            .with_details(vec![
                "path references and application settings below are incomplete".into(),
            ])
        }
        Some(Ok(inspection)) => inspection,
    };
    let old = facts
        .profile_dir
        .as_ref()
        .map(|d| d.path.display().to_string())
        .unwrap_or_default();
    let new = facts
        .target_dir
        .as_ref()
        .map(|d| d.path.display().to_string())
        .unwrap_or_else(|| "the new folder".into());
    let mut details = with_more(
        &inspection.text_path_refs[..inspection
            .text_path_refs
            .len()
            .min(crate::model::Tally::MAX_SAMPLES)],
        inspection.text_path_refs.len(),
    );
    if !inspection.binary_path_refs.is_empty() {
        details.push(format!(
            "{} binary values embed {old} and are not rewritten automatically:",
            inspection.binary_path_refs.len()
        ));
        details.extend(with_more(
            &inspection.binary_path_refs[..inspection
                .binary_path_refs
                .len()
                .min(crate::model::Tally::MAX_SAMPLES)],
            inspection.binary_path_refs.len(),
        ));
    }
    if !inspection.loose_path_refs.is_empty() {
        details.push(format!(
            "{} text values mention {old} but not as a whole path, and are left as they are:",
            inspection.loose_path_refs.len()
        ));
        details.extend(with_more(
            &inspection.loose_path_refs[..inspection
                .loose_path_refs
                .len()
                .min(crate::model::Tally::MAX_SAMPLES)],
            inspection.loose_path_refs.len(),
        ));
    }
    details.extend(inspection.errors.iter().map(|e| format!("not read: {e}")));
    let severity = if inspection.binary_path_refs.is_empty()
        && inspection.loose_path_refs.is_empty()
        && inspection.errors.is_empty()
    {
        Severity::Info
    } else {
        Severity::Warning
    };
    Finding::new(
        ids::REGISTRY_PATHS,
        severity,
        format!(
            "{} registry values read ({}): {} text values contain {old} and will be rewritten to {new}",
            inspection.values_scanned,
            inspection.method,
            inspection.text_path_refs.len()
        ),
    )
    .with_details(details)
}

fn check_local_groups(facts: &SystemFacts) -> Finding {
    let Some(groups) = &facts.local_groups else {
        return Finding::new(
            ids::LOCAL_GROUPS,
            Severity::Info,
            "not evaluated: source or target unresolved",
        );
    };
    let (source, target) = match (&groups.source, &groups.target) {
        (Ok(source), Ok(target)) => (source, target),
        (source, target) => {
            let details = [("source", source), ("target", target)]
                .into_iter()
                .filter_map(|(role, result)| result.as_ref().err().map(|e| format!("{role}: {e}")))
                .collect();
            return Finding::new(
                ids::LOCAL_GROUPS,
                Severity::Warning,
                "local group memberships could not be compared",
            )
            .with_details(details);
        }
    };
    let missing: Vec<&String> = source
        .iter()
        .filter(|g| !target.iter().any(|t| t.eq_ignore_ascii_case(g)))
        .collect();
    let target_name = facts
        .target
        .account()
        .map(|a| a.qualified_name())
        .unwrap_or_else(|| "the target".into());
    if missing.is_empty() {
        return Finding::new(
            ids::LOCAL_GROUPS,
            Severity::Pass,
            format!(
                "the target already has the source's local groups ({})",
                source.join(", ")
            ),
        );
    }
    Finding::new(
        ids::LOCAL_GROUPS,
        Severity::Warning,
        format!(
            "the target is not in all of the source's local groups: {}",
            missing
                .iter()
                .map(|g| g.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    )
    .with_details(
        missing
            .iter()
            .map(|g| {
                format!(
                    "add {target_name} to {g} if the user still needs it (not done automatically)"
                )
            })
            .collect(),
    )
}

fn check_account_references(facts: &SystemFacts) -> Finding {
    let Some(refs) = &facts.account_references else {
        return Finding::new(
            ids::ACCOUNT_REFERENCES,
            Severity::Info,
            "not evaluated: source account unresolved",
        );
    };
    if refs.services.is_empty() && refs.scheduled_tasks.is_empty() && refs.errors.is_empty() {
        return Finding::new(
            ids::ACCOUNT_REFERENCES,
            Severity::Pass,
            "no services or scheduled tasks run as the source account",
        );
    }
    let mut details: Vec<String> = refs
        .services
        .iter()
        .map(|s| format!("service: {s}"))
        .collect();
    details.extend(
        refs.scheduled_tasks
            .iter()
            .map(|t| format!("scheduled task: {t}")),
    );
    details.extend(refs.errors.iter().map(|e| format!("not read: {e}")));
    Finding::new(
        ids::ACCOUNT_REFERENCES,
        Severity::Warning,
        format!(
            "{} service(s) and {} scheduled task(s) run as the source account; reconfigure them for the target",
            refs.services.len(),
            refs.scheduled_tasks.len()
        ),
    )
    .with_details(details)
}

fn app_finding(app: &AppReport) -> Finding {
    let severity = if app.actions.is_empty() {
        Severity::Info
    } else {
        Severity::Warning
    };
    let mut details: Vec<String> = app
        .carried
        .iter()
        .map(|c| format!("carried: {c}"))
        .collect();
    details.extend(app.actions.iter().map(|a| format!("action: {a}")));
    Finding::new(app.id, severity, format!("{} detected", app.name)).with_details(details)
}

/// Binary (1024-based) size with one decimal, for the console report.
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["KB", "MB", "GB", "TB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64 / 1024.0;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

fn with_more(samples: &[String], count: usize) -> Vec<String> {
    let mut details = samples.to_vec();
    if count > samples.len() {
        details.push(format!("... and {} more", count - samples.len()));
    }
    details
}

/// Case-insensitive path comparison that ignores a trailing separator,
/// matching how Windows treats profile paths.
fn same_path(a: &str, b: &str) -> bool {
    normalize(a) == normalize(b)
}

fn is_direct_child(path: &str, parent: &str) -> bool {
    normalize(path)
        .rsplit_once('\\')
        .is_some_and(|(dir, _)| dir == normalize(parent))
}

fn normalize(path: &str) -> String {
    path.trim()
        .trim_end_matches(['\\', '/'])
        .replace('/', "\\")
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;
    use std::path::PathBuf;

    const SRC: &str = "S-1-5-21-100-200-300-1001";
    const TGT: &str = "S-1-5-21-900-800-700-1105";

    fn entry(key: &str, path: &str) -> ProfileListEntry {
        ProfileListEntry {
            key_name: key.into(),
            profile_image_path: Some(path.replace(r"C:\", r"%SystemDrive%\")),
            profile_image_path_expanded: Some(path.into()),
            flags: Some(0),
            state: Some(0),
            ref_count: Some(0),
            sid_value: SidValue::Valid(key.trim_end_matches(".bak").into()),
            guid: None,
            migration_marker: None,
        }
    }

    fn account(sid: &str, domain: &str, name: &str) -> AccountInfo {
        AccountInfo {
            sid: sid.into(),
            domain: domain.into(),
            name: name.into(),
            kind: AccountKind::User,
        }
    }

    /// A machine where a Local -> Domain migration should pass cleanly.
    fn clean_facts() -> SystemFacts {
        SystemFacts {
            token: TokenInfo {
                user_sid: "S-1-5-21-100-200-300-1000".into(),
                is_elevated: true,
                is_admin_member: true,
                privileges: REQUIRED_PRIVILEGES.iter().map(|p| p.to_string()).collect(),
            },
            os: Ok(OsVersion {
                product_name: "Windows 10 Enterprise".into(),
                display_version: "24H2".into(),
                installation_type: "Client".into(),
                build: 26100,
                ubr: 2033,
            }),
            computer_name: "PC01".into(),
            domain: DomainMembership::Domain("CORP".into()),
            source: AccountResolution {
                input: r".\jdoe".into(),
                input_kind: AccountInput::Qualified,
                lookup: LookupOutcome::Found(account(SRC, "PC01", "jdoe")),
            },
            target: AccountResolution {
                input: r"CORP\jdoe".into(),
                input_kind: AccountInput::Qualified,
                lookup: LookupOutcome::Found(account(TGT, "CORP", "jdoe")),
            },
            profile_list: ProfileListSnapshot {
                profiles_directory: Some(r"C:\Users".into()),
                entries: vec![
                    entry("S-1-5-18", r"C:\Windows\system32\config\systemprofile"),
                    entry(SRC, r"C:\Users\jdoe"),
                ],
            },
            loaded_hives: vec![".DEFAULT".into(), "S-1-5-18".into()],
            hive_files: vec![
                HiveFileProbe {
                    label: "NTUSER.DAT",
                    path: PathBuf::from(r"C:\Users\jdoe\NTUSER.DAT"),
                    state: LockState::Unlocked,
                },
                HiveFileProbe {
                    label: "UsrClass.dat",
                    path: PathBuf::from(
                        r"C:\Users\jdoe\AppData\Local\Microsoft\Windows\UsrClass.dat",
                    ),
                    state: LockState::Unlocked,
                },
            ],
            appx_store_present: false,
            profile_dir: Some(ProfileDirFacts {
                path: PathBuf::from(r"C:\Users\jdoe"),
                exists: true,
                is_reparse_point: false,
            }),
            known_paths: Some(KnownPaths::default()),
            scan: Some(ProfileScan {
                directories: 10,
                files: 40,
                file_bytes: 5 << 30,
                owned_by_source: Tally {
                    count: 50,
                    samples: vec![],
                },
                ..ProfileScan::default()
            }),
            target_dir: Some(TargetDirFacts {
                folder_name: "jdoe.new".into(),
                path: PathBuf::from(r"C:\Users\jdoe.new"),
                exists: false,
                staging_path: PathBuf::from(format!(r"C:\Users\jdoe.new{STAGING_SUFFIX}")),
                staging_exists: false,
            }),
            free_bytes: Some(Ok(100 << 30)),
            registry: Some(Ok(RegistryInspection {
                method: "private copy".into(),
                values_scanned: 1000,
                text_path_refs: vec![r"HKCU\Software\App\Dir".into()],
                ..RegistryInspection::default()
            })),
            local_groups: Some(LocalGroups {
                source: Ok(vec!["Users".into()]),
                target: Ok(vec!["Users".into()]),
            }),
            account_references: Some(AccountReferences::default()),
            apps: vec![],
        }
    }

    fn finding<'a>(report: &'a Report, id: &str) -> &'a Finding {
        report
            .findings
            .iter()
            .find(|f| f.id == id)
            .unwrap_or_else(|| panic!("no finding {id}"))
    }

    fn severity_of(facts: &SystemFacts, id: &str) -> Severity {
        finding(&evaluate(facts, &Options::default()), id).severity
    }

    #[test]
    fn clean_machine_passes_preflight() {
        let report = evaluate(&clean_facts(), &Options::default());
        let blocking: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.severity >= Severity::Warning)
            .collect();
        assert!(blocking.is_empty(), "unexpected: {blocking:#?}");
        assert!(!report.is_blocked());
    }

    #[test]
    fn non_elevated_admin_is_blocked() {
        let mut facts = clean_facts();
        facts.token.is_elevated = false;
        assert_eq!(severity_of(&facts, ids::ELEVATION), Severity::Blocking);
    }

    #[test]
    fn local_system_passes_elevation_without_admin_membership() {
        let mut facts = clean_facts();
        facts.token.user_sid = LOCAL_SYSTEM_SID.into();
        facts.token.is_admin_member = false;
        facts.token.is_elevated = false;
        assert_eq!(severity_of(&facts, ids::ELEVATION), Severity::Pass);
    }

    #[test]
    fn missing_privilege_is_blocked() {
        let mut facts = clean_facts();
        facts.token.privileges.retain(|p| p != "SeRestorePrivilege");
        let report = evaluate(&facts, &Options::default());
        let f = finding(&report, ids::PRIVILEGES);
        assert_eq!(f.severity, Severity::Blocking);
        assert_eq!(f.details, vec!["SeRestorePrivilege".to_string()]);
    }

    #[test]
    fn unsupported_os_can_be_accepted() {
        let mut facts = clean_facts();
        facts.os.as_mut().unwrap().build = 22621;
        assert_eq!(severity_of(&facts, ids::OS_SUPPORTED), Severity::Blocking);
        let options = Options {
            accepted: vec![ids::OS_SUPPORTED.into()],
            ..Options::default()
        };
        let report = evaluate(&facts, &options);
        let f = finding(&report, ids::OS_SUPPORTED);
        assert_eq!(f.severity, Severity::Warning);
        assert!(f.accepted);
    }

    #[test]
    fn accept_does_not_downgrade_hard_checks() {
        let mut facts = clean_facts();
        facts.token.is_elevated = false;
        let options = Options {
            accepted: vec![ids::ELEVATION.into()],
            ..Options::default()
        };
        let report = evaluate(&facts, &options);
        assert_eq!(
            finding(&report, ids::ELEVATION).severity,
            Severity::Blocking
        );
    }

    #[test]
    fn workgroup_machine_is_blocked() {
        let mut facts = clean_facts();
        facts.domain = DomainMembership::Workgroup("WORKGROUP".into());
        assert_eq!(severity_of(&facts, ids::DOMAIN_JOINED), Severity::Blocking);
    }

    #[test]
    fn target_in_other_domain_than_joined_warns() {
        let mut facts = clean_facts();
        facts.domain = DomainMembership::Domain("OLDCORP".into());
        assert_eq!(severity_of(&facts, ids::DOMAIN_JOINED), Severity::Warning);
    }

    #[test]
    fn bare_target_name_is_ambiguous() {
        let mut facts = clean_facts();
        facts.target.input = "jdoe".into();
        facts.target.input_kind = AccountInput::Bare;
        assert_eq!(severity_of(&facts, ids::TARGET_ACCOUNT), Severity::Blocking);
    }

    #[test]
    fn local_target_is_blocked() {
        let mut facts = clean_facts();
        facts.target.lookup =
            LookupOutcome::Found(account("S-1-5-21-100-200-300-1002", "PC01", "jdoe2"));
        assert_eq!(severity_of(&facts, ids::TARGET_ACCOUNT), Severity::Blocking);
    }

    #[test]
    fn group_target_is_blocked() {
        let mut facts = clean_facts();
        let mut info = account(TGT, "CORP", "Staff");
        info.kind = AccountKind::Group;
        facts.target.lookup = LookupOutcome::Found(info);
        assert_eq!(severity_of(&facts, ids::TARGET_ACCOUNT), Severity::Blocking);
    }

    #[test]
    fn lookup_failure_is_not_reported_as_not_found() {
        let mut facts = clean_facts();
        facts.target.lookup = LookupOutcome::Failed("The RPC server is unavailable.".into());
        let report = evaluate(&facts, &Options::default());
        let f = finding(&report, ids::TARGET_ACCOUNT);
        assert_eq!(f.severity, Severity::Blocking);
        assert!(f.summary.contains("lookup failed"));
    }

    #[test]
    fn same_sid_for_source_and_target_is_blocked() {
        let mut facts = clean_facts();
        facts.target.lookup = LookupOutcome::Found(account(SRC, "CORP", "jdoe"));
        assert_eq!(severity_of(&facts, ids::TARGET_ACCOUNT), Severity::Blocking);
    }

    #[test]
    fn builtin_administrator_source_is_blocked() {
        let mut facts = clean_facts();
        let admin = "S-1-5-21-100-200-300-500";
        facts.source.lookup = LookupOutcome::Found(account(admin, "PC01", "Administrator"));
        assert_eq!(severity_of(&facts, ids::SOURCE_ACCOUNT), Severity::Blocking);
    }

    #[test]
    fn unresolvable_source_sid_with_profile_is_overridable() {
        let mut facts = clean_facts();
        facts.source = AccountResolution {
            input: SRC.into(),
            input_kind: AccountInput::Sid(SRC.into()),
            lookup: LookupOutcome::NotFound,
        };
        let report = evaluate(&facts, &Options::default());
        let f = finding(&report, ids::SOURCE_ACCOUNT);
        assert_eq!(f.severity, Severity::Blocking);
        assert!(f.overridable);
        assert!(f.details[0].contains("--accept SOURCE_ACCOUNT"));

        let options = Options {
            accepted: vec![ids::SOURCE_ACCOUNT.into()],
            ..Options::default()
        };
        let report = evaluate(&facts, &options);
        assert_eq!(
            finding(&report, ids::SOURCE_ACCOUNT).severity,
            Severity::Warning
        );
        // The profile itself is still evaluated through the literal SID.
        assert_eq!(
            finding(&report, ids::PROFILE_SOURCE_ENTRY).severity,
            Severity::Pass
        );
    }

    #[test]
    fn unresolvable_source_given_by_name_is_not_overridable() {
        let mut facts = clean_facts();
        facts.source.lookup = LookupOutcome::NotFound;
        let options = Options {
            accepted: vec![ids::SOURCE_ACCOUNT.into()],
            ..Options::default()
        };
        let report = evaluate(&facts, &options);
        assert_eq!(
            finding(&report, ids::SOURCE_ACCOUNT).severity,
            Severity::Blocking
        );
    }

    #[test]
    fn group_source_cannot_be_accepted() {
        let mut facts = clean_facts();
        let mut info = account(SRC, "PC01", "Users2");
        info.kind = AccountKind::Alias;
        facts.source.lookup = LookupOutcome::Found(info);
        let options = Options {
            accepted: vec![ids::SOURCE_ACCOUNT.into()],
            ..Options::default()
        };
        let report = evaluate(&facts, &options);
        assert_eq!(
            finding(&report, ids::SOURCE_ACCOUNT).severity,
            Severity::Blocking
        );
    }

    #[test]
    fn sid_history_is_detected() {
        let mut facts = clean_facts();
        // Old SID resolves to the new account's name.
        facts.source.lookup = LookupOutcome::Found(account(SRC, "CORP", "jdoe"));
        let report = evaluate(&facts, &Options::default());
        let f = finding(&report, ids::SCENARIO);
        assert_eq!(f.severity, Severity::Warning);
        assert!(f.details.iter().any(|d| d.contains("SID history")));
    }

    #[test]
    fn scenario_is_identified() {
        let report = evaluate(&clean_facts(), &Options::default());
        assert!(finding(&report, ids::SCENARIO)
            .summary
            .starts_with("Local -> Domain"));
    }

    #[test]
    fn missing_source_entry_is_blocked() {
        let mut facts = clean_facts();
        facts.profile_list.entries.retain(|e| e.key_name != SRC);
        assert_eq!(
            severity_of(&facts, ids::PROFILE_SOURCE_ENTRY),
            Severity::Blocking
        );
    }

    #[test]
    fn temp_profile_state_is_blocked() {
        let mut facts = clean_facts();
        facts.profile_list.entries[1].state = Some(profile_state::TEMP_ASSIGNED);
        assert_eq!(
            severity_of(&facts, ids::PROFILE_SOURCE_ENTRY),
            Severity::Blocking
        );
    }

    #[test]
    fn nonzero_ref_count_is_blocked() {
        let mut facts = clean_facts();
        facts.profile_list.entries[1].ref_count = Some(1);
        assert_eq!(
            severity_of(&facts, ids::PROFILE_SOURCE_ENTRY),
            Severity::Blocking
        );
    }

    #[test]
    fn sid_value_mismatch_is_blocked() {
        let mut facts = clean_facts();
        facts.profile_list.entries[1].sid_value = SidValue::Valid(TGT.into());
        assert_eq!(
            severity_of(&facts, ids::PROFILE_SOURCE_ENTRY),
            Severity::Blocking
        );
    }

    #[test]
    fn profile_path_assertion_mismatch_is_blocked() {
        let facts = clean_facts();
        let options = Options {
            expected_profile_path: Some(PathBuf::from(r"C:\Users\someoneelse")),
            ..Options::default()
        };
        let report = evaluate(&facts, &options);
        assert_eq!(
            finding(&report, ids::PROFILE_SOURCE_ENTRY).severity,
            Severity::Blocking
        );
    }

    #[test]
    fn profile_path_assertion_ignores_case_and_trailing_slash() {
        let facts = clean_facts();
        let options = Options {
            expected_profile_path: Some(PathBuf::from(r"c:\users\JDOE\")),
            ..Options::default()
        };
        let report = evaluate(&facts, &options);
        assert_eq!(
            finding(&report, ids::PROFILE_SOURCE_ENTRY).severity,
            Severity::Pass
        );
    }

    #[test]
    fn roaming_state_warns() {
        let mut facts = clean_facts();
        facts.profile_list.entries[1].state = Some(profile_state::UPDATE_CENTRAL);
        assert_eq!(
            severity_of(&facts, ids::PROFILE_SOURCE_ENTRY),
            Severity::Warning
        );
    }

    #[test]
    fn existing_target_profile_is_blocked() {
        let mut facts = clean_facts();
        facts
            .profile_list
            .entries
            .push(entry(TGT, r"C:\Users\jdoe.CORP"));
        assert_eq!(
            severity_of(&facts, ids::PROFILE_TARGET_ENTRY),
            Severity::Blocking
        );
    }

    #[test]
    fn bak_for_source_blocks_but_unrelated_bak_warns() {
        let mut facts = clean_facts();
        facts
            .profile_list
            .entries
            .push(entry("S-1-5-21-1-2-3-4444.bak", r"C:\Users\other"));
        assert_eq!(
            severity_of(&facts, ids::PROFILE_LIST_BAK),
            Severity::Warning
        );

        facts
            .profile_list
            .entries
            .push(entry(&format!("{SRC}.bak"), r"C:\Users\jdoe.PC01"));
        assert_eq!(
            severity_of(&facts, ids::PROFILE_LIST_BAK),
            Severity::Blocking
        );
    }

    #[test]
    fn duplicate_profile_path_is_blocked() {
        let mut facts = clean_facts();
        facts
            .profile_list
            .entries
            .push(entry("S-1-5-21-1-2-3-4444", r"C:\Users\JDOE"));
        assert_eq!(
            severity_of(&facts, ids::PROFILE_PATH_UNIQUE),
            Severity::Blocking
        );
    }

    #[test]
    fn interrupted_migration_marker_is_blocked() {
        let mut facts = clean_facts();
        facts.profile_list.entries[1].migration_marker = Some(SRC.into());
        assert_eq!(
            severity_of(&facts, ids::MIGRATION_MARKER),
            Severity::Blocking
        );
    }

    #[test]
    fn loaded_source_classes_hive_is_blocked() {
        let mut facts = clean_facts();
        facts.loaded_hives.push(format!("{SRC}_Classes"));
        assert_eq!(severity_of(&facts, ids::HIVES_UNLOADED), Severity::Blocking);
    }

    #[test]
    fn leftover_windows_profile_migration_mount_is_blocked() {
        let mut facts = clean_facts();
        facts
            .loaded_hives
            .push("windows-profile-migration_ntuser".into());
        assert_eq!(severity_of(&facts, ids::HIVES_UNLOADED), Severity::Blocking);
    }

    #[test]
    fn locked_hive_file_is_blocked() {
        let mut facts = clean_facts();
        facts.hive_files[0].state = LockState::Locked;
        assert_eq!(severity_of(&facts, ids::HIVE_FILES), Severity::Blocking);
    }

    #[test]
    fn missing_usrclass_only_warns() {
        let mut facts = clean_facts();
        facts.hive_files[1].state = LockState::Missing;
        assert_eq!(severity_of(&facts, ids::HIVE_FILES), Severity::Warning);
        facts.hive_files[0].state = LockState::Missing;
        assert_eq!(severity_of(&facts, ids::HIVE_FILES), Severity::Blocking);
    }

    #[test]
    fn reparse_profile_root_is_blocked() {
        let mut facts = clean_facts();
        facts.profile_dir.as_mut().unwrap().is_reparse_point = true;
        assert_eq!(
            severity_of(&facts, ids::PROFILE_DIRECTORY),
            Severity::Blocking
        );
    }

    #[test]
    fn efs_files_block_until_accepted() {
        let mut facts = clean_facts();
        facts
            .scan
            .as_mut()
            .unwrap()
            .encrypted
            .add(r"C:\Users\jdoe\secret.txt");
        assert_eq!(severity_of(&facts, ids::EFS_FILES), Severity::Blocking);
        let options = Options {
            accepted: vec![ids::EFS_FILES.into()],
            ..Options::default()
        };
        assert!(!evaluate(&facts, &options).is_blocked());
    }

    #[test]
    fn empty_acl_footprint_warns_about_wrong_source() {
        let mut facts = clean_facts();
        facts.scan.as_mut().unwrap().owned_by_source = Tally::default();
        assert_eq!(severity_of(&facts, ids::ACL_FOOTPRINT), Severity::Warning);
    }

    #[test]
    fn dpapi_and_appx_warn() {
        let mut facts = clean_facts();
        facts.known_paths = Some(KnownPaths {
            dpapi_master_keys: true,
            credential_files: 2,
            appx_package_dirs: 80,
            ..KnownPaths::default()
        });
        facts.appx_store_present = true;
        for id in [ids::DPAPI_SECRETS, ids::APPX_STATE] {
            assert_eq!(severity_of(&facts, id), Severity::Warning, "{id}");
        }
    }

    #[test]
    fn existing_target_folder_is_blocked() {
        let mut facts = clean_facts();
        facts.target_dir.as_mut().unwrap().exists = true;
        assert_eq!(severity_of(&facts, ids::TARGET_FOLDER), Severity::Blocking);
    }

    #[test]
    fn target_folder_claimed_by_another_profile_is_blocked() {
        let mut facts = clean_facts();
        facts
            .profile_list
            .entries
            .push(entry("S-1-5-21-9-9-9-1001", r"C:\Users\JDOE.NEW"));
        let report = evaluate(&facts, &Options::default());
        let finding = finding(&report, ids::TARGET_FOLDER);
        assert_eq!(finding.severity, Severity::Blocking);
        assert!(finding.details[0].contains("S-1-5-21-9-9-9-1001"));
    }

    #[test]
    fn leftover_staging_copy_is_blocked() {
        let mut facts = clean_facts();
        facts.target_dir.as_mut().unwrap().staging_exists = true;
        let report = evaluate(&facts, &Options::default());
        let finding = finding(&report, ids::TARGET_FOLDER);
        assert_eq!(finding.severity, Severity::Blocking);
        assert!(finding.summary.contains(STAGING_SUFFIX));
    }

    #[test]
    fn insufficient_disk_space_is_blocked() {
        let mut facts = clean_facts();
        // 5 GB of files + 10% + 1 GB margin = 6.5 GB needed.
        facts.free_bytes = Some(Ok(6 << 30));
        assert_eq!(severity_of(&facts, ids::DISK_SPACE), Severity::Blocking);
        facts.free_bytes = Some(Ok(7 << 30));
        assert_eq!(severity_of(&facts, ids::DISK_SPACE), Severity::Pass);
        facts.free_bytes = Some(Err("access denied".into()));
        assert_eq!(severity_of(&facts, ids::DISK_SPACE), Severity::Blocking);
    }

    #[test]
    fn registry_text_paths_are_info_but_binary_paths_warn() {
        let mut facts = clean_facts();
        let report = evaluate(&facts, &Options::default());
        let finding = finding(&report, ids::REGISTRY_PATHS);
        assert_eq!(finding.severity, Severity::Info);
        assert!(finding.summary.contains("1 text values"));
        assert!(finding.summary.contains(r"C:\Users\jdoe.new"));

        if let Some(Ok(inspection)) = facts.registry.as_mut() {
            inspection
                .binary_path_refs
                .push(r"HKCU\Software\Mru\0".into());
        }
        assert_eq!(severity_of(&facts, ids::REGISTRY_PATHS), Severity::Warning);
        facts.registry = Some(Err("copy failed".into()));
        assert_eq!(severity_of(&facts, ids::REGISTRY_PATHS), Severity::Warning);
    }

    #[test]
    fn missing_local_group_warns_with_the_fix() {
        let mut facts = clean_facts();
        facts.local_groups = Some(LocalGroups {
            source: Ok(vec!["Administrators".into(), "Users".into()]),
            target: Ok(vec!["users".into()]),
        });
        let report = evaluate(&facts, &Options::default());
        let finding = finding(&report, ids::LOCAL_GROUPS);
        assert_eq!(finding.severity, Severity::Warning);
        assert_eq!(
            finding.details,
            vec![r"add CORP\jdoe to Administrators if the user still needs it (not done automatically)".to_string()]
        );
    }

    #[test]
    fn unreadable_local_groups_warn() {
        let mut facts = clean_facts();
        facts.local_groups = Some(LocalGroups {
            source: Ok(vec![]),
            target: Err("domain controller unreachable".into()),
        });
        let report = evaluate(&facts, &Options::default());
        let finding = finding(&report, ids::LOCAL_GROUPS);
        assert_eq!(finding.severity, Severity::Warning);
        assert_eq!(
            finding.details,
            vec!["target: domain controller unreachable".to_string()]
        );
    }

    #[test]
    fn services_and_tasks_running_as_source_warn() {
        let mut facts = clean_facts();
        facts.account_references = Some(AccountReferences {
            services: vec!["Backup Agent".into()],
            scheduled_tasks: vec![r"\Sync".into()],
            errors: vec![],
        });
        let report = evaluate(&facts, &Options::default());
        let finding = finding(&report, ids::ACCOUNT_REFERENCES);
        assert_eq!(finding.severity, Severity::Warning);
        assert_eq!(finding.details.len(), 2);
    }

    #[test]
    fn apps_warn_only_when_an_action_is_needed() {
        let mut facts = clean_facts();
        facts.apps = vec![
            AppReport {
                id: "APP_PRINTERS",
                name: "Network printer connections",
                carried: vec![r"\\srv\HP".into()],
                actions: vec![],
            },
            AppReport {
                id: "APP_TEAMS",
                name: "Microsoft Teams",
                carried: vec![],
                actions: vec!["sign in again".into()],
            },
        ];
        assert_eq!(severity_of(&facts, "APP_PRINTERS"), Severity::Info);
        assert_eq!(severity_of(&facts, "APP_TEAMS"), Severity::Warning);
    }

    #[test]
    fn bytes_are_formatted_in_binary_units() {
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(5 << 30), "5.0 GB");
    }

    #[test]
    fn direct_child_detection() {
        assert!(is_direct_child(r"C:\Users\jdoe", r"C:\Users"));
        assert!(is_direct_child(r"c:\users\jdoe\", r"C:\Users\"));
        assert!(!is_direct_child(r"D:\Profiles\jdoe", r"C:\Users"));
        assert!(!is_direct_child(r"C:\Users\x\jdoe", r"C:\Users"));
    }
}
