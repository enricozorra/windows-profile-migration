//! Dry-run plan: the exact steps the execution phase would perform,
//! derived only from gathered facts. Building a plan writes nothing.
//!
//! The migration never modifies the source profile. It builds a working
//! copy next to the final folder, rewrites SIDs and paths in the copy only,
//! verifies it, and commits by renaming the copy and adding the target's
//! ProfileList entry. Until the operator finalizes, rolling back means
//! deleting the copy and that entry; the source account keeps working.

use crate::model::{
    ProfileListEntry, SystemFacts, TargetDirFacts, MIGRATION_MARKER_VALUE, PROFILE_LIST_KEY,
};
use crate::preflight::format_bytes;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Area {
    Copy,
    Rewrite,
    Verify,
    Commit,
    Unchanged,
    FollowUp,
}

impl Area {
    pub fn label(self) -> &'static str {
        match self {
            Area::Copy => "copy",
            Area::Rewrite => "rewrite",
            Area::Verify => "verify",
            Area::Commit => "commit",
            Area::Unchanged => "unchanged",
            Area::FollowUp => "follow-up",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Create,
    Modify,
    Check,
    Skip,
    Manual,
}

impl Op {
    pub fn symbol(self) -> char {
        match self {
            Op::Create => '+',
            Op::Modify => '~',
            Op::Check => '?',
            Op::Skip => '=',
            Op::Manual => '!',
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedChange {
    pub area: Area,
    pub op: Op,
    pub target: String,
    pub lines: Vec<String>,
}

/// Builds the plan. Returns a single note when the prerequisites (both
/// SIDs, the source entry and the target folder) are missing.
pub fn build(facts: &SystemFacts) -> Vec<PlannedChange> {
    let (Some(source_sid), Some(target_sid), Some(entry), Some(dir), Some(source_root)) = (
        facts.source.sid(),
        facts.target.sid(),
        facts.source_entry(),
        facts.target_dir.as_ref(),
        facts.profile_dir.as_ref(),
    ) else {
        return vec![PlannedChange {
            area: Area::FollowUp,
            op: Op::Manual,
            target: "plan".into(),
            lines: vec![
                "cannot plan: source/target SID, source ProfileList entry or target folder is unknown"
                    .into(),
            ],
        }];
    };
    let source = source_root.path.display().to_string();
    let staging = dir.staging_path.display().to_string();
    let target = dir.path.display().to_string();

    let mut plan = vec![copy_step(facts, &source, &staging)];
    if let Some(scan) = &facts.scan {
        if scan.reparse_points.count > 0 {
            let mut lines = vec![format!(
                "{} junctions/symlinks are recreated, retargeted from {source} to {target}",
                scan.reparse_points.count
            )];
            lines.extend(scan.reparse_points.samples.iter().cloned());
            plan.push(PlannedChange {
                area: Area::Copy,
                op: Op::Create,
                target: "junctions".into(),
                lines,
            });
        }
        if scan.cloud_placeholders.count > 0 {
            plan.push(PlannedChange {
                area: Area::Copy,
                op: Op::Skip,
                target: "cloud placeholders".into(),
                lines: vec![format!(
                    "{} online-only files are not copied (copying would download them)",
                    scan.cloud_placeholders.count
                )],
            });
        }
    }

    plan.push(hive_step(facts, source_sid, target_sid, &source, &target));
    if let Some(scan) = &facts.scan {
        plan.push(PlannedChange {
            area: Area::Rewrite,
            op: Op::Modify,
            target: format!("{staging} (file security)"),
            lines: vec![
                format!(
                    "owner {source_sid} -> {target_sid} on {} entries",
                    scan.owned_by_source.count
                ),
                format!(
                    "explicit ACEs {source_sid} -> {target_sid} on {} entries ({} with protected DACLs)",
                    scan.explicit_source_aces.count, scan.protected_dacls_with_source.count
                ),
                "translated while copying, inherited ACEs included; other SIDs are kept byte for byte"
                    .into(),
            ],
        });
    }
    plan.push(PlannedChange {
        area: Area::Verify,
        op: Op::Check,
        target: staging.clone(),
        lines: vec![
            "same number of folders and files, same sizes as the source".into(),
            "both hive copies load, and no key owner or ACE still names the source SID".into(),
            "no file owner or explicit ACE still names the source SID".into(),
            "any failure stops here: the copy is deleted and nothing outside it has changed".into(),
        ],
    });
    plan.push(commit_step(entry, dir, source_sid, target_sid, &staging));
    plan.push(PlannedChange {
        area: Area::Unchanged,
        op: Op::Skip,
        target: source.clone(),
        lines: vec![
            format!("the source folder and HKLM\\{PROFILE_LIST_KEY}\\{source_sid} are not modified"),
            "rollback until finalize: delete the target entry and folder; the source account logs on as before".into(),
        ],
    });
    plan.extend(follow_ups(facts));
    plan
}

fn copy_step(facts: &SystemFacts, source: &str, staging: &str) -> PlannedChange {
    let mut lines = vec![format!("from {source} (read-only, never modified)")];
    if let Some(scan) = &facts.scan {
        lines.push(format!(
            "{} folders, {} files, {}",
            scan.directories,
            scan.files,
            format_bytes(scan.file_bytes)
        ));
    }
    lines.push(
        "with backup semantics: attributes, timestamps and security descriptors are kept".into(),
    );
    PlannedChange {
        area: Area::Copy,
        op: Op::Create,
        target: staging.to_string(),
        lines,
    }
}

fn hive_step(
    facts: &SystemFacts,
    source_sid: &str,
    target_sid: &str,
    source: &str,
    target: &str,
) -> PlannedChange {
    let mut lines = vec![
        "NTUSER.DAT and UsrClass.dat are rewritten in the copy; the originals are never loaded"
            .into(),
        format!("{source_sid} -> {target_sid} in every key owner and ACE, and in text values"),
        "UserChoice keys (default apps for http, https, .pdf) are protected by Windows and \
         left as they are: Windows resets those defaults at the first logon"
            .into(),
    ];
    match &facts.registry {
        Some(Ok(inspection)) => {
            lines.push(format!(
                "{} text values: {source} -> {target}",
                inspection.text_path_refs.len()
            ));
            if !inspection.binary_path_refs.is_empty() {
                lines.push(format!(
                    "{} binary values that embed {source} are reported, not rewritten",
                    inspection.binary_path_refs.len()
                ));
            }
            if !inspection.loose_path_refs.is_empty() {
                lines.push(format!(
                    "{} text values that mention {source} but not as a whole path are reported, not rewritten",
                    inspection.loose_path_refs.len()
                ));
            }
            lines.push("each hive is reloaded and checked after the rewrite".into());
        }
        _ => lines.push(format!(
            "text values containing {source} -> {target} (not counted: registry not inspected)"
        )),
    }
    PlannedChange {
        area: Area::Rewrite,
        op: Op::Modify,
        target: "registry hives (copies)".into(),
        lines,
    }
}

fn commit_step(
    entry: &ProfileListEntry,
    dir: &TargetDirFacts,
    source_sid: &str,
    target_sid: &str,
    staging: &str,
) -> PlannedChange {
    let target = dir.path.display().to_string();
    // Keep the source entry's unexpanded form (%SystemDrive%\Users\...) so
    // the new entry looks exactly like one the profile service writes.
    let image_path = entry
        .profile_image_path
        .as_deref()
        .and_then(|p| p.rsplit_once('\\'))
        .map(|(parent, _)| format!("{parent}\\{}", dir.folder_name))
        .unwrap_or_else(|| target.clone());
    PlannedChange {
        area: Area::Commit,
        op: Op::Create,
        target: format!("HKLM\\{PROFILE_LIST_KEY}\\{target_sid}"),
        lines: vec![
            format!("rename {staging} -> {target}"),
            format!("+ {MIGRATION_MARKER_VALUE:<18} REG_SZ         {source_sid}   (in-progress marker, removed on success)"),
            format!("+ {:<18} REG_EXPAND_SZ  {image_path}", "ProfileImagePath"),
            format!(
                "+ {:<18} REG_DWORD      0x{:08X}   (copied)",
                "Flags",
                entry.flags.unwrap_or(0)
            ),
            format!(
                "+ {:<18} REG_DWORD      0x00000000   (reset; source was 0x{:08X})",
                "State",
                entry.state.unwrap_or(0)
            ),
            format!("+ {:<18} REG_BINARY     <binary {target_sid}>", "Sid"),
            "  not set: RefCount, Guid (Windows adds them at the target's first logon)".into(),
        ],
    }
}

fn follow_ups(facts: &SystemFacts) -> Vec<PlannedChange> {
    let mut items = Vec::new();
    let mut manual = |target: &str, lines: Vec<String>| {
        items.push(PlannedChange {
            area: Area::FollowUp,
            op: Op::Manual,
            target: target.into(),
            lines,
        });
    };
    if let Some(known) = &facts.known_paths {
        if known.dpapi_master_keys || known.credential_files > 0 {
            manual(
                "saved credentials",
                vec!["re-enter saved Windows credentials as the target; they cannot be re-keyed offline (the source profile keeps them)".into()],
            );
        }
    }
    for app in facts.apps.iter().filter(|a| !a.actions.is_empty()) {
        manual(app.name, app.actions.clone());
    }
    if let Some(groups) = &facts.local_groups {
        if let (Ok(source), Ok(target)) = (&groups.source, &groups.target) {
            let missing: Vec<String> = source
                .iter()
                .filter(|g| !target.iter().any(|t| t.eq_ignore_ascii_case(g)))
                .map(|g| format!("add the target to {g}"))
                .collect();
            if !missing.is_empty() {
                manual("local groups", missing);
            }
        }
    }
    if let Some(refs) = &facts.account_references {
        let mut lines: Vec<String> = refs
            .services
            .iter()
            .map(|s| format!("service {s}"))
            .collect();
        lines.extend(
            refs.scheduled_tasks
                .iter()
                .map(|t| format!("scheduled task {t}")),
        );
        if !lines.is_empty() {
            manual("run-as account", lines);
        }
    }
    if facts.appx_store_present
        || facts
            .known_paths
            .as_ref()
            .is_some_and(|k| k.appx_package_dirs > 0)
    {
        manual(
            "AppX",
            vec!["after first logon, verify Start/Settings; re-register packages if broken".into()],
        );
    }
    if facts.scan.as_ref().is_some_and(|s| s.encrypted.count > 0) {
        manual(
            "EFS",
            vec![
                "decrypt EFS files as the source user before migrating, or accept their loss"
                    .into(),
            ],
        );
    }
    items
}

/// Human-readable diff-style rendering.
pub fn render(plan: &[PlannedChange]) -> String {
    let mut out = String::from("DRY RUN: planned changes (nothing has been written)\n");
    for change in plan {
        out.push_str(&format!(
            "\n[{}] {} {}\n",
            change.area.label(),
            change.op.symbol(),
            change.target
        ));
        for line in &change.lines {
            out.push_str("    ");
            out.push_str(line);
            out.push('\n');
        }
    }
    out.push_str("\nlegend: + create  ~ modify  ? verify  = unchanged/skip  ! manual follow-up\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apps::AppReport;
    use crate::model::*;
    use std::path::PathBuf;

    const SRC: &str = "S-1-5-21-100-200-300-1001";
    const TGT: &str = "S-1-5-21-900-800-700-1105";

    fn facts() -> SystemFacts {
        let found = |sid: &str, domain: &str| {
            LookupOutcome::Found(AccountInfo {
                sid: sid.into(),
                domain: domain.into(),
                name: "jdoe".into(),
                kind: AccountKind::User,
            })
        };
        SystemFacts {
            token: TokenInfo {
                user_sid: "S-1-5-18".into(),
                is_elevated: true,
                is_admin_member: true,
                privileges: vec![],
            },
            os: Err("n/a".into()),
            computer_name: "PC01".into(),
            domain: DomainMembership::Domain("CORP".into()),
            source: AccountResolution {
                input: r".\jdoe".into(),
                input_kind: AccountInput::Qualified,
                lookup: found(SRC, "PC01"),
            },
            target: AccountResolution {
                input: r"CORP\jdoe".into(),
                input_kind: AccountInput::Qualified,
                lookup: found(TGT, "CORP"),
            },
            profile_list: ProfileListSnapshot {
                profiles_directory: Some(r"C:\Users".into()),
                entries: vec![ProfileListEntry {
                    key_name: SRC.into(),
                    profile_image_path: Some(r"%SystemDrive%\Users\jdoe".into()),
                    profile_image_path_expanded: Some(r"C:\Users\jdoe".into()),
                    flags: Some(0),
                    state: Some(0x0100),
                    ref_count: Some(0),
                    sid_value: SidValue::Valid(SRC.into()),
                    guid: Some("{0f2a-guid}".into()),
                    migration_marker: None,
                }],
            },
            loaded_hives: vec![],
            hive_files: vec![],
            appx_store_present: true,
            profile_dir: Some(ProfileDirFacts {
                path: PathBuf::from(r"C:\Users\jdoe"),
                exists: true,
                is_reparse_point: false,
            }),
            known_paths: Some(KnownPaths::default()),
            scan: Some(ProfileScan {
                directories: 2,
                files: 3,
                file_bytes: 2048,
                reparse_points: Tally {
                    count: 1,
                    samples: vec![r"C:\Users\jdoe\Application Data".into()],
                },
                ..ProfileScan::default()
            }),
            target_dir: Some(TargetDirFacts {
                folder_name: "jdoe.corp".into(),
                path: PathBuf::from(r"C:\Users\jdoe.corp"),
                exists: false,
                staging_path: PathBuf::from(format!(r"C:\Users\jdoe.corp{STAGING_SUFFIX}")),
                staging_exists: false,
            }),
            free_bytes: Some(Ok(1 << 40)),
            registry: Some(Ok(RegistryInspection {
                text_path_refs: vec!["a".into(), "b".into()],
                binary_path_refs: vec!["c".into()],
                ..RegistryInspection::default()
            })),
            local_groups: Some(LocalGroups {
                source: Ok(vec!["Administrators".into(), "Users".into()]),
                target: Ok(vec!["Users".into()]),
            }),
            account_references: Some(AccountReferences::default()),
            apps: vec![AppReport {
                id: "APP_TEAMS",
                name: "Microsoft Teams",
                carried: vec![],
                actions: vec!["sign in to Teams again as the target".into()],
            }],
        }
    }

    fn step(plan: &[PlannedChange], area: Area) -> &PlannedChange {
        plan.iter()
            .find(|c| c.area == area)
            .unwrap_or_else(|| panic!("no {area:?} step"))
    }

    #[test]
    fn plan_copies_into_staging_then_commits_to_the_new_folder() {
        let plan = build(&facts());
        let copy = &plan[0];
        assert_eq!((copy.area, copy.op), (Area::Copy, Op::Create));
        assert!(copy.target.ends_with(STAGING_SUFFIX));
        assert!(copy.lines.iter().any(|l| l == "2 folders, 3 files, 2.0 KB"));

        let commit = step(&plan, Area::Commit);
        assert!(commit.target.ends_with(TGT));
        assert!(commit
            .lines
            .iter()
            .any(|l| l.contains(r"%SystemDrive%\Users\jdoe.corp")));
        assert!(commit
            .lines
            .iter()
            .any(|l| l.contains("reset; source was 0x00000100")));
    }

    #[test]
    fn source_profile_is_declared_unchanged() {
        let plan = build(&facts());
        let unchanged = step(&plan, Area::Unchanged);
        assert_eq!(unchanged.target, r"C:\Users\jdoe");
        assert!(unchanged.lines[0].contains(SRC));
        assert!(!plan.iter().any(|c| c.target.contains("ProfileGuid")));
    }

    #[test]
    fn verification_comes_before_commit() {
        let plan = build(&facts());
        let position = |area| plan.iter().position(|c| c.area == area).unwrap();
        assert!(position(Area::Rewrite) < position(Area::Verify));
        assert!(position(Area::Verify) < position(Area::Commit));
    }

    #[test]
    fn registry_counts_and_binary_caveat_are_shown() {
        let plan = build(&facts());
        let hive = plan
            .iter()
            .find(|c| c.target == "registry hives (copies)")
            .unwrap();
        assert!(hive.lines.iter().any(|l| l.starts_with("2 text values")));
        assert!(hive
            .lines
            .iter()
            .any(|l| l.contains("reported, not rewritten")));
    }

    #[test]
    fn junctions_are_recreated_for_the_new_folder() {
        let plan = build(&facts());
        let junctions = plan.iter().find(|c| c.target == "junctions").unwrap();
        assert!(junctions.lines[0].contains(r"to C:\Users\jdoe.corp"));
    }

    #[test]
    fn follow_ups_include_apps_and_missing_groups() {
        let plan = build(&facts());
        let follow: Vec<&str> = plan
            .iter()
            .filter(|c| c.area == Area::FollowUp)
            .map(|c| c.target.as_str())
            .collect();
        assert!(follow.contains(&"Microsoft Teams"));
        assert!(follow.contains(&"local groups"));
        assert!(follow.contains(&"AppX"));
    }

    #[test]
    fn unknown_target_yields_a_note_not_a_plan() {
        let mut f = facts();
        f.target.lookup = LookupOutcome::NotFound;
        let plan = build(&f);
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].op, Op::Manual);
    }

    #[test]
    fn render_marks_dry_run() {
        let text = render(&build(&facts()));
        assert!(text.starts_with("DRY RUN"));
        assert!(text.contains(&format!("[commit] + HKLM\\{PROFILE_LIST_KEY}\\{TGT}")));
    }
}
