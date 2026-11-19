//! Dry-run plan: the exact mutations the execution phase would perform,
//! derived only from gathered facts. Building a plan writes nothing.
//!
//! Hives are deliberately not mounted in dry-run: RegLoadKey replays a
//! hive's transaction logs into the file, so even a "read-only" mount can
//! modify NTUSER.DAT. Hive changes are therefore described, not counted.

use crate::model::{
    ProfileListEntry, SystemFacts, HIVE_MOUNT_PREFIX, MIGRATION_MARKER_VALUE, PROFILE_GUID_KEY,
    PROFILE_LIST_KEY,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Area {
    Registry,
    Hive,
    FileSystem,
    FollowUp,
}

impl Area {
    pub fn label(self) -> &'static str {
        match self {
            Area::Registry => "registry",
            Area::Hive => "hive",
            Area::FileSystem => "filesystem",
            Area::FollowUp => "follow-up",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Create,
    Remove,
    Modify,
    Skip,
    Manual,
}

impl Op {
    pub fn symbol(self) -> char {
        match self {
            Op::Create => '+',
            Op::Remove => '-',
            Op::Modify => '~',
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

/// Builds the plan. Returns an empty plan with a single note when the
/// prerequisites (both SIDs and the source entry) are missing.
pub fn build(facts: &SystemFacts) -> Vec<PlannedChange> {
    let (Some(source_sid), Some(target_sid), Some(entry)) =
        (facts.source.sid(), facts.target.sid(), facts.source_entry())
    else {
        return vec![PlannedChange {
            area: Area::Registry,
            op: Op::Manual,
            target: "plan".into(),
            lines: vec![
                "cannot plan: source/target SID or source ProfileList entry is unknown".into(),
            ],
        }];
    };

    let mut plan = vec![
        target_entry(entry, source_sid, target_sid),
        PlannedChange {
            area: Area::Registry,
            op: Op::Remove,
            target: format!("HKLM\\{PROFILE_LIST_KEY}\\{source_sid}"),
            lines: vec![
                "removed only after the target entry and hives are verified".into(),
                "restorable from ProfileList.reg in the backup".into(),
            ],
        },
    ];
    if let Some(guid) = &entry.guid {
        plan.push(PlannedChange {
            area: Area::Registry,
            op: Op::Remove,
            target: format!("HKLM\\{PROFILE_GUID_KEY}\\{guid}"),
            lines: vec![
                "mapping from the source account's objectGUID; the target's is created by Windows at first logon".into(),
            ],
        });
    }

    for (label, mount) in [("NTUSER.DAT", "ntuser"), ("UsrClass.dat", "usrclass")] {
        let Some(probe) = facts.hive_files.iter().find(|h| h.label == label) else {
            continue;
        };
        if probe.state == crate::model::LockState::Missing {
            continue;
        }
        plan.push(PlannedChange {
            area: Area::Hive,
            op: Op::Modify,
            target: probe.path.display().to_string(),
            lines: vec![
                format!("mount at HKU\\{HIVE_MOUNT_PREFIX}{mount} (SeRestorePrivilege)"),
                format!(
                    "replace {source_sid} with {target_sid} in every key owner and explicit ACE"
                ),
                "unload and verify the file is no longer held".into(),
            ],
        });
    }

    if let Some(scan) = &facts.scan {
        let root = facts
            .profile_dir
            .as_ref()
            .map(|d| d.path.display().to_string())
            .unwrap_or_default();
        let mut lines = vec![
            format!(
                "owner {source_sid} -> {target_sid} on {} entries",
                scan.owned_by_source.count
            ),
            format!(
                "explicit ACEs {source_sid} -> {target_sid} on {} entries ({} with protected DACLs)",
                scan.explicit_source_aces.count, scan.protected_dacls_with_source.count
            ),
            "SYSTEM, Administrators and inherited ACEs are left unchanged".into(),
        ];
        lines.extend(
            scan.explicit_source_aces
                .samples
                .iter()
                .map(|s| format!("e.g. {s}")),
        );
        plan.push(PlannedChange {
            area: Area::FileSystem,
            op: Op::Modify,
            target: root,
            lines,
        });
        if scan.reparse_points.count + scan.cloud_placeholders.count > 0 {
            let mut lines = vec![format!(
                "{} junctions/symlinks and {} cloud placeholders are not traversed or modified",
                scan.reparse_points.count, scan.cloud_placeholders.count
            )];
            lines.extend(scan.reparse_points.samples.iter().cloned());
            plan.push(PlannedChange {
                area: Area::FileSystem,
                op: Op::Skip,
                target: "reparse points".into(),
                lines,
            });
        }
    }

    plan.extend(follow_ups(facts));
    plan
}

fn target_entry(entry: &ProfileListEntry, source_sid: &str, target_sid: &str) -> PlannedChange {
    let mut lines = vec![format!(
        "+ {MIGRATION_MARKER_VALUE:<18} REG_SZ         {source_sid}   (in-progress marker, removed on success)"
    )];
    if let Some(path) = &entry.profile_image_path {
        lines.push(format!(
            "+ {:<18} REG_EXPAND_SZ  {path}",
            "ProfileImagePath"
        ));
    }
    lines.push(format!(
        "+ {:<18} REG_DWORD      0x{:08X}   (copied)",
        "Flags",
        entry.flags.unwrap_or(0)
    ));
    lines.push(format!(
        "+ {:<18} REG_DWORD      0x00000000   (reset; source was 0x{:08X})",
        "State",
        entry.state.unwrap_or(0)
    ));
    lines.push(format!(
        "+ {:<18} REG_BINARY     <binary {target_sid}>",
        "Sid"
    ));
    lines.push("  not copied: RefCount, Guid, ProfileLoadTime*/ProfileUnloadTime*".into());
    PlannedChange {
        area: Area::Registry,
        op: Op::Create,
        target: format!("HKLM\\{PROFILE_LIST_KEY}\\{target_sid}"),
        lines,
    }
}

fn follow_ups(facts: &SystemFacts) -> Vec<PlannedChange> {
    let mut items = Vec::new();
    let mut manual = |target: &str, line: String| {
        items.push(PlannedChange {
            area: Area::FollowUp,
            op: Op::Manual,
            target: target.into(),
            lines: vec![line],
        });
    };
    if let Some(known) = &facts.known_paths {
        if known.dpapi_master_keys || known.credential_files > 0 {
            manual(
                "DPAPI",
                "re-enter saved credentials/browser passwords as the target; they cannot be re-keyed offline".into(),
            );
        }
        if !known.onedrive_folders.is_empty() || known.onedrive_client_state {
            manual(
                "OneDrive",
                "unlink before migration, sign in as the target afterwards".into(),
            );
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
            "after first logon, verify Start/Settings; re-register packages if broken".into(),
        );
    }
    if facts.scan.as_ref().is_some_and(|s| s.encrypted.count > 0) {
        manual(
            "EFS",
            "decrypt EFS files as the source user before migrating, or accept their loss".into(),
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
    out.push_str("\nlegend: + create  - remove  ~ modify  = skip  ! manual follow-up\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
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
            hive_files: vec![
                HiveFileProbe {
                    label: "NTUSER.DAT",
                    path: PathBuf::from(r"C:\Users\jdoe\NTUSER.DAT"),
                    state: LockState::Unlocked,
                },
                HiveFileProbe {
                    label: "UsrClass.dat",
                    path: PathBuf::from("UsrClass.dat"),
                    state: LockState::Missing,
                },
            ],
            appx_store_present: true,
            profile_dir: Some(ProfileDirFacts {
                path: PathBuf::from(r"C:\Users\jdoe"),
                exists: true,
                is_reparse_point: false,
            }),
            known_paths: Some(KnownPaths::default()),
            scan: Some(ProfileScan {
                reparse_points: Tally {
                    count: 1,
                    samples: vec![r"C:\Users\jdoe\Application Data".into()],
                },
                ..ProfileScan::default()
            }),
        }
    }

    #[test]
    fn plan_creates_target_and_removes_source_entry() {
        let plan = build(&facts());
        assert_eq!(plan[0].op, Op::Create);
        assert!(plan[0].target.ends_with(TGT));
        assert!(plan[0]
            .lines
            .iter()
            .any(|l| l.contains(r"%SystemDrive%\Users\jdoe")));
        assert!(plan[0]
            .lines
            .iter()
            .any(|l| l.contains("reset; source was 0x00000100")));
        assert_eq!(plan[1].op, Op::Remove);
        assert!(plan[1].target.ends_with(SRC));
    }

    #[test]
    fn plan_drops_profile_guid_mapping_when_present() {
        let plan = build(&facts());
        assert!(plan
            .iter()
            .any(|c| c.op == Op::Remove && c.target.ends_with("{0f2a-guid}")));
    }

    #[test]
    fn missing_hive_file_is_not_planned() {
        let plan = build(&facts());
        let hives: Vec<_> = plan.iter().filter(|c| c.area == Area::Hive).collect();
        assert_eq!(hives.len(), 1);
        assert!(hives[0].target.ends_with("NTUSER.DAT"));
    }

    #[test]
    fn reparse_points_are_listed_as_skipped() {
        let plan = build(&facts());
        let skip = plan.iter().find(|c| c.op == Op::Skip).unwrap();
        assert!(skip.lines.iter().any(|l| l.contains("Application Data")));
    }

    #[test]
    fn appx_follow_up_is_included() {
        let plan = build(&facts());
        assert!(plan
            .iter()
            .any(|c| c.area == Area::FollowUp && c.target == "AppX"));
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
        assert!(text.contains(&format!("[registry] + HKLM\\{PROFILE_LIST_KEY}\\{TGT}")));
    }
}
