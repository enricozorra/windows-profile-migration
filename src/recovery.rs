//! Pure decisions for `status` and `rollback`.
//!
//! The journal says what a migration may have created; the observation
//! says what exists now and whether it carries this migration's marker.
//! From the two, `plan_rollback` decides what to undo, in which order, or
//! why it must refuse. Nothing here touches the system.

use std::path::PathBuf;

use crate::journal::{Artifact, ArtifactKind, ArtifactState, JournalState};

/// What exists now at an artifact's location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Presence {
    Absent,
    /// Present and carrying this migration's marker.
    Ours,
    /// Present but not provably created by this migration: never deleted.
    Foreign(String),
    /// Could not be checked.
    Unknown(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observed {
    /// One entry per journal artifact, in the same order.
    pub artifacts: Vec<Presence>,
    pub target_logged_on: bool,
    /// Whether the target's hive changed after the commit, i.e. the user
    /// has worked in the migrated profile.
    pub target_used_after_commit: Result<bool, String>,
    /// Err describes how the source profile no longer looks as recorded.
    pub source_intact: Result<(), String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Preparing,
    Committed,
    Finalized,
    RolledBack,
}

impl Phase {
    pub fn label(self) -> &'static str {
        match self {
            Phase::Preparing => "preparing (not committed: the source is still the active profile)",
            Phase::Committed => "committed (the target logs on to the migrated profile)",
            Phase::Finalized => "finalized",
            Phase::RolledBack => "rolled back",
        }
    }
}

pub fn phase(state: &JournalState) -> Phase {
    if state.finalized_at.is_some() {
        Phase::Finalized
    } else if state.rolled_back_at.is_some() {
        Phase::RolledBack
    } else if state.committed_at.is_some() {
        Phase::Committed
    } else {
        Phase::Preparing
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    UnloadHive(String),
    DeleteProfileListEntry(String),
    DeleteFolder(PathBuf),
}

impl Action {
    pub fn describe(&self) -> String {
        match self {
            Action::UnloadHive(name) => format!("unload HKU\\{name}"),
            Action::DeleteProfileListEntry(sid) => format!("delete ProfileList entry {sid}"),
            Action::DeleteFolder(path) => format!("delete folder {}", path.display()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RollbackPlan {
    NothingToDo {
        notes: Vec<String>,
    },
    Refused {
        reasons: Vec<String>,
    },
    Ready {
        actions: Vec<Action>,
        notes: Vec<String>,
    },
}

#[derive(Debug, Clone, Copy, Default)]
pub struct RollbackOptions {
    pub discard_target_changes: bool,
}

/// Undo order: mounts first (they hold files open), then the ProfileList
/// entry (so Windows stops pointing at the folder), then the folders.
fn undo_rank(kind: ArtifactKind) -> u8 {
    match kind {
        ArtifactKind::HiveMount => 0,
        ArtifactKind::ProfileListEntry => 1,
        ArtifactKind::TargetDir => 2,
        ArtifactKind::StagingDir => 3,
    }
}

pub fn describe_artifact(artifact: &Artifact) -> String {
    format!("{} {}", artifact.kind.name(), artifact.value)
}

pub fn plan_rollback(
    state: &JournalState,
    observed: &Observed,
    options: RollbackOptions,
) -> RollbackPlan {
    if let Some(at) = &state.finalized_at {
        return RollbackPlan::Refused {
            reasons: vec![format!(
                "the migration was finalized at {at}; the source account was retired and cannot be restored by rollback"
            )],
        };
    }

    let mut reasons = Vec::new();
    if observed.target_logged_on {
        reasons.push(format!(
            "{} is logged on; sign the user out first",
            state.header.target_name
        ));
    }
    if state.committed_at.is_some() && !options.discard_target_changes {
        match &observed.target_used_after_commit {
            Ok(false) => {}
            Ok(true) => reasons.push(
                "the target has used the migrated profile since the commit; rollback would discard those changes. \
                 Copy what is needed, then re-run with --discard-target-changes"
                    .into(),
            ),
            Err(err) => reasons.push(format!(
                "could not tell whether the target used the migrated profile ({err}); \
                 re-run with --discard-target-changes to roll back anyway"
            )),
        }
    }
    for (artifact, presence) in state.artifacts.iter().zip(&observed.artifacts) {
        match presence {
            Presence::Foreign(why) => reasons.push(format!(
                "{} exists but was not created by this migration ({why}); it is never deleted",
                describe_artifact(artifact)
            )),
            Presence::Unknown(err) => reasons.push(format!(
                "could not check {}: {err}",
                describe_artifact(artifact)
            )),
            Presence::Absent | Presence::Ours => {}
        }
    }
    if !reasons.is_empty() {
        return RollbackPlan::Refused { reasons };
    }

    let mut notes = Vec::new();
    let mut pending: Vec<(&Artifact, &Presence)> =
        state.artifacts.iter().zip(&observed.artifacts).collect();
    pending.sort_by_key(|(artifact, _)| undo_rank(artifact.kind));
    let mut actions = Vec::new();
    for (artifact, presence) in pending {
        match (presence, artifact.state) {
            (Presence::Ours, _) => actions.push(match artifact.kind {
                ArtifactKind::HiveMount => Action::UnloadHive(artifact.value.clone()),
                ArtifactKind::ProfileListEntry => {
                    Action::DeleteProfileListEntry(artifact.value.clone())
                }
                ArtifactKind::TargetDir | ArtifactKind::StagingDir => {
                    Action::DeleteFolder(PathBuf::from(&artifact.value))
                }
            }),
            (Presence::Absent, ArtifactState::Removed) => {}
            (Presence::Absent, _) => notes.push(format!(
                "{}: not present (never created, or already removed)",
                describe_artifact(artifact)
            )),
            (Presence::Foreign(_) | Presence::Unknown(_), _) => {}
        }
    }
    if let Err(problem) = &observed.source_intact {
        notes.push(format!(
            "WARNING: the source profile has changed: {problem}"
        ));
    }
    if actions.is_empty() {
        RollbackPlan::NothingToDo { notes }
    } else {
        RollbackPlan::Ready { actions, notes }
    }
}

/// Leftovers that carry this tool's naming but belong to no journal.
pub fn find_orphans(
    journals: &[JournalState],
    staging_dirs: &[String],
    marked_entries: &[String],
    mounts: &[String],
) -> Vec<String> {
    let known = |kind: ArtifactKind, value: &str| {
        journals.iter().any(|j| {
            j.artifacts
                .iter()
                .any(|a| a.kind == kind && a.value.eq_ignore_ascii_case(value))
        })
    };
    let mut orphans = Vec::new();
    for dir in staging_dirs {
        if !known(ArtifactKind::StagingDir, dir) {
            orphans.push(format!("working copy {dir}"));
        }
    }
    for sid in marked_entries {
        if !known(ArtifactKind::ProfileListEntry, sid) {
            orphans.push(format!("ProfileList entry {sid} with a migration marker"));
        }
    }
    for mount in mounts {
        if !known(ArtifactKind::HiveMount, mount) {
            orphans.push(format!("registry mount HKU\\{mount}"));
        }
    }
    orphans
}

pub fn render_status(state: &JournalState, observed: &Observed, plan: &RollbackPlan) -> String {
    let header = &state.header;
    let mut out = format!(
        "migration {}\n    {} -> {}\n    {} -> {}\n    started {} (tool {})\n    phase: {}\n",
        header.id,
        header.source_name,
        header.target_name,
        header.source_path,
        header.target_path,
        header.started,
        header.version,
        phase(state).label()
    );
    for (artifact, presence) in state.artifacts.iter().zip(&observed.artifacts) {
        let now = match presence {
            Presence::Absent => "absent".to_string(),
            Presence::Ours => "present".to_string(),
            Presence::Foreign(why) => format!("present, NOT OURS ({why})"),
            Presence::Unknown(err) => format!("unknown ({err})"),
        };
        out.push_str(&format!(
            "    {:<10} {:<60} now {now}\n",
            format!("{:?}", artifact.state).to_lowercase(),
            describe_artifact(artifact)
        ));
    }
    match &observed.source_intact {
        Ok(()) => out.push_str("    source profile: intact\n"),
        Err(problem) => out.push_str(&format!("    source profile: CHANGED: {problem}\n")),
    }
    for problem in &state.problems {
        out.push_str(&format!("    journal: {problem}\n"));
    }
    match plan {
        RollbackPlan::NothingToDo { .. } => out.push_str("    rollback: nothing left to undo\n"),
        RollbackPlan::Refused { reasons } => {
            out.push_str("    rollback: refused\n");
            for reason in reasons {
                out.push_str(&format!("      - {reason}\n"));
            }
        }
        RollbackPlan::Ready { actions, .. } => {
            out.push_str(&format!(
                "    rollback would: {}\n",
                actions
                    .iter()
                    .map(Action::describe)
                    .collect::<Vec<_>>()
                    .join("; ")
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::Header;

    fn artifact(kind: ArtifactKind, value: &str, state: ArtifactState) -> Artifact {
        Artifact {
            kind,
            value: value.into(),
            state,
        }
    }

    fn journal(artifacts: Vec<Artifact>) -> JournalState {
        JournalState {
            header: Header {
                id: "m1".into(),
                source_sid: "S-1-5-21-1-2-3-1001".into(),
                target_name: r"CORP\new".into(),
                ..Header::default()
            },
            artifacts,
            ..JournalState::default()
        }
    }

    fn observed(artifacts: Vec<Presence>) -> Observed {
        Observed {
            artifacts,
            target_logged_on: false,
            target_used_after_commit: Ok(false),
            source_intact: Ok(()),
        }
    }

    fn preparing() -> JournalState {
        journal(vec![
            artifact(
                ArtifactKind::StagingDir,
                r"C:\Users\new.staging",
                ArtifactState::Created,
            ),
            artifact(
                ArtifactKind::HiveMount,
                "wpm_ntuser",
                ArtifactState::Intended,
            ),
        ])
    }

    fn committed() -> JournalState {
        let mut state = journal(vec![
            artifact(
                ArtifactKind::TargetDir,
                r"C:\Users\new",
                ArtifactState::Created,
            ),
            artifact(
                ArtifactKind::ProfileListEntry,
                "S-1-5-21-9-8-7-2601",
                ArtifactState::Created,
            ),
        ]);
        state.committed_at = Some("2026-11-20T10:00:00.000Z".into());
        state
    }

    #[test]
    fn interrupted_preparation_unloads_then_deletes_the_copy() {
        let plan = plan_rollback(
            &preparing(),
            &observed(vec![Presence::Ours, Presence::Ours]),
            RollbackOptions::default(),
        );
        assert_eq!(
            plan,
            RollbackPlan::Ready {
                actions: vec![
                    Action::UnloadHive("wpm_ntuser".into()),
                    Action::DeleteFolder(PathBuf::from(r"C:\Users\new.staging")),
                ],
                notes: vec![],
            }
        );
    }

    #[test]
    fn intended_but_absent_artifacts_are_only_noted() {
        let plan = plan_rollback(
            &preparing(),
            &observed(vec![Presence::Ours, Presence::Absent]),
            RollbackOptions::default(),
        );
        let RollbackPlan::Ready { actions, notes } = plan else {
            panic!("expected Ready, got {plan:?}");
        };
        assert_eq!(actions.len(), 1);
        assert!(notes[0].contains("hive_mount wpm_ntuser: not present"));
    }

    #[test]
    fn committed_migration_removes_the_entry_before_the_folder() {
        let plan = plan_rollback(
            &committed(),
            &observed(vec![Presence::Ours, Presence::Ours]),
            RollbackOptions::default(),
        );
        let RollbackPlan::Ready { actions, .. } = plan else {
            panic!("expected Ready, got {plan:?}");
        };
        assert_eq!(
            actions,
            vec![
                Action::DeleteProfileListEntry("S-1-5-21-9-8-7-2601".into()),
                Action::DeleteFolder(PathBuf::from(r"C:\Users\new")),
            ]
        );
    }

    #[test]
    fn foreign_artifact_refuses_the_whole_rollback() {
        let plan = plan_rollback(
            &preparing(),
            &observed(vec![
                Presence::Foreign("has no migration marker".into()),
                Presence::Ours,
            ]),
            RollbackOptions::default(),
        );
        let RollbackPlan::Refused { reasons } = plan else {
            panic!("expected Refused, got {plan:?}");
        };
        assert!(reasons[0].contains("never deleted"));
    }

    #[test]
    fn unknown_presence_refuses() {
        let plan = plan_rollback(
            &preparing(),
            &observed(vec![
                Presence::Unknown("access denied".into()),
                Presence::Absent,
            ]),
            RollbackOptions::default(),
        );
        assert!(matches!(plan, RollbackPlan::Refused { .. }));
    }

    #[test]
    fn logged_on_target_refuses() {
        let mut seen = observed(vec![Presence::Ours, Presence::Ours]);
        seen.target_logged_on = true;
        let plan = plan_rollback(&committed(), &seen, RollbackOptions::default());
        let RollbackPlan::Refused { reasons } = plan else {
            panic!("expected Refused");
        };
        assert!(reasons[0].contains(r"CORP\new is logged on"));
    }

    #[test]
    fn target_changes_need_explicit_discard() {
        let mut seen = observed(vec![Presence::Ours, Presence::Ours]);
        seen.target_used_after_commit = Ok(true);
        assert!(matches!(
            plan_rollback(&committed(), &seen, RollbackOptions::default()),
            RollbackPlan::Refused { .. }
        ));
        seen.target_used_after_commit = Err("NTUSER.DAT unreadable".into());
        assert!(matches!(
            plan_rollback(&committed(), &seen, RollbackOptions::default()),
            RollbackPlan::Refused { .. }
        ));
        let discard = RollbackOptions {
            discard_target_changes: true,
        };
        assert!(matches!(
            plan_rollback(&committed(), &seen, discard),
            RollbackPlan::Ready { .. }
        ));
    }

    #[test]
    fn usage_is_irrelevant_before_the_commit() {
        let mut seen = observed(vec![Presence::Ours, Presence::Absent]);
        seen.target_used_after_commit = Err("no profile yet".into());
        assert!(matches!(
            plan_rollback(&preparing(), &seen, RollbackOptions::default()),
            RollbackPlan::Ready { .. }
        ));
    }

    #[test]
    fn finalized_migration_cannot_be_rolled_back() {
        let mut state = committed();
        state.finalized_at = Some("t".into());
        assert!(matches!(
            plan_rollback(
                &state,
                &observed(vec![Presence::Ours, Presence::Ours]),
                RollbackOptions {
                    discard_target_changes: true
                }
            ),
            RollbackPlan::Refused { .. }
        ));
    }

    #[test]
    fn completed_rollback_has_nothing_left() {
        let mut state = preparing();
        state
            .artifacts
            .iter_mut()
            .for_each(|a| a.state = ArtifactState::Removed);
        state.rolled_back_at = Some("t".into());
        let plan = plan_rollback(
            &state,
            &observed(vec![Presence::Absent, Presence::Absent]),
            RollbackOptions::default(),
        );
        assert_eq!(plan, RollbackPlan::NothingToDo { notes: vec![] });
        assert_eq!(phase(&state), Phase::RolledBack);
    }

    #[test]
    fn changed_source_is_flagged_loudly() {
        let mut seen = observed(vec![Presence::Ours, Presence::Absent]);
        seen.source_intact = Err("ProfileList entry is missing".into());
        let RollbackPlan::Ready { notes, .. } =
            plan_rollback(&preparing(), &seen, RollbackOptions::default())
        else {
            panic!("expected Ready");
        };
        assert!(notes.iter().any(|n| n.starts_with("WARNING")));
    }

    #[test]
    fn orphans_are_leftovers_no_journal_knows() {
        let journals = vec![preparing()];
        let orphans = find_orphans(
            &journals,
            &[r"c:\users\NEW.staging".into(), r"C:\Users\x.staging".into()],
            &["S-1-5-21-5-5-5-1".into()],
            &["wpm_ntuser".into(), "wpm_other".into()],
        );
        assert_eq!(
            orphans,
            vec![
                r"working copy C:\Users\x.staging".to_string(),
                "ProfileList entry S-1-5-21-5-5-5-1 with a migration marker".to_string(),
                r"registry mount HKU\wpm_other".to_string(),
            ]
        );
    }

    #[test]
    fn status_shows_phase_artifacts_and_verdict() {
        let state = preparing();
        let seen = observed(vec![Presence::Ours, Presence::Absent]);
        let plan = plan_rollback(&state, &seen, RollbackOptions::default());
        let text = render_status(&state, &seen, &plan);
        assert!(text.contains("phase: preparing"));
        assert!(text.contains("now present"));
        assert!(text.contains("rollback would: delete folder"));
        assert!(text.contains("source profile: intact"));
    }
}
