//! `status` and `rollback`: observe what a migration left on the system
//! and undo it. Decisions are made in `recovery`; this module only reads
//! the system, and for `rollback` performs the planned actions, journaling
//! each one so an interrupted rollback can simply be run again.

use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use crate::app::{EXIT_BLOCKED, EXIT_OK};
use crate::journal::{
    self, Artifact, ArtifactKind, JournalState, JournalWriter, FOLDER_MARKER_FILE, JOURNAL_FILE,
    LOCK_FILE,
};
use crate::json::Json;
use crate::log::{Level, Logger};
use crate::model::{ProfileListSnapshot, HIVE_MOUNT_PREFIX, STAGING_SUFFIX};
use crate::platform;
use crate::recovery::{self, Action, Observed, Phase, Presence, RollbackOptions, RollbackPlan};
use crate::scan::FILE_ATTRIBUTE_REPARSE_POINT;
use crate::sid::sid_eq;
use crate::timefmt;

/// The live state the decisions are made against.
struct SystemView {
    profile_list: ProfileListSnapshot,
    loaded_hives: Vec<String>,
}

impl SystemView {
    fn read() -> io::Result<SystemView> {
        Ok(SystemView {
            profile_list: platform::read_profile_list()?,
            loaded_hives: platform::loaded_user_hives()?,
        })
    }
}

pub fn run_status(migrations_root: &Path, log: &mut Logger) -> Result<i32, Box<dyn Error>> {
    let view = SystemView::read()?;
    let mut journals = Vec::new();
    let mut attention = false;

    for dir in migration_dirs(migrations_root)? {
        let id = dir_name(&dir);
        let state = match read_journal(&dir) {
            Ok(state) => state,
            Err(err) => {
                attention = true;
                println!("migration {id}\n    journal unreadable: {err}\n");
                log.event(
                    Level::Error,
                    "status",
                    "journal_unreadable",
                    &err.to_string(),
                    vec![("migration", id.as_str().into())],
                )?;
                continue;
            }
        };
        let observed = observe(&state, &view);
        let plan = recovery::plan_rollback(&state, &observed, RollbackOptions::default());
        let phase = recovery::phase(&state);
        if !matches!(phase, Phase::RolledBack | Phase::Finalized)
            || !matches!(plan, RollbackPlan::NothingToDo { .. })
            || !state.problems.is_empty()
        {
            attention = true;
        }
        println!("{}", recovery::render_status(&state, &observed, &plan));
        log.event(
            Level::Info,
            "status",
            "migration",
            &format!("{id}: {}", phase.label()),
            vec![
                ("migration", id.as_str().into()),
                ("problems", Json::strings(&state.problems)),
            ],
        )?;
        journals.push(state);
    }

    let orphans = recovery::find_orphans(
        &journals,
        &staging_dirs(&view.profile_list)?,
        &view
            .profile_list
            .entries
            .iter()
            .filter(|e| e.migration_marker.is_some() && !e.is_bak())
            .map(|e| e.key_name.clone())
            .collect::<Vec<_>>(),
        &view
            .loaded_hives
            .iter()
            .filter(|h| h.to_ascii_lowercase().starts_with(HIVE_MOUNT_PREFIX))
            .cloned()
            .collect::<Vec<_>>(),
    );
    if journals.is_empty() && orphans.is_empty() {
        println!("no migrations found in {}", migrations_root.display());
    }
    if !orphans.is_empty() {
        attention = true;
        println!("leftovers that belong to no journal (inspect and remove them by hand):");
        for orphan in &orphans {
            println!("    - {orphan}");
            log.event(Level::Warn, "status", "orphan", orphan, vec![])?;
        }
    }
    Ok(if attention { EXIT_BLOCKED } else { EXIT_OK })
}

pub fn run_rollback(
    migrations_root: &Path,
    id: &str,
    options: RollbackOptions,
    log: &mut Logger,
) -> Result<i32, Box<dyn Error>> {
    // The id names a folder; refuse anything that could step outside.
    if id.is_empty() || id.contains(['\\', '/', ':']) || id.starts_with('.') {
        return Err(format!("'{id}' is not a migration id").into());
    }
    let dir = migrations_root.join(id);
    if !dir.join(JOURNAL_FILE).is_file() {
        return Err(format!(
            "no journal for migration '{id}' in {}",
            migrations_root.display()
        )
        .into());
    }
    let _lock = platform::lock_file(&dir.join(LOCK_FILE)).map_err(|err| {
        format!("cannot lock migration '{id}' (is another windows-profile-migration running on it?): {err}")
    })?;
    let state = read_journal(&dir)?;
    let view = SystemView::read()?;
    let observed = observe(&state, &view);
    let plan = recovery::plan_rollback(&state, &observed, options);
    print!("{}", recovery::render_status(&state, &observed, &plan));

    let mut writer = JournalWriter::open(&dir.join(JOURNAL_FILE))?;
    match plan {
        RollbackPlan::Refused { reasons } => {
            for reason in &reasons {
                log.event(
                    Level::Error,
                    "rollback",
                    "refused",
                    reason,
                    vec![("migration", id.into())],
                )?;
            }
            println!("\nRollback refused; nothing was changed.");
            Ok(EXIT_BLOCKED)
        }
        RollbackPlan::NothingToDo { notes } => {
            log_notes(&notes, id, log)?;
            if state.rolled_back_at.is_none() {
                writer.append("rollback_done", &[])?;
            }
            println!("\nNothing left to undo.");
            Ok(EXIT_OK)
        }
        RollbackPlan::Ready { actions, notes } => {
            log_notes(&notes, id, log)?;
            writer.append("rollback_started", &[])?;
            for action in &actions {
                let artifact = artifact_for(&state, action).ok_or_else(|| {
                    format!(
                        "internal error: no journal artifact for '{}'",
                        action.describe()
                    )
                })?;
                execute(&state, artifact, action, &mut writer, log)?;
                println!("done: {}", action.describe());
            }
            verify_rolled_back(&state, id, &mut writer, log)
        }
    }
}

fn execute(
    state: &JournalState,
    artifact: &Artifact,
    action: &Action,
    writer: &mut JournalWriter,
    log: &mut Logger,
) -> Result<(), Box<dyn Error>> {
    let fields = [
        ("kind", artifact.kind.name()),
        ("value", artifact.value.as_str()),
    ];
    // Ownership is checked again right before acting, so nothing that
    // changed since the plan was made can be deleted by mistake.
    let view = SystemView::read()?;
    let presence = observe_artifact(state, artifact, &view);
    if presence != Presence::Ours {
        let message = format!(
            "{} changed since the plan was made ({presence:?}); stopping",
            recovery::describe_artifact(artifact)
        );
        writer.append(
            "step",
            &[
                ("name", "rollback"),
                ("state", "failed"),
                ("detail", &message),
            ],
        )?;
        return Err(message.into());
    }
    let result = match action {
        Action::UnloadHive(name) => platform::unload_hive(name),
        Action::DeleteProfileListEntry(sid) => platform::delete_profile_list_entry(sid),
        // std's remove_dir_all deletes junctions and symlinks without
        // following them, so nothing outside the folder can be reached.
        Action::DeleteFolder(path) => fs::remove_dir_all(path),
    };
    match result {
        Ok(()) => {
            writer.append("removed", &fields)?;
            log.event(
                Level::Info,
                "rollback",
                "removed",
                &action.describe(),
                vec![],
            )?;
            Ok(())
        }
        Err(err) => {
            let message = format!("{}: {err}", action.describe());
            writer.append(
                "step",
                &[
                    ("name", "rollback"),
                    ("state", "failed"),
                    ("detail", &message),
                ],
            )?;
            log.event(Level::Error, "rollback", "failed", &message, vec![])?;
            Err(format!("{message}\nThe rollback stopped; fix the cause and run it again (completed steps are not repeated).").into())
        }
    }
}

/// Confirms nothing of ours is left before recording the rollback as done.
fn verify_rolled_back(
    state: &JournalState,
    id: &str,
    writer: &mut JournalWriter,
    log: &mut Logger,
) -> Result<i32, Box<dyn Error>> {
    let view = SystemView::read()?;
    let left: Vec<String> = state
        .artifacts
        .iter()
        .filter(|a| observe_artifact(state, a, &view) == Presence::Ours)
        .map(recovery::describe_artifact)
        .collect();
    if !left.is_empty() {
        return Err(format!("still present after rollback: {}", left.join(", ")).into());
    }
    writer.append("rollback_done", &[])?;
    let source = source_intact(state, &view);
    log.event(
        Level::Info,
        "rollback",
        "rollback_done",
        "rollback complete",
        vec![
            ("migration", id.into()),
            ("source_intact", source.is_ok().into()),
        ],
    )?;
    match source {
        Ok(()) => println!(
            "\nRollback complete. {} can log on with the original profile {}.",
            state.header.source_name, state.header.source_path
        ),
        Err(problem) => {
            println!("\nRollback complete, but the source profile has changed: {problem}")
        }
    }
    Ok(EXIT_OK)
}

fn log_notes(notes: &[String], id: &str, log: &mut Logger) -> io::Result<()> {
    for note in notes {
        println!("note: {note}");
        let level = if note.starts_with("WARNING") {
            Level::Warn
        } else {
            Level::Info
        };
        log.event(
            level,
            "rollback",
            "note",
            note,
            vec![("migration", id.into())],
        )?;
    }
    Ok(())
}

fn artifact_for<'a>(state: &'a JournalState, action: &Action) -> Option<&'a Artifact> {
    let (kind, value): (&[ArtifactKind], String) = match action {
        Action::UnloadHive(name) => (&[ArtifactKind::HiveMount], name.clone()),
        Action::DeleteProfileListEntry(sid) => (&[ArtifactKind::ProfileListEntry], sid.clone()),
        Action::DeleteFolder(path) => (
            &[ArtifactKind::StagingDir, ArtifactKind::TargetDir],
            path.display().to_string(),
        ),
    };
    state
        .artifacts
        .iter()
        .find(|a| kind.contains(&a.kind) && a.value.eq_ignore_ascii_case(&value))
}

fn observe(state: &JournalState, view: &SystemView) -> Observed {
    let target_sid = &state.header.target_sid;
    Observed {
        artifacts: state
            .artifacts
            .iter()
            .map(|a| observe_artifact(state, a, view))
            .collect(),
        target_logged_on: !target_sid.is_empty()
            && view
                .loaded_hives
                .iter()
                .any(|h| sid_eq(h, target_sid) || sid_eq(h, &format!("{target_sid}_Classes"))),
        target_used_after_commit: target_used_after_commit(state),
        source_intact: source_intact(state, view),
    }
}

fn observe_artifact(state: &JournalState, artifact: &Artifact, view: &SystemView) -> Presence {
    match artifact.kind {
        ArtifactKind::StagingDir | ArtifactKind::TargetDir => {
            folder_presence(Path::new(&artifact.value), &state.header.id)
        }
        ArtifactKind::ProfileListEntry => {
            let entry = view
                .profile_list
                .entries
                .iter()
                .find(|e| !e.is_bak() && sid_eq(&e.key_name, &artifact.value));
            match entry {
                None => Presence::Absent,
                Some(e) => match &e.migration_marker {
                    Some(marker) if sid_eq(marker, &state.header.source_sid) => Presence::Ours,
                    Some(marker) => Presence::Foreign(format!("its marker names source {marker}")),
                    None => Presence::Foreign("it has no migration marker".into()),
                },
            }
        }
        ArtifactKind::HiveMount => {
            if !artifact
                .value
                .to_ascii_lowercase()
                .starts_with(HIVE_MOUNT_PREFIX)
            {
                Presence::Foreign(format!("the name lacks the {HIVE_MOUNT_PREFIX} prefix"))
            } else if view
                .loaded_hives
                .iter()
                .any(|h| h.eq_ignore_ascii_case(&artifact.value))
            {
                Presence::Ours
            } else {
                Presence::Absent
            }
        }
    }
}

/// A folder is ours only if it is a real directory (not a junction) whose
/// marker file names this migration.
pub fn folder_presence(path: &Path, id: &str) -> Presence {
    let metadata = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Presence::Absent,
        Err(err) => return Presence::Unknown(err.to_string()),
    };
    if platform::file_attributes(&metadata) & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Presence::Foreign("it is a junction or symlink".into());
    }
    if !metadata.is_dir() {
        return Presence::Foreign("it is not a folder".into());
    }
    match fs::read_to_string(path.join(FOLDER_MARKER_FILE)) {
        Ok(text) if text.trim() == id => Presence::Ours,
        Ok(text) => Presence::Foreign(format!("its marker names migration '{}'", text.trim())),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            Presence::Foreign(format!("it has no {FOLDER_MARKER_FILE} marker"))
        }
        Err(err) => Presence::Unknown(format!("reading its marker: {err}")),
    }
}

/// Whether the target's hive was written after the commit, i.e. the user
/// logged on and worked in the migrated profile.
fn target_used_after_commit(state: &JournalState) -> Result<bool, String> {
    let Some(committed) = &state.committed_at else {
        return Ok(false);
    };
    let hive = Path::new(&state.header.target_path).join("NTUSER.DAT");
    let modified = match fs::metadata(&hive).and_then(|m| m.modified()) {
        Ok(time) => time,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(format!("{}: {err}", hive.display())),
    };
    let millis = modified
        .duration_since(UNIX_EPOCH)
        .map_err(|err| format!("{}: {err}", hive.display()))?
        .as_millis() as u64;
    // Both timestamps use the same fixed-width RFC 3339 form, so comparing
    // the strings compares the instants.
    Ok(timefmt::from_unix_millis(millis).rfc3339().as_str() > committed.as_str())
}

fn source_intact(state: &JournalState, view: &SystemView) -> Result<(), String> {
    let header = &state.header;
    let entry = view
        .profile_list
        .entries
        .iter()
        .find(|e| !e.is_bak() && sid_eq(&e.key_name, &header.source_sid))
        .ok_or_else(|| format!("ProfileList entry {} is missing", header.source_sid))?;
    let path = entry
        .profile_image_path_expanded
        .as_deref()
        .unwrap_or_default();
    if !path.eq_ignore_ascii_case(&header.source_path) {
        return Err(format!(
            "ProfileImagePath is {path}, the journal recorded {}",
            header.source_path
        ));
    }
    if !Path::new(&header.source_path).is_dir() {
        return Err(format!("{} is missing", header.source_path));
    }
    Ok(())
}

fn read_journal(dir: &Path) -> Result<JournalState, Box<dyn Error>> {
    let path = dir.join(JOURNAL_FILE);
    let text = fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    journal::replay(&text).map_err(|e| format!("{}: {e}", path.display()).into())
}

fn migration_dirs(root: &Path) -> io::Result<Vec<PathBuf>> {
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err),
    };
    let mut dirs = Vec::new();
    for entry in entries {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            dirs.push(entry.path());
        }
    }
    dirs.sort();
    Ok(dirs)
}

fn staging_dirs(profile_list: &ProfileListSnapshot) -> io::Result<Vec<String>> {
    let Some(root) = &profile_list.profiles_directory else {
        return Ok(Vec::new());
    };
    let mut dirs = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.to_ascii_lowercase().ends_with(STAGING_SUFFIX) {
            dirs.push(entry.path().display().to_string());
        }
    }
    Ok(dirs)
}

fn dir_name(dir: &Path) -> String {
    dir.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> TempDir {
            let nanos = std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let dir = std::env::temp_dir().join(format!(
                "windows-profile-migration-rollback-{name}-{}-{nanos}",
                std::process::id()
            ));
            fs::create_dir_all(&dir).unwrap();
            TempDir(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn folder_is_ours_only_with_the_matching_marker() {
        let tmp = TempDir::new("marker");
        let dir = tmp.0.join("copy");
        assert_eq!(folder_presence(&dir, "m1"), Presence::Absent);
        fs::create_dir(&dir).unwrap();
        assert!(matches!(folder_presence(&dir, "m1"), Presence::Foreign(_)));
        fs::write(dir.join(FOLDER_MARKER_FILE), "m2\n").unwrap();
        assert!(matches!(folder_presence(&dir, "m1"), Presence::Foreign(_)));
        fs::write(dir.join(FOLDER_MARKER_FILE), "m1\r\n").unwrap();
        assert_eq!(folder_presence(&dir, "m1"), Presence::Ours);
    }

    #[test]
    fn a_file_is_never_taken_for_our_folder() {
        let tmp = TempDir::new("file");
        let file = tmp.0.join("copy");
        fs::write(&file, "m1").unwrap();
        assert!(matches!(folder_presence(&file, "m1"), Presence::Foreign(_)));
    }

    #[cfg(unix)]
    #[test]
    fn a_link_to_our_folder_is_not_ours() {
        let tmp = TempDir::new("link");
        let real = tmp.0.join("real");
        fs::create_dir(&real).unwrap();
        fs::write(real.join(FOLDER_MARKER_FILE), "m1").unwrap();
        let link = tmp.0.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(matches!(folder_presence(&link, "m1"), Presence::Foreign(_)));
    }

    #[test]
    fn hive_usage_after_commit_compares_timestamps() {
        let tmp = TempDir::new("usage");
        fs::write(tmp.0.join("NTUSER.DAT"), "hive").unwrap();
        let mut state = JournalState::default();
        state.header.target_path = tmp.0.display().to_string();
        assert_eq!(target_used_after_commit(&state), Ok(false));
        state.committed_at = Some("2000-01-01T00:00:00.000Z".into());
        assert_eq!(target_used_after_commit(&state), Ok(true));
        state.committed_at = Some("2999-01-01T00:00:00.000Z".into());
        assert_eq!(target_used_after_commit(&state), Ok(false));
    }
}
