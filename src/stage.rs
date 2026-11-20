//! `migrate --stage-only`: builds the working copy next to the target
//! folder and verifies it, then stops. Nothing outside the copy and the
//! migration's own folder is created or changed, so the system stays as
//! it was; `rollback` removes the copy.
//!
//! Every step is journaled before it acts. If the copy or its verification
//! fails, the copy is removed straight away through the regular rollback,
//! which only deletes what carries this migration's marker.

use std::error::Error;
use std::fs;
use std::io;
use std::path::Path;

use crate::app::EXIT_OK;
use crate::copy::{self, CopyClass, CopyPaths, Manifest, MANIFEST_FILE};
use crate::hives;
use crate::journal::{ArtifactKind, JournalWriter, JOURNAL_FILE, LOCK_FILE};
use crate::json::Json;
use crate::log::{Level, Logger};
use crate::model::SystemFacts;
use crate::platform;
use crate::preflight::format_bytes;
use crate::recovery::RollbackOptions;
use crate::rewrite::Substitution;
use crate::rollback;
use crate::timefmt;

const PHASE: &str = "stage";
/// How many verification differences are printed; the log has all of them.
const SHOWN_PROBLEMS: usize = 20;

/// The accounts and folders of one migration, taken from the facts the
/// preflight just approved.
struct Subject {
    source_sid: String,
    source_name: String,
    source_path: String,
    target_sid: String,
    target_name: String,
    target_path: String,
    staging_path: String,
}

impl Subject {
    fn from_facts(facts: &SystemFacts) -> Result<Subject, Box<dyn Error>> {
        let source = facts
            .source
            .account()
            .ok_or("the source account is unknown")?;
        let target = facts
            .target
            .account()
            .ok_or("the target account is unknown")?;
        let profile = facts
            .profile_dir
            .as_ref()
            .ok_or("the source profile folder is unknown")?;
        let dir = facts
            .target_dir
            .as_ref()
            .ok_or("the target profile folder is unknown")?;
        Ok(Subject {
            source_sid: source.sid.clone(),
            source_name: source.qualified_name(),
            source_path: profile.path.display().to_string(),
            target_sid: target.sid.clone(),
            target_name: target.qualified_name(),
            target_path: dir.path.display().to_string(),
            staging_path: dir.staging_path.display().to_string(),
        })
    }

    fn substitution(&self) -> Substitution {
        Substitution {
            source_sid: self.source_sid.clone(),
            target_sid: self.target_sid.clone(),
            source_path: self.source_path.clone(),
            target_path: self.target_path.clone(),
        }
    }
}

pub fn run_stage(
    facts: &SystemFacts,
    migrations_root: &Path,
    log: &mut Logger,
) -> Result<i32, Box<dyn Error>> {
    let subject = Subject::from_facts(facts)?;
    // The preflight checked these too; they are checked again because time
    // has passed, and a folder that appeared meanwhile is never reused.
    for path in [&subject.staging_path, &subject.target_path] {
        match fs::symlink_metadata(path) {
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Ok(_) => return Err(format!("{path} already exists; nothing was changed").into()),
            Err(err) => return Err(format!("{path}: {err}").into()),
        }
    }

    let id = format!("{}-{}", timefmt::now().compact(), std::process::id());
    if !migrations_root.exists() {
        if let Some(parent) = migrations_root.parent() {
            fs::create_dir_all(parent)?;
        }
        platform::create_private_dir(migrations_root)?;
    }
    let dir = migrations_root.join(&id);
    platform::create_private_dir(&dir)?;
    log.event(
        Level::Info,
        PHASE,
        "migration_started",
        &format!("migration {id}"),
        vec![
            ("migration", id.as_str().into()),
            ("folder", dir.display().to_string().into()),
            ("staging", subject.staging_path.as_str().into()),
        ],
    )?;
    println!("\nmigration {id}");
    println!("    journal and copy manifest: {}", dir.display());

    let failure = match stage(&subject, &id, &dir, log) {
        Ok(()) => return Ok(EXIT_OK),
        Err(err) => err,
    };
    // The lock was released when `stage` returned, so the rollback can take
    // it. The rollback re-checks every marker before it deletes anything.
    log.event(
        Level::Error,
        PHASE,
        "stage_failed",
        &failure.to_string(),
        vec![("migration", id.as_str().into())],
    )?;
    println!("\nThe working copy could not be completed:\n    {failure}");
    println!("\nRemoving it (rollback of migration {id}):\n");
    match rollback::run_rollback(migrations_root, &id, RollbackOptions::default(), log) {
        Ok(EXIT_OK) => Err(format!(
            "{failure}\nThe working copy was removed; the system is as it was before."
        )
        .into()),
        Ok(_) => Err(format!(
            "{failure}\nThe working copy could not be removed automatically; see `status` and run `rollback --migration {id}`."
        )
        .into()),
        Err(rollback_err) => Err(format!(
            "{failure}\nRemoving the working copy also failed: {rollback_err}\nSee `status` and run `rollback --migration {id}` once the cause is fixed."
        )
        .into()),
    }
}

/// Journals, copies and verifies. Holds the migration's lock throughout.
fn stage(subject: &Subject, id: &str, dir: &Path, log: &mut Logger) -> Result<(), Box<dyn Error>> {
    let _lock = platform::lock_file(&dir.join(LOCK_FILE))?;
    let mut journal = JournalWriter::create(&dir.join(JOURNAL_FILE))?;
    journal.append(
        "started",
        &[
            ("id", id),
            ("version", env!("CARGO_PKG_VERSION")),
            ("source_sid", &subject.source_sid),
            ("source_name", &subject.source_name),
            ("source_path", &subject.source_path),
            ("target_sid", &subject.target_sid),
            ("target_name", &subject.target_name),
            ("target_path", &subject.target_path),
            ("staging_path", &subject.staging_path),
        ],
    )?;
    platform::enable_copy_privileges()?;

    let substitution = subject.substitution();
    let paths = CopyPaths {
        source: Path::new(&subject.source_path),
        staging: Path::new(&subject.staging_path),
        substitution: &substitution,
    };
    let staging = [
        ("kind", ArtifactKind::StagingDir.name()),
        ("value", subject.staging_path.as_str()),
    ];
    journal.append("intent", &staging)?;
    println!(
        "\ncopying {} -> {}",
        subject.source_path, subject.staging_path
    );
    let root = copy::create_root(&paths, id)?;
    journal.append("created", &staging)?;

    let mut manifest = Manifest::create(&dir.join(MANIFEST_FILE))?;
    let copied = copy::copy_tree(&paths, root, &mut manifest);
    manifest.finish()?;
    let outcome = copied?;
    let counts = [
        ("folders", outcome.count(CopyClass::Directory).to_string()),
        ("files", outcome.count(CopyClass::File).to_string()),
        ("links", outcome.count(CopyClass::Link).to_string()),
        ("retargeted_links", outcome.retargeted.len().to_string()),
        ("security_translated", outcome.translated.to_string()),
        ("cloud_only_skipped", outcome.cloud_only.len().to_string()),
        ("bytes", outcome.bytes.to_string()),
    ];
    let mut fields: Vec<(&str, &str)> = vec![("name", "copy"), ("state", "done")];
    fields.extend(counts.iter().map(|(k, v)| (*k, v.as_str())));
    journal.append("step", &fields)?;
    log.event(
        Level::Info,
        PHASE,
        "copied",
        "working copy written",
        counts
            .iter()
            .map(|(k, v)| (*k, Json::from(v.as_str())))
            .collect(),
    )?;
    println!(
        "    {} folders, {} files, {} links ({} retargeted), {}",
        outcome.count(CopyClass::Directory),
        outcome.count(CopyClass::File),
        outcome.count(CopyClass::Link),
        outcome.retargeted.len(),
        format_bytes(outcome.bytes)
    );
    println!(
        "    {} security descriptors moved from {} to {}",
        outcome.translated, subject.source_sid, subject.target_sid
    );
    for relative in &outcome.cloud_only {
        log.event(Level::Warn, PHASE, "cloud_only_skipped", relative, vec![])?;
    }
    if !outcome.cloud_only.is_empty() {
        println!(
            "    {} online-only cloud files not copied (the cloud keeps them; listed in {MANIFEST_FILE})",
            outcome.cloud_only.len()
        );
    }

    println!("verifying the copy against the source...");
    let problems = copy::verify(&paths, &outcome)?;
    if !problems.is_empty() {
        for problem in &problems {
            log.event(Level::Error, PHASE, "verify_mismatch", problem, vec![])?;
        }
        journal.append(
            "step",
            &[
                ("name", "verify"),
                ("state", "failed"),
                ("problems", &problems.len().to_string()),
            ],
        )?;
        let shown: Vec<&str> = problems
            .iter()
            .take(SHOWN_PROBLEMS)
            .map(String::as_str)
            .collect();
        return Err(format!(
            "the copy differs from the source in {} place(s) (all are in the log):\n    {}",
            problems.len(),
            shown.join("\n    ")
        )
        .into());
    }
    journal.append("step", &[("name", "verify"), ("state", "done")])?;
    log.event(
        Level::Info,
        PHASE,
        "verified",
        "the copy matches the source",
        vec![("entries", outcome.entries.len().into())],
    )?;
    println!(
        "    verified: all {} entries match the source (content SHA-256, attributes, timestamps, translated security, streams, link targets)",
        outcome.entries.len()
    );

    rewrite_hives(subject, id, &substitution, &mut journal, log)?;

    println!(
        "\nWorking copy ready: {}\nNothing outside it was changed; {} still logs on to {}.\nTo remove it: windows-profile-migration rollback --migration {id}",
        subject.staging_path, subject.source_name, subject.source_path
    );
    Ok(())
}

/// Rewrites and verifies each hive of the copy, journaling every mount.
fn rewrite_hives(
    subject: &Subject,
    id: &str,
    substitution: &Substitution,
    journal: &mut JournalWriter,
    log: &mut Logger,
) -> Result<(), Box<dyn Error>> {
    for hive in hives::hive_files(Path::new(&subject.staging_path)) {
        println!("rewriting registry hive {}...", hive.path.display());
        let outcome = hives::rewrite(&hive, id, substitution, journal)?;
        let report = &outcome.report;
        let counts = [
            ("keys_translated", report.keys_translated.to_string()),
            (
                "values_rewritten",
                report.values_rewritten.len().to_string(),
            ),
            ("keys_skipped", outcome.skipped.keys.len().to_string()),
            ("values_skipped", outcome.skipped.values.len().to_string()),
            ("residues", report.residues.len().to_string()),
            ("names", report.names.len().to_string()),
        ];
        let mut fields: Vec<(&str, &str)> = vec![
            ("name", "rewrite_hive"),
            ("hive", outcome.label),
            ("state", "done"),
        ];
        fields.extend(counts.iter().map(|(k, v)| (*k, v.as_str())));
        journal.append("step", &fields)?;
        log.event(
            Level::Info,
            PHASE,
            "hive_rewritten",
            &hive.path.display().to_string(),
            counts
                .iter()
                .map(|(k, v)| (*k, Json::from(v.as_str())))
                .collect(),
        )?;
        for place in &report.values_rewritten {
            log.event(Level::Info, PHASE, "value_rewritten", place, vec![])?;
        }
        // Everything still pointing at the source is listed, so it can be
        // fixed by hand or by an application-specific step later.
        let leftovers = outcome
            .skipped
            .keys
            .iter()
            .map(|key| {
                let key = if key.is_empty() { "(root)" } else { key };
                format!("key {key}: Windows refuses changes to its security")
            })
            .chain(
                outcome
                    .skipped
                    .values
                    .iter()
                    .map(|(place, why)| format!("{place}: {why}")),
            )
            .chain(report.residues.iter().cloned())
            .chain(
                report
                    .names
                    .iter()
                    .map(|n| format!("{n}: the name mentions the source")),
            );
        let mut shown = 0;
        for leftover in leftovers {
            log.event(Level::Warn, PHASE, "hive_leftover", &leftover, vec![])?;
            if shown < SHOWN_PROBLEMS {
                println!("    left as is: {leftover}");
            }
            shown += 1;
        }
        if shown > SHOWN_PROBLEMS {
            println!(
                "    ... and {} more (all in the log)",
                shown - SHOWN_PROBLEMS
            );
        }
        println!(
            "    {} key permissions and {} values rewritten; reloaded and verified",
            report.keys_translated,
            report.values_rewritten.len()
        );
    }
    Ok(())
}
