//! Runs one command end to end: gather facts, evaluate, report, and (for
//! `backup`) snapshot. Every decision and skipped item is logged.

use std::env;
use std::error::Error;
use std::path::PathBuf;

use crate::backup;
use crate::cli::{Args, Command};
use crate::facts::{self, Request};
use crate::json::Json;
use crate::log::{Level, Logger};
use crate::model::{LookupOutcome, SkipReason, SystemFacts};
use crate::plan;
use crate::preflight::{self, Options, Severity};
use crate::recovery::RollbackOptions;
use crate::report;
use crate::rollback;
use crate::stage;

pub const EXIT_OK: i32 = 0;
pub const EXIT_BLOCKED: i32 = 1;
pub const EXIT_USAGE: i32 = 2;
pub const EXIT_ERROR: i32 = 3;

pub fn run(args: &Args) -> Result<i32, Box<dyn Error>> {
    let log_dir = match &args.log_dir {
        Some(dir) => dir.clone(),
        None => base_dir()?.join("logs"),
    };
    let mut log = Logger::create(&log_dir, args.command.name())?;
    eprintln!("log: {}", log.path().display());
    log.event(
        Level::Info,
        "run",
        "run_started",
        "windows-profile-migration started",
        vec![
            ("version", env!("CARGO_PKG_VERSION").into()),
            ("command", args.command.name().into()),
            ("source_input", args.source.clone().into()),
            ("target_input", args.target.clone().into()),
            ("migration", args.migration.clone().into()),
            (
                "profile_path",
                args.profile_path
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .into(),
            ),
            ("accept", Json::strings(&args.accept)),
        ],
    )?;

    let result = run_logged(args, &mut log);
    match &result {
        Ok(code) => log.event(
            Level::Info,
            "run",
            "run_finished",
            "windows-profile-migration finished",
            vec![("exit_code", Json::Int(i64::from(*code)))],
        )?,
        Err(err) => log.event(
            Level::Error,
            "run",
            "run_failed",
            &err.to_string(),
            vec![("exit_code", Json::Int(i64::from(EXIT_ERROR)))],
        )?,
    }
    result
}

fn run_logged(args: &Args, log: &mut Logger) -> Result<i32, Box<dyn Error>> {
    let migrations_root = base_dir()?.join("migrations");
    match args.command {
        Command::Status => return rollback::run_status(&migrations_root, log),
        Command::Rollback => {
            let id = args
                .migration
                .as_deref()
                .ok_or("rollback needs --migration")?;
            let options = RollbackOptions {
                discard_target_changes: args.discard_target_changes,
            };
            return rollback::run_rollback(&migrations_root, id, options, log);
        }
        Command::Preflight | Command::Backup | Command::MigrateDryRun | Command::MigrateStage => {}
    }
    let (Some(source), Some(target)) = (&args.source, &args.target) else {
        return Err(format!("{} needs --source and --target", args.command.name()).into());
    };
    eprintln!("gathering system state (read-only)...");
    let facts = facts::gather(&Request {
        source: source.clone(),
        target: target.clone(),
        work_dir: base_dir()?.join("work"),
    })?;
    log_facts(&facts, log)?;

    let options = Options {
        expected_profile_path: args.profile_path.clone(),
        accepted: args.accept.clone(),
    };
    let report = preflight::evaluate(&facts, &options);
    for finding in &report.findings {
        let level = match finding.severity {
            Severity::Pass | Severity::Info => Level::Info,
            Severity::Warning => Level::Warn,
            Severity::Blocking => Level::Error,
        };
        log.event(
            level,
            "preflight",
            "check",
            &finding.summary,
            vec![
                ("check", finding.id.into()),
                ("severity", finding.severity.label().into()),
                ("accepted", finding.accepted.into()),
                ("details", Json::strings(&finding.details)),
            ],
        )?;
    }
    print!("{}", report::render(&report));
    log.event(
        if report.is_blocked() {
            Level::Error
        } else {
            Level::Info
        },
        "preflight",
        "verdict",
        &report::summary_line(&report),
        vec![("blocked", report.is_blocked().into())],
    )?;
    let verdict = if report.is_blocked() {
        EXIT_BLOCKED
    } else {
        EXIT_OK
    };

    match args.command {
        // Status and Rollback returned above; listed only to keep the match
        // exhaustive.
        Command::Preflight | Command::Status | Command::Rollback => Ok(verdict),
        Command::MigrateDryRun => {
            let changes = plan::build(&facts);
            for change in &changes {
                log.event(
                    Level::Info,
                    "dry-run",
                    "planned_change",
                    &change.target,
                    vec![
                        ("area", change.area.label().into()),
                        ("op", change.op.symbol().to_string().into()),
                        ("lines", Json::strings(&change.lines)),
                    ],
                )?;
            }
            println!();
            if report.is_blocked() {
                println!("NOTE: preflight is blocked; this plan is for review only.\n");
            }
            print!("{}", plan::render(&changes));
            Ok(verdict)
        }
        Command::Backup => {
            if report.is_blocked() {
                println!("\nBackup refused: resolve the blocking findings first.");
                return Ok(EXIT_BLOCKED);
            }
            let backup_root = match &args.backup_dir {
                Some(dir) => dir.clone(),
                None => base_dir()?.join("backups"),
            };
            let outcome = backup::create(&backup_root, &facts, log)?;
            println!("\nBackup written to {}", outcome.dir.display());
            for (name, bytes) in &outcome.files {
                println!("    {name:<60} {bytes:>12} bytes");
            }
            Ok(EXIT_OK)
        }
        Command::MigrateStage => {
            if report.is_blocked() {
                println!("\nWorking copy refused: resolve the blocking findings first.");
                return Ok(EXIT_BLOCKED);
            }
            stage::run_stage(&facts, &migrations_root, log)
        }
    }
}

/// `%WINDOWS_PROFILE_MIGRATION_HOME%` if set, else `%ProgramData%\windows-profile-migration`. Environment-driven
/// so fleets can redirect logs and backups (e.g. to a data volume).
fn base_dir() -> Result<PathBuf, Box<dyn Error>> {
    if let Some(home) = env::var_os("WINDOWS_PROFILE_MIGRATION_HOME") {
        return Ok(PathBuf::from(home));
    }
    match env::var_os("ProgramData") {
        Some(data) => Ok(PathBuf::from(data).join("windows-profile-migration")),
        None => {
            Err("neither WINDOWS_PROFILE_MIGRATION_HOME nor ProgramData is set; pass --log-dir/--backup-dir".into())
        }
    }
}

fn log_facts(facts: &SystemFacts, log: &mut Logger) -> Result<(), Box<dyn Error>> {
    let account = |lookup: &LookupOutcome| -> Json {
        match lookup {
            LookupOutcome::Found(info) => Json::obj(vec![
                ("sid", info.sid.as_str().into()),
                ("name", info.qualified_name().into()),
                ("kind", format!("{:?}", info.kind).into()),
            ]),
            other => format!("{other:?}").into(),
        }
    };
    log.event(
        Level::Info,
        "preflight",
        "facts",
        "system state gathered",
        vec![
            ("computer", facts.computer_name.as_str().into()),
            ("domain", format!("{:?}", facts.domain).into()),
            (
                "os",
                match &facts.os {
                    Ok(os) => format!(
                        "{} {} {}.{}",
                        os.product_name, os.display_version, os.build, os.ubr
                    ),
                    Err(e) => format!("error: {e}"),
                }
                .into(),
            ),
            ("operator_sid", facts.token.user_sid.as_str().into()),
            ("source", account(&facts.source.lookup)),
            ("target", account(&facts.target.lookup)),
            (
                "profile_list_entries",
                facts.profile_list.entries.len().into(),
            ),
            ("loaded_hives", Json::strings(&facts.loaded_hives)),
        ],
    )?;
    match &facts.registry {
        Some(Ok(inspection)) => {
            log.event(
                Level::Info,
                "preflight",
                "registry_inspected",
                "source registry inspected",
                vec![
                    ("method", inspection.method.as_str().into()),
                    ("values", inspection.values_scanned.into()),
                    ("network_drives", Json::strings(&inspection.network_drives)),
                    ("printers", Json::strings(&inspection.printer_connections)),
                    (
                        "outlook_profiles",
                        Json::strings(&inspection.outlook_profiles),
                    ),
                    (
                        "outlook_data_files",
                        Json::strings(&inspection.outlook_data_files),
                    ),
                    (
                        "onedrive_accounts",
                        Json::strings(&inspection.onedrive_accounts),
                    ),
                ],
            )?;
            // One record per reference, so the log is the complete list the
            // console only samples.
            for (kind, refs) in [
                ("text", &inspection.text_path_refs),
                ("binary", &inspection.binary_path_refs),
            ] {
                for location in refs {
                    log.event(
                        Level::Info,
                        "preflight",
                        "registry_path_ref",
                        location,
                        vec![("kind", kind.into())],
                    )?;
                }
            }
            for error in &inspection.errors {
                log.event(
                    Level::Warn,
                    "preflight",
                    "registry_unreadable",
                    error,
                    vec![],
                )?;
            }
        }
        Some(Err(reason)) => log.event(
            Level::Warn,
            "preflight",
            "registry_unreadable",
            reason,
            vec![],
        )?,
        None => {}
    }
    if let Some(scan) = &facts.scan {
        for skipped in &scan.skipped {
            let (level, reason) = match &skipped.reason {
                SkipReason::ReparsePoint => {
                    (Level::Info, "reparse point (not traversed)".to_string())
                }
                SkipReason::CloudPlaceholder => {
                    (Level::Warn, "cloud placeholder (not opened)".to_string())
                }
                SkipReason::Inaccessible(e) => (Level::Warn, format!("inaccessible: {e}")),
                SkipReason::UnparsableSddl(e) => (Level::Warn, format!("unparsable SDDL: {e}")),
            };
            log.event(
                level,
                "preflight",
                "scan_skipped",
                &reason,
                vec![("path", skipped.path.as_str().into())],
            )?;
        }
    }
    Ok(())
}
