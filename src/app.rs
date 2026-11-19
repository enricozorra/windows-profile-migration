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
use crate::report;

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
        "profmig started",
        vec![
            ("version", env!("CARGO_PKG_VERSION").into()),
            ("command", args.command.name().into()),
            ("source_input", args.source.as_str().into()),
            ("target_input", args.target.as_str().into()),
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
            "profmig finished",
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
    eprintln!("gathering system state (read-only)...");
    let facts = facts::gather(&Request {
        source: args.source.clone(),
        target: args.target.clone(),
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
        Command::Preflight => Ok(verdict),
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
    }
}

/// `%PROFMIG_HOME%` if set, else `%ProgramData%\profmig`. Environment-driven
/// so fleets can redirect logs and backups (e.g. to a data volume).
fn base_dir() -> Result<PathBuf, Box<dyn Error>> {
    if let Some(home) = env::var_os("PROFMIG_HOME") {
        return Ok(PathBuf::from(home));
    }
    match env::var_os("ProgramData") {
        Some(data) => Ok(PathBuf::from(data).join("profmig")),
        None => {
            Err("neither PROFMIG_HOME nor ProgramData is set; pass --log-dir/--backup-dir".into())
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
