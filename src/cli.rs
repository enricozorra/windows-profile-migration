//! Command-line parsing. Hand-written: the surface is a handful of options
//! and an argument-parser dependency would outweigh it.

use std::path::PathBuf;

use crate::preflight::OVERRIDABLE_CHECKS;

pub const USAGE: &str = r#"windows-profile-migration - re-map a Windows user profile to a new account SID

USAGE:
    windows-profile-migration <COMMAND> --source <ACCOUNT> --target <ACCOUNT>
                              [OPTIONS]

COMMANDS:
    preflight          Run read-only checks and print a pass/fail report
    backup             Run preflight, then snapshot ProfileList, hives and ACLs
    migrate --dry-run  Run preflight and print the changes a migration would make
                       (execution without --dry-run is not implemented yet)

ACCOUNTS:
    --source <ACCOUNT>   PC01\user, .\user, OLDDOMAIN\user, or a SID
    --target <ACCOUNT>   DOMAIN\user, user@domain.tld, or a SID
                         Bare names ("user") are rejected as ambiguous.

OPTIONS:
    --profile-path <PATH>  Assert where the source profile lives; mismatch blocks
    --accept <CHECK>       Downgrade an overridable blocking check to a warning
                           (repeatable): OS_SUPPORTED, SOURCE_ACCOUNT, EFS_FILES
    --log-dir <DIR>        Log folder. Default: %WINDOWS_PROFILE_MIGRATION_HOME%\logs,
                           else %ProgramData%\windows-profile-migration\logs
    --backup-dir <DIR>     Backup folder for `backup` (default: ...\backups)
    -h, --help             Show this help
    -V, --version          Show the version

EXIT CODES:
    0 success / preflight passed    1 preflight blocked
    2 usage error                   3 runtime error
"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Preflight,
    Backup,
    MigrateDryRun,
}

impl Command {
    pub fn name(self) -> &'static str {
        match self {
            Command::Preflight => "preflight",
            Command::Backup => "backup",
            Command::MigrateDryRun => "migrate-dry-run",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    pub command: Command,
    pub source: String,
    pub target: String,
    pub profile_path: Option<PathBuf>,
    pub accept: Vec<String>,
    pub log_dir: Option<PathBuf>,
    pub backup_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parsed {
    Help,
    Version,
    Run(Args),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageError(pub String);

impl std::fmt::Display for UsageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for UsageError {}

fn usage(message: impl Into<String>) -> UsageError {
    UsageError(message.into())
}

/// Parses arguments (without the program name). Accepts `--opt value` and
/// `--opt=value`.
pub fn parse<I: IntoIterator<Item = String>>(args: I) -> Result<Parsed, UsageError> {
    let mut args = args.into_iter();
    let mut command_word: Option<String> = None;
    let mut dry_run = false;
    let mut source = None;
    let mut target = None;
    let mut profile_path = None;
    let mut accept = Vec::new();
    let mut log_dir = None;
    let mut backup_dir = None;

    while let Some(arg) = args.next() {
        let (flag, inline_value) = match arg.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f.to_string(), Some(v.to_string())),
            _ => (arg.clone(), None),
        };
        let mut value = |name: &str| -> Result<String, UsageError> {
            match inline_value.clone().or_else(|| args.next()) {
                Some(v) if !v.is_empty() => Ok(v),
                _ => Err(usage(format!("{name} needs a value"))),
            }
        };
        match flag.as_str() {
            "-h" | "--help" => return Ok(Parsed::Help),
            "-V" | "--version" => return Ok(Parsed::Version),
            "--dry-run" => dry_run = true,
            "--source" => set_once(&mut source, value("--source")?, "--source")?,
            "--target" => set_once(&mut target, value("--target")?, "--target")?,
            "--profile-path" => set_once(
                &mut profile_path,
                PathBuf::from(value("--profile-path")?),
                "--profile-path",
            )?,
            "--log-dir" => set_once(
                &mut log_dir,
                PathBuf::from(value("--log-dir")?),
                "--log-dir",
            )?,
            "--backup-dir" => set_once(
                &mut backup_dir,
                PathBuf::from(value("--backup-dir")?),
                "--backup-dir",
            )?,
            "--accept" => {
                let id = value("--accept")?.to_ascii_uppercase();
                if !OVERRIDABLE_CHECKS.contains(&id.as_str()) {
                    return Err(usage(format!(
                        "--accept {id}: not an overridable check (allowed: {})",
                        OVERRIDABLE_CHECKS.join(", ")
                    )));
                }
                if !accept.contains(&id) {
                    accept.push(id);
                }
            }
            other if other.starts_with('-') => {
                return Err(usage(format!("unknown option {other}")))
            }
            word => {
                if command_word.is_some() {
                    return Err(usage(format!("unexpected argument '{word}'")));
                }
                command_word = Some(word.to_string());
            }
        }
    }

    let command = match command_word.as_deref() {
        Some("preflight") => Command::Preflight,
        Some("backup") => Command::Backup,
        Some("migrate") if dry_run => Command::MigrateDryRun,
        Some("migrate") => {
            return Err(usage(
                "migrate requires --dry-run: destructive execution is not implemented yet",
            ))
        }
        Some(other) => return Err(usage(format!("unknown command '{other}'"))),
        None => return Err(usage("missing command")),
    };
    if dry_run && command != Command::MigrateDryRun {
        return Err(usage("--dry-run only applies to migrate"));
    }
    if backup_dir.is_some() && command != Command::Backup {
        return Err(usage("--backup-dir only applies to backup"));
    }
    Ok(Parsed::Run(Args {
        command,
        source: source.ok_or_else(|| usage("--source is required"))?,
        target: target.ok_or_else(|| usage("--target is required"))?,
        profile_path,
        accept,
        log_dir,
        backup_dir,
    }))
}

fn set_once<T>(slot: &mut Option<T>, value: T, name: &str) -> Result<(), UsageError> {
    if slot.is_some() {
        return Err(usage(format!("{name} given more than once")));
    }
    *slot = Some(value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_str(line: &str) -> Result<Parsed, UsageError> {
        parse(line.split_whitespace().map(String::from))
    }

    fn run_args(line: &str) -> Args {
        match parse_str(line).unwrap() {
            Parsed::Run(args) => args,
            other => panic!("expected Run, got {other:?}"),
        }
    }

    #[test]
    fn preflight_with_both_flag_styles() {
        let args = run_args(r"preflight --source .\jdoe --target=CORP\jdoe");
        assert_eq!(args.command, Command::Preflight);
        assert_eq!(args.source, r".\jdoe");
        assert_eq!(args.target, r"CORP\jdoe");
    }

    #[test]
    fn migrate_requires_dry_run() {
        assert!(parse_str("migrate --source a\\b --target c\\d").is_err());
        let args = run_args(r"migrate --dry-run --source a\b --target c\d");
        assert_eq!(args.command, Command::MigrateDryRun);
    }

    #[test]
    fn accept_is_validated_and_normalized() {
        let args =
            run_args(r"preflight --source a\b --target c\d --accept efs_files --accept EFS_FILES");
        assert_eq!(args.accept, vec!["EFS_FILES".to_string()]);
        assert!(parse_str(r"preflight --source a\b --target c\d --accept ELEVATION").is_err());
    }

    #[test]
    fn missing_or_duplicate_values_are_errors() {
        assert!(parse_str("preflight --target c\\d").is_err());
        assert!(parse_str("preflight --source").is_err());
        assert!(parse_str("preflight --source a --source b --target c").is_err());
        assert!(parse_str("preflight --source= --target c").is_err());
    }

    #[test]
    fn options_scoped_to_their_command() {
        assert!(parse_str(r"preflight --dry-run --source a\b --target c\d").is_err());
        assert!(parse_str(r"preflight --backup-dir X --source a\b --target c\d").is_err());
        let args = run_args(r"backup --backup-dir D:\bk --source a\b --target c\d");
        assert_eq!(args.backup_dir, Some(PathBuf::from(r"D:\bk")));
    }

    #[test]
    fn unknown_input_is_rejected() {
        assert!(parse_str("frobnicate --source a --target b").is_err());
        assert!(parse_str("preflight --force --source a --target b").is_err());
        assert!(parse_str("preflight extra --source a --target b").is_err());
        assert!(parse_str("").is_err());
    }

    #[test]
    fn help_and_version_short_circuit() {
        assert_eq!(parse_str("--help").unwrap(), Parsed::Help);
        assert_eq!(parse_str("preflight -V").unwrap(), Parsed::Version);
    }
}
