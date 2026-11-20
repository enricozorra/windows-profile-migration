//! windows-profile-migration: in-place Windows profile re-mapping
//! (Local -> AD, Domain A -> B).
//!
//! This build implements the read-only phases (preflight, backup, dry-run
//! planning), the working copy (`migrate --stage-only`), and `status` and
//! `rollback`. No command modifies the source profile or its registry entry.

// Win32 FFI is confined to `win`, which opts back in with allow(unsafe_code).
#![deny(unsafe_code)]

mod account;
mod app;
mod apps;
mod backup;
mod cli;
mod copy;
mod facts;
mod hive_scan;
mod journal;
mod json;
mod log;
mod model;
mod os_support;
mod plan;
mod platform;
mod preflight;
mod profile_state;
mod recovery;
mod references;
mod reparse;
mod report;
mod rollback;
mod scan;
mod sddl;
mod sid;
mod stage;
mod timefmt;
#[cfg(windows)]
mod win;

use std::process::exit;

fn main() {
    let parsed = match cli::parse(std::env::args().skip(1)) {
        Ok(parsed) => parsed,
        Err(err) => {
            eprintln!("error: {err}\n\n{}", cli::USAGE);
            exit(app::EXIT_USAGE);
        }
    };
    let args = match parsed {
        cli::Parsed::Help => {
            print!("{}", cli::USAGE);
            exit(app::EXIT_OK);
        }
        cli::Parsed::Version => {
            println!("windows-profile-migration {}", env!("CARGO_PKG_VERSION"));
            exit(app::EXIT_OK);
        }
        cli::Parsed::Run(args) => args,
    };
    match app::run(&args) {
        Ok(code) => exit(code),
        Err(err) => {
            eprintln!("error: {err}");
            exit(app::EXIT_ERROR);
        }
    }
}
