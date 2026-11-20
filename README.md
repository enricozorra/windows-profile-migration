# windows-profile-migration

> **Status: early development.** Only the read-only phases exist and they
> have not yet been validated on real Windows machines. Test on a disposable
> VM, never on a production profile.

Moves an existing Windows user profile to a new account, for
**Local → AD domain** and **Domain A → Domain B** migrations on Windows
10/11 clients. The profile folder is renamed after the new account
(`C:\Users\Test` → `C:\Users\enrico.zorra`).

The source profile is never modified. The migration builds a working copy
next to the final folder, rewrites SIDs and paths in the copy only,
verifies it, and then commits: it renames the copy and adds the target's
ProfileList entry. Until the migration is finalized, rolling back means
deleting the copy and that entry, and the old account logs on as before.

This build implements the **read-only phases**: preflight, backup and
dry-run planning. No command modifies the profile or the registry. The
only writes are the log file, a short-lived private copy of the user's
hives used to inspect them (deleted before the command ends) and, for
`backup`, a new backup folder.

## Usage

Run from an elevated terminal (Administrator or SYSTEM):

```text
windows-profile-migration preflight         --source .\jdoe --target CORP\jdoe
windows-profile-migration migrate --dry-run --source .\jdoe --target CORP\jdoe
windows-profile-migration backup            --source .\jdoe --target CORP\jdoe [--backup-dir D:\pm]

# Domain A -> B when the old domain no longer resolves:
windows-profile-migration preflight --source S-1-5-21-...-1105 --target NEWCORP\jdoe --accept SOURCE_ACCOUNT
```

Accounts must be qualified (`PC01\user`, `.\user`, `DOMAIN\user`,
`user@domain`, or a SID). A bare `jdoe` is rejected because it matches the
local account before the domain one.

| Exit code | Meaning |
|---|---|
| 0 | success / preflight passed (warnings allowed) |
| 1 | preflight blocked |
| 2 | usage error |
| 3 | runtime error |

Logs are JSONL, one record per action, finding and skipped item, written
to `--log-dir`, else `%WINDOWS_PROFILE_MIGRATION_HOME%\logs`, else
`%ProgramData%\windows-profile-migration\logs`.
Backups go to a new folder whose DACL admits only SYSTEM and Administrators,
because it contains copies of the user's hives.

## Application catalog

Preflight reports, for each application it finds in the profile, what the
copy carries over by itself and what needs an action:

| Check | Detects | Typical action |
|---|---|---|
| `APP_CHROME`, `APP_EDGE`, `APP_BRAVE` | browser profiles, saved-password stores | enable sync or export passwords first |
| `APP_FIREFOX` | profiles.ini, absolute profile paths | none (Firefox passwords move with the files) |
| `APP_OUTLOOK` | mail profiles, .pst/.ost paths, signatures | sign in again; data files inside the profile are repointed |
| `APP_NETWORK_DRIVES`, `APP_PRINTERS` | per-user mappings and connections | none (saved share passwords are not carried) |
| `APP_CERTIFICATES` | personal certificates and private keys | export as .pfx and import as the target |
| `APP_ONEDRIVE`, `APP_TEAMS` | signed-in accounts, local state | sign in again as the target |

Each entry is one `detect_*` function in `src/apps.rs`; adding an
application is a small, self-contained contribution.

## Layout

```text
src/
  main.rs           thin entrypoint: parse, run, exit code
  cli.rs            argument parsing and validation
  app.rs            command orchestration and logging
  facts.rs          gathers SystemFacts via the platform layer (read-only)
  model.rs          plain data passed between modules
  preflight.rs      every check -> Finding (pure, unit-tested)
  plan.rs           dry-run plan: copy, rewrite, verify, commit (pure)
  apps.rs           application catalog (detection only)
  hive_scan.rs      registry value analysis: old paths, app settings (pure)
  references.rs     services/scheduled tasks running as the source (pure)
  backup.rs         ProfileList .reg export, hive copies, ACL manifest
  scan.rs           profile walk that never follows reparse points
  sddl.rs sid.rs account.rs os_support.rs profile_state.rs   pure helpers
  json.rs log.rs report.rs timefmt.rs                       output
  platform.rs       the only OS seam; non-Windows stubs return Unsupported
  win/              Win32 FFI (the only place `unsafe` is allowed)
scripts/
  vm-validate.ps1   end-to-end checks on a disposable VM
```

All decision logic is platform-neutral, so `cargo test` runs on macOS or
Linux. Win32 calls live only in `src/win/`; the crate root is
`#![deny(unsafe_code)]` and `win` opts back in with a `// SAFETY:` comment
on every block.

## Building

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo clippy --target x86_64-pc-windows-gnu --all-targets --all-features -- -D warnings
cargo test

# Windows binary from macOS/Linux (needs a linker):
brew install mingw-w64                       # or: cargo install cargo-xwin
cargo build --release --target x86_64-pc-windows-gnu
```

MSVC builds statically link the CRT (`.cargo/config.toml`), so the binary
has no runtime dependency on the target machine.

## Supporting another Windows version

Run `scripts/vm-validate.ps1` on that build, then add one row to
`VALIDATED_BUILDS` in `src/os_support.rs`. Nothing else is keyed on the
build number. Newer builds than the table produce a warning; older ones
block (overridable with `--accept OS_SUPPORTED`).

## Validation on a VM

```powershell
.\scripts\vm-validate.ps1 -WindowsProfileMigration .\windows-profile-migration.exe -TargetAccount CORP\pmtarget
```

The script creates a throwaway local user and profile, then asserts the
blocking cases (bare/local target, loaded hive, `.bak` twin) and the passing
path. It also checks that ProfileList and NTUSER.DAT are byte-identical
before and after preflight and dry-run. Run it on a disposable snapshot only.

## Not implemented yet

- Execution: copy, rewrite, verify, commit. `migrate` without `--dry-run`
  is refused.
- Rollback and finalize.

## Contributing

Issues and pull requests are welcome. Before opening a PR:

1. Run the four commands under [Building](#building); all must pass.
2. Keep Win32 calls inside `src/win/`, each `unsafe` block with a
   `// SAFETY:` comment. Everything else must stay platform-neutral.
3. Add or update unit tests for any behavior you change.

Reports from real Windows runs are especially useful: include the OS build,
the scenario (Local → Domain or Domain → Domain) and the JSONL log, with
account names redacted.

## License

[MIT](LICENSE)
