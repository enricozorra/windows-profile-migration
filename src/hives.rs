//! Rewrites the registry hives of the working copy: key security
//! descriptors and text values move from the source SID and folder to the
//! target ones (decisions in `rewrite`).
//!
//! Each hive is mounted under an HKU name that carries this tool's prefix,
//! and every mount is journaled before it happens, so an interruption
//! leaves a mount that `rollback` removes. After the rewrite the hive is
//! unmounted, mounted again and walked once more: it must load, and
//! nothing that the rewrite should have changed may be left.

use std::cell::RefCell;
use std::error::Error;
use std::path::{Path, PathBuf};

use crate::journal::{ArtifactKind, JournalWriter};
use crate::model::{HiveSkips, HIVE_MOUNT_PREFIX};
use crate::platform;
use crate::rewrite::{value_place, HiveReport, Substitution};

/// A hive file of the working copy.
pub struct HiveFile {
    /// Short name used in mount names and messages.
    pub label: &'static str,
    pub path: PathBuf,
}

/// The user's two hives in the copy. The Classes hive is absent from
/// profiles that never logged on to a desktop.
pub fn hive_files(staging: &Path) -> Vec<HiveFile> {
    let mut files = vec![HiveFile {
        label: "ntuser",
        path: staging.join("NTUSER.DAT"),
    }];
    let classes = staging.join(r"AppData\Local\Microsoft\Windows\UsrClass.dat");
    if classes.is_file() {
        files.push(HiveFile {
            label: "usrclass",
            path: classes,
        });
    }
    files
}

/// What happened to one hive.
pub struct HiveOutcome {
    pub label: &'static str,
    pub report: HiveReport,
    /// Keys and values that needed a change but were left as they are.
    pub skipped: HiveSkips,
}

/// Rewrites and then verifies one hive of the copy.
pub fn rewrite(
    hive: &HiveFile,
    migration_id: &str,
    substitution: &Substitution,
    journal: &mut JournalWriter,
) -> Result<HiveOutcome, Box<dyn Error>> {
    let mount = format!("{HIVE_MOUNT_PREFIX}{migration_id}_{}", hive.label);

    // Both callbacks record into the same report, one at a time.
    let report = RefCell::new(HiveReport::default());
    let skipped = mounted(hive, &mount, journal, &mut |mount| {
        platform::rewrite_hive(
            mount,
            &mut |key, sd| substitution.rewrite_key(&mut report.borrow_mut(), key, sd),
            &mut |key, name, data| {
                substitution.rewrite_value(&mut report.borrow_mut(), key, name, data)
            },
        )
    })?;

    // Second pass on a fresh mount: proves the hive still loads and that
    // nothing is left to rewrite, apart from what was skipped above.
    let left = RefCell::new(Vec::new());
    mounted(hive, &mount, journal, &mut |mount| {
        platform::rewrite_hive(
            mount,
            &mut |key, sd| {
                if substitution.security_bytes(sd)?.is_some()
                    && !skipped.keys.iter().any(|k| k == key)
                {
                    left.borrow_mut()
                        .push(format!("key {key}: security still names the source"));
                }
                Ok(None)
            },
            &mut |key, name, data| {
                let place = value_place(key, name);
                if substitution.value(data).is_some()
                    && !skipped.values.iter().any(|(p, _)| *p == place)
                {
                    left.borrow_mut()
                        .push(format!("value {place}: still refers to the source"));
                }
                None
            },
        )
    })?;
    let left = left.into_inner();
    if !left.is_empty() {
        return Err(format!(
            "{} after its rewrite still refers to the source in {} place(s):\n    {}",
            hive.path.display(),
            left.len(),
            left.join("\n    ")
        )
        .into());
    }
    Ok(HiveOutcome {
        label: hive.label,
        report: report.into_inner(),
        skipped,
    })
}

/// Mounts the hive, runs `work` on the mount name and unmounts it again,
/// journaling the mount. The unmount is attempted even when `work` fails;
/// a mount that cannot be removed stays in the journal for `rollback`.
fn mounted(
    hive: &HiveFile,
    mount: &str,
    journal: &mut JournalWriter,
    work: &mut dyn FnMut(&str) -> std::io::Result<HiveSkips>,
) -> Result<HiveSkips, Box<dyn Error>> {
    let artifact = [("kind", ArtifactKind::HiveMount.name()), ("value", mount)];
    journal.append("intent", &artifact)?;
    platform::mount_hive(&hive.path, mount)
        .map_err(|err| format!("{}: {err}", hive.path.display()))?;
    journal.append("created", &artifact)?;

    let result = work(mount);
    let unloaded = platform::unload_hive(mount);
    if unloaded.is_ok() {
        journal.append("removed", &artifact)?;
    }
    match (result, unloaded) {
        (Ok(skipped), Ok(())) => Ok(skipped),
        (Err(err), Ok(())) => Err(format!("HKU\\{mount}: {err}").into()),
        (Ok(_), Err(err)) => Err(err.into()),
        (Err(err), Err(unload_err)) => {
            Err(format!("HKU\\{mount}: {err}; in addition {unload_err}").into())
        }
    }
}
