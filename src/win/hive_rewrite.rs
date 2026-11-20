//! Mounting a hive of the working copy and rewriting it in place.
//!
//! Only files inside the working copy are ever mounted here. Keys are
//! opened with backup/restore intent, which with the backup and restore
//! privileges grants read and write access regardless of the key's DACL,
//! and registry links are opened as links, never followed.

use std::io;
use std::path::Path;
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;
use windows_sys::Win32::Security::PSECURITY_DESCRIPTOR;
use windows_sys::Win32::System::Registry::{
    RegGetKeySecurity, RegLoadKeyW, RegOpenKeyExW, RegSetKeySecurity, RegSetValueExW, HKEY,
    HKEY_USERS, KEY_ALL_ACCESS, REG_EXPAND_SZ, REG_MULTI_SZ, REG_OPTION_BACKUP_RESTORE,
    REG_OPTION_OPEN_LINK, REG_SZ,
};

use super::registry::{decode_data, utf16_units, RegKey};
use super::security::{descriptor_to_sddl, SDDL_PARTS};
use super::token::enable_privilege;
use super::wide::{aligned_buffer, path_to_wide_verbatim, to_wide, win32_error};
use crate::model::{HiveSkips, RegData};
use crate::rewrite::value_place;
use crate::secdesc::{with_auto_inherit_request, Edited};

/// Mounts the hive file `path` at `HKU\<mount>`.
pub fn mount_hive(path: &Path, mount: &str) -> io::Result<()> {
    enable_privilege("SeBackupPrivilege")?;
    enable_privilege("SeRestorePrivilege")?;
    let wide_mount = to_wide(mount);
    let wide_path = path_to_wide_verbatim(path);
    // SAFETY: predefined root, NUL-terminated mount name and file path.
    let status = unsafe { RegLoadKeyW(HKEY_USERS, wide_mount.as_ptr(), wide_path.as_ptr()) };
    if status != 0 {
        return Err(win32_error(
            &format!("RegLoadKeyW({})", path.display()),
            status,
        ));
    }
    Ok(())
}

/// Walks every key of `HKU\<mount>`. `security(key, descriptor)` may return
/// a new binary descriptor (owner, group, DACL) for the key; `value(key, name, data)` may return new data
/// for a text value, which is written back with its original type.
///
/// Returns what was left as it is: values whose stored form could not be
/// reproduced exactly (text after an embedded NUL, empty items in a
/// multi-string), since rewriting them would lose data, and keys or values
/// Windows refuses to let even a backup/restore writer change (the
/// UserChoice keys guarded by the UCPD driver). Any other failure stops
/// the walk.
pub fn rewrite_hive(
    mount: &str,
    security: &mut dyn FnMut(&str, &[u8]) -> Edited,
    value: &mut dyn FnMut(&str, &str, &RegData) -> Option<RegData>,
) -> io::Result<HiveSkips> {
    enable_privilege("SeBackupPrivilege")?;
    enable_privilege("SeRestorePrivilege")?;
    let mut skipped = HiveSkips::default();
    let mut pending = vec![String::new()];
    while let Some(path) = pending.pop() {
        let full = if path.is_empty() {
            mount.to_string()
        } else {
            format!("{mount}\\{path}")
        };
        let key = open_for_rewrite(&full)?;
        let shown = if path.is_empty() { "(root)" } else { &path };

        let descriptor = key_descriptor(&key).map_err(|e| context(shown, e))?;
        if let Some(new) =
            security(&path, &descriptor).map_err(|e| context(shown, io::Error::other(e)))?
        {
            match set_key_descriptor(&key, &new) {
                Err(err) if is_access_denied(&err) => skipped.keys.push(path.clone()),
                Err(err) => return Err(context(shown, err)),
                Ok(()) => {
                    // What was written must read back as asked for:
                    // registry writes are known to merge control flags.
                    let written = key_descriptor(&key).map_err(|e| context(shown, e))?;
                    let (want, got) = (sddl_of(&new)?, sddl_of(&written)?);
                    if want != got {
                        return Err(io::Error::other(format!(
                            "{shown}: the key's security reads back as {got}, expected {want}"
                        )));
                    }
                }
            }
        }

        for stored_value in key.raw_values().map_err(|e| context(shown, e))? {
            let (name, kind, raw) = (&stored_value.name, stored_value.kind, &stored_value.data);
            let text_name = String::from_utf16_lossy(name);
            let current = decode_data(kind, raw);
            let Some(new) = value(&path, &text_name, &current) else {
                continue;
            };
            let stored = encode(&current, kind);
            if stored.as_deref().map(trim_terminators) != Some(trim_terminators(raw)) {
                skipped.values.push((
                    value_place(&path, &text_name),
                    "its stored form cannot be reproduced exactly".into(),
                ));
                continue;
            }
            let data = encode(&new, kind).ok_or_else(|| {
                io::Error::other(format!(
                    "{shown}\\{text_name}: new data does not fit type {kind}"
                ))
            })?;
            match set_value(&key, name, kind, &data) {
                Err(err) if is_access_denied(&err) => skipped.values.push((
                    value_place(&path, &text_name),
                    "Windows refuses changes to it".into(),
                )),
                Err(err) => return Err(context(&format!("{shown}\\{text_name}"), err)),
                Ok(()) => {}
            }
        }

        for child in key.subkey_names().map_err(|e| context(shown, e))? {
            pending.push(if path.is_empty() {
                child
            } else {
                format!("{path}\\{child}")
            });
        }
    }
    Ok(skipped)
}

/// ERROR_ACCESS_DENIED, which `win32_error` keeps as the error kind.
fn is_access_denied(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::PermissionDenied
}

fn open_for_rewrite(path: &str) -> io::Result<RegKey> {
    let wide = to_wide(path);
    let mut key: HKEY = null_mut();
    // SAFETY: predefined root, NUL-terminated path, out-pointer. With
    // REG_OPTION_BACKUP_RESTORE the requested access is granted through
    // the backup/restore privileges.
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_USERS,
            wide.as_ptr(),
            REG_OPTION_BACKUP_RESTORE | REG_OPTION_OPEN_LINK,
            KEY_ALL_ACCESS,
            &mut key,
        )
    };
    if status != 0 {
        return Err(win32_error(&format!("RegOpenKeyExW(HKU\\{path})"), status));
    }
    Ok(RegKey(key))
}

/// Owner, group and DACL of the key as a self-relative descriptor.
fn key_descriptor(key: &RegKey) -> io::Result<Vec<u8>> {
    let mut len = 0u32;
    // SAFETY: a size query with a null buffer.
    let status = unsafe { RegGetKeySecurity(key.0, SDDL_PARTS, null_mut(), &mut len) };
    if status != ERROR_INSUFFICIENT_BUFFER && status != 0 {
        return Err(win32_error("RegGetKeySecurity", status));
    }
    let mut buf = aligned_buffer(len);
    // SAFETY: the buffer is aligned and `len` bytes long.
    let status = unsafe {
        RegGetKeySecurity(
            key.0,
            SDDL_PARTS,
            buf.as_mut_ptr() as PSECURITY_DESCRIPTOR,
            &mut len,
        )
    };
    if status != 0 {
        return Err(win32_error("RegGetKeySecurity", status));
    }
    // SAFETY: the API wrote `len` bytes into the buffer.
    let bytes = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, len as usize) };
    Ok(bytes.to_vec())
}

fn set_key_descriptor(key: &RegKey, descriptor: &[u8]) -> io::Result<()> {
    let flagged = with_auto_inherit_request(descriptor).map_err(io::Error::other)?;
    let mut buf = aligned(&flagged);
    // SAFETY: valid open key and a valid, aligned self-relative descriptor.
    let status =
        unsafe { RegSetKeySecurity(key.0, SDDL_PARTS, buf.as_mut_ptr() as PSECURITY_DESCRIPTOR) };
    if status != 0 {
        return Err(win32_error("RegSetKeySecurity", status));
    }
    Ok(())
}

fn sddl_of(descriptor: &[u8]) -> io::Result<String> {
    let mut buf = aligned(descriptor);
    descriptor_to_sddl(buf.as_mut_ptr() as PSECURITY_DESCRIPTOR, SDDL_PARTS)
}

/// The descriptor structures need their natural alignment.
fn aligned(bytes: &[u8]) -> Vec<u64> {
    let mut buf = aligned_buffer(bytes.len() as u32);
    // SAFETY: `buf` holds at least bytes.len() bytes and does not overlap.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf.as_mut_ptr() as *mut u8, bytes.len())
    };
    buf
}

fn set_value(key: &RegKey, name: &[u16], kind: u32, data: &[u8]) -> io::Result<()> {
    let mut wide_name = name.to_vec();
    wide_name.push(0);
    // SAFETY: valid open key, NUL-terminated name, data slice of the given
    // length.
    let status = unsafe {
        RegSetValueExW(
            key.0,
            wide_name.as_ptr(),
            0,
            kind,
            data.as_ptr(),
            data.len() as u32,
        )
    };
    if status != 0 {
        return Err(win32_error("RegSetValueExW", status));
    }
    Ok(())
}

/// The stored form of text data, as Windows writes it: NUL-terminated
/// strings, and an extra NUL closing a multi-string.
fn encode(data: &RegData, kind: u32) -> Option<Vec<u8>> {
    let mut units: Vec<u16> = Vec::new();
    match (data, kind) {
        (RegData::Text(text), REG_SZ | REG_EXPAND_SZ) => {
            units.extend(text.encode_utf16());
            units.push(0);
        }
        (RegData::MultiText(items), REG_MULTI_SZ) => {
            for item in items {
                units.extend(item.encode_utf16());
                units.push(0);
            }
            units.push(0);
        }
        _ => return None,
    }
    Some(units.iter().flat_map(|u| u.to_le_bytes()).collect())
}

/// Text data without its trailing NUL units, which applications store
/// inconsistently (none, one, or several).
fn trim_terminators(data: &[u8]) -> Vec<u16> {
    let mut units = utf16_units(data);
    while units.last() == Some(&0) {
        units.pop();
    }
    units
}

fn context(place: &str, err: io::Error) -> io::Error {
    io::Error::new(err.kind(), format!("{place}: {err}"))
}
