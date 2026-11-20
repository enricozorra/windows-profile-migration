//! File-level probes and the reg.exe export.

use std::fs::{Metadata, OpenOptions};
use std::io;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use windows_sys::Win32::Foundation::{ERROR_LOCK_VIOLATION, ERROR_SHARING_VIOLATION};
use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;

use super::wide::{from_wide_buf, last_error, to_wide};
use crate::model::LockState;

pub fn file_attributes(metadata: &Metadata) -> u32 {
    metadata.file_attributes()
}

/// Opens `path` with no sharing. If any other process (the profile service,
/// a backup agent, an indexer) holds the file, this fails with a sharing
/// violation. The handle is closed immediately, so the probe itself holds
/// the file only for the duration of one open/close.
pub fn probe_exclusive(path: &Path) -> LockState {
    match OpenOptions::new().read(true).share_mode(0).open(path) {
        Ok(_) => LockState::Unlocked,
        Err(err) if err.kind() == io::ErrorKind::NotFound => LockState::Missing,
        Err(err)
            if err.raw_os_error() == Some(ERROR_SHARING_VIOLATION as i32)
                || err.raw_os_error() == Some(ERROR_LOCK_VIOLATION as i32) =>
        {
            LockState::Locked
        }
        Err(err) => LockState::Error(err.to_string()),
    }
}

/// Creates or opens `path` with no sharing and keeps it open: as long as the
/// returned handle lives, no other process can open the same lock file.
pub fn lock_file(path: &Path) -> io::Result<std::fs::File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .share_mode(0)
        .open(path)
}

/// Bytes available to the caller on the volume that holds `path` (which
/// honors quotas, unlike the volume total).
pub fn free_bytes(path: &Path) -> io::Result<u64> {
    let wide = to_wide(&path.display().to_string());
    let mut available = 0u64;
    // SAFETY: NUL-terminated directory; the two totals we do not need are null.
    let ok = unsafe {
        GetDiskFreeSpaceExW(
            wide.as_ptr(),
            &mut available,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(last_error(&format!(
            "GetDiskFreeSpaceExW({})",
            path.display()
        )));
    }
    Ok(available)
}

/// `reg.exe export HKLM\<subkey> <dest> /y`. Uses the absolute System32
/// path so a planted reg.exe earlier in PATH is never run elevated.
pub fn export_registry_key(hklm_subkey: &str, dest: &Path) -> io::Result<()> {
    let reg = system_directory()?.join("reg.exe");
    let output = Command::new(&reg)
        .arg("export")
        .arg(format!("HKLM\\{hklm_subkey}"))
        .arg(dest)
        .arg("/y")
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "reg.exe export HKLM\\{hklm_subkey} failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

fn system_directory() -> io::Result<PathBuf> {
    let mut buf = [0u16; 260];
    // SAFETY: `buf` has buf.len() elements.
    let len = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) };
    if len == 0 || len as usize >= buf.len() {
        return Err(last_error("GetSystemDirectoryW"));
    }
    Ok(PathBuf::from(from_wide_buf(&buf[..len as usize])))
}
