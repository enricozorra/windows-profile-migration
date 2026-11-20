//! Directory listing and tree removal with backup semantics.
//!
//! A profile copy carries the source's security descriptors, including the
//! "Everyone: deny list folder" entry on the legacy junctions (`Application
//! Data`, `Cookies`, ...) and whatever restrictive DACLs applications set.
//! Opening with backup semantics and the backup/restore privileges is what
//! lets an administrator list and delete such entries without changing
//! their security first. Reparse points are always opened as themselves, so
//! neither function ever reaches outside the tree it is given.

use std::ffi::c_void;
use std::fs::OpenOptions;
use std::io;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};

use windows_sys::Win32::Foundation::{
    ERROR_INVALID_FUNCTION, ERROR_INVALID_PARAMETER, ERROR_NOT_SUPPORTED, ERROR_NO_MORE_FILES,
    HANDLE,
};
use windows_sys::Win32::Storage::FileSystem::{
    FileBasicInfo, FileDispositionInfo, FileDispositionInfoEx, FileFullDirectoryInfo,
    FileFullDirectoryRestartInfo, GetFileInformationByHandleEx, SetFileInformationByHandle, DELETE,
    FILE_BASIC_INFO, FILE_DISPOSITION_FLAG_DELETE, FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE,
    FILE_DISPOSITION_FLAG_POSIX_SEMANTICS, FILE_DISPOSITION_INFO, FILE_DISPOSITION_INFO_EX,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_NO_RECALL, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_LIST_DIRECTORY, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FILE_WRITE_ATTRIBUTES, SYNCHRONIZE,
};

use super::token::enable_privilege;
use super::wide::{aligned_buffer, last_error};
use crate::copy::COPIED_ATTRIBUTES;

const FILE_ATTRIBUTE_READONLY: u32 = 0x1;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
const LIST_BUFFER_BYTES: u32 = 64 * 1024;
// FILE_FULL_DIR_INFO field offsets (winbase.h).
const NEXT_ENTRY_OFFSET: usize = 0;
const ATTRIBUTES_OFFSET: usize = 56;
const NAME_LENGTH_OFFSET: usize = 60;
const NAME_OFFSET: usize = 68;

/// Names and Win32 attributes of the entries in `dir`, without `.` and `..`.
pub fn list_dir(dir: &Path) -> io::Result<Vec<(String, u32)>> {
    let handle = OpenOptions::new()
        .access_mode(FILE_LIST_DIRECTORY | SYNCHRONIZE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_OPEN_NO_RECALL,
        )
        .open(dir)?;
    let mut buffer = aligned_buffer(LIST_BUFFER_BYTES);
    let mut entries = Vec::new();
    let mut class = FileFullDirectoryRestartInfo;
    loop {
        // SAFETY: valid directory handle; the buffer is 8-byte aligned and
        // LIST_BUFFER_BYTES long.
        let ok = unsafe {
            GetFileInformationByHandleEx(
                handle.as_raw_handle() as HANDLE,
                class,
                buffer.as_mut_ptr() as *mut c_void,
                LIST_BUFFER_BYTES,
            )
        };
        if ok == 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(ERROR_NO_MORE_FILES as i32) {
                break;
            }
            return Err(last_error(
                "GetFileInformationByHandleEx(FileFullDirectoryInfo)",
            ));
        }
        class = FileFullDirectoryInfo;
        // SAFETY: the buffer is LIST_BUFFER_BYTES of initialized memory; it
        // is only read as bytes, with every offset bounds-checked below.
        let bytes = unsafe {
            std::slice::from_raw_parts(buffer.as_ptr() as *const u8, LIST_BUFFER_BYTES as usize)
        };
        let mut offset = 0;
        loop {
            let entry = bytes
                .get(offset..)
                .ok_or_else(|| io::Error::other("directory listing points outside its buffer"))?;
            let next = read_u32(entry, NEXT_ENTRY_OFFSET)? as usize;
            let attributes = read_u32(entry, ATTRIBUTES_OFFSET)?;
            let name_len = read_u32(entry, NAME_LENGTH_OFFSET)? as usize;
            let name_bytes = entry
                .get(NAME_OFFSET..NAME_OFFSET + name_len)
                .ok_or_else(|| io::Error::other("directory entry name outside its buffer"))?;
            let units: Vec<u16> = name_bytes
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            let name = String::from_utf16(&units).map_err(|_| {
                io::Error::other(format!(
                    "{}: an entry name is not valid UTF-16",
                    dir.display()
                ))
            })?;
            if name != "." && name != ".." {
                entries.push((name, attributes));
            }
            if next == 0 {
                break;
            }
            offset += next;
        }
    }
    Ok(entries)
}

/// Deletes `root` and everything below it. Links are deleted as links;
/// read-only entries are deleted too. Stops at the first error.
///
/// The root entry named `last` (the folder's marker) is deleted after
/// everything else, so a deletion that stops halfway leaves a folder that
/// is still recognizably ours and can be removed by running it again.
pub fn delete_tree(root: &Path, last: &str) -> io::Result<()> {
    enable_privilege("SeBackupPrivilege")?;
    enable_privilege("SeRestorePrivilege")?;
    let mut order: Vec<(PathBuf, u32)> = vec![(root.to_path_buf(), FILE_ATTRIBUTE_DIRECTORY)];
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for (name, attributes) in list_dir(&dir).map_err(|e| with_path(&dir, e))? {
            let path = dir.join(name);
            if attributes & FILE_ATTRIBUTE_DIRECTORY != 0
                && attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
            {
                pending.push(path.clone());
            }
            order.push((path, attributes));
        }
    }
    // Every entry was listed after its parent, so the reverse order deletes
    // contents before the folder that holds them.
    let marker = root.join(last);
    if let Some(index) = order.iter().position(|(path, _)| *path == marker) {
        let entry = order.remove(index);
        order.insert(1, entry);
    }
    for (path, attributes) in order.iter().rev() {
        delete_entry(path, *attributes).map_err(|e| with_path(path, e))?;
    }
    Ok(())
}

fn delete_entry(path: &Path, attributes: u32) -> io::Result<()> {
    let file = OpenOptions::new()
        .access_mode(DELETE | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_OPEN_NO_RECALL,
        )
        .open(path)?;
    let handle = file.as_raw_handle() as HANDLE;
    // POSIX semantics remove the name at once instead of when the last
    // handle closes, so the parent folder is empty when its turn comes.
    let info = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_FLAG_DELETE
            | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS
            | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE,
    };
    // SAFETY: valid handle opened with DELETE; the buffer is a
    // FILE_DISPOSITION_INFO_EX of the size given.
    let ok = unsafe {
        SetFileInformationByHandle(
            handle,
            FileDispositionInfoEx,
            &info as *const _ as *const c_void,
            std::mem::size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
        )
    };
    if ok != 0 {
        return Ok(());
    }
    let err = io::Error::last_os_error();
    let unsupported = [
        ERROR_INVALID_PARAMETER,
        ERROR_NOT_SUPPORTED,
        ERROR_INVALID_FUNCTION,
    ]
    .iter()
    .any(|&code| err.raw_os_error() == Some(code as i32));
    if !unsupported {
        return Err(last_error(
            "SetFileInformationByHandle(FileDispositionInfoEx)",
        ));
    }

    // File systems without the extended disposition: clear read-only, then
    // use the classic delete-on-close.
    if attributes & FILE_ATTRIBUTE_READONLY != 0 {
        let cleared = match attributes & !FILE_ATTRIBUTE_READONLY & COPIED_ATTRIBUTES {
            0 if attributes & FILE_ATTRIBUTE_DIRECTORY == 0 => FILE_ATTRIBUTE_NORMAL,
            other => other,
        };
        // SAFETY: plain-old-data structure; zero times mean "unchanged".
        let mut basic: FILE_BASIC_INFO = unsafe { std::mem::zeroed() };
        basic.FileAttributes = cleared;
        // SAFETY: valid handle opened with FILE_WRITE_ATTRIBUTES; the
        // buffer is a FILE_BASIC_INFO of the size given.
        let ok = unsafe {
            SetFileInformationByHandle(
                handle,
                FileBasicInfo,
                &basic as *const _ as *const c_void,
                std::mem::size_of::<FILE_BASIC_INFO>() as u32,
            )
        };
        if ok == 0 {
            return Err(last_error("SetFileInformationByHandle(FileBasicInfo)"));
        }
    }
    let info = FILE_DISPOSITION_INFO { DeleteFile: 1 };
    // SAFETY: valid handle opened with DELETE; the buffer is a
    // FILE_DISPOSITION_INFO of the size given.
    let ok = unsafe {
        SetFileInformationByHandle(
            handle,
            FileDispositionInfo,
            &info as *const _ as *const c_void,
            std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    };
    if ok == 0 {
        return Err(last_error(
            "SetFileInformationByHandle(FileDispositionInfo)",
        ));
    }
    Ok(())
}

fn read_u32(bytes: &[u8], at: usize) -> io::Result<u32> {
    bytes
        .get(at..at + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or_else(|| io::Error::other("directory entry truncated"))
}

fn with_path(path: &Path, err: io::Error) -> io::Error {
    io::Error::new(err.kind(), format!("{}: {err}", path.display()))
}
