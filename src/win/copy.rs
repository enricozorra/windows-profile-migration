//! Entry-level primitives of the working copy: copy one file, folder or
//! link with backup semantics, read an entry's facts, hash its data and set
//! its timestamps.
//!
//! Handles are opened through std's `OpenOptions` (which already handles
//! long paths and owns the handle); only the calls std has no wrapper for
//! are made here directly.

use std::ffi::c_void;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{
    ERROR_HANDLE_EOF, ERROR_NOT_A_REPARSE_POINT, GENERIC_READ, GENERIC_WRITE, HANDLE,
    INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Cryptography::{
    BCryptCloseAlgorithmProvider, BCryptCreateHash, BCryptDestroyHash, BCryptFinishHash,
    BCryptHashData, BCryptOpenAlgorithmProvider, BCRYPT_ALG_HANDLE, BCRYPT_HASH_HANDLE,
    BCRYPT_SHA256_ALGORITHM,
};
use windows_sys::Win32::Storage::FileSystem::{
    BackupRead, BackupWrite, FileBasicInfo, FileStandardInfo, FindClose, FindFirstStreamW,
    FindNextStreamW, FindStreamInfoStandard, GetFileInformationByHandleEx,
    SetFileInformationByHandle, FILE_BASIC_INFO, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_NO_RECALL, FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_SEQUENTIAL_SCAN,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_STANDARD_INFO,
    FILE_WRITE_ATTRIBUTES, WIN32_FIND_STREAM_DATA, WRITE_DAC, WRITE_OWNER,
};
use windows_sys::Win32::System::IO::DeviceIoControl;

use super::security::handle_sddl;
use super::token::enable_privilege;
use super::wide::{from_wide_buf, last_error, path_to_wide_verbatim};
use crate::copy::COPIED_ATTRIBUTES;
use crate::model::{CopiedEntry, EntryFacts};
use crate::secdesc::Edited;

const FSCTL_GET_REPARSE_POINT: u32 = 0x0009_00A8;
const MAXIMUM_REPARSE_DATA_BUFFER_SIZE: usize = 16 * 1024;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

// WIN32_STREAM_ID stream ids and attributes (winbase.h).
const BACKUP_DATA: u32 = 1;
const BACKUP_EA_DATA: u32 = 2;
const BACKUP_SECURITY_DATA: u32 = 3;
const BACKUP_ALTERNATE_DATA: u32 = 4;
const BACKUP_PROPERTY_DATA: u32 = 6;
const BACKUP_OBJECT_ID: u32 = 7;
const BACKUP_REPARSE_DATA: u32 = 8;
const BACKUP_SPARSE_BLOCK: u32 = 9;
const BACKUP_TXFS_DATA: u32 = 10;
const STREAM_SPARSE_ATTRIBUTE: u32 = 8;
/// Bytes of WIN32_STREAM_ID before the variable-length stream name.
const STREAM_HEADER_LEN: usize = 20;
const CHUNK: usize = 1 << 20;

/// Enables the privileges the copy relies on: reading and writing any file
/// regardless of its DACL, setting owners other than ourselves, and
/// recreating symbolic links.
pub fn enable_copy_privileges() -> io::Result<()> {
    enable_privilege("SeBackupPrivilege")?;
    enable_privilege("SeRestorePrivilege")?;
    enable_privilege("SeCreateSymbolicLinkPrivilege")
}

/// Copies one entry from `source` to the new path `dest`, which must not
/// exist. `reparse` is the reparse data to give the copy (possibly
/// retargeted); `None` drops any reparse data, which is how a hydrated
/// cloud file becomes a plain file. `edit_security` may rewrite the
/// binary security descriptor on its way into the copy.
pub fn copy_entry(
    source: &Path,
    dest: &Path,
    is_dir: bool,
    reparse: Option<&[u8]>,
    edit_security: &dyn Fn(&[u8]) -> Edited,
) -> io::Result<CopiedEntry> {
    // Sharing read access only: nothing can modify the file while it is
    // being copied, and an unexpected writer makes the copy fail rather
    // than produce a torn file.
    let input = OpenOptions::new()
        .access_mode(GENERIC_READ)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(
            FILE_FLAG_BACKUP_SEMANTICS
                | FILE_FLAG_OPEN_REPARSE_POINT
                | FILE_FLAG_OPEN_NO_RECALL
                | FILE_FLAG_SEQUENTIAL_SCAN,
        )
        .open(source)?;
    let facts = facts_of(&input, source)?;

    let mut output_options = OpenOptions::new();
    output_options
        .write(true)
        .access_mode(GENERIC_WRITE | WRITE_DAC | WRITE_OWNER)
        .share_mode(0)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    let output = if is_dir {
        fs::create_dir(dest)?;
        output_options.open(dest)?
    } else {
        output_options.create_new(true).open(dest)?
    };

    let sha256 = transfer_streams(&input, &output, is_dir, reparse, edit_security)?;

    let mut attributes = facts.attributes & COPIED_ATTRIBUTES;
    // Zero would mean "leave unchanged" and keep what creation gave the
    // copy: the archive bit on a new file, and not-content-indexed, which
    // files and folders inherit from a parent that has it. NORMAL clears
    // both.
    if attributes == 0 {
        attributes = FILE_ATTRIBUTE_NORMAL;
    }
    set_basic_info(
        output.as_raw_handle() as HANDLE,
        facts.created,
        facts.written,
        attributes,
    )?;
    Ok(CopiedEntry {
        source: facts,
        sha256,
    })
}

/// Facts of an entry, read without following reparse points or recalling
/// cloud data.
pub fn read_entry(path: &Path) -> io::Result<EntryFacts> {
    let file = OpenOptions::new()
        .access_mode(GENERIC_READ)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_OPEN_NO_RECALL,
        )
        .open(path)?;
    facts_of(&file, path)
}

/// SHA-256 of the unnamed data stream.
pub fn hash_data(path: &Path) -> io::Result<[u8; 32]> {
    let mut file = OpenOptions::new()
        .access_mode(GENERIC_READ)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_NO_RECALL | FILE_FLAG_SEQUENTIAL_SCAN,
        )
        .open(path)?;
    let mut hash = Sha256::new()?;
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n])?;
    }
    hash.finish()
}

/// Sets creation and last-write time, leaving everything else as it is.
pub fn set_times(path: &Path, created: i64, written: i64) -> io::Result<()> {
    let file = OpenOptions::new()
        .access_mode(FILE_WRITE_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    set_basic_info(file.as_raw_handle() as HANDLE, created, written, 0)
}

fn facts_of(file: &File, path: &Path) -> io::Result<EntryFacts> {
    let handle = file.as_raw_handle() as HANDLE;
    // SAFETY: plain-old-data structures, fully written on success.
    let mut basic: FILE_BASIC_INFO = unsafe { std::mem::zeroed() };
    // SAFETY: valid handle; the buffer is a FILE_BASIC_INFO of the size given.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileBasicInfo,
            &mut basic as *mut _ as *mut c_void,
            std::mem::size_of::<FILE_BASIC_INFO>() as u32,
        )
    };
    if ok == 0 {
        return Err(last_error("GetFileInformationByHandleEx(FileBasicInfo)"));
    }
    // SAFETY: as above.
    let mut standard: FILE_STANDARD_INFO = unsafe { std::mem::zeroed() };
    // SAFETY: valid handle; the buffer is a FILE_STANDARD_INFO of the size given.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileStandardInfo,
            &mut standard as *mut _ as *mut c_void,
            std::mem::size_of::<FILE_STANDARD_INFO>() as u32,
        )
    };
    if ok == 0 {
        return Err(last_error("GetFileInformationByHandleEx(FileStandardInfo)"));
    }
    let is_link = basic.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0;
    Ok(EntryFacts {
        attributes: basic.FileAttributes,
        created: basic.CreationTime,
        written: basic.LastWriteTime,
        size: if standard.Directory != 0 {
            0
        } else {
            standard.EndOfFile as u64
        },
        reparse: if is_link { reparse_data(handle)? } else { None },
        security: handle_sddl(handle)?,
        // Stream enumeration goes by name and would follow a link.
        streams: if is_link {
            Vec::new()
        } else {
            alternate_streams(path)?
        },
    })
}

fn reparse_data(handle: HANDLE) -> io::Result<Option<Vec<u8>>> {
    let mut buf = vec![0u8; MAXIMUM_REPARSE_DATA_BUFFER_SIZE];
    let mut returned = 0u32;
    // SAFETY: valid handle; the output buffer has the declared length and
    // the call is synchronous (no OVERLAPPED).
    let ok = unsafe {
        DeviceIoControl(
            handle,
            FSCTL_GET_REPARSE_POINT,
            std::ptr::null(),
            0,
            buf.as_mut_ptr() as *mut c_void,
            buf.len() as u32,
            &mut returned,
            null_mut(),
        )
    };
    if ok == 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(ERROR_NOT_A_REPARSE_POINT as i32) {
            return Ok(None);
        }
        return Err(last_error("DeviceIoControl(FSCTL_GET_REPARSE_POINT)"));
    }
    buf.truncate(returned as usize);
    Ok(Some(buf))
}

/// Alternate data streams as `name=size`, sorted. The unnamed stream
/// (`::$DATA`) is the file's content and is left out.
fn alternate_streams(path: &Path) -> io::Result<Vec<String>> {
    let wide = path_to_wide_verbatim(path);
    // SAFETY: plain-old-data structure, written by the calls below.
    let mut data: WIN32_FIND_STREAM_DATA = unsafe { std::mem::zeroed() };
    // SAFETY: NUL-terminated path; `data` is the structure the standard
    // info level writes.
    let find = unsafe {
        FindFirstStreamW(
            wide.as_ptr(),
            FindStreamInfoStandard,
            &mut data as *mut _ as *mut c_void,
            0,
        )
    };
    if find == INVALID_HANDLE_VALUE {
        let err = io::Error::last_os_error();
        // A folder without named streams reports end-of-data straight away.
        if err.raw_os_error() == Some(ERROR_HANDLE_EOF as i32) {
            return Ok(Vec::new());
        }
        return Err(last_error("FindFirstStreamW"));
    }
    let mut streams = Vec::new();
    loop {
        let name = from_wide_buf(&data.cStreamName);
        if name != "::$DATA" {
            streams.push(format!("{name}={}", data.StreamSize));
        }
        // SAFETY: valid find handle and the same structure.
        if unsafe { FindNextStreamW(find, &mut data as *mut _ as *mut c_void) } == 0 {
            let err = io::Error::last_os_error();
            // SAFETY: the find handle is closed exactly once.
            unsafe { FindClose(find) };
            if err.raw_os_error() == Some(ERROR_HANDLE_EOF as i32) {
                break;
            }
            return Err(last_error("FindNextStreamW"));
        }
    }
    streams.sort();
    Ok(streams)
}

fn set_basic_info(handle: HANDLE, created: i64, written: i64, attributes: u32) -> io::Result<()> {
    // Zero fields mean "leave unchanged".
    let info = FILE_BASIC_INFO {
        CreationTime: created,
        LastAccessTime: 0,
        LastWriteTime: written,
        ChangeTime: 0,
        FileAttributes: attributes,
    };
    // SAFETY: valid handle opened with FILE_WRITE_ATTRIBUTES; the buffer is
    // a FILE_BASIC_INFO of the size given.
    let ok = unsafe {
        SetFileInformationByHandle(
            handle,
            FileBasicInfo,
            &info as *const _ as *const c_void,
            std::mem::size_of::<FILE_BASIC_INFO>() as u32,
        )
    };
    if ok == 0 {
        return Err(last_error("SetFileInformationByHandle(FileBasicInfo)"));
    }
    Ok(())
}

/// Moves every stream BackupRead produces for `input` into `output` through
/// BackupWrite, except object ids (unique per volume), transaction and
/// property data, and the reparse data, which is replaced by `reparse`.
/// The security descriptor passes through `edit_security`; writing it in
/// the stream, as a restore does, keeps its control flags (protected,
/// auto-inherited) exactly. Returns the SHA-256 of the data stream for
/// files copied as one plain stream.
fn transfer_streams(
    input: &File,
    output: &File,
    is_dir: bool,
    reparse: Option<&[u8]>,
    edit_security: &dyn Fn(&[u8]) -> Edited,
) -> io::Result<Option<[u8; 32]>> {
    let mut reader = BackupStream::new(input.as_raw_handle() as HANDLE, false);
    let mut writer = BackupStream::new(output.as_raw_handle() as HANDLE, true);
    let mut hash = if is_dir { None } else { Some(Sha256::new()?) };
    let mut wrote_reparse = false;
    let mut buf = vec![0u8; CHUNK];

    loop {
        let mut header = [0u8; STREAM_HEADER_LEN];
        let n = reader.read_full(&mut header)?;
        if n == 0 {
            break;
        }
        if n < STREAM_HEADER_LEN {
            return Err(io::Error::other(
                "BackupRead returned a truncated stream header",
            ));
        }
        let id = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        let stream_attributes = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
        let mut size_bytes = [0u8; 8];
        size_bytes.copy_from_slice(&header[8..16]);
        let size = u64::from_le_bytes(size_bytes);
        let name_len =
            u32::from_le_bytes([header[16], header[17], header[18], header[19]]) as usize;
        let mut name = vec![0u8; name_len];
        if reader.read_full(&mut name)? != name_len {
            return Err(io::Error::other("BackupRead ended inside a stream name"));
        }

        match id {
            BACKUP_SECURITY_DATA => {
                let mut descriptor = vec![0u8; size as usize];
                if reader.read_full(&mut descriptor)? != descriptor.len() {
                    return Err(io::Error::other("BackupRead ended inside a stream"));
                }
                if let Some(edited) = edit_security(&descriptor).map_err(io::Error::other)? {
                    descriptor = edited;
                }
                let mut replaced = header;
                replaced[8..16].copy_from_slice(&(descriptor.len() as u64).to_le_bytes());
                writer.write_all(&replaced)?;
                writer.write_all(&name)?;
                writer.write_all(&descriptor)?;
            }
            BACKUP_DATA | BACKUP_EA_DATA | BACKUP_ALTERNATE_DATA | BACKUP_SPARSE_BLOCK => {
                let sparse = id == BACKUP_SPARSE_BLOCK
                    || (id == BACKUP_DATA && stream_attributes & STREAM_SPARSE_ATTRIBUTE != 0);
                if sparse {
                    hash = None;
                }
                writer.write_all(&header)?;
                writer.write_all(&name)?;
                let mut remaining = size;
                while remaining > 0 {
                    let want = remaining.min(buf.len() as u64) as usize;
                    let got = reader.read_full(&mut buf[..want])?;
                    if got == 0 {
                        return Err(io::Error::other("BackupRead ended inside a stream"));
                    }
                    if id == BACKUP_DATA {
                        if let Some(hash) = hash.as_mut() {
                            hash.update(&buf[..got])?;
                        }
                    }
                    writer.write_all(&buf[..got])?;
                    remaining -= got as u64;
                }
            }
            BACKUP_REPARSE_DATA => {
                reader.skip(size, &mut buf)?;
                if let Some(data) = reparse {
                    let mut replaced = header;
                    replaced[8..16].copy_from_slice(&(data.len() as u64).to_le_bytes());
                    writer.write_all(&replaced)?;
                    writer.write_all(&name)?;
                    writer.write_all(data)?;
                    wrote_reparse = true;
                }
            }
            BACKUP_OBJECT_ID | BACKUP_PROPERTY_DATA | BACKUP_TXFS_DATA => {
                reader.skip(size, &mut buf)?;
            }
            other => {
                return Err(io::Error::other(format!(
                    "unsupported backup stream type {other}; nothing of this kind is copied"
                )))
            }
        }
    }
    if reparse.is_some() && !wrote_reparse {
        return Err(io::Error::other(
            "the source is a link but BackupRead returned no reparse data",
        ));
    }
    match hash {
        Some(hash) => hash.finish().map(Some),
        None => Ok(None),
    }
}

/// A BackupRead or BackupWrite session on one handle. The context the API
/// allocates is released on drop.
struct BackupStream {
    handle: HANDLE,
    write: bool,
    context: *mut c_void,
}

impl BackupStream {
    fn new(handle: HANDLE, write: bool) -> BackupStream {
        BackupStream {
            handle,
            write,
            context: null_mut(),
        }
    }

    /// Fills `buf` unless the stream ends first; returns the bytes read.
    fn read_full(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut filled = 0;
        while filled < buf.len() {
            let mut read = 0u32;
            // SAFETY: valid handle opened for reading; the buffer slice is
            // writable for the length given; the context is ours.
            let ok = unsafe {
                BackupRead(
                    self.handle,
                    buf[filled..].as_mut_ptr(),
                    (buf.len() - filled) as u32,
                    &mut read,
                    0,
                    1,
                    &mut self.context,
                )
            };
            if ok == 0 {
                return Err(last_error("BackupRead"));
            }
            if read == 0 {
                break;
            }
            filled += read as usize;
        }
        Ok(filled)
    }

    fn skip(&mut self, mut bytes: u64, buf: &mut [u8]) -> io::Result<()> {
        while bytes > 0 {
            let want = bytes.min(buf.len() as u64) as usize;
            let got = self.read_full(&mut buf[..want])?;
            if got == 0 {
                return Err(io::Error::other("BackupRead ended inside a stream"));
            }
            bytes -= got as u64;
        }
        Ok(())
    }

    fn write_all(&mut self, mut data: &[u8]) -> io::Result<()> {
        while !data.is_empty() {
            let mut written = 0u32;
            // SAFETY: valid handle opened for writing; the data slice is
            // readable for the length given; the context is ours.
            let ok = unsafe {
                BackupWrite(
                    self.handle,
                    data.as_ptr(),
                    data.len() as u32,
                    &mut written,
                    0,
                    1,
                    &mut self.context,
                )
            };
            if ok == 0 {
                return Err(last_error("BackupWrite"));
            }
            if written == 0 {
                return Err(io::Error::other("BackupWrite accepted no data"));
            }
            data = &data[written as usize..];
        }
        Ok(())
    }
}

impl Drop for BackupStream {
    fn drop(&mut self) {
        if self.context.is_null() {
            return;
        }
        let mut count = 0u32;
        // SAFETY: an abort call with the context we own releases it; the
        // buffer is not accessed when bAbort is TRUE.
        unsafe {
            if self.write {
                BackupWrite(
                    self.handle,
                    std::ptr::null(),
                    0,
                    &mut count,
                    1,
                    1,
                    &mut self.context,
                );
            } else {
                BackupRead(
                    self.handle,
                    null_mut(),
                    0,
                    &mut count,
                    1,
                    1,
                    &mut self.context,
                );
            }
        }
    }
}

/// SHA-256 through Windows CNG, so no hashing code or crate is needed.
struct Sha256 {
    algorithm: BCRYPT_ALG_HANDLE,
    hash: BCRYPT_HASH_HANDLE,
}

impl Sha256 {
    fn new() -> io::Result<Sha256> {
        let mut algorithm: BCRYPT_ALG_HANDLE = null_mut();
        // SAFETY: valid out-pointer and constant algorithm name.
        let status = unsafe {
            BCryptOpenAlgorithmProvider(
                &mut algorithm,
                BCRYPT_SHA256_ALGORITHM,
                std::ptr::null(),
                0,
            )
        };
        check_status("BCryptOpenAlgorithmProvider", status)?;
        let mut sha = Sha256 {
            algorithm,
            hash: null_mut(),
        };
        // SAFETY: open provider; CNG allocates the hash object itself when
        // no buffer is passed.
        let status = unsafe {
            BCryptCreateHash(
                sha.algorithm,
                &mut sha.hash,
                null_mut(),
                0,
                std::ptr::null(),
                0,
                0,
            )
        };
        check_status("BCryptCreateHash", status)?;
        Ok(sha)
    }

    fn update(&mut self, data: &[u8]) -> io::Result<()> {
        // SAFETY: valid hash handle; the slice is readable for its length.
        let status = unsafe { BCryptHashData(self.hash, data.as_ptr(), data.len() as u32, 0) };
        check_status("BCryptHashData", status)
    }

    fn finish(self) -> io::Result<[u8; 32]> {
        let mut digest = [0u8; 32];
        // SAFETY: valid hash handle; the output has the SHA-256 length.
        let status =
            unsafe { BCryptFinishHash(self.hash, digest.as_mut_ptr(), digest.len() as u32, 0) };
        check_status("BCryptFinishHash", status)?;
        Ok(digest)
    }
}

impl Drop for Sha256 {
    fn drop(&mut self) {
        // SAFETY: each handle was created by us and is released once.
        unsafe {
            if !self.hash.is_null() {
                BCryptDestroyHash(self.hash);
            }
            if !self.algorithm.is_null() {
                BCryptCloseAlgorithmProvider(self.algorithm, 0);
            }
        }
    }
}

fn check_status(op: &str, status: i32) -> io::Result<()> {
    if status < 0 {
        return Err(io::Error::other(format!(
            "{op} failed: NTSTATUS {status:#010x}"
        )));
    }
    Ok(())
}
