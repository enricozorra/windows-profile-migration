//! UTF-16 conversion and owned Win32 resources.

use std::ffi::c_void;
use std::io;
use std::iter::once;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE};

pub fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(once(0)).collect()
}

/// Wide path with the `\\?\` prefix for absolute drive paths, so APIs that
/// do not opt into long paths still accept profile files beyond MAX_PATH
/// (deep AppData trees routinely exceed it).
pub fn path_to_wide_verbatim(path: &Path) -> Vec<u16> {
    let text = path.as_os_str();
    let lossy = text.to_string_lossy();
    let bytes = lossy.as_bytes();
    let is_drive_absolute = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/');
    let mut wide: Vec<u16> = Vec::with_capacity(text.len() + 5);
    if is_drive_absolute {
        wide.extend(r"\\?\".encode_utf16());
        wide.extend(text.encode_wide().map(|c| {
            if c == u16::from(b'/') {
                u16::from(b'\\')
            } else {
                c
            }
        }));
    } else {
        wide.extend(text.encode_wide());
    }
    wide.push(0);
    wide
}

/// String from a buffer that may contain a terminating NUL.
pub fn from_wide_buf(buf: &[u16]) -> String {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..len])
}

/// String from a NUL-terminated pointer.
///
/// # Safety
/// `ptr` must be non-null and point to a NUL-terminated UTF-16 string that
/// stays valid for the duration of the call.
pub unsafe fn from_wide_ptr(ptr: *const u16) -> String {
    let mut len = 0usize;
    // SAFETY: caller guarantees NUL termination, so every read up to and
    // including the terminator is in bounds.
    while unsafe { *ptr.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: the `len` elements before the terminator were just read.
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(ptr, len) })
}

/// io::Error for the calling thread's last Win32 error, prefixed by `op`.
pub fn last_error(op: &str) -> io::Error {
    with_context(op, io::Error::last_os_error())
}

/// io::Error for an explicit Win32/LSTATUS code, prefixed by `op`.
pub fn win32_error(op: &str, code: u32) -> io::Error {
    with_context(op, io::Error::from_raw_os_error(code as i32))
}

fn with_context(op: &str, err: io::Error) -> io::Error {
    io::Error::new(err.kind(), format!("{op}: {err}"))
}

/// Memory returned by APIs documented as "free with LocalFree".
pub struct LocalBox(pub *mut c_void);

impl Drop for LocalBox {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer came from an API that allocates with
            // LocalAlloc and is freed exactly once here.
            unsafe { LocalFree(self.0) };
        }
    }
}

pub struct OwnedHandle(pub HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the handle was opened by us and is closed exactly once.
            unsafe { CloseHandle(self.0) };
        }
    }
}

/// A zeroed buffer of at least `bytes` bytes with 8-byte alignment, for
/// variable-length Win32 structures (TOKEN_USER, SIDs) that contain
/// pointers and must not live in a `Vec<u8>`.
pub fn aligned_buffer(bytes: u32) -> Vec<u64> {
    vec![0u64; (bytes as usize).div_ceil(8)]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verbatim_prefix_only_for_drive_paths() {
        let wide = path_to_wide_verbatim(Path::new(r"C:\Users\jdoe"));
        assert_eq!(from_wide_buf(&wide), r"\\?\C:\Users\jdoe");
        let wide = path_to_wide_verbatim(Path::new(r"\\server\share"));
        assert_eq!(from_wide_buf(&wide), r"\\server\share");
    }
}
