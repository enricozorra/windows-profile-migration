//! Account name <-> SID resolution through LSA.

use std::ffi::c_void;
use std::io;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{GetLastError, ERROR_INSUFFICIENT_BUFFER, ERROR_NONE_MAPPED};
use windows_sys::Win32::Security::Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW};
use windows_sys::Win32::Security::{
    IsValidSid, LookupAccountNameW, LookupAccountSidW, PSID, SID_NAME_USE,
};

use super::wide::{aligned_buffer, from_wide_buf, from_wide_ptr, to_wide, win32_error, LocalBox};
use crate::model::{AccountInfo, AccountKind, LookupOutcome};

/// Resolves `DOMAIN\user` or `user@domain` to a SID, then resolves that SID
/// back so the reported name is the canonical SAM name (a UPN input does
/// not yield one from LookupAccountNameW).
pub fn lookup_account_name(name: &str) -> LookupOutcome {
    let wide_name = to_wide(name);
    let mut sid_len = 0u32;
    let mut domain_len = 0u32;
    let mut sid_use: SID_NAME_USE = 0;
    // SAFETY: null buffers with zero lengths query the required sizes.
    let ok = unsafe {
        LookupAccountNameW(
            null(),
            wide_name.as_ptr(),
            null_mut(),
            &mut sid_len,
            null_mut(),
            &mut domain_len,
            &mut sid_use,
        )
    };
    if ok == 0 {
        // SAFETY: reads the calling thread's last-error value.
        let code = unsafe { GetLastError() };
        if code != ERROR_INSUFFICIENT_BUFFER {
            return lookup_failure("LookupAccountNameW", code);
        }
    }
    let mut sid = aligned_buffer(sid_len);
    let mut domain = vec![0u16; domain_len as usize];
    // SAFETY: both buffers have the sizes LSA just asked for.
    let ok = unsafe {
        LookupAccountNameW(
            null(),
            wide_name.as_ptr(),
            sid.as_mut_ptr() as PSID,
            &mut sid_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut sid_use,
        )
    };
    if ok == 0 {
        // SAFETY: reads the calling thread's last-error value.
        return lookup_failure("LookupAccountNameW", unsafe { GetLastError() });
    }
    // SAFETY: LookupAccountNameW wrote a valid SID into `sid`.
    let sid_string = match unsafe { sid_to_string(sid.as_mut_ptr() as PSID) } {
        Ok(s) => s,
        Err(err) => return LookupOutcome::Failed(err.to_string()),
    };
    match lookup_account_sid(&sid_string) {
        LookupOutcome::Found(info) => LookupOutcome::Found(info),
        // The forward lookup succeeded, so report what it gave rather than
        // failing on the reverse lookup.
        _ => LookupOutcome::Found(AccountInfo {
            sid: sid_string,
            domain: from_wide_buf(&domain),
            name: name
                .rsplit_once('\\')
                .map(|(_, user)| user)
                .or_else(|| name.split_once('@').map(|(user, _)| user))
                .unwrap_or(name)
                .to_string(),
            kind: account_kind(sid_use),
        }),
    }
}

pub fn lookup_account_sid(sid: &str) -> LookupOutcome {
    let wide_sid = to_wide(sid);
    let mut raw_sid: PSID = null_mut();
    // SAFETY: valid NUL-terminated input; the output is LocalAlloc'd and
    // owned by `_owned` below.
    if unsafe { ConvertStringSidToSidW(wide_sid.as_ptr(), &mut raw_sid) } == 0 {
        return LookupOutcome::Invalid(format!("'{sid}' is not a valid SID"));
    }
    let _owned = LocalBox(raw_sid);

    let mut name_len = 0u32;
    let mut domain_len = 0u32;
    let mut sid_use: SID_NAME_USE = 0;
    // SAFETY: size query with null buffers.
    let ok = unsafe {
        LookupAccountSidW(
            null(),
            raw_sid,
            null_mut(),
            &mut name_len,
            null_mut(),
            &mut domain_len,
            &mut sid_use,
        )
    };
    if ok == 0 {
        // SAFETY: reads the calling thread's last-error value.
        let code = unsafe { GetLastError() };
        if code != ERROR_INSUFFICIENT_BUFFER {
            return lookup_failure("LookupAccountSidW", code);
        }
    }
    let mut name = vec![0u16; name_len as usize];
    let mut domain = vec![0u16; domain_len as usize];
    // SAFETY: buffers sized from the query above.
    let ok = unsafe {
        LookupAccountSidW(
            null(),
            raw_sid,
            name.as_mut_ptr(),
            &mut name_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut sid_use,
        )
    };
    if ok == 0 {
        // SAFETY: reads the calling thread's last-error value.
        return lookup_failure("LookupAccountSidW", unsafe { GetLastError() });
    }
    // SAFETY: raw_sid is the valid SID produced above.
    let canonical = match unsafe { sid_to_string(raw_sid) } {
        Ok(s) => s,
        Err(err) => return LookupOutcome::Failed(err.to_string()),
    };
    LookupOutcome::Found(AccountInfo {
        sid: canonical,
        domain: from_wide_buf(&domain),
        name: from_wide_buf(&name),
        kind: account_kind(sid_use),
    })
}

/// ERROR_NONE_MAPPED means "no such account"; every other error (DC down,
/// broken trust, RPC failure) is a failure, never a "not found".
fn lookup_failure(op: &str, code: u32) -> LookupOutcome {
    if code == ERROR_NONE_MAPPED {
        LookupOutcome::NotFound
    } else {
        LookupOutcome::Failed(win32_error(op, code).to_string())
    }
}

fn account_kind(sid_use: SID_NAME_USE) -> AccountKind {
    match sid_use {
        1 => AccountKind::User,
        2 => AccountKind::Group,
        3 => AccountKind::Domain,
        4 => AccountKind::Alias,
        5 => AccountKind::WellKnownGroup,
        6 => AccountKind::DeletedAccount,
        9 => AccountKind::Computer,
        other => AccountKind::Other(other),
    }
}

/// # Safety
/// `sid` must point to a valid SID.
pub unsafe fn sid_to_string(sid: PSID) -> io::Result<String> {
    let mut text: *mut u16 = null_mut();
    // SAFETY: caller guarantees a valid SID; output is LocalAlloc'd.
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(super::wide::last_error("ConvertSidToStringSidW"));
    }
    let _owned = LocalBox(text as *mut c_void);
    // SAFETY: ConvertSidToStringSidW returns a NUL-terminated string.
    Ok(unsafe { from_wide_ptr(text) })
}

/// Converts a binary SID from a REG_BINARY value. Returns None unless the
/// bytes form exactly one structurally valid SID.
pub fn binary_sid_to_string(bytes: &[u8]) -> Option<String> {
    // Header: revision (1), sub-authority count, 6-byte authority, then
    // 4 bytes per sub-authority. Validate before handing to Win32 so it
    // never reads past the buffer.
    if bytes.len() < 8 || bytes[0] != 1 {
        return None;
    }
    let expected = 8 + 4 * bytes[1] as usize;
    if bytes.len() != expected {
        return None;
    }
    let mut buf = aligned_buffer(bytes.len() as u32);
    // SAFETY: `buf` has at least bytes.len() bytes and does not overlap.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf.as_mut_ptr() as *mut u8, bytes.len());
    }
    let sid = buf.as_mut_ptr() as PSID;
    // SAFETY: the buffer holds a structurally complete SID of the declared
    // length, checked above.
    if unsafe { IsValidSid(sid) } == 0 {
        return None;
    }
    // SAFETY: validated just above.
    unsafe { sid_to_string(sid) }.ok()
}
