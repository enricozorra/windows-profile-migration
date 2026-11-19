//! Inspection of the current process token: identity, elevation,
//! Administrators membership and held privileges.

use std::ffi::c_void;
use std::io;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{GetLastError, ERROR_INSUFFICIENT_BUFFER, HANDLE, LUID};
use windows_sys::Win32::Security::{
    CheckTokenMembership, CreateWellKnownSid, GetTokenInformation, LookupPrivilegeNameW,
    TokenElevation, TokenPrivileges, TokenUser, WinBuiltinAdministratorsSid, LUID_AND_ATTRIBUTES,
    SECURITY_MAX_SID_SIZE, TOKEN_ELEVATION, TOKEN_INFORMATION_CLASS, TOKEN_PRIVILEGES, TOKEN_QUERY,
    TOKEN_USER,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use super::account::sid_to_string;
use super::wide::{aligned_buffer, from_wide_buf, last_error, OwnedHandle};
use crate::model::TokenInfo;

pub fn current_token() -> io::Result<TokenInfo> {
    let mut raw: HANDLE = null_mut();
    // SAFETY: GetCurrentProcess returns a pseudo-handle that needs no
    // closing; `raw` is a valid out-pointer.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
        return Err(last_error("OpenProcessToken"));
    }
    let token = OwnedHandle(raw);

    let user_buf = token_information(&token, TokenUser)?;
    // SAFETY: GetTokenInformation(TokenUser) filled the 8-byte aligned
    // buffer with a TOKEN_USER whose Sid points inside the same buffer.
    let user_sid = unsafe {
        let user = &*(user_buf.as_ptr() as *const TOKEN_USER);
        sid_to_string(user.User.Sid)?
    };

    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut returned = 0u32;
    // SAFETY: the output buffer is a TOKEN_ELEVATION of the stated size.
    let ok = unsafe {
        GetTokenInformation(
            token.0,
            TokenElevation,
            &mut elevation as *mut TOKEN_ELEVATION as *mut c_void,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    };
    if ok == 0 {
        return Err(last_error("GetTokenInformation(TokenElevation)"));
    }

    Ok(TokenInfo {
        user_sid,
        is_elevated: elevation.TokenIsElevated != 0,
        is_admin_member: is_admin_member()?,
        privileges: privilege_names(&token)?,
    })
}

/// Membership in BUILTIN\Administrators as an *enabled* group. Under UAC
/// the filtered token has it deny-only, which CheckTokenMembership reports
/// as not a member, so this is false in a non-elevated admin shell.
fn is_admin_member() -> io::Result<bool> {
    let mut sid_buf = aligned_buffer(SECURITY_MAX_SID_SIZE);
    let mut size = SECURITY_MAX_SID_SIZE;
    // SAFETY: the buffer holds SECURITY_MAX_SID_SIZE bytes, as declared.
    let ok = unsafe {
        CreateWellKnownSid(
            WinBuiltinAdministratorsSid,
            null_mut(),
            sid_buf.as_mut_ptr() as *mut c_void,
            &mut size,
        )
    };
    if ok == 0 {
        return Err(last_error("CreateWellKnownSid"));
    }
    let mut is_member = 0;
    // SAFETY: a null token means "the calling thread's effective token";
    // the SID buffer was initialized above.
    let ok = unsafe {
        CheckTokenMembership(
            null_mut(),
            sid_buf.as_mut_ptr() as *mut c_void,
            &mut is_member,
        )
    };
    if ok == 0 {
        return Err(last_error("CheckTokenMembership"));
    }
    Ok(is_member != 0)
}

fn privilege_names(token: &OwnedHandle) -> io::Result<Vec<String>> {
    let buf = token_information(token, TokenPrivileges)?;
    // SAFETY: GetTokenInformation(TokenPrivileges) wrote a TOKEN_PRIVILEGES
    // header followed by PrivilegeCount LUID_AND_ATTRIBUTES entries, all
    // inside `buf`.
    let entries: &[LUID_AND_ATTRIBUTES] = unsafe {
        let header = &*(buf.as_ptr() as *const TOKEN_PRIVILEGES);
        std::slice::from_raw_parts(header.Privileges.as_ptr(), header.PrivilegeCount as usize)
    };
    entries
        .iter()
        .map(|entry| privilege_name(&entry.Luid))
        .collect()
}

fn privilege_name(luid: &LUID) -> io::Result<String> {
    // Privilege names are short constants (longest is ~40 chars).
    let mut name = [0u16; 128];
    let mut len = name.len() as u32;
    // SAFETY: `name` has `len` elements; `luid` is a valid LUID.
    let ok = unsafe { LookupPrivilegeNameW(null(), luid, name.as_mut_ptr(), &mut len) };
    if ok == 0 {
        return Err(last_error("LookupPrivilegeNameW"));
    }
    Ok(from_wide_buf(&name[..len as usize]))
}

/// Two-call GetTokenInformation into an 8-byte aligned buffer.
fn token_information(token: &OwnedHandle, class: TOKEN_INFORMATION_CLASS) -> io::Result<Vec<u64>> {
    let mut needed = 0u32;
    // SAFETY: a null buffer of length 0 is the documented way to query size.
    let ok = unsafe { GetTokenInformation(token.0, class, null_mut(), 0, &mut needed) };
    // SAFETY: reads the calling thread's last-error value.
    if ok == 0 && unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
        return Err(last_error("GetTokenInformation(size)"));
    }
    let mut buf = aligned_buffer(needed);
    // SAFETY: `buf` holds at least `needed` bytes.
    let ok = unsafe {
        GetTokenInformation(
            token.0,
            class,
            buf.as_mut_ptr() as *mut c_void,
            needed,
            &mut needed,
        )
    };
    if ok == 0 {
        return Err(last_error("GetTokenInformation"));
    }
    Ok(buf)
}
