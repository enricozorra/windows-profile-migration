//! Security descriptors as SDDL, and creation of the private backup folder.

use std::ffi::c_void;
use std::io;
use std::path::Path;
use std::ptr::null_mut;

use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW, SDDL_REVISION_1,
    SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
};
use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;

use super::wide::{
    from_wide_ptr, last_error, path_to_wide_verbatim, to_wide, win32_error, LocalBox,
};

/// Protected DACL: full control for SYSTEM and Administrators only. Backups
/// contain copies of the user's hives (credentials, DPAPI blobs), and
/// %ProgramData% subfolders otherwise inherit write access for Users.
const PRIVATE_DIR_SDDL: &str = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

/// Owner, group and DACL of `path` as SDDL. The SACL is not requested: that
/// needs SeSecurityPrivilege enabled and the tool never changes SACLs.
pub fn read_sddl(path: &Path) -> io::Result<String> {
    let wide = path_to_wide_verbatim(path);
    let info = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: NUL-terminated path; we only request the self-relative
    // descriptor (freed by LocalBox), not the individual component pointers.
    let code = unsafe {
        GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            info,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            &mut descriptor,
        )
    };
    if code != 0 {
        return Err(win32_error("GetNamedSecurityInfoW", code));
    }
    let _descriptor = LocalBox(descriptor);

    let mut text: *mut u16 = null_mut();
    // SAFETY: `descriptor` is the valid descriptor returned above.
    let ok = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            SDDL_REVISION_1,
            info,
            &mut text,
            null_mut(),
        )
    };
    if ok == 0 {
        return Err(last_error(
            "ConvertSecurityDescriptorToStringSecurityDescriptorW",
        ));
    }
    let _text = LocalBox(text as *mut c_void);
    // SAFETY: the conversion returns a NUL-terminated string.
    Ok(unsafe { from_wide_ptr(text) })
}

/// Creates a new directory (the parent must exist) whose DACL admits only
/// SYSTEM and Administrators. Fails if it already exists, so a backup never
/// lands in a folder someone else prepared.
pub fn create_private_dir(path: &Path) -> io::Result<()> {
    let sddl = to_wide(PRIVATE_DIR_SDDL);
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: constant, valid SDDL; output is LocalAlloc'd.
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        )
    };
    if ok == 0 {
        return Err(last_error(
            "ConvertStringSecurityDescriptorToSecurityDescriptorW",
        ));
    }
    let _descriptor = LocalBox(descriptor);
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let wide = path_to_wide_verbatim(path);
    // SAFETY: valid path and security attributes that outlive the call.
    if unsafe { CreateDirectoryW(wide.as_ptr(), &attributes) } == 0 {
        return Err(last_error(&format!("CreateDirectoryW({})", path.display())));
    }
    Ok(())
}
