//! Machine identity: computer name, domain membership, OS version.

use std::io;
use std::ptr::null;

use windows_sys::Win32::NetworkManagement::NetManagement::{
    NetApiBufferFree, NetGetJoinInformation, NetSetupDomainName, NetSetupUnjoined,
    NetSetupWorkgroupName, NETSETUP_JOIN_STATUS,
};
use windows_sys::Win32::System::Environment::ExpandEnvironmentStringsW;
use windows_sys::Win32::System::Registry::HKEY_LOCAL_MACHINE;
use windows_sys::Win32::System::SystemInformation::{ComputerNameNetBIOS, GetComputerNameExW};

use super::registry::{RegKey, RegValue};
use super::wide::{from_wide_buf, from_wide_ptr, last_error, to_wide, win32_error};
use crate::model::{DomainMembership, OsVersion};

const CURRENT_VERSION_KEY: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";

/// NetBIOS computer name: the "domain" LSA reports for local accounts.
pub fn computer_name() -> io::Result<String> {
    let mut buf = [0u16; 64];
    let mut len = buf.len() as u32;
    // SAFETY: `buf` has `len` elements (NetBIOS names are at most 15).
    if unsafe { GetComputerNameExW(ComputerNameNetBIOS, buf.as_mut_ptr(), &mut len) } == 0 {
        return Err(last_error("GetComputerNameExW"));
    }
    Ok(from_wide_buf(&buf[..len as usize]))
}

pub fn domain_membership() -> DomainMembership {
    let mut name: *mut u16 = std::ptr::null_mut();
    let mut status: NETSETUP_JOIN_STATUS = 0;
    // SAFETY: null server = local machine; out-pointers are valid.
    let code = unsafe { NetGetJoinInformation(null(), &mut name, &mut status) };
    if code != 0 {
        return DomainMembership::Unknown(win32_error("NetGetJoinInformation", code).to_string());
    }
    let text = if name.is_null() {
        String::new()
    } else {
        // SAFETY: NetGetJoinInformation returns a NUL-terminated buffer that
        // must be released with NetApiBufferFree, done right after.
        let text = unsafe { from_wide_ptr(name) };
        // SAFETY: frees the buffer allocated by NetGetJoinInformation.
        unsafe { NetApiBufferFree(name as *const _) };
        text
    };
    // The NETSETUP_JOIN_STATUS constants are CamelCase in windows-sys, so
    // compare with if/else rather than match them as patterns.
    if status == NetSetupDomainName {
        DomainMembership::Domain(text)
    } else if status == NetSetupWorkgroupName {
        DomainMembership::Workgroup(text)
    } else if status == NetSetupUnjoined {
        DomainMembership::Unjoined
    } else {
        DomainMembership::Unknown(format!("join status {status}"))
    }
}

pub fn os_version() -> io::Result<OsVersion> {
    let key = RegKey::open(HKEY_LOCAL_MACHINE, CURRENT_VERSION_KEY)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "CurrentVersion key not found"))?;
    let string = |name: &str| -> io::Result<String> {
        Ok(match key.value(name)? {
            Some(RegValue::String(s) | RegValue::ExpandString(s)) => s,
            _ => String::new(),
        })
    };
    let build_text = string("CurrentBuildNumber")?;
    let build = build_text.trim().parse::<u32>().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("CurrentBuildNumber '{build_text}' is not a number"),
        )
    })?;
    let ubr = match key.value("UBR")? {
        Some(RegValue::Dword(v)) => v,
        _ => 0,
    };
    Ok(OsVersion {
        // ProductName still says "Windows 10" on Windows 11; the build
        // number is what os_support keys on.
        product_name: string("ProductName")?,
        display_version: string("DisplayVersion")?,
        installation_type: string("InstallationType")?,
        build,
        ubr,
    })
}

/// Expands `%SystemDrive%`-style variables in REG_EXPAND_SZ values using
/// this process's environment (which, elevated, matches the machine's).
pub fn expand_environment(raw: &str) -> io::Result<String> {
    let wide = to_wide(raw);
    // SAFETY: size query with a null destination.
    let needed = unsafe { ExpandEnvironmentStringsW(wide.as_ptr(), std::ptr::null_mut(), 0) };
    if needed == 0 {
        return Err(last_error("ExpandEnvironmentStringsW"));
    }
    let mut buf = vec![0u16; needed as usize];
    // SAFETY: `buf` has `needed` elements as requested.
    let written = unsafe { ExpandEnvironmentStringsW(wide.as_ptr(), buf.as_mut_ptr(), needed) };
    if written == 0 || written > needed {
        return Err(last_error("ExpandEnvironmentStringsW"));
    }
    Ok(from_wide_buf(&buf))
}
