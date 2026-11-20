//! Read-only registry access: ProfileList, HKU mount points, key existence,
//! service accounts, and full walks of a user hive.

use std::io;
use std::path::Path;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread::sleep;
use std::time::Duration;

use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegEnumKeyExW, RegEnumValueW, RegLoadKeyW, RegOpenKeyExW, RegQueryValueExW,
    RegUnLoadKeyW, HKEY, HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_READ, KEY_WOW64_64KEY, REG_BINARY,
    REG_DWORD, REG_EXPAND_SZ, REG_MULTI_SZ, REG_OPTION_OPEN_LINK, REG_SZ,
};

use super::account::binary_sid_to_string;
use super::system::expand_environment;
use super::token::enable_privilege;
use super::wide::{from_wide_buf, path_to_wide_verbatim, to_wide, win32_error};
use crate::model::{
    ProfileListEntry, ProfileListSnapshot, RegData, SidValue, HIVE_MOUNT_PREFIX,
    MIGRATION_MARKER_VALUE, PROFILE_LIST_KEY,
};

const SERVICES_KEY: &str = r"SYSTEM\CurrentControlSet\Services";
/// Longest value name the registry allows, plus the terminator.
const MAX_VALUE_NAME: usize = 16_384;
/// Unload attempts, spaced by UNLOAD_RETRY_DELAY: an antivirus or indexer
/// can briefly hold a handle into a freshly mounted hive.
const UNLOAD_ATTEMPTS: u32 = 10;
const UNLOAD_RETRY_DELAY: Duration = Duration::from_millis(300);

static NEXT_MOUNT: AtomicU32 = AtomicU32::new(0);

pub enum RegValue {
    String(String),
    ExpandString(String),
    Dword(u32),
    Binary(Vec<u8>),
    Other,
}

pub struct RegKey(HKEY);

impl Drop for RegKey {
    fn drop(&mut self) {
        // SAFETY: the key was opened by RegOpenKeyExW and is closed once.
        unsafe { RegCloseKey(self.0) };
    }
}

impl RegKey {
    /// Opens `root\path` for reading in the 64-bit view. Returns Ok(None)
    /// if the key does not exist.
    pub fn open(root: HKEY, path: &str) -> io::Result<Option<RegKey>> {
        let wide = to_wide(path);
        let mut key: HKEY = null_mut();
        // SAFETY: valid predefined root, NUL-terminated path, out-pointer.
        let status =
            unsafe { RegOpenKeyExW(root, wide.as_ptr(), 0, KEY_READ | KEY_WOW64_64KEY, &mut key) };
        match status {
            0 => Ok(Some(RegKey(key))),
            ERROR_FILE_NOT_FOUND => Ok(None),
            code => Err(win32_error(&format!("RegOpenKeyExW({path})"), code)),
        }
    }

    /// Opens `path` below this key for reading. Registry symbolic links are
    /// opened as links, not followed: a live user hive links
    /// `Software\Classes` to the separately mounted Classes hive, and
    /// following it would read that hive twice.
    fn open_below(&self, path: &str) -> io::Result<RegKey> {
        let wide = to_wide(path);
        let mut key: HKEY = null_mut();
        // SAFETY: valid open key, NUL-terminated path, out-pointer.
        let status = unsafe {
            RegOpenKeyExW(
                self.0,
                wide.as_ptr(),
                REG_OPTION_OPEN_LINK,
                KEY_READ,
                &mut key,
            )
        };
        match status {
            0 => Ok(RegKey(key)),
            code => Err(win32_error(&format!("RegOpenKeyExW({path})"), code)),
        }
    }

    /// Calls `visit(name, data)` for every value of this key.
    fn for_each_value(&self, visit: &mut dyn FnMut(&str, RegData)) -> io::Result<()> {
        let mut name = vec![0u16; MAX_VALUE_NAME];
        let mut data: Vec<u8> = vec![0; 4096];
        let mut index = 0u32;
        loop {
            let mut name_len = name.len() as u32;
            let mut data_len = data.len() as u32;
            let mut kind = 0u32;
            // SAFETY: both buffers have the lengths passed in; on
            // ERROR_MORE_DATA `data_len` holds the size needed for this value.
            let status = unsafe {
                RegEnumValueW(
                    self.0,
                    index,
                    name.as_mut_ptr(),
                    &mut name_len,
                    null(),
                    &mut kind,
                    data.as_mut_ptr(),
                    &mut data_len,
                )
            };
            match status {
                0 => {
                    let value_name = from_wide_buf(&name[..name_len as usize]);
                    visit(&value_name, decode_data(kind, &data[..data_len as usize]));
                    index += 1;
                }
                // The name buffer is already the maximum size, so only the
                // data can be too small: grow it and retry the same index.
                ERROR_MORE_DATA => data.resize(data_len as usize, 0),
                ERROR_NO_MORE_ITEMS => return Ok(()),
                code => return Err(win32_error("RegEnumValueW", code)),
            }
        }
    }

    pub fn subkey_names(&self) -> io::Result<Vec<String>> {
        let mut names = Vec::new();
        // Registry key names are limited to 255 characters.
        let mut buf = [0u16; 256];
        for index in 0u32.. {
            let mut len = buf.len() as u32;
            // SAFETY: `buf` has `len` elements; unused out-params are null.
            let status = unsafe {
                RegEnumKeyExW(
                    self.0,
                    index,
                    buf.as_mut_ptr(),
                    &mut len,
                    null(),
                    null_mut(),
                    null_mut(),
                    null_mut(),
                )
            };
            match status {
                0 => names.push(from_wide_buf(&buf[..len as usize])),
                ERROR_NO_MORE_ITEMS => break,
                code => return Err(win32_error("RegEnumKeyExW", code)),
            }
        }
        Ok(names)
    }

    pub fn value(&self, name: &str) -> io::Result<Option<RegValue>> {
        let wide = to_wide(name);
        let mut data: Vec<u8> = vec![0; 256];
        loop {
            let mut kind = 0u32;
            let mut size = data.len() as u32;
            // SAFETY: `data` has `size` bytes; RegQueryValueExW writes at
            // most that and reports the needed size on ERROR_MORE_DATA.
            let status = unsafe {
                RegQueryValueExW(
                    self.0,
                    wide.as_ptr(),
                    null(),
                    &mut kind,
                    data.as_mut_ptr(),
                    &mut size,
                )
            };
            match status {
                0 => {
                    data.truncate(size as usize);
                    return Ok(Some(decode_value(kind, data)));
                }
                ERROR_FILE_NOT_FOUND => return Ok(None),
                ERROR_MORE_DATA => data.resize(size as usize, 0),
                code => return Err(win32_error(&format!("RegQueryValueExW({name})"), code)),
            }
        }
    }

    fn string(&self, name: &str) -> io::Result<Option<String>> {
        Ok(match self.value(name)? {
            Some(RegValue::String(s) | RegValue::ExpandString(s)) => Some(s),
            _ => None,
        })
    }

    fn dword(&self, name: &str) -> io::Result<Option<u32>> {
        Ok(match self.value(name)? {
            Some(RegValue::Dword(v)) => Some(v),
            _ => None,
        })
    }
}

fn utf16_units(data: &[u8]) -> Vec<u16> {
    data.chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect()
}

fn decode_data(kind: u32, data: &[u8]) -> RegData {
    match kind {
        REG_SZ | REG_EXPAND_SZ => RegData::Text(from_wide_buf(&utf16_units(data))),
        REG_MULTI_SZ => RegData::MultiText(
            utf16_units(data)
                .split(|&unit| unit == 0)
                .filter(|item| !item.is_empty())
                .map(String::from_utf16_lossy)
                .collect(),
        ),
        REG_BINARY => RegData::Binary(data.to_vec()),
        _ => RegData::Other,
    }
}

/// Visits every value below `root`. Keys that cannot be opened or listed
/// are returned as errors and the walk continues with the rest.
fn walk(root: &RegKey, visit: &mut dyn FnMut(&str, &str, &RegData)) -> Vec<String> {
    let mut errors = Vec::new();
    // Iterative: user hives can nest deeper than is comfortable to recurse.
    let mut pending = vec![String::new()];
    while let Some(path) = pending.pop() {
        let opened;
        let key = if path.is_empty() {
            root
        } else {
            match root.open_below(&path) {
                Ok(key) => {
                    opened = key;
                    &opened
                }
                Err(err) => {
                    errors.push(err.to_string());
                    continue;
                }
            }
        };
        let mut on_value = |name: &str, data: RegData| visit(&path, name, &data);
        if let Err(err) = key.for_each_value(&mut on_value) {
            errors.push(format!("{path}: {err}"));
        }
        match key.subkey_names() {
            Ok(names) => pending.extend(names.into_iter().map(|name| {
                if path.is_empty() {
                    name
                } else {
                    format!("{path}\\{name}")
                }
            })),
            Err(err) => errors.push(format!("{path}: {err}")),
        }
    }
    errors
}

/// Walks a hive already mounted at `HKU\<hku_subkey>` (a logged-on user).
pub fn walk_loaded_hive(
    hku_subkey: &str,
    visit: &mut dyn FnMut(&str, &str, &RegData),
) -> io::Result<Vec<String>> {
    let root = RegKey::open(HKEY_USERS, hku_subkey)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("HKU\\{hku_subkey} is not mounted"),
        )
    })?;
    Ok(walk(&root, visit))
}

/// Mounts the hive file `path` under a temporary `HKU` name, walks it and
/// unmounts it. Mounting can replay the hive's logs into the file, so
/// callers only ever pass a copy. (RegLoadAppKey would keep the mount
/// private, but it rejects real user hives with ERROR_BADDB.)
///
/// A mount that cannot be removed is reported among the returned errors;
/// preflight also flags any leftover mount by its name prefix.
pub fn walk_hive_file(
    path: &Path,
    visit: &mut dyn FnMut(&str, &str, &RegData),
) -> io::Result<Vec<String>> {
    enable_privilege("SeBackupPrivilege")?;
    enable_privilege("SeRestorePrivilege")?;
    let mount = format!(
        "{HIVE_MOUNT_PREFIX}inspect_{}_{}",
        std::process::id(),
        NEXT_MOUNT.fetch_add(1, Ordering::Relaxed)
    );
    let wide_mount = to_wide(&mount);
    let wide_path = path_to_wide_verbatim(path);
    // SAFETY: predefined root, NUL-terminated mount name and file path.
    let status = unsafe { RegLoadKeyW(HKEY_USERS, wide_mount.as_ptr(), wide_path.as_ptr()) };
    if status != 0 {
        return Err(win32_error(
            &format!("RegLoadKeyW({})", path.display()),
            status,
        ));
    }
    // The root handle must be closed before the unload, hence the scope.
    let walked = match RegKey::open(HKEY_USERS, &mount) {
        Ok(Some(root)) => Ok(walk(&root, visit)),
        Ok(None) => Err(io::Error::other(format!(
            "HKU\\{mount} vanished right after loading"
        ))),
        Err(err) => Err(err),
    };
    let unloaded = unload(&mount);
    match (walked, unloaded) {
        (Ok(errors), Ok(())) => Ok(errors),
        (Ok(mut errors), Err(err)) => {
            errors.push(format!("{err}; remove it with: reg unload HKU\\{mount}"));
            Ok(errors)
        }
        (Err(err), Ok(())) => Err(err),
        (Err(err), Err(unload_err)) => Err(io::Error::other(format!(
            "{err}; in addition {unload_err}, remove it with: reg unload HKU\\{mount}"
        ))),
    }
}

fn unload(mount: &str) -> io::Result<()> {
    let wide = to_wide(mount);
    let mut attempt = 1;
    loop {
        // SAFETY: predefined root and NUL-terminated mount name.
        let status = unsafe { RegUnLoadKeyW(HKEY_USERS, wide.as_ptr()) };
        if status == 0 {
            return Ok(());
        }
        if attempt == UNLOAD_ATTEMPTS {
            return Err(win32_error(&format!("RegUnLoadKeyW(HKU\\{mount})"), status));
        }
        attempt += 1;
        sleep(UNLOAD_RETRY_DELAY);
    }
}

/// `(service name, ObjectName)` for every service that has a logon account.
pub fn service_accounts() -> io::Result<Vec<(String, String)>> {
    let services = RegKey::open(HKEY_LOCAL_MACHINE, SERVICES_KEY)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("HKLM\\{SERVICES_KEY} does not exist"),
        )
    })?;
    let mut accounts = Vec::new();
    for name in services.subkey_names()? {
        // A service removed between enumeration and open is simply gone.
        let Some(service) = RegKey::open(HKEY_LOCAL_MACHINE, &format!("{SERVICES_KEY}\\{name}"))?
        else {
            continue;
        };
        if let Some(account) = service.string("ObjectName")? {
            accounts.push((name, account));
        }
    }
    Ok(accounts)
}

fn decode_value(kind: u32, data: Vec<u8>) -> RegValue {
    match kind {
        REG_SZ | REG_EXPAND_SZ => {
            let units: Vec<u16> = data
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect();
            let text = from_wide_buf(&units);
            if kind == REG_SZ {
                RegValue::String(text)
            } else {
                RegValue::ExpandString(text)
            }
        }
        REG_DWORD if data.len() == 4 => {
            RegValue::Dword(u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
        }
        REG_BINARY => RegValue::Binary(data),
        _ => RegValue::Other,
    }
}

pub fn read_profile_list() -> io::Result<ProfileListSnapshot> {
    let list = RegKey::open(HKEY_LOCAL_MACHINE, PROFILE_LIST_KEY)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("HKLM\\{PROFILE_LIST_KEY} does not exist"),
        )
    })?;
    let profiles_directory = list
        .string("ProfilesDirectory")?
        .map(|raw| expand_environment(&raw))
        .transpose()?;

    let mut entries = Vec::new();
    for key_name in list.subkey_names()? {
        let path = format!("{PROFILE_LIST_KEY}\\{key_name}");
        // A profile deleted between enumeration and open is simply gone.
        let Some(key) = RegKey::open(HKEY_LOCAL_MACHINE, &path)? else {
            continue;
        };
        let profile_image_path = key.string("ProfileImagePath")?;
        let profile_image_path_expanded = profile_image_path
            .as_deref()
            .map(expand_environment)
            .transpose()?;
        let sid_value = match key.value("Sid")? {
            None => SidValue::Missing,
            Some(RegValue::Binary(bytes)) => match binary_sid_to_string(&bytes) {
                Some(s) => SidValue::Valid(s),
                None => SidValue::Invalid,
            },
            Some(_) => SidValue::Invalid,
        };
        entries.push(ProfileListEntry {
            key_name,
            profile_image_path,
            profile_image_path_expanded,
            flags: key.dword("Flags")?,
            state: key.dword("State")?,
            ref_count: key.dword("RefCount")?,
            sid_value,
            guid: key.string("Guid")?,
            migration_marker: key.string(MIGRATION_MARKER_VALUE)?,
        });
    }
    Ok(ProfileListSnapshot {
        profiles_directory,
        entries,
    })
}

/// Names of the hives currently mounted under HKEY_USERS.
pub fn loaded_user_hives() -> io::Result<Vec<String>> {
    let users = RegKey::open(HKEY_USERS, "")?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "HKEY_USERS not available"))?;
    users.subkey_names()
}

pub fn hklm_key_exists(subkey: &str) -> io::Result<bool> {
    Ok(RegKey::open(HKEY_LOCAL_MACHINE, subkey)?.is_some())
}
