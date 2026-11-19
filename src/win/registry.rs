//! Read-only registry access: ProfileList, HKU mount points, key existence.

use std::io;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE,
    HKEY_USERS, KEY_READ, KEY_WOW64_64KEY, REG_BINARY, REG_DWORD, REG_EXPAND_SZ, REG_SZ,
};

use super::account::binary_sid_to_string;
use super::system::expand_environment;
use super::wide::{from_wide_buf, to_wide, win32_error};
use crate::model::{
    ProfileListEntry, ProfileListSnapshot, SidValue, MIGRATION_MARKER_VALUE, PROFILE_LIST_KEY,
};

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
