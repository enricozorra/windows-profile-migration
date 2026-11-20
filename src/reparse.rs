//! Reparse point data (the `REPARSE_DATA_BUFFER` layout) for junctions and
//! symbolic links.
//!
//! Profiles carry legacy junctions such as `Application Data`, whose
//! targets are absolute paths into the profile itself. A copy that kept
//! them would point back into the source profile, so links whose target
//! lies under the source folder are rewritten to the same place under the
//! target folder. Everything else (relative links, links elsewhere,
//! other reparse types) is copied byte for byte.

pub const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA000_0003;
pub const IO_REPARSE_TAG_SYMLINK: u32 = 0xA000_000C;
const SYMLINK_FLAG_RELATIVE: u32 = 1;
/// `\??\`, the NT namespace prefix of absolute substitute names.
const NT_PREFIX: &str = r"\??\";
const HEADER_LEN: usize = 8;

/// The reparse tag, i.e. the first four bytes of the buffer.
pub fn tag(data: &[u8]) -> Option<u32> {
    data.get(..4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// OneDrive and other Cloud Files placeholders: `IO_REPARSE_TAG_CLOUD`
/// and its sixteen variants `IO_REPARSE_TAG_CLOUD_1..F`, which differ only
/// in bits 12-15.
pub fn is_cloud_tag(tag: u32) -> bool {
    tag & 0xFFFF_0FFF == 0x9000_001A
}

/// Target of a junction or symbolic link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkTarget {
    pub tag: u32,
    /// The name the file system resolves, e.g. `\??\C:\Users\jdoe\AppData`.
    pub substitute: String,
    /// The name shown to users, e.g. `C:\Users\jdoe\AppData`.
    pub print: String,
    pub relative: bool,
}

/// Decodes a junction or symbolic link. Other reparse types return `None`.
pub fn link_target(data: &[u8]) -> Result<Option<LinkTarget>, String> {
    let Some(tag) = tag(data) else {
        return Err("reparse data shorter than its header".into());
    };
    let (path_start, relative) = match tag {
        IO_REPARSE_TAG_MOUNT_POINT => (HEADER_LEN + 8, false),
        IO_REPARSE_TAG_SYMLINK => {
            let flags = read_u32(data, HEADER_LEN + 8)?;
            (HEADER_LEN + 12, flags & SYMLINK_FLAG_RELATIVE != 0)
        }
        _ => return Ok(None),
    };
    let name = |offset_at: usize| -> Result<String, String> {
        let offset = usize::from(read_u16(data, offset_at)?);
        let length = usize::from(read_u16(data, offset_at + 2)?);
        let start = path_start + offset;
        let bytes = data
            .get(start..start + length)
            .ok_or("reparse name lies outside the buffer")?;
        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16(&units).map_err(|e| format!("reparse name is not UTF-16: {e}"))
    };
    Ok(Some(LinkTarget {
        tag,
        substitute: name(HEADER_LEN)?,
        print: name(HEADER_LEN + 4)?,
        relative,
    }))
}

/// Rewrites a junction or absolute symbolic link that points at `from` or
/// below it so that it points at the same place under `to`. Returns `None`
/// when the data needs no change.
pub fn retarget(data: &[u8], from: &str, to: &str) -> Result<Option<Vec<u8>>, String> {
    let Some(link) = link_target(data)? else {
        return Ok(None);
    };
    if link.relative {
        return Ok(None);
    }
    let Some(substitute) = link
        .substitute
        .strip_prefix(NT_PREFIX)
        .and_then(|path| replace_root(path, from, to))
    else {
        return Ok(None);
    };
    // The print name is cosmetic; keep it consistent when it names the
    // same path, otherwise leave it as it was.
    let print = replace_root(&link.print, from, to).unwrap_or(link.print);
    let flags = if link.tag == IO_REPARSE_TAG_SYMLINK {
        Some(read_u32(data, HEADER_LEN + 8)?)
    } else {
        None
    };
    Ok(Some(build(
        link.tag,
        &format!("{NT_PREFIX}{substitute}"),
        &print,
        flags,
    )))
}

/// `path` with the folder `from` replaced by `to`, if `path` is `from` or
/// lies below it. Windows paths compare case-insensitively.
fn replace_root(path: &str, from: &str, to: &str) -> Option<String> {
    let from = from.trim_end_matches('\\');
    let head = path.get(..from.len())?;
    let rest = &path[from.len()..];
    if !head.eq_ignore_ascii_case(from) || !(rest.is_empty() || rest.starts_with('\\')) {
        return None;
    }
    Some(format!("{}{rest}", to.trim_end_matches('\\')))
}

/// Lays out a junction (`flags` is `None`) or symbolic link buffer: the
/// substitute name, then the print name, each followed by a NUL that the
/// lengths do not count, as Windows itself writes them.
fn build(tag: u32, substitute: &str, print: &str, flags: Option<u32>) -> Vec<u8> {
    let substitute: Vec<u16> = substitute.encode_utf16().collect();
    let print: Vec<u16> = print.encode_utf16().collect();
    let substitute_len = substitute.len() * 2;
    let print_len = print.len() * 2;
    let mut names = Vec::with_capacity(substitute_len + print_len + 4);
    for unit in substitute.iter().chain(&[0]).chain(&print).chain(&[0]) {
        names.extend_from_slice(&unit.to_le_bytes());
    }
    let fixed = if flags.is_some() { 12 } else { 8 };
    let mut out = Vec::with_capacity(HEADER_LEN + fixed + names.len());
    out.extend_from_slice(&tag.to_le_bytes());
    out.extend_from_slice(&((fixed + names.len()) as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&(substitute_len as u16).to_le_bytes());
    out.extend_from_slice(&((substitute_len + 2) as u16).to_le_bytes());
    out.extend_from_slice(&(print_len as u16).to_le_bytes());
    if let Some(flags) = flags {
        out.extend_from_slice(&flags.to_le_bytes());
    }
    out.extend_from_slice(&names);
    out
}

fn read_u16(data: &[u8], at: usize) -> Result<u16, String> {
    data.get(at..at + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .ok_or_else(|| "reparse data is truncated".into())
}

fn read_u32(data: &[u8], at: usize) -> Result<u32, String> {
    data.get(at..at + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or_else(|| "reparse data is truncated".into())
}

/// Lowercase hex, used to record reparse data and hashes in the manifest.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const FROM: &str = r"C:\Users\jdoe";
    const TO: &str = r"C:\Users\jdoe.corp";

    fn junction(target: &str) -> Vec<u8> {
        build(
            IO_REPARSE_TAG_MOUNT_POINT,
            &format!(r"\??\{target}"),
            target,
            None,
        )
    }

    #[test]
    fn junction_round_trips() {
        let data = junction(r"C:\Users\jdoe\AppData\Roaming");
        let link = link_target(&data).unwrap().unwrap();
        assert_eq!(link.substitute, r"\??\C:\Users\jdoe\AppData\Roaming");
        assert_eq!(link.print, r"C:\Users\jdoe\AppData\Roaming");
        assert!(!link.relative);
    }

    #[test]
    fn junction_into_the_profile_is_retargeted() {
        let data = junction(r"C:\Users\jdoe\AppData\Roaming");
        let rewritten = retarget(&data, FROM, TO).unwrap().unwrap();
        let link = link_target(&rewritten).unwrap().unwrap();
        assert_eq!(link.substitute, r"\??\C:\Users\jdoe.corp\AppData\Roaming");
        assert_eq!(link.print, r"C:\Users\jdoe.corp\AppData\Roaming");
    }

    #[test]
    fn junction_to_the_profile_root_is_retargeted() {
        let data = junction(r"c:\users\JDOE");
        let link = link_target(&retarget(&data, FROM, TO).unwrap().unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(link.substitute, r"\??\C:\Users\jdoe.corp");
    }

    #[test]
    fn sibling_with_a_common_prefix_is_not_retargeted() {
        let data = junction(r"C:\Users\jdoe2\Documents");
        assert_eq!(retarget(&data, FROM, TO).unwrap(), None);
    }

    #[test]
    fn link_outside_the_profile_is_kept() {
        let data = junction(r"D:\Data");
        assert_eq!(retarget(&data, FROM, TO).unwrap(), None);
    }

    #[test]
    fn relative_symlink_is_kept_and_absolute_one_rewritten_with_its_flags() {
        let relative = build(IO_REPARSE_TAG_SYMLINK, r"..\x", r"..\x", Some(1));
        assert_eq!(retarget(&relative, FROM, TO).unwrap(), None);

        let absolute = build(
            IO_REPARSE_TAG_SYMLINK,
            r"\??\C:\Users\jdoe\file.txt",
            r"C:\Users\jdoe\file.txt",
            Some(0),
        );
        let rewritten = retarget(&absolute, FROM, TO).unwrap().unwrap();
        let link = link_target(&rewritten).unwrap().unwrap();
        assert_eq!(link.tag, IO_REPARSE_TAG_SYMLINK);
        assert_eq!(link.substitute, r"\??\C:\Users\jdoe.corp\file.txt");
        assert!(!link.relative);
    }

    #[test]
    fn other_reparse_types_are_left_alone() {
        // An app execution alias (IO_REPARSE_TAG_APPEXECLINK).
        let mut data = 0x8000_001Bu32.to_le_bytes().to_vec();
        data.extend_from_slice(&[4, 0, 0, 0, 1, 2, 3, 4]);
        assert_eq!(link_target(&data).unwrap(), None);
        assert_eq!(retarget(&data, FROM, TO).unwrap(), None);
    }

    #[test]
    fn truncated_data_is_an_error() {
        let data = junction(r"C:\Users\jdoe");
        assert!(link_target(&data[..12]).is_err());
        assert!(link_target(&data[..2]).is_err());
    }

    #[test]
    fn cloud_tags_are_recognized() {
        assert!(is_cloud_tag(0x9000_001A));
        assert!(is_cloud_tag(0x9000_301A));
        assert!(!is_cloud_tag(IO_REPARSE_TAG_MOUNT_POINT));
        assert!(!is_cloud_tag(0x8000_001B));
    }
}
