//! Pure analysis of the source user's registry values.
//!
//! The platform layer walks a hive and hands every value to `Inspector`;
//! nothing here knows how the hive was opened. Renaming the profile folder
//! means every absolute `C:\Users\<old>` path stored in the registry must be
//! rewritten, so the inspector lists all of them, plus the per-user
//! settings the application catalog reports on (mapped drives, printers,
//! Outlook data files, OneDrive accounts).

use crate::model::{RegData, RegistryInspection};
use crate::rewrite::replace_path;

const OUTLOOK_DATA_EXTENSIONS: &[&str] = &[".pst", ".ost"];
/// Shortest UTF-16 run worth treating as a string inside a binary value.
const MIN_EMBEDDED_STRING: usize = 6;

pub struct Inspector {
    profile_path: String,
    result: RegistryInspection,
}

impl Inspector {
    pub fn new(profile_path: &str, method: &str) -> Inspector {
        Inspector {
            profile_path: profile_path.trim_end_matches('\\').to_string(),
            result: RegistryInspection {
                method: method.to_string(),
                ..RegistryInspection::default()
            },
        }
    }

    /// `hive` labels the origin (`HKCU` or `HKCU\Classes`); `key` is relative
    /// to the hive root; `value` is the value name (empty for the default).
    pub fn visit(&mut self, hive: &str, key: &str, value: &str, data: &RegData) {
        self.result.values_scanned += 1;
        let location = format!("{hive}\\{key}\\{value}");
        match data {
            RegData::Text(text) => self.classify_text(std::slice::from_ref(text), location),
            RegData::MultiText(items) => self.classify_text(items, location),
            RegData::Binary(bytes) => {
                if binary_contains_path(bytes, &self.profile_path) {
                    self.result.binary_path_refs.push(location);
                }
            }
            RegData::Other => {}
        }
        if hive.eq_ignore_ascii_case("HKCU") {
            self.collect_settings(key, value, data);
        }
    }

    fn collect_settings(&mut self, key: &str, value: &str, data: &RegData) {
        let parts: Vec<&str> = key.split('\\').collect();
        let is = |i: usize, name: &str| parts.get(i).is_some_and(|p| p.eq_ignore_ascii_case(name));

        if parts.len() == 2 && is(0, "Network") && value.eq_ignore_ascii_case("RemotePath") {
            if let RegData::Text(remote) = data {
                push_unique(
                    &mut self.result.network_drives,
                    format!("{}: -> {remote}", parts[1].to_ascii_uppercase()),
                );
            }
        }
        if parts.len() == 3 && is(0, "Printers") && is(1, "Connections") {
            // Connection keys are named ",,server,printer".
            push_unique(
                &mut self.result.printer_connections,
                format!(
                    "\\\\{}",
                    parts[2].trim_start_matches(',').replace(',', "\\")
                ),
            );
        }
        // Software\Microsoft\Office\<version>\Outlook\Profiles\<name>\...
        if parts.len() >= 7
            && is(0, "Software")
            && is(1, "Microsoft")
            && is(2, "Office")
            && is(4, "Outlook")
            && is(5, "Profiles")
        {
            push_unique(&mut self.result.outlook_profiles, parts[6].to_string());
            if let RegData::Binary(bytes) = data {
                for text in utf16_strings(bytes) {
                    let lower = text.to_ascii_lowercase();
                    if OUTLOOK_DATA_EXTENSIONS
                        .iter()
                        .any(|ext| lower.ends_with(ext))
                    {
                        push_unique(&mut self.result.outlook_data_files, text);
                    }
                }
            }
        }
        // Software\Microsoft\OneDrive\Accounts\<account>
        if parts.len() == 5
            && is(0, "Software")
            && is(1, "Microsoft")
            && is(2, "OneDrive")
            && is(3, "Accounts")
            && value.eq_ignore_ascii_case("UserFolder")
        {
            if let RegData::Text(folder) = data {
                push_unique(
                    &mut self.result.onedrive_accounts,
                    format!("{} -> {folder}", parts[4]),
                );
            }
        }
    }

    /// Text the migration rewrites (the folder as a whole path component,
    /// the same rule `rewrite` applies) versus text that only mentions it.
    fn classify_text(&mut self, items: &[String], location: String) {
        let profile = self.profile_path.as_str();
        if items
            .iter()
            .any(|t| replace_path(t, profile, profile).is_some())
        {
            self.result.text_path_refs.push(location);
        } else if items.iter().any(|t| contains_path(t, profile)) {
            self.result.loose_path_refs.push(location);
        }
    }

    pub fn record_error(&mut self, error: String) {
        self.result.errors.push(error);
    }

    pub fn finish(self) -> RegistryInspection {
        self.result
    }
}

fn push_unique(list: &mut Vec<String>, item: String) {
    if !list
        .iter()
        .any(|existing| existing.eq_ignore_ascii_case(&item))
    {
        list.push(item);
    }
}

/// Whether `haystack` contains `path` as a whole path component, ignoring
/// case: `C:\Users\Test` matches `C:\Users\Test\AppData` and `"C:\Users\Test"`
/// but not `C:\Users\Tester`.
pub fn contains_path(haystack: &str, path: &str) -> bool {
    if path.is_empty() {
        return false;
    }
    let hay = haystack.to_lowercase();
    let needle = path.to_lowercase();
    let mut start = 0;
    while let Some(found) = hay[start..].find(&needle) {
        let end = start + found + needle.len();
        match hay[end..].chars().next() {
            None => return true,
            Some(c) if is_path_boundary(c) => return true,
            Some(_) => start = start + found + 1,
        }
        while !hay.is_char_boundary(start) {
            start += 1;
        }
    }
    false
}

/// Characters that can follow a folder name without extending it. Space is
/// included on purpose: over-reporting `C:\Users\Test User` is harmless,
/// missing `C:\Users\Test -flag` is not.
fn is_path_boundary(c: char) -> bool {
    matches!(
        c,
        '\\' | '/' | '"' | '\'' | ';' | ',' | ')' | ']' | '\0' | '|'
    ) || c.is_whitespace()
}

/// Looks for the path inside binary data stored as UTF-16 (at either byte
/// alignment) or as single-byte text.
pub fn binary_contains_path(bytes: &[u8], path: &str) -> bool {
    for offset in 0..2 {
        if bytes.len() < offset + 2 {
            break;
        }
        let units: Vec<u16> = bytes[offset..]
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        if contains_path(&String::from_utf16_lossy(&units), path) {
            return true;
        }
    }
    contains_path(&String::from_utf8_lossy(bytes), path)
}

/// Printable UTF-16LE runs inside a binary value (MAPI property blobs store
/// paths this way).
pub fn utf16_strings(bytes: &[u8]) -> Vec<String> {
    let mut found = Vec::new();
    for offset in 0..2 {
        let mut current: Vec<u16> = Vec::new();
        let units = bytes
            .get(offset..)
            .unwrap_or_default()
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]));
        for unit in units.chain(std::iter::once(0)) {
            // Reading ASCII text one byte off yields units like 0x4400 (low
            // byte zero); real characters of that shape are rare, so such
            // units end a run instead of producing garbage strings.
            let shifted_ascii = unit >= 0x100 && unit & 0xFF == 0;
            let printable = unit >= 0x20
                && unit != 0xFFFF
                && !(0xD800..=0xDFFF).contains(&unit)
                && !shifted_ascii;
            if printable {
                current.push(unit);
                continue;
            }
            if current.len() >= MIN_EMBEDDED_STRING {
                found.push(String::from_utf16_lossy(&current));
            }
            current.clear();
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16(text: &str) -> Vec<u8> {
        text.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    #[test]
    fn path_match_respects_component_boundaries() {
        let path = r"C:\Users\Test";
        assert!(contains_path(r"c:\users\test\AppData\x.exe", path));
        assert!(contains_path(r#""C:\Users\Test" -run"#, path));
        assert!(contains_path(r"C:\Users\Test", path));
        assert!(!contains_path(r"C:\Users\Tester\x", path));
        assert!(contains_path(r"C:\Users\Tester;C:\Users\Test\bin", path));
        assert!(!contains_path(r"%USERPROFILE%\AppData", path));
    }

    #[test]
    fn binary_values_match_utf16_at_either_alignment_and_ansi() {
        let path = r"C:\Users\Test";
        let mut odd = vec![0xAA];
        odd.extend(utf16(r"C:\Users\Test\Documents\a.pst"));
        assert!(binary_contains_path(&utf16(r"x C:\Users\Test\a"), path));
        assert!(binary_contains_path(&odd, path));
        assert!(binary_contains_path(br"C:\Users\Test\b", path));
        assert!(!binary_contains_path(&utf16(r"C:\Users\Other"), path));
        assert!(!binary_contains_path(&[], path));
    }

    #[test]
    fn utf16_strings_are_extracted_from_blobs() {
        let mut blob = vec![1, 0, 2, 0];
        blob.extend(utf16(r"D:\Mail\archive.pst"));
        blob.extend([0, 0, 5, 0]);
        assert_eq!(
            utf16_strings(&blob),
            vec![r"D:\Mail\archive.pst".to_string()]
        );
    }

    #[test]
    fn inspector_lists_every_path_reference() {
        let mut inspector = Inspector::new(r"C:\Users\Test\", "private copy");
        inspector.visit(
            "HKCU",
            r"Software\App",
            "Dir",
            &RegData::Text(r"C:\Users\Test\Data".into()),
        );
        inspector.visit(
            "HKCU",
            r"Software\App",
            "Other",
            &RegData::Text(r"D:\Data".into()),
        );
        inspector.visit(
            "HKCU\\Classes",
            r"Local Settings\Mui",
            "",
            &RegData::MultiText(vec!["a".into(), r"c:\users\test\x".into()]),
        );
        inspector.visit(
            "HKCU",
            r"Software\Blob",
            "Mru",
            &RegData::Binary(utf16(r"C:\Users\Test\x.txt")),
        );
        let result = inspector.finish();
        assert_eq!(result.values_scanned, 4);
        assert_eq!(
            result.text_path_refs,
            vec![
                r"HKCU\Software\App\Dir".to_string(),
                r"HKCU\Classes\Local Settings\Mui\".to_string()
            ]
        );
        assert_eq!(
            result.binary_path_refs,
            vec![r"HKCU\Software\Blob\Mru".to_string()]
        );
        assert_eq!(result.method, "private copy");
    }

    #[test]
    fn inspector_collects_drives_printers_outlook_and_onedrive() {
        let mut inspector = Inspector::new(r"C:\Users\Test", "live");
        inspector.visit(
            "HKCU",
            r"Network\z",
            "RemotePath",
            &RegData::Text(r"\\srv\share".into()),
        );
        inspector.visit(
            "HKCU",
            r"Printers\Connections\,,printsrv,HP Floor 2",
            "Server",
            &RegData::Text(r"\\printsrv".into()),
        );
        inspector.visit(
            "HKCU",
            r"Printers\Connections\,,printsrv,HP Floor 2",
            "Provider",
            &RegData::Text("win32spl.dll".into()),
        );
        let mut mapi = vec![0, 0];
        mapi.extend(utf16(r"C:\Users\Test\Documents\Outlook Files\mail.pst"));
        mapi.extend([0, 0]);
        inspector.visit(
            "HKCU",
            r"Software\Microsoft\Office\16.0\Outlook\Profiles\Outlook\9207f3e0a3b11019908b08002b2a56c2",
            "01023d00",
            &RegData::Binary(mapi),
        );
        inspector.visit(
            "HKCU",
            r"Software\Microsoft\OneDrive\Accounts\Business1",
            "UserFolder",
            &RegData::Text(r"C:\Users\Test\OneDrive - Contoso".into()),
        );
        // The same settings under the Classes hive are not user settings.
        inspector.visit(
            "HKCU\\Classes",
            r"Network\Y",
            "RemotePath",
            &RegData::Text(r"\\other\share".into()),
        );
        let result = inspector.finish();
        assert_eq!(
            result.network_drives,
            vec![r"Z: -> \\srv\share".to_string()]
        );
        assert_eq!(
            result.printer_connections,
            vec![r"\\printsrv\HP Floor 2".to_string()]
        );
        assert_eq!(result.outlook_profiles, vec!["Outlook".to_string()]);
        assert_eq!(
            result.outlook_data_files,
            vec![r"C:\Users\Test\Documents\Outlook Files\mail.pst".to_string()]
        );
        assert_eq!(
            result.onedrive_accounts,
            vec![r"Business1 -> C:\Users\Test\OneDrive - Contoso".to_string()]
        );
        assert_eq!(result.text_path_refs.len(), 1);
        assert_eq!(result.binary_path_refs.len(), 1);
    }

    #[test]
    fn loose_mentions_are_kept_apart_from_rewritable_paths() {
        let mut inspector = Inspector::new(r"C:\Users\Test", "private copy");
        inspector.visit(
            "HKCU",
            "App",
            "Dir",
            &RegData::Text(r"C:\Users\Test\x".into()),
        );
        inspector.visit(
            "HKCU",
            "App",
            "Cmd",
            &RegData::Text(r"C:\Users\Test -flag".into()),
        );
        inspector.visit(
            "HKCU",
            "App",
            "Other",
            &RegData::Text(r"C:\Users\Tester".into()),
        );
        let result = inspector.finish();
        assert_eq!(result.text_path_refs, vec![r"HKCU\App\Dir".to_string()]);
        assert_eq!(result.loose_path_refs, vec![r"HKCU\App\Cmd".to_string()]);
    }
}
