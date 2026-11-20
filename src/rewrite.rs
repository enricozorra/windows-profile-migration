//! What the migration changes inside the working copy: the source SID
//! becomes the target SID (in security descriptors and in registry text),
//! and the source profile folder becomes the target folder (in registry
//! text). All decisions are made here; the platform layer only applies
//! them.
//!
//! Matching is deliberately strict, because a wrong replacement corrupts a
//! value: a SID only matches as a whole token (`...-1001` never matches
//! `...-10012`), and a folder only matches as a whole path component
//! (`C:\Users\Test` never matches `C:\Users\Tester` or `C:\Users\Test User`).
//! References that look related but are not matched strictly are reported,
//! not rewritten.

use crate::hive_scan::{binary_contains_path, contains_path};
use crate::model::RegData;
use crate::secdesc::{self, sid_to_bytes, Edited};

/// The two substitutions of one migration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Substitution {
    pub source_sid: String,
    pub target_sid: String,
    pub source_path: String,
    pub target_path: String,
}

impl Substitution {
    /// A security descriptor (SDDL) with the source SID replaced, or `None`
    /// when it does not mention the source.
    pub fn security(&self, sddl: &str) -> Option<String> {
        replace_sid(sddl, &self.source_sid, &self.target_sid)
    }

    /// A binary self-relative security descriptor with the source SID
    /// replaced in place (see `secdesc`), or `None` when it does not
    /// contain the source.
    pub fn security_bytes(&self, descriptor: &[u8]) -> Edited {
        let from = sid_to_bytes(&self.source_sid)
            .ok_or_else(|| format!("{} is not a SID", self.source_sid))?;
        let to = sid_to_bytes(&self.target_sid)
            .ok_or_else(|| format!("{} is not a SID", self.target_sid))?;
        secdesc::replace_sid(descriptor, &from, &to)
    }

    /// Registry text with both substitutions applied, or `None` when
    /// nothing matched.
    pub fn text(&self, text: &str) -> Option<String> {
        let paths = replace_path(text, &self.source_path, &self.target_path);
        let current = paths.as_deref().unwrap_or(text);
        match replace_sid(current, &self.source_sid, &self.target_sid) {
            Some(both) => Some(both),
            None => paths,
        }
    }

    /// A registry value with both substitutions applied. Binary and other
    /// data is never changed.
    pub fn value(&self, data: &RegData) -> Option<RegData> {
        match data {
            RegData::Text(text) => self.text(text).map(RegData::Text),
            RegData::MultiText(items) => {
                let rewritten: Vec<Option<String>> = items.iter().map(|i| self.text(i)).collect();
                if rewritten.iter().all(Option::is_none) {
                    return None;
                }
                Some(RegData::MultiText(
                    rewritten
                        .into_iter()
                        .zip(items)
                        .map(|(new, old)| new.unwrap_or_else(|| old.clone()))
                        .collect(),
                ))
            }
            RegData::Binary(_) | RegData::Other => None,
        }
    }

    /// Why a value that is left as it is still refers to the source, if it
    /// does: binary data that embeds the folder, or text that mentions it
    /// in a way the strict match does not accept.
    pub fn residue(&self, data: &RegData) -> Option<&'static str> {
        let loosely = |text: &str| {
            contains_path(text, &self.source_path)
                || text
                    .to_ascii_uppercase()
                    .contains(&self.source_sid.to_ascii_uppercase())
        };
        match data {
            RegData::Binary(bytes) if binary_contains_path(bytes, &self.source_path) => {
                Some("binary data embeds the source folder")
            }
            RegData::Text(text) if loosely(text) => Some("text mentions the source"),
            RegData::MultiText(items) if items.iter().any(|i| loosely(i)) => {
                Some("text mentions the source")
            }
            _ => None,
        }
    }

    /// Whether a name (of a registry key or value) mentions the source.
    /// Names are reported, not renamed.
    pub fn name_mentions_source(&self, name: &str) -> bool {
        replace_sid(name, &self.source_sid, &self.target_sid).is_some()
            || replace_path(name, &self.source_path, &self.target_path).is_some()
    }
}

/// What rewriting one hive did, for the journal, the log and the report.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HiveReport {
    pub keys_translated: usize,
    /// `key\value` of every value whose text was rewritten.
    pub values_rewritten: Vec<String>,
    /// Values left as they are that still refer to the source, with why.
    pub residues: Vec<String>,
    /// Key and value names that mention the source (names are not changed).
    pub names: Vec<String>,
}

impl Substitution {
    /// Decides the new descriptor of a registry key and records it.
    pub fn rewrite_key(&self, report: &mut HiveReport, key: &str, descriptor: &[u8]) -> Edited {
        let leaf = key.rsplit('\\').next().unwrap_or(key);
        if self.name_mentions_source(leaf) {
            report.names.push(format!("key {key}"));
        }
        let new = self.security_bytes(descriptor)?;
        if new.is_some() {
            report.keys_translated += 1;
        }
        Ok(new)
    }

    /// Decides the new data of a registry value and records it.
    pub fn rewrite_value(
        &self,
        report: &mut HiveReport,
        key: &str,
        name: &str,
        data: &RegData,
    ) -> Option<RegData> {
        let place = value_place(key, name);
        if self.name_mentions_source(name) {
            report.names.push(format!("value {place}"));
        }
        match self.value(data) {
            Some(new) => {
                report.values_rewritten.push(place);
                Some(new)
            }
            None => {
                if let Some(why) = self.residue(data) {
                    report.residues.push(format!("{place}: {why}"));
                }
                None
            }
        }
    }
}

/// How a value is named in reports: `key\name`, with the root key shown as
/// `(root)` and the default value as `(default)`.
pub fn value_place(key: &str, name: &str) -> String {
    let key = if key.is_empty() { "(root)" } else { key };
    let name = if name.is_empty() { "(default)" } else { name };
    format!("{key}\\{name}")
}

/// Replaces every whole-token occurrence of `from` (a SID string) with `to`.
pub fn replace_sid(text: &str, from: &str, to: &str) -> Option<String> {
    let is_sid_char = |c: char| c.is_ascii_alphanumeric() || c == '-';
    replace_matches(text, from, to, |before, after| {
        !before.is_some_and(is_sid_char) && !after.is_some_and(|c| c.is_ascii_digit() || c == '-')
    })
}

/// Replaces every occurrence of the folder `from` that is a whole path
/// component (it ends the text or is followed by a separator or quoting
/// character) and is not itself inside a longer path.
pub fn replace_path(text: &str, from: &str, to: &str) -> Option<String> {
    let from = from.trim_end_matches('\\');
    let to = to.trim_end_matches('\\');
    replace_matches(text, from, to, |before, after| {
        let starts_cleanly = !before.is_some_and(|c| c.is_alphanumeric() || c == '\\');
        let ends_cleanly = match after {
            None => true,
            Some(c) => matches!(
                c,
                '\\' | '/' | '"' | '\'' | ';' | ',' | ')' | ']' | '|' | '\0'
            ),
        };
        starts_cleanly && ends_cleanly
    })
}

/// Case-insensitive search and replace; `accept(char before, char after)`
/// decides whether a match stands on its own.
fn replace_matches(
    text: &str,
    from: &str,
    to: &str,
    accept: impl Fn(Option<char>, Option<char>) -> bool,
) -> Option<String> {
    if from.is_empty() {
        return None;
    }
    let mut out = String::with_capacity(text.len());
    let mut changed = false;
    let mut rest = text;
    let mut before: Option<char> = None;
    while !rest.is_empty() {
        if let Some(len) = prefix_len_ignoring_case(rest, from) {
            let after = rest[len..].chars().next();
            if accept(before, after) {
                out.push_str(to);
                rest = &rest[len..];
                before = to.chars().last();
                changed = true;
                continue;
            }
        }
        let Some(c) = rest.chars().next() else { break };
        out.push(c);
        rest = &rest[c.len_utf8()..];
        before = Some(c);
    }
    changed.then_some(out)
}

/// Byte length of the prefix of `text` that equals `pattern` ignoring case.
fn prefix_len_ignoring_case(text: &str, pattern: &str) -> Option<usize> {
    let mut text_chars = text.char_indices();
    for p in pattern.chars() {
        let (_, t) = text_chars.next()?;
        if !t.to_lowercase().eq(p.to_lowercase()) {
            return None;
        }
    }
    Some(text_chars.next().map_or(text.len(), |(i, _)| i))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC: &str = "S-1-5-21-111-222-333-1001";
    const TGT: &str = "S-1-5-21-777-888-999-2601";

    fn subst() -> Substitution {
        Substitution {
            source_sid: SRC.into(),
            target_sid: TGT.into(),
            source_path: r"C:\Users\Test".into(),
            target_path: r"C:\Users\enrico.zorra".into(),
        }
    }

    #[test]
    fn sid_is_replaced_in_owner_and_aces() {
        let sddl = format!("O:{SRC}G:SYD:PAI(A;OICI;FA;;;SY)(A;OICIID;FA;;;{SRC})");
        assert_eq!(
            replace_sid(&sddl, SRC, TGT).unwrap(),
            format!("O:{TGT}G:SYD:PAI(A;OICI;FA;;;SY)(A;OICIID;FA;;;{TGT})")
        );
    }

    #[test]
    fn longer_sid_with_the_same_prefix_is_not_replaced() {
        let sddl = format!("O:{SRC}2G:SY");
        assert_eq!(replace_sid(&sddl, SRC, TGT), None);
        let sddl = format!("O:{SRC}-5G:SY");
        assert_eq!(replace_sid(&sddl, SRC, TGT), None);
    }

    #[test]
    fn sid_followed_by_classes_suffix_is_replaced() {
        assert_eq!(
            replace_sid(&format!("{SRC}_Classes"), SRC, TGT).unwrap(),
            format!("{TGT}_Classes")
        );
    }

    #[test]
    fn descriptor_without_the_source_is_left_alone() {
        assert_eq!(subst().security("O:SYG:SYD:(A;;FA;;;BA)"), None);
    }

    #[test]
    fn path_is_replaced_as_a_whole_component_ignoring_case() {
        let s = subst();
        assert_eq!(
            s.text(r"c:\users\test\AppData\Roaming").unwrap(),
            r"C:\Users\enrico.zorra\AppData\Roaming"
        );
        assert_eq!(s.text(r"C:\Users\Test").unwrap(), r"C:\Users\enrico.zorra");
        assert_eq!(
            s.text(r#""C:\Users\Test\app.exe" -x;C:\Users\Test"#)
                .unwrap(),
            r#""C:\Users\enrico.zorra\app.exe" -x;C:\Users\enrico.zorra"#
        );
    }

    #[test]
    fn similar_paths_are_not_replaced() {
        let s = subst();
        assert_eq!(s.text(r"C:\Users\Tester\x"), None);
        assert_eq!(s.text(r"C:\Users\Test User\x"), None);
        assert_eq!(s.text(r"D:\Backup\C:\Users\Test"), None);
        assert_eq!(s.text(r"C:\Users\Test.old"), None);
    }

    #[test]
    fn a_target_that_extends_the_source_is_stable() {
        let s = Substitution {
            source_path: r"C:\Users\enrico".into(),
            target_path: r"C:\Users\enrico.zorra".into(),
            ..subst()
        };
        let once = s.text(r"C:\Users\enrico\Desktop").unwrap();
        assert_eq!(once, r"C:\Users\enrico.zorra\Desktop");
        assert_eq!(s.text(&once), None);
    }

    #[test]
    fn text_gets_both_substitutions() {
        let s = subst();
        let text = format!(r"C:\Users\Test\x;{SRC}");
        assert_eq!(
            s.text(&text).unwrap(),
            format!(r"C:\Users\enrico.zorra\x;{TGT}")
        );
    }

    #[test]
    fn multi_text_keeps_unchanged_items() {
        let s = subst();
        let data = RegData::MultiText(vec!["a".into(), r"C:\Users\Test\b".into()]);
        assert_eq!(
            s.value(&data).unwrap(),
            RegData::MultiText(vec!["a".into(), r"C:\Users\enrico.zorra\b".into()])
        );
        assert_eq!(s.value(&RegData::MultiText(vec!["a".into()])), None);
    }

    #[test]
    fn binary_is_never_rewritten_but_reported() {
        let s = subst();
        let mut bytes = Vec::new();
        for unit in r"C:\Users\Test\x".encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        let data = RegData::Binary(bytes);
        assert_eq!(s.value(&data), None);
        assert!(s.residue(&data).is_some());
    }

    #[test]
    fn loose_mentions_are_reported_as_residue() {
        let s = subst();
        let data = RegData::Text(r"C:\Users\Test -flag".into());
        assert_eq!(s.value(&data), None);
        assert!(s.residue(&data).is_some());
        assert_eq!(s.residue(&RegData::Text("nothing".into())), None);
    }

    #[test]
    fn non_ascii_text_around_a_match_survives() {
        let s = subst();
        assert_eq!(
            s.text(r"città;C:\Users\Test\é").unwrap(),
            r"città;C:\Users\enrico.zorra\é"
        );
    }

    #[test]
    fn hive_report_counts_what_changed_and_what_did_not() {
        let s = subst();
        let mut report = HiveReport::default();
        // Owner-only descriptors: the header, then the SID.
        let owned_by = |sid: &str| {
            let mut sd = vec![1, 0, 0x00, 0x80, 20, 0, 0, 0];
            sd.extend_from_slice(&[0; 12]);
            sd.extend(sid_to_bytes(sid).unwrap());
            sd
        };
        let translated = s.rewrite_key(&mut report, r"Software\x", &owned_by(SRC));
        assert_eq!(translated.unwrap().unwrap(), owned_by(TGT));
        assert_eq!(
            s.rewrite_key(&mut report, "", &owned_by("S-1-5-18")),
            Ok(None)
        );
        let path = RegData::Text(r"C:\Users\Test\Desktop".into());
        assert!(s
            .rewrite_value(&mut report, "Shell", "Desktop", &path)
            .is_some());
        let loose = RegData::Text(r"C:\Users\Test -x".into());
        assert!(s.rewrite_value(&mut report, "", "", &loose).is_none());
        let named = RegData::Other;
        s.rewrite_value(&mut report, "MuiCache", r"C:\Users\Test\a.exe", &named);
        assert_eq!(report.keys_translated, 1);
        assert_eq!(report.values_rewritten, vec![r"Shell\Desktop".to_string()]);
        assert_eq!(report.residues.len(), 1);
        assert!(report.residues[0].starts_with(r"(root)\(default)"));
        assert_eq!(
            report.names,
            vec![r"value MuiCache\C:\Users\Test\a.exe".to_string()]
        );
    }

    #[test]
    fn names_mentioning_the_source_are_detected() {
        let s = subst();
        assert!(s.name_mentions_source(r"C:\Users\Test\app.exe.FriendlyAppName"));
        assert!(s.name_mentions_source(&format!("{SRC}_Classes")));
        assert!(!s.name_mentions_source("Software"));
    }
}
