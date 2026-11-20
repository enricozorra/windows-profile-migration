//! Per-migration journal: an append-only file of flat JSON records, one per
//! line, stored in the migration's private folder.
//!
//! The execution phase writes an `intent` record and syncs it to disk
//! before it creates anything, and a `created` record afterwards. After a
//! crash or reboot the journal therefore lists everything that may exist,
//! which is what `status` reports and `rollback` undoes. Records hold only
//! string fields, so a small parser is enough to read them back.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

use crate::json::Json;
use crate::timefmt;

pub const JOURNAL_FILE: &str = "journal.log";
pub const LOCK_FILE: &str = "lock";
/// File placed at the root of every folder a migration creates, holding the
/// migration id. A folder without it is never deleted.
pub const FOLDER_MARKER_FILE: &str = ".windows-profile-migration";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactKind {
    StagingDir,
    TargetDir,
    ProfileListEntry,
    HiveMount,
}

impl ArtifactKind {
    pub fn name(self) -> &'static str {
        match self {
            ArtifactKind::StagingDir => "staging_dir",
            ArtifactKind::TargetDir => "target_dir",
            ArtifactKind::ProfileListEntry => "profile_list_entry",
            ArtifactKind::HiveMount => "hive_mount",
        }
    }

    fn parse(name: &str) -> Option<ArtifactKind> {
        [
            ArtifactKind::StagingDir,
            ArtifactKind::TargetDir,
            ArtifactKind::ProfileListEntry,
            ArtifactKind::HiveMount,
        ]
        .into_iter()
        .find(|kind| kind.name() == name)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactState {
    /// Announced but not confirmed: it may or may not exist.
    Intended,
    Created,
    Removed,
}

/// Something a migration creates outside its own folder. `value` is a path,
/// a SID (ProfileList entry) or an HKU mount name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Artifact {
    pub kind: ArtifactKind,
    pub value: String,
    pub state: ArtifactState,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Header {
    pub id: String,
    pub version: String,
    pub started: String,
    pub source_sid: String,
    pub source_name: String,
    pub source_path: String,
    pub target_sid: String,
    pub target_name: String,
    pub target_path: String,
    pub staging_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct JournalState {
    pub header: Header,
    /// In order of first appearance.
    pub artifacts: Vec<Artifact>,
    pub committed_at: Option<String>,
    pub finalized_at: Option<String>,
    pub rolled_back_at: Option<String>,
    /// Lines that could not be read or understood. They are reported, never
    /// skipped silently.
    pub problems: Vec<String>,
}

/// Appends records to an existing journal. Each record is synced to disk
/// before `append` returns, so it is durable before the action it announces.
pub struct JournalWriter {
    file: File,
}

impl JournalWriter {
    pub fn open(path: &Path) -> io::Result<JournalWriter> {
        let file = OpenOptions::new().append(true).open(path)?;
        Ok(JournalWriter { file })
    }

    pub fn append(&mut self, event: &str, fields: &[(&str, &str)]) -> io::Result<()> {
        let now = timefmt::now().rfc3339();
        let mut line = render(event, &now, fields);
        line.push('\n');
        self.file.write_all(line.as_bytes())?;
        self.file.sync_data()
    }
}

pub fn render(event: &str, ts: &str, fields: &[(&str, &str)]) -> String {
    let mut pairs = vec![("ts", Json::from(ts)), ("event", Json::from(event))];
    pairs.extend(fields.iter().map(|(k, v)| (*k, Json::from(*v))));
    Json::obj(pairs).render()
}

/// Rebuilds the migration's state from the journal text.
pub fn replay(text: &str) -> Result<JournalState, String> {
    // Editors such as Notepad add a UTF-8 BOM when a journal is saved.
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut state = JournalState::default();
    let mut has_header = false;
    let lines: Vec<&str> = text.lines().collect();
    for (index, line) in lines.iter().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let number = index + 1;
        let record = match parse_line(line) {
            Ok(record) => record,
            // A crash while writing can only tear the last line. Its action
            // never started, because records are synced before acting.
            Err(err) if number == lines.len() => {
                state.problems.push(format!(
                    "line {number}: incomplete last record (interrupted write), ignored: {err}"
                ));
                continue;
            }
            Err(err) => {
                state.problems.push(format!("line {number}: {err}"));
                continue;
            }
        };
        let field = |name: &str| -> String {
            record
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };
        let ts = field("ts");
        match field("event").as_str() {
            "started" => {
                if has_header {
                    state
                        .problems
                        .push(format!("line {number}: second 'started' record ignored"));
                    continue;
                }
                has_header = true;
                state.header = Header {
                    id: field("id"),
                    version: field("version"),
                    started: ts,
                    source_sid: field("source_sid"),
                    source_name: field("source_name"),
                    source_path: field("source_path"),
                    target_sid: field("target_sid"),
                    target_name: field("target_name"),
                    target_path: field("target_path"),
                    staging_path: field("staging_path"),
                };
            }
            event @ ("intent" | "created" | "removed") => {
                let Some(kind) = ArtifactKind::parse(&field("kind")) else {
                    state.problems.push(format!(
                        "line {number}: unknown artifact kind '{}'",
                        field("kind")
                    ));
                    continue;
                };
                let value = field("value");
                let new_state = match event {
                    "intent" => ArtifactState::Intended,
                    "created" => ArtifactState::Created,
                    _ => ArtifactState::Removed,
                };
                match state
                    .artifacts
                    .iter_mut()
                    .find(|a| a.kind == kind && a.value.eq_ignore_ascii_case(&value))
                {
                    // A later `intent` for an existing artifact (e.g. a retry)
                    // must not downgrade what is already known to exist.
                    Some(existing)
                        if new_state == ArtifactState::Intended
                            && existing.state == ArtifactState::Created => {}
                    Some(existing) => existing.state = new_state,
                    None => state.artifacts.push(Artifact {
                        kind,
                        value,
                        state: new_state,
                    }),
                }
            }
            "committed" => state.committed_at = Some(ts),
            "finalized" => state.finalized_at = Some(ts),
            "rollback_done" => state.rolled_back_at = Some(ts),
            "rollback_started" | "step" => {}
            other => state
                .problems
                .push(format!("line {number}: unknown event '{other}'")),
        }
    }
    if !has_header {
        return Err("the journal has no 'started' record".into());
    }
    if state.header.id.is_empty() || state.header.source_sid.is_empty() {
        return Err("the 'started' record is missing the id or the source SID".into());
    }
    Ok(state)
}

/// Parses one flat JSON object whose values are all strings.
pub fn parse_line(line: &str) -> Result<Vec<(String, String)>, String> {
    let mut chars = line.trim().chars().peekable();
    if chars.next() != Some('{') {
        return Err("record does not start with '{'".into());
    }
    let mut fields = Vec::new();
    skip_whitespace(&mut chars);
    if chars.peek() == Some(&'}') {
        chars.next();
    } else {
        loop {
            skip_whitespace(&mut chars);
            let key = parse_string(&mut chars)?;
            skip_whitespace(&mut chars);
            if chars.next() != Some(':') {
                return Err(format!("expected ':' after \"{key}\""));
            }
            skip_whitespace(&mut chars);
            let value = parse_string(&mut chars)?;
            fields.push((key, value));
            skip_whitespace(&mut chars);
            match chars.next() {
                Some(',') => continue,
                Some('}') => break,
                Some(c) => return Err(format!("unexpected '{c}' between fields")),
                None => return Err("record ends before '}'".into()),
            }
        }
    }
    skip_whitespace(&mut chars);
    if let Some(c) = chars.next() {
        return Err(format!("unexpected '{c}' after the record"));
    }
    Ok(fields)
}

type Chars<'a> = std::iter::Peekable<std::str::Chars<'a>>;

fn skip_whitespace(chars: &mut Chars) {
    while chars.peek().is_some_and(|c| c.is_whitespace()) {
        chars.next();
    }
}

fn parse_string(chars: &mut Chars) -> Result<String, String> {
    if chars.next() != Some('"') {
        return Err("expected a string (only string values are allowed)".into());
    }
    let mut out = String::new();
    loop {
        match chars.next() {
            None => return Err("unterminated string".into()),
            Some('"') => return Ok(out),
            Some('\\') => match chars.next() {
                Some('"') => out.push('"'),
                Some('\\') => out.push('\\'),
                Some('/') => out.push('/'),
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some('b') => out.push('\u{8}'),
                Some('f') => out.push('\u{c}'),
                Some('u') => out.push(parse_unicode_escape(chars)?),
                other => return Err(format!("invalid escape \\{other:?}")),
            },
            Some(c) if (c as u32) < 0x20 => {
                return Err("raw control character inside a string".into())
            }
            Some(c) => out.push(c),
        }
    }
}

fn parse_unicode_escape(chars: &mut Chars) -> Result<char, String> {
    let first = hex4(chars)?;
    if !(0xD800..0xDC00).contains(&first) {
        return char::from_u32(first).ok_or_else(|| format!("invalid \\u{first:04x}"));
    }
    // A high surrogate must be followed by an escaped low surrogate.
    if chars.next() != Some('\\') || chars.next() != Some('u') {
        return Err("unpaired surrogate in \\u escape".into());
    }
    let second = hex4(chars)?;
    if !(0xDC00..0xE000).contains(&second) {
        return Err("unpaired surrogate in \\u escape".into());
    }
    let code = 0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00);
    char::from_u32(code).ok_or_else(|| format!("invalid code point {code:x}"))
}

fn hex4(chars: &mut Chars) -> Result<u32, String> {
    let digits: String = chars.take(4).collect();
    if digits.len() != 4 {
        return Err("truncated \\u escape".into());
    }
    u32::from_str_radix(&digits, 16).map_err(|_| format!("invalid \\u escape '{digits}'"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn started() -> String {
        render(
            "started",
            "2026-11-20T10:00:00.000Z",
            &[
                ("id", "m1"),
                ("version", "0.1.0"),
                ("source_sid", "S-1-5-21-1-2-3-1001"),
                ("source_name", r"PC01\Test"),
                ("source_path", r"C:\Users\Test"),
                ("target_sid", "S-1-5-21-9-8-7-2601"),
                ("target_name", r"CORP\new"),
                ("target_path", r"C:\Users\new"),
                ("staging_path", r"C:\Users\new.staging"),
            ],
        )
    }

    fn line(event: &str, ts: &str, fields: &[(&str, &str)]) -> String {
        render(event, ts, fields)
    }

    #[test]
    fn rendered_records_parse_back_including_escapes() {
        let text = render("note", "t", &[("path", "C:\\Users\\\"x\"\n\u{1}é😀")]);
        let fields = parse_line(&text).unwrap();
        assert_eq!(
            fields[2],
            ("path".to_string(), "C:\\Users\\\"x\"\n\u{1}é😀".to_string())
        );
    }

    #[test]
    fn parser_accepts_surrogate_pairs_and_rejects_bad_input() {
        let fields = parse_line(r#"{"a":"\ud83d\ude00"}"#).unwrap();
        assert_eq!(fields[0].1, "😀");
        for bad in [
            r#"{"a":1}"#,
            r#"{"a":"x""#,
            r#"{"a":"\q"}"#,
            r#"{"a":"\ud83d"}"#,
            r#"{"a":"x"} trailing"#,
            r#"["a"]"#,
        ] {
            assert!(parse_line(bad).is_err(), "{bad}");
        }
        assert!(parse_line("{}").unwrap().is_empty());
    }

    #[test]
    fn replay_tracks_artifacts_and_phases() {
        let text = [
            started(),
            line(
                "intent",
                "t1",
                &[("kind", "staging_dir"), ("value", r"C:\Users\new.staging")],
            ),
            line(
                "created",
                "t2",
                &[("kind", "staging_dir"), ("value", r"C:\Users\new.staging")],
            ),
            line(
                "intent",
                "t3",
                &[("kind", "hive_mount"), ("value", "m_ntuser")],
            ),
            line("committed", "t4", &[]),
        ]
        .join("\n");
        let state = replay(&text).unwrap();
        assert_eq!(state.header.id, "m1");
        assert_eq!(state.header.started, "2026-11-20T10:00:00.000Z");
        assert_eq!(state.artifacts.len(), 2);
        assert_eq!(state.artifacts[0].state, ArtifactState::Created);
        assert_eq!(state.artifacts[1].state, ArtifactState::Intended);
        assert_eq!(state.committed_at.as_deref(), Some("t4"));
        assert!(state.problems.is_empty());
    }

    #[test]
    fn a_retried_intent_does_not_hide_a_created_artifact() {
        let created = line(
            "created",
            "t1",
            &[("kind", "target_dir"), ("value", r"C:\Users\new")],
        );
        let retry = line(
            "intent",
            "t2",
            &[("kind", "target_dir"), ("value", r"c:\users\NEW")],
        );
        let state = replay(&[started(), created, retry].join("\n")).unwrap();
        assert_eq!(state.artifacts.len(), 1);
        assert_eq!(state.artifacts[0].state, ArtifactState::Created);
    }

    #[test]
    fn torn_last_line_is_reported_not_fatal() {
        let text = format!("{}\n{{\"ts\":\"t\",\"event\":\"inte", started());
        let state = replay(&text).unwrap();
        assert_eq!(state.problems.len(), 1);
        assert!(state.problems[0].contains("incomplete last record"));
    }

    #[test]
    fn damaged_middle_lines_and_unknown_events_are_reported() {
        let text = [
            started(),
            "garbage".to_string(),
            line("teleported", "t", &[]),
            line("intent", "t", &[("kind", "spaceship"), ("value", "x")]),
            line("committed", "t", &[]),
        ]
        .join("\n");
        let state = replay(&text).unwrap();
        assert_eq!(state.problems.len(), 3, "{:?}", state.problems);
        assert!(state.committed_at.is_some());
    }

    #[test]
    fn a_leading_byte_order_mark_is_tolerated() {
        let text = format!("\u{feff}{}", started());
        assert_eq!(replay(&text).unwrap().header.id, "m1");
    }

    #[test]
    fn journal_without_header_is_rejected() {
        assert!(replay(&line("committed", "t", &[])).is_err());
        assert!(replay("").is_err());
    }

    #[test]
    fn writer_appends_synced_records() {
        let dir = std::env::temp_dir().join(format!(
            "windows-profile-migration-journal-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(JOURNAL_FILE);
        std::fs::write(&path, format!("{}\n", started())).unwrap();
        let mut writer = JournalWriter::open(&path).unwrap();
        writer.append("rollback_started", &[]).unwrap();
        writer
            .append("removed", &[("kind", "staging_dir"), ("value", "x")])
            .unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        let state = replay(&text).unwrap();
        assert_eq!(state.artifacts[0].state, ArtifactState::Removed);
        assert!(state.problems.is_empty());
    }
}
