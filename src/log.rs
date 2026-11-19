//! Structured JSONL run log: one self-contained JSON object per line, so a
//! log survives a crash mid-run and can be grepped or ingested as-is.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::json::Json;
use crate::timefmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Info,
    Warn,
    Error,
}

impl Level {
    fn as_str(self) -> &'static str {
        match self {
            Level::Info => "info",
            Level::Warn => "warn",
            Level::Error => "error",
        }
    }
}

pub struct Logger {
    file: File,
    path: PathBuf,
    run_id: String,
}

impl Logger {
    /// Creates `<dir>/profmig-<UTC timestamp>-<command>.jsonl`. Refuses to
    /// append to an existing file so each run has its own log.
    pub fn create(dir: &Path, command: &str) -> io::Result<Logger> {
        fs::create_dir_all(dir)?;
        let run_id = format!("{}-{}", timefmt::now().compact(), std::process::id());
        let path = dir.join(format!("profmig-{run_id}-{command}.jsonl"));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        Ok(Logger { file, path, run_id })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    /// Writes one record and flushes it to the OS immediately; a log that
    /// lags behind the actions it describes is useless after a crash.
    pub fn event(
        &mut self,
        level: Level,
        phase: &str,
        event: &str,
        message: &str,
        fields: Vec<(&str, Json)>,
    ) -> io::Result<()> {
        let mut record = vec![
            ("ts", Json::from(timefmt::now().rfc3339())),
            ("run", Json::from(self.run_id.as_str())),
            ("level", Json::from(level.as_str())),
            ("phase", Json::from(phase)),
            ("event", Json::from(event)),
            ("message", Json::from(message)),
        ];
        record.extend(fields);
        let mut line = Json::obj(record).render();
        line.push('\n');
        self.file.write_all(line.as_bytes())?;
        self.file.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_one_json_object_per_line() {
        let dir = std::env::temp_dir().join(format!("profmig-log-test-{}", std::process::id()));
        let mut log = Logger::create(&dir, "test").unwrap();
        log.event(Level::Info, "preflight", "a", "first", vec![])
            .unwrap();
        log.event(
            Level::Warn,
            "preflight",
            "b",
            "second",
            vec![("path", Json::from(r"C:\Users\x"))],
        )
        .unwrap();
        let text = fs::read_to_string(log.path()).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("{\"ts\":"));
        assert!(lines[1].contains(r#""level":"warn""#));
        assert!(lines[1].contains(r#""path":"C:\\Users\\x""#));
        fs::remove_dir_all(&dir).unwrap();
    }
}
