//! UTC timestamps for log records and backup folder names.

use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UtcTime {
    pub year: i64,
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub minute: u32,
    pub second: u32,
    pub millis: u32,
}

pub fn now() -> UtcTime {
    // A clock before 1970 is a broken machine; clamping to the epoch keeps
    // logging alive and the odd timestamp makes the problem visible.
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    from_unix_millis(millis)
}

pub fn from_unix_millis(total_millis: u64) -> UtcTime {
    let secs = total_millis / 1000;
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    UtcTime {
        year,
        month,
        day,
        hour: (rem / 3600) as u32,
        minute: ((rem % 3600) / 60) as u32,
        second: (rem % 60) as u32,
        millis: (total_millis % 1000) as u32,
    }
}

impl UtcTime {
    /// `2026-11-19T14:30:05.123Z`
    pub fn rfc3339(&self) -> String {
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
            self.year, self.month, self.day, self.hour, self.minute, self.second, self.millis
        )
    }

    /// `20261119T143005Z`: sortable and safe in file names.
    pub fn compact(&self) -> String {
        format!(
            "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        )
    }
}

/// Days since 1970-01-01 to (year, month, day) in the proleptic Gregorian
/// calendar (Howard Hinnant's `civil_from_days`).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_is_1970_01_01() {
        assert_eq!(from_unix_millis(0).rfc3339(), "1970-01-01T00:00:00.000Z");
    }

    #[test]
    fn known_timestamp_formats_correctly() {
        // 2026-11-19T14:30:05.123Z
        let t = from_unix_millis(1_795_098_605_123);
        assert_eq!(t.rfc3339(), "2026-11-19T14:30:05.123Z");
        assert_eq!(t.compact(), "20261119T143005Z");
    }

    #[test]
    fn leap_day_is_handled() {
        // 2024-02-29T00:00:00Z
        let t = from_unix_millis(1_709_164_800_000);
        assert_eq!((t.year, t.month, t.day), (2024, 2, 29));
    }
}
