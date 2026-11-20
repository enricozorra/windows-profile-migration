//! Pure matching of the source account in service and scheduled-task
//! configuration. Those run as the account, outside the profile, and stop
//! working once the account is retired, so preflight lists them.

use crate::sid::sid_eq;

/// The spellings under which an account appears in Windows configuration.
pub struct AccountNames<'a> {
    pub sid: &'a str,
    pub domain: &'a str,
    pub name: &'a str,
}

/// Whether a configured account (`.\user`, `DOMAIN\user`, `user@domain`, a
/// SID or a bare name) is this account. A bare name is accepted on purpose:
/// over-reporting a same-named account is harmless, missing one is not.
pub fn names_account(configured: &str, account: &AccountNames) -> bool {
    let configured = configured.trim();
    if configured.is_empty() {
        return false;
    }
    if sid_eq(configured, account.sid) {
        return true;
    }
    let (domain, user) = match configured.split_once('\\') {
        Some((domain, user)) => (Some(domain), user),
        None => match configured.split_once('@') {
            Some((user, _)) => (None, user),
            None => (None, configured),
        },
    };
    if !user.eq_ignore_ascii_case(account.name) {
        return false;
    }
    match domain {
        None => true,
        Some(d) => d == "." || d.eq_ignore_ascii_case(account.domain),
    }
}

/// Contents of every `<UserId>` element in a task definition.
pub fn task_user_ids(xml: &str) -> Vec<String> {
    const OPEN: &str = "<UserId>";
    const CLOSE: &str = "</UserId>";
    let mut ids = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find(OPEN) {
        let after = &rest[start + OPEN.len()..];
        let Some(end) = after.find(CLOSE) else { break };
        ids.push(after[..end].trim().to_string());
        rest = &after[end + CLOSE.len()..];
    }
    ids
}

/// Task files are UTF-16LE with a BOM; tolerate UTF-8 as well.
pub fn decode_text_file(bytes: &[u8]) -> String {
    if let Some(body) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        let units: Vec<u16> = body
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        return String::from_utf16_lossy(&units);
    }
    let body = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    String::from_utf8_lossy(body).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCOUNT: AccountNames = AccountNames {
        sid: "S-1-5-21-1-2-3-1001",
        domain: "PC01",
        name: "Test",
    };

    #[test]
    fn every_spelling_of_the_account_matches() {
        for configured in [
            r".\Test",
            r"PC01\test",
            "test@pc01",
            "Test",
            "S-1-5-21-1-2-3-1001",
        ] {
            assert!(names_account(configured, &ACCOUNT), "{configured}");
        }
    }

    #[test]
    fn other_accounts_do_not_match() {
        for configured in [
            r"NT AUTHORITY\LocalService",
            "LocalSystem",
            r"OTHERPC\Test",
            r"PC01\Tester",
            "S-1-5-21-1-2-3-1002",
            "",
        ] {
            assert!(!names_account(configured, &ACCOUNT), "{configured}");
        }
    }

    #[test]
    fn task_user_ids_are_extracted() {
        let xml = "<Principals><Principal id=\"Author\"><UserId>S-1-5-21-1-2-3-1001</UserId>\
                   </Principal></Principals><Triggers><LogonTrigger><UserId>PC01\\Test</UserId>";
        assert_eq!(
            task_user_ids(xml),
            vec!["S-1-5-21-1-2-3-1001".to_string(), r"PC01\Test".to_string()]
        );
        assert!(task_user_ids("<UserId>unterminated").is_empty());
    }

    #[test]
    fn task_files_decode_from_utf16_and_utf8() {
        let mut utf16 = vec![0xFF, 0xFE];
        utf16.extend("<Task/>".encode_utf16().flat_map(u16::to_le_bytes));
        assert_eq!(decode_text_file(&utf16), "<Task/>");
        assert_eq!(decode_text_file(b"\xEF\xBB\xBF<Task/>"), "<Task/>");
        assert_eq!(decode_text_file(b"<Task/>"), "<Task/>");
    }
}
