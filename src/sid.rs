//! Platform-neutral helpers for SID strings (`S-1-5-21-a-b-c-rid`).
//!
//! Binary SIDs are converted to strings in `win::` and every decision in the
//! tool is made on the canonical string form, so it can be unit-tested
//! without Windows.

/// Well-known SIDs the tool must never treat as a migratable user.
const LOCAL_SYSTEM: &str = "S-1-5-18";
const LOCAL_SERVICE: &str = "S-1-5-19";
const NETWORK_SERVICE: &str = "S-1-5-20";

/// RIDs of the built-in Administrator and Guest accounts. SDDL renders the
/// local Administrator as the `LA` alias instead of its SID string, which
/// would hide it from SID-based ACL analysis, so these are rejected outright.
const RID_BUILTIN_ADMINISTRATOR: u32 = 500;
const RID_BUILTIN_GUEST: u32 = 501;

/// A syntactically valid SID string, normalized to an upper-case `S` prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SidString {
    text: String,
    sub_authorities: Vec<u32>,
}

impl SidString {
    /// Parses `S-1-<authority>-<sub>...`. Returns `None` for anything that is
    /// not a revision-1 SID with at least one sub-authority.
    pub fn parse(input: &str) -> Option<SidString> {
        let trimmed = input.trim();
        let mut parts = trimmed.split('-');
        let prefix = parts.next()?;
        if !prefix.eq_ignore_ascii_case("S") {
            return None;
        }
        if parts.next()? != "1" {
            return None;
        }
        let authority = parts.next()?;
        if authority.is_empty() || !authority.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        // Windows SIDs carry at most 15 sub-authorities.
        let sub_authorities: Vec<u32> = parts
            .map(|p| {
                if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
                    None
                } else {
                    p.parse::<u32>().ok()
                }
            })
            .collect::<Option<Vec<u32>>>()?;
        if sub_authorities.is_empty() || sub_authorities.len() > 15 {
            return None;
        }
        let mut text = String::from("S");
        text.push_str(&trimmed[1..]);
        Some(SidString {
            text,
            sub_authorities,
        })
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The last sub-authority (the relative identifier).
    pub fn rid(&self) -> u32 {
        // parse() guarantees at least one sub-authority.
        self.sub_authorities[self.sub_authorities.len() - 1]
    }

    /// The account-domain SID: everything except the RID.
    pub fn domain_part(&self) -> &str {
        match self.text.rfind('-') {
            Some(idx) => &self.text[..idx],
            None => &self.text,
        }
    }

    /// True for `S-1-5-21-...` account SIDs (local SAM or AD domain users).
    pub fn is_account_domain_sid(&self) -> bool {
        self.text.starts_with("S-1-5-21-") && self.sub_authorities.len() == 5
    }

    pub fn is_service_account(&self) -> bool {
        matches!(
            self.text.as_str(),
            LOCAL_SYSTEM | LOCAL_SERVICE | NETWORK_SERVICE
        )
    }

    pub fn is_builtin_admin_or_guest(&self) -> bool {
        self.is_account_domain_sid()
            && matches!(self.rid(), RID_BUILTIN_ADMINISTRATOR | RID_BUILTIN_GUEST)
    }
}

impl std::fmt::Display for SidString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text)
    }
}

/// Case-insensitive SID comparison on string forms.
pub fn sid_eq(a: &str, b: &str) -> bool {
    a.trim().eq_ignore_ascii_case(b.trim())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_accepts_domain_user_sid() {
        let sid = SidString::parse("S-1-5-21-1004336348-1177238915-682003330-1105").unwrap();
        assert_eq!(sid.rid(), 1105);
        assert_eq!(
            sid.domain_part(),
            "S-1-5-21-1004336348-1177238915-682003330"
        );
        assert!(sid.is_account_domain_sid());
    }

    #[test]
    fn parse_normalizes_lowercase_prefix() {
        let sid = SidString::parse(" s-1-5-18 ").unwrap();
        assert_eq!(sid.as_str(), "S-1-5-18");
        assert!(sid.is_service_account());
    }

    #[test]
    fn parse_rejects_malformed_input() {
        for bad in [
            "",
            "S",
            "S-1",
            "S-1-5",
            "S-2-5-21",
            "X-1-5-21",
            "S-1-5--21",
            "S-1-5-21-abc",
            "S-1-5-21-99999999999",
            "S-1-5-21-1-2-3-1001.bak",
            "jdoe",
        ] {
            assert!(SidString::parse(bad).is_none(), "accepted {bad:?}");
        }
    }

    #[test]
    fn parse_rejects_more_than_fifteen_sub_authorities() {
        let too_long = format!("S-1-5{}", "-1".repeat(16));
        assert!(SidString::parse(&too_long).is_none());
        let max = format!("S-1-5{}", "-1".repeat(15));
        assert!(SidString::parse(&max).is_some());
    }

    #[test]
    fn builtin_admin_and_guest_are_detected() {
        let admin = SidString::parse("S-1-5-21-1-2-3-500").unwrap();
        let guest = SidString::parse("S-1-5-21-1-2-3-501").unwrap();
        let user = SidString::parse("S-1-5-21-1-2-3-1001").unwrap();
        assert!(admin.is_builtin_admin_or_guest());
        assert!(guest.is_builtin_admin_or_guest());
        assert!(!user.is_builtin_admin_or_guest());
    }

    #[test]
    fn well_known_group_is_not_account_domain_sid() {
        let admins = SidString::parse("S-1-5-32-544").unwrap();
        assert!(!admins.is_account_domain_sid());
    }

    #[test]
    fn sid_eq_ignores_case_and_whitespace() {
        assert!(sid_eq("s-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1001 "));
        assert!(!sid_eq("S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1002"));
    }
}
