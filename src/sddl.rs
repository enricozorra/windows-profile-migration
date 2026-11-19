//! Minimal SDDL parser for owner and DACL analysis.
//!
//! Security descriptors are read on Windows and converted to SDDL text
//! (`O:..G:..D:PAI(A;OICI;FA;;;S-1-5-...)`). Parsing that text instead of
//! walking binary ACLs keeps the analysis pure and testable, and SDDL is the
//! format the rollback manifest stores anyway.

use crate::sid::sid_eq;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ace {
    pub ace_type: String,
    pub flags: String,
    pub rights: String,
    pub trustee: String,
}

impl Ace {
    /// True when the ACE was propagated from a parent (`ID` flag). Inherited
    /// ACEs are fixed by re-ACLing the parent, not the child.
    pub fn is_inherited(&self) -> bool {
        two_letter_tokens(&self.flags).any(|t| t == "ID")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SecurityDescriptor {
    pub owner: Option<String>,
    pub group: Option<String>,
    pub dacl_flags: Vec<String>,
    pub dacl: Vec<Ace>,
}

impl SecurityDescriptor {
    /// A protected DACL (`P`) blocks inheritance, so it needs explicit
    /// handling during re-ACL instead of relying on parent propagation.
    pub fn dacl_is_protected(&self) -> bool {
        self.dacl_flags.iter().any(|f| f == "P")
    }
}

/// How a security descriptor refers to one SID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SidReferences {
    pub is_owner: bool,
    pub explicit_aces: usize,
    pub inherited_aces: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SddlError(pub String);

impl std::fmt::Display for SddlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid SDDL: {}", self.0)
    }
}

impl std::error::Error for SddlError {}

/// Parses the O:, G: and D: sections. A SACL (S:) is tolerated and ignored
/// because the tool does not read SACLs (that needs SeSecurityPrivilege).
pub fn parse(sddl: &str) -> Result<SecurityDescriptor, SddlError> {
    let mut sd = SecurityDescriptor::default();
    for (tag, body) in split_sections(sddl)? {
        match tag {
            'O' => sd.owner = Some(body.to_string()),
            'G' => sd.group = Some(body.to_string()),
            'D' => {
                let (flags, aces) = parse_acl(body)?;
                sd.dacl_flags = flags;
                sd.dacl = aces;
            }
            'S' => {}
            other => return Err(SddlError(format!("unknown section '{other}:'"))),
        }
    }
    Ok(sd)
}

/// Counts how `sid` appears in the owner and DACL.
pub fn references(sd: &SecurityDescriptor, sid: &str) -> SidReferences {
    let mut refs = SidReferences {
        is_owner: sd.owner.as_deref().is_some_and(|o| sid_eq(o, sid)),
        ..SidReferences::default()
    };
    for ace in sd.dacl.iter().filter(|a| sid_eq(&a.trustee, sid)) {
        if ace.is_inherited() {
            refs.inherited_aces += 1;
        } else {
            refs.explicit_aces += 1;
        }
    }
    refs
}

/// Splits SDDL into `(tag, body)` sections. A tag is one of O/G/D/S followed
/// by ':' at parenthesis depth 0; conditional ACEs may nest parentheses, and
/// neither SID strings nor SDDL aliases contain ':'.
fn split_sections(sddl: &str) -> Result<Vec<(char, &str)>, SddlError> {
    let bytes = sddl.as_bytes();
    let mut starts: Vec<(char, usize)> = Vec::new();
    let mut depth: i32 = 0;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth < 0 {
                    return Err(SddlError("unbalanced ')'".into()));
                }
            }
            b @ (b'O' | b'G' | b'D' | b'S') if depth == 0 && bytes.get(i + 1) == Some(&b':') => {
                starts.push((b as char, i + 2));
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }
    if depth != 0 {
        return Err(SddlError("unbalanced '('".into()));
    }
    if starts.is_empty() && !sddl.trim().is_empty() {
        return Err(SddlError("no O:/G:/D:/S: section found".into()));
    }
    let mut sections = Vec::with_capacity(starts.len());
    for (idx, &(tag, body_start)) in starts.iter().enumerate() {
        let body_end = starts
            .get(idx + 1)
            .map(|&(_, next_body)| next_body - 2)
            .unwrap_or(sddl.len());
        sections.push((tag, &sddl[body_start..body_end]));
    }
    Ok(sections)
}

fn parse_acl(body: &str) -> Result<(Vec<String>, Vec<Ace>), SddlError> {
    let first_paren = body.find('(').unwrap_or(body.len());
    let flags = parse_acl_flags(&body[..first_paren])?;
    let mut aces = Vec::new();
    let rest = &body[first_paren..];
    let bytes = rest.as_bytes();
    let mut depth = 0;
    let mut ace_start = 0;
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'(' => {
                if depth == 0 {
                    ace_start = i + 1;
                }
                depth += 1;
            }
            b')' => {
                depth -= 1;
                if depth == 0 {
                    aces.push(parse_ace(&rest[ace_start..i])?);
                }
            }
            _ if depth == 0 => {
                return Err(SddlError(format!("unexpected text between ACEs: {rest}")));
            }
            _ => {}
        }
    }
    Ok((flags, aces))
}

fn parse_acl_flags(text: &str) -> Result<Vec<String>, SddlError> {
    let mut flags = Vec::new();
    let mut rest = text;
    while !rest.is_empty() {
        let token = if rest.starts_with("NO_ACCESS_CONTROL") {
            "NO_ACCESS_CONTROL"
        } else if rest.starts_with("AI") || rest.starts_with("AR") {
            &rest[..2]
        } else if rest.starts_with('P') {
            "P"
        } else {
            return Err(SddlError(format!("unknown ACL flags '{text}'")));
        };
        flags.push(token.to_string());
        rest = &rest[token.len()..];
    }
    Ok(flags)
}

fn parse_ace(text: &str) -> Result<Ace, SddlError> {
    // ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid[;(resource)]
    let fields: Vec<&str> = text.splitn(7, ';').collect();
    if fields.len() < 6 {
        return Err(SddlError(format!("ACE has fewer than 6 fields: ({text})")));
    }
    Ok(Ace {
        ace_type: fields[0].to_string(),
        flags: fields[1].to_string(),
        rights: fields[2].to_string(),
        trustee: fields[5].to_string(),
    })
}

fn two_letter_tokens(flags: &str) -> impl Iterator<Item = &str> {
    (0..flags.len() / 2).map(move |i| &flags[i * 2..i * 2 + 2])
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER: &str = "S-1-5-21-111-222-333-1001";

    #[test]
    fn parses_typical_profile_root_descriptor() {
        let text =
            format!("O:{USER}G:{USER}D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{USER})");
        let sd = parse(&text).unwrap();
        assert_eq!(sd.owner.as_deref(), Some(USER));
        assert!(sd.dacl_is_protected());
        assert_eq!(sd.dacl.len(), 3);
        let refs = references(&sd, USER);
        assert!(refs.is_owner);
        assert_eq!(refs.explicit_aces, 1);
        assert_eq!(refs.inherited_aces, 0);
    }

    #[test]
    fn inherited_aces_are_counted_separately() {
        let text = format!("O:BAD:AI(A;OICIID;FA;;;{USER})(A;ID;0x1200a9;;;BU)");
        let sd = parse(&text).unwrap();
        let refs = references(&sd, USER);
        assert!(!refs.is_owner);
        assert_eq!(refs.explicit_aces, 0);
        assert_eq!(refs.inherited_aces, 1);
        assert!(!sd.dacl_is_protected());
    }

    #[test]
    fn id_flag_must_be_a_whole_token() {
        // "CIID" tokenizes as CI + ID (inherited); "OICI" has no ID token.
        let inherited = Ace {
            ace_type: "A".into(),
            flags: "CIID".into(),
            rights: "FA".into(),
            trustee: USER.into(),
        };
        let explicit = Ace {
            flags: "OICI".into(),
            ..inherited.clone()
        };
        assert!(inherited.is_inherited());
        assert!(!explicit.is_inherited());
    }

    #[test]
    fn sid_comparison_is_case_insensitive() {
        let sd = parse("O:s-1-5-21-111-222-333-1001D:(A;;FA;;;s-1-5-21-111-222-333-1001)").unwrap();
        let refs = references(&sd, USER);
        assert!(refs.is_owner);
        assert_eq!(refs.explicit_aces, 1);
    }

    #[test]
    fn conditional_ace_with_nested_parentheses_is_parsed() {
        let text = format!("D:(XA;;FA;;;{USER};(@User.Project == \"x\"))(A;;FA;;;SY)");
        let sd = parse(&text).unwrap();
        assert_eq!(sd.dacl.len(), 2);
        assert_eq!(sd.dacl[0].trustee, USER);
    }

    #[test]
    fn sacl_section_is_ignored() {
        let sd = parse("O:SYD:(A;;FA;;;SY)S:(AU;SA;FA;;;WD)").unwrap();
        assert_eq!(sd.dacl.len(), 1);
    }

    #[test]
    fn empty_dacl_and_null_dacl_flag() {
        let sd = parse("O:SYD:NO_ACCESS_CONTROL").unwrap();
        assert_eq!(sd.dacl_flags, vec!["NO_ACCESS_CONTROL".to_string()]);
        assert!(sd.dacl.is_empty());
    }

    #[test]
    fn malformed_descriptors_are_rejected() {
        for bad in [
            "garbage",
            "D:(A;;FA;;;SY",
            "D:A;;FA;;;SY)",
            "D:(A;;FA)",
            "D:XYZ(A;;FA;;;SY)",
            "D:(A;;FA;;;SY)junk",
        ] {
            assert!(parse(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn sid_digits_do_not_start_sections() {
        // "S-1-5-21-..." starts with S but is followed by '-', not ':'.
        let sd = parse("O:S-1-5-21-111-222-333-1001G:SYD:(A;;FA;;;SY)").unwrap();
        assert_eq!(sd.owner.as_deref(), Some(USER));
        assert_eq!(sd.group.as_deref(), Some("SY"));
    }
}
