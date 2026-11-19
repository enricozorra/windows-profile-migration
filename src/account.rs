//! Classifies how an account was written on the command line, before any
//! lookup happens.

use crate::model::AccountInput;
use crate::sid::SidString;

/// Classifies `input`. A string that starts like a SID but does not parse is
/// an error rather than a name, so a typo never falls through to a name
/// lookup that might match something else.
pub fn classify(input: &str) -> Result<AccountInput, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("account is empty".into());
    }
    if trimmed.len() > 2 && trimmed[..2].eq_ignore_ascii_case("S-") {
        return match SidString::parse(trimmed) {
            Some(sid) => Ok(AccountInput::Sid(sid.as_str().to_string())),
            None => Err(format!("'{trimmed}' looks like a SID but is not valid")),
        };
    }
    if let Some((domain, user)) = trimmed.split_once('\\') {
        if domain.is_empty() || user.is_empty() || user.contains('\\') {
            return Err(format!("'{trimmed}' is not a valid DOMAIN\\user name"));
        }
        return Ok(AccountInput::Qualified);
    }
    if let Some((user, domain)) = trimmed.split_once('@') {
        if user.is_empty() || domain.is_empty() || domain.contains('@') {
            return Err(format!("'{trimmed}' is not a valid user@domain name"));
        }
        return Ok(AccountInput::Upn);
    }
    Ok(AccountInput::Bare)
}

/// LookupAccountNameW does not understand the `.\user` shorthand for the
/// local machine, so it is rewritten to `COMPUTER\user` before lookup.
pub fn expand_local_shorthand(input: &str, computer_name: &str) -> String {
    let trimmed = input.trim();
    match trimmed.strip_prefix(".\\") {
        Some(user) => format!("{computer_name}\\{user}"),
        None => trimmed.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sid_input_is_normalized() {
        assert_eq!(
            classify("s-1-5-21-1-2-3-1001"),
            Ok(AccountInput::Sid("S-1-5-21-1-2-3-1001".into()))
        );
    }

    #[test]
    fn malformed_sid_is_an_error_not_a_name() {
        assert!(classify("S-1-5-21-1-2-x").is_err());
    }

    #[test]
    fn name_forms_are_distinguished() {
        assert_eq!(classify(r"CORP\jdoe"), Ok(AccountInput::Qualified));
        assert_eq!(classify(r".\jdoe"), Ok(AccountInput::Qualified));
        assert_eq!(classify("jdoe@corp.example"), Ok(AccountInput::Upn));
        assert_eq!(classify("jdoe"), Ok(AccountInput::Bare));
        // A user literally named like "Sam" must not be mistaken for a SID.
        assert_eq!(classify("Sam"), Ok(AccountInput::Bare));
    }

    #[test]
    fn malformed_names_are_rejected() {
        for bad in [
            "", "  ", r"\jdoe", r"CORP\", r"A\B\C", "@corp", "jdoe@", "a@b@c",
        ] {
            assert!(classify(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn local_shorthand_expands_to_computer_name() {
        assert_eq!(expand_local_shorthand(r".\jdoe", "PC01"), r"PC01\jdoe");
        assert_eq!(expand_local_shorthand(r"CORP\jdoe", "PC01"), r"CORP\jdoe");
    }
}
