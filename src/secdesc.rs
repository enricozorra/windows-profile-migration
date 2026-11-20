//! SID replacement inside a binary self-relative security descriptor.
//!
//! Rewriting through SDDL text is not lossless: an empty SACL comes back as
//! a NULL one, for instance. Account SIDs all have the same length (five
//! sub-authorities), so the source SID can instead be overwritten in place,
//! at the positions where the descriptor format stores a SID: owner, group,
//! and the trustee of each ACE. Every other byte stays as it was.

/// SECURITY_DESCRIPTOR_RELATIVE header length and field offsets.
const HEADER_LEN: usize = 20;
const CONTROL: usize = 2;
const OWNER: usize = 4;
const GROUP: usize = 8;
const SACL: usize = 12;
const DACL: usize = 16;
const SE_SELF_RELATIVE: u16 = 0x8000;
// Used by the Windows registry layer only.
#[cfg_attr(not(windows), allow(dead_code))]
const SE_DACL_AUTO_INHERIT_REQ: u16 = 0x0100;
#[cfg_attr(not(windows), allow(dead_code))]
const SE_DACL_AUTO_INHERITED: u16 = 0x0400;
const ACL_HEADER_LEN: usize = 8;
const ACE_HEADER_LEN: usize = 4;
const ACE_OBJECT_TYPE_PRESENT: u32 = 1;
const ACE_INHERITED_OBJECT_TYPE_PRESENT: u32 = 2;

/// The outcome of editing a descriptor: the new bytes, `None` for "leave it
/// as it is", or why it cannot be edited safely.
pub type Edited = Result<Option<Vec<u8>>, String>;

/// Binary form of a SID string such as `S-1-5-21-1-2-3-1001`.
pub fn sid_to_bytes(sid: &str) -> Option<Vec<u8>> {
    let mut parts = sid.strip_prefix("S-")?.split('-');
    let revision: u8 = parts.next()?.parse().ok()?;
    let authority: u64 = parts.next()?.parse().ok()?;
    let subs: Vec<u32> = parts.map(|p| p.parse().ok()).collect::<Option<_>>()?;
    if revision != 1 || subs.is_empty() || subs.len() > 15 || authority >= 1 << 48 {
        return None;
    }
    let mut out = vec![revision, subs.len() as u8];
    out.extend_from_slice(&authority.to_be_bytes()[2..]);
    for sub in subs {
        out.extend_from_slice(&sub.to_le_bytes());
    }
    Some(out)
}

/// The descriptor with every structural occurrence of the SID `from`
/// replaced by `to`, or `None` when it does not contain `from`.
///
/// Fails when the SIDs differ in length, when the descriptor is malformed,
/// or when `from` also appears somewhere this function does not rewrite
/// (an ACE type it does not know, conditional expression data): a partly
/// translated descriptor is never returned.
pub fn replace_sid(descriptor: &[u8], from: &[u8], to: &[u8]) -> Edited {
    if from.len() != to.len() {
        return Err("source and target SIDs differ in length".into());
    }
    if !contains(descriptor, from) {
        return Ok(None);
    }
    if descriptor.len() < HEADER_LEN || u16_at(descriptor, CONTROL)? & SE_SELF_RELATIVE == 0 {
        return Err("not a self-relative security descriptor".into());
    }
    let mut out = descriptor.to_vec();
    for field in [OWNER, GROUP] {
        let offset = u32_at(descriptor, field)? as usize;
        if offset != 0 {
            replace_at(&mut out, offset, from, to)?;
        }
    }
    for field in [SACL, DACL] {
        let offset = u32_at(descriptor, field)? as usize;
        if offset != 0 {
            for sid_offset in ace_sid_offsets(descriptor, offset)? {
                replace_at(&mut out, sid_offset, from, to)?;
            }
        }
    }
    if contains(&out, from) {
        return Err("the SID also appears where it cannot be translated safely".into());
    }
    Ok(Some(out))
}

/// The descriptor with the auto-inherit request flag added when its DACL
/// is auto-inherited. Setting a descriptor on a registry key drops the
/// auto-inherited flag unless the request accompanies it.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn with_auto_inherit_request(descriptor: &[u8]) -> Result<Vec<u8>, String> {
    let control = u16_at(descriptor, CONTROL)?;
    let mut out = descriptor.to_vec();
    if control & SE_DACL_AUTO_INHERITED != 0 {
        out[CONTROL..CONTROL + 2]
            .copy_from_slice(&(control | SE_DACL_AUTO_INHERIT_REQ).to_le_bytes());
    }
    Ok(out)
}

/// Offsets of the trustee SID of every ACE in the ACL at `acl`.
fn ace_sid_offsets(descriptor: &[u8], acl: usize) -> Result<Vec<usize>, String> {
    let count = u16_at(descriptor, acl + 4)? as usize;
    let size = u16_at(descriptor, acl + 2)? as usize;
    let end = acl + size;
    if end > descriptor.len() {
        return Err("ACL extends past the descriptor".into());
    }
    let mut offsets = Vec::with_capacity(count);
    let mut ace = acl + ACL_HEADER_LEN;
    for _ in 0..count {
        let ace_type = *descriptor.get(ace).ok_or("ACE header past the ACL")?;
        let ace_size = u16_at(descriptor, ace + 2)? as usize;
        if ace_size < ACE_HEADER_LEN || ace + ace_size > end {
            return Err("ACE size outside its ACL".into());
        }
        let body = ace + ACE_HEADER_LEN;
        match ace_type {
            // Mask, then the SID: allowed, denied, audit, alarm, their
            // callback forms, mandatory label, resource attribute, scoped
            // policy, trust label, access filter.
            0..=3 | 0x9 | 0xA | 0xD | 0xE | 0x11..=0x15 => offsets.push(body + 4),
            // Object ACEs: mask, flags, the GUIDs the flags announce, SID.
            0x5..=0x8 | 0xB | 0xC | 0xF | 0x10 => {
                let flags = u32_at(descriptor, body + 4)?;
                let mut sid = body + 8;
                if flags & ACE_OBJECT_TYPE_PRESENT != 0 {
                    sid += 16;
                }
                if flags & ACE_INHERITED_OBJECT_TYPE_PRESENT != 0 {
                    sid += 16;
                }
                offsets.push(sid);
            }
            // Unknown types are left alone; the final containment check
            // catches the source SID if one of them holds it.
            _ => {}
        }
        ace += ace_size;
    }
    Ok(offsets)
}

/// Overwrites the SID at `offset` if it is exactly `from`.
fn replace_at(out: &mut [u8], offset: usize, from: &[u8], to: &[u8]) -> Result<(), String> {
    let count = *out.get(offset + 1).ok_or("SID past the descriptor")? as usize;
    let len = 8 + 4 * count;
    let sid = out
        .get_mut(offset..offset + len)
        .ok_or("SID past the descriptor")?;
    if sid == from {
        sid.copy_from_slice(to);
    }
    Ok(())
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

fn u16_at(data: &[u8], at: usize) -> Result<u16, String> {
    data.get(at..at + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .ok_or_else(|| "security descriptor is truncated".into())
}

fn u32_at(data: &[u8], at: usize) -> Result<u32, String> {
    data.get(at..at + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or_else(|| "security descriptor is truncated".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC: &str = "S-1-5-21-111-222-333-1001";
    const TGT: &str = "S-1-5-21-777-888-999-2601";

    fn sid(s: &str) -> Vec<u8> {
        sid_to_bytes(s).unwrap()
    }

    fn ace(ace_type: u8, flags: u8, mask: u32, trustee: &[u8]) -> Vec<u8> {
        let mut out = vec![ace_type, flags];
        out.extend_from_slice(&((8 + trustee.len()) as u16).to_le_bytes());
        out.extend_from_slice(&mask.to_le_bytes());
        out.extend_from_slice(trustee);
        out
    }

    fn acl(aces: &[Vec<u8>]) -> Vec<u8> {
        let body: Vec<u8> = aces.concat();
        let mut out = vec![2, 0];
        out.extend_from_slice(&((8 + body.len()) as u16).to_le_bytes());
        out.extend_from_slice(&(aces.len() as u16).to_le_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend(body);
        out
    }

    /// Owner, group, optional SACL, DACL, laid out like Windows does.
    fn descriptor(
        control: u16,
        owner: &[u8],
        group: &[u8],
        sacl: Option<Vec<u8>>,
        dacl: Vec<u8>,
    ) -> Vec<u8> {
        let mut out = vec![1, 0];
        out.extend_from_slice(&(control | SE_SELF_RELATIVE).to_le_bytes());
        let owner_at = HEADER_LEN;
        let group_at = owner_at + owner.len();
        let sacl_at = group_at + group.len();
        let dacl_at = sacl_at + sacl.as_ref().map_or(0, Vec::len);
        for offset in [owner_at, group_at] {
            out.extend_from_slice(&(offset as u32).to_le_bytes());
        }
        out.extend_from_slice(&(if sacl.is_some() { sacl_at as u32 } else { 0 }).to_le_bytes());
        out.extend_from_slice(&(dacl_at as u32).to_le_bytes());
        out.extend_from_slice(owner);
        out.extend_from_slice(group);
        if let Some(sacl) = sacl {
            out.extend(sacl);
        }
        out.extend(dacl);
        out
    }

    #[test]
    fn sid_bytes_match_the_windows_layout() {
        assert_eq!(
            sid_to_bytes("S-1-5-18").unwrap(),
            vec![1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]
        );
        assert_eq!(sid(SRC).len(), 28);
        assert_eq!(sid_to_bytes("S-1-5"), None);
        assert_eq!(sid_to_bytes("X-1-5-18"), None);
    }

    #[test]
    fn owner_and_aces_are_translated_and_nothing_else_moves() {
        let system = sid("S-1-5-18");
        let empty_sacl = acl(&[]);
        let original = descriptor(
            0x0400 | 0x0004 | 0x0010,
            &sid(SRC),
            &system,
            Some(empty_sacl),
            acl(&[
                ace(0, 0x13, 0x1F01FF, &system),
                ace(0, 0x10, 0x1F01FF, &sid(SRC)),
            ]),
        );
        let rewritten = replace_sid(&original, &sid(SRC), &sid(TGT))
            .unwrap()
            .unwrap();
        let expected = descriptor(
            0x0400 | 0x0004 | 0x0010,
            &sid(TGT),
            &system,
            Some(acl(&[])),
            acl(&[
                ace(0, 0x13, 0x1F01FF, &system),
                ace(0, 0x10, 0x1F01FF, &sid(TGT)),
            ]),
        );
        assert_eq!(rewritten, expected);
    }

    #[test]
    fn descriptor_without_the_source_is_not_touched() {
        let system = sid("S-1-5-18");
        let original = descriptor(0x0004, &system, &system, None, acl(&[]));
        assert_eq!(replace_sid(&original, &sid(SRC), &sid(TGT)).unwrap(), None);
    }

    #[test]
    fn object_ace_sid_is_found_after_its_guids() {
        let mut object = vec![5, 0];
        let body_len = 4 + 4 + 16 + 28;
        object.extend_from_slice(&((4 + body_len) as u16).to_le_bytes());
        object.extend_from_slice(&1u32.to_le_bytes());
        object.extend_from_slice(&ACE_OBJECT_TYPE_PRESENT.to_le_bytes());
        object.extend_from_slice(&[0xAB; 16]);
        object.extend_from_slice(&sid(SRC));
        let system = sid("S-1-5-18");
        let original = descriptor(0x0004, &system, &system, None, acl(&[object]));
        let rewritten = replace_sid(&original, &sid(SRC), &sid(TGT))
            .unwrap()
            .unwrap();
        assert!(contains(&rewritten, &sid(TGT)));
        assert!(contains(&rewritten, &[0xAB; 16]));
    }

    #[test]
    fn a_sid_in_an_unknown_place_is_an_error() {
        // A compound ACE (type 4) is not interpreted.
        let system = sid("S-1-5-18");
        let original = descriptor(
            0x0004,
            &system,
            &system,
            None,
            acl(&[ace(4, 0, 1, &sid(SRC))]),
        );
        assert!(replace_sid(&original, &sid(SRC), &sid(TGT)).is_err());
    }

    #[test]
    fn a_longer_sid_with_the_same_prefix_is_left_alone() {
        let longer = sid("S-1-5-21-111-222-333-1001-5");
        let system = sid("S-1-5-18");
        let original = descriptor(0x0004, &longer, &system, None, acl(&[]));
        // Its sub-authority count differs, so its bytes never match.
        assert_eq!(replace_sid(&original, &sid(SRC), &sid(TGT)).unwrap(), None);
    }

    #[test]
    fn different_lengths_and_truncation_are_errors() {
        let system = sid("S-1-5-18");
        let original = descriptor(
            0x0004,
            &sid(SRC),
            &system,
            None,
            acl(&[ace(0, 0, 1, &sid(SRC))]),
        );
        assert!(replace_sid(&original, &sid(SRC), &system).is_err());
        let truncated = &original[..original.len() - 2];
        assert!(replace_sid(truncated, &sid(SRC), &sid(TGT)).is_err());
    }

    #[test]
    fn auto_inherit_request_is_added_only_to_auto_inherited_dacls() {
        let system = sid("S-1-5-18");
        let inherited = descriptor(0x0400 | 0x0004, &system, &system, None, acl(&[]));
        let flagged = with_auto_inherit_request(&inherited).unwrap();
        assert_eq!(u16_at(&flagged, CONTROL).unwrap() & 0x0100, 0x0100);
        let plain = descriptor(0x0004, &system, &system, None, acl(&[]));
        assert_eq!(with_auto_inherit_request(&plain).unwrap(), plain);
    }
}
