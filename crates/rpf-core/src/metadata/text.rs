//! The XML text, names and numbers both metadata encodings write: how a byte
//! string becomes XML text, how a float is spelled so it reads back to the same
//! bits, and what counts as a name.
//!
//! Values are bytes and XML text is characters, so the escape is byte-exact and
//! escapes everything XML would otherwise normalise. It is canonical, which
//! makes [`decode`] of [`encode`] the identity on every byte string.

/// The escape character, and the one character that always escapes itself.
const ESCAPE: char = '\\';

/// A space at either end of the text, escaped so a text node made only of
/// whitespace is unambiguously indentation and never a blob.
const SPACE: u8 = b' ';

/// How an escaped space is written.
const ESCAPED_SPACE: &str = "\\x20";

/// Writes `bytes` as XML text: valid UTF-8, with no character XML has to
/// normalise and no space at either end.
pub(crate) fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    let mut body = bytes;
    let mut trailing = "";
    if let Some((&SPACE, rest)) = body.split_first() {
        out.push_str(ESCAPED_SPACE);
        body = rest;
    }
    if let Some((&SPACE, rest)) = body.split_last() {
        trailing = ESCAPED_SPACE;
        body = rest;
    }
    encode_body(&mut out, body);
    out.push_str(trailing);
    out
}

/// [`encode`] without the leading and trailing space rule.
fn encode_body(out: &mut String, bytes: &[u8]) {
    let mut rest = bytes;
    while !rest.is_empty() {
        let error = match str::from_utf8(rest) {
            Ok(text) => {
                push_text(out, text);
                return;
            }
            Err(error) => error,
        };
        let Some((valid, invalid)) = rest.split_at_checked(error.valid_up_to()) else {
            return;
        };
        if let Ok(text) = str::from_utf8(valid) {
            push_text(out, text);
        }
        // `None` means the input ended mid-sequence: every remaining byte is
        // unusable.
        let width = error.error_len().unwrap_or(invalid.len());
        let Some((bad, next)) = invalid.split_at_checked(width) else {
            return;
        };
        for byte in bad {
            push_byte(out, *byte);
        }
        rest = next;
    }
}

/// Appends `text`, escaping the characters that cannot be literal.
fn push_text(out: &mut String, text: &str) {
    for character in text.chars() {
        if literal(character) {
            out.push(character);
        } else {
            let mut buffer = [0u8; 4];
            for byte in character.encode_utf8(&mut buffer).as_bytes() {
                push_byte(out, *byte);
            }
        }
    }
}

/// Appends one byte as `\xNN`, lower case.
fn push_byte(out: &mut String, byte: u8) {
    out.push(ESCAPE);
    out.push('x');
    out.push(nibble(byte >> 4));
    out.push(nibble(byte & 0x0F));
}

/// The hex digit for the low four bits of `value`.
fn nibble(value: u8) -> char {
    char::from_digit(u32::from(value & 0x0F), 16).unwrap_or('0')
}

/// Whether a character may appear literally in the XML.
///
/// Not the escape character, not `0x7F` (legal XML but invisible), and nothing
/// outside XML 1.0's `Char` production — which excludes tab, newline and
/// carriage return, all three of which XML rewrites.
fn literal(character: char) -> bool {
    character != ESCAPE
        && character != '\u{7f}'
        && matches!(character, '\u{20}'..='\u{d7ff}' | '\u{e000}'..='\u{fffd}' | '\u{10000}'..)
}

/// Reads back what [`encode`] wrote.
///
/// Returns `None` if `text` carries a backslash that does not begin `\\` or
/// `\xNN` — an escape this never writes, which a hand edit can still produce.
pub(crate) fn decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find(ESCAPE) {
        let (literal_part, escaped) = rest.split_at_checked(at)?;
        out.extend_from_slice(literal_part.as_bytes());
        let body = escaped.get(ESCAPE.len_utf8()..)?;
        if let Some(after) = body.strip_prefix(ESCAPE) {
            out.push(u8::try_from(u32::from(ESCAPE)).ok()?);
            rest = after;
        } else {
            let hex = body.strip_prefix('x')?;
            let digits = hex
                .get(..2)
                .filter(|digits| digits.chars().all(|c| c.is_ascii_hexdigit()))?;
            out.push(u8::from_str_radix(digits, 16).ok()?);
            rest = hex.get(2..)?;
        }
    }
    out.extend_from_slice(rest.as_bytes());
    Some(out)
}

/// A float written as its raw bits, for the values whose shortest decimal does
/// not read back to the same bits.
const BITS_PREFIX: &str = "0x";

/// A float, as the shortest decimal that reads back to the same bits, falling
/// back to the bits themselves when no decimal does.
pub(crate) fn float(number: f32) -> String {
    let shortest = format!("{number:?}");
    if shortest.parse::<f32>().map(f32::to_bits) == Ok(number.to_bits()) {
        shortest
    } else {
        format!("{BITS_PREFIX}{:08x}", number.to_bits())
    }
}

/// Reads back the float [`float`] wrote.
pub(crate) fn unfloat(text: &str) -> Option<f32> {
    match text.strip_prefix(BITS_PREFIX) {
        Some(bits) => u32::from_str_radix(bits, 16).ok().map(f32::from_bits),
        None => text.parse().ok(),
    }
}

/// Whether `text` is an XML name of the shape this layer writes: a subset of
/// XML 1.0's `Name`, ASCII only, starting with a letter, `_` or `:`.
pub(crate) fn is_xml_name(text: &str) -> bool {
    let mut chars = text.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    let start = first.is_ascii_alphabetic() || first == '_' || first == ':';
    start && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | ':' | '.' | '-'))
}

#[cfg(test)]
mod tests {
    use super::{decode, encode, float, is_xml_name, unfloat};

    #[test]
    fn a_shipped_blob_shows_its_own_trailing_nul() {
        // A trailing NUL is part of the blob, never stripped.
        assert_eq!(encode(b"DES_gasstation01\0"), "DES_gasstation01\\x00");
        assert_eq!(encode(b"DES_gasstation01"), "DES_gasstation01");
    }

    #[test]
    fn a_byte_that_is_not_utf8_survives() {
        assert_eq!(encode(b"\x913"), "\\x913");
        assert_eq!(decode("\\x913").as_deref(), Some(&b"\x913"[..]));
    }

    #[test]
    fn whitespace_at_either_end_is_never_literal() {
        assert_eq!(encode(b" "), "\\x20");
        assert_eq!(encode(b"  "), "\\x20\\x20");
        assert_eq!(encode(b" a "), "\\x20a\\x20");
        assert_eq!(encode(b"a b"), "a b");
    }

    #[test]
    fn every_byte_string_up_to_two_bytes_round_trips() {
        for first in 0u16..=255 {
            let one = [u8::try_from(first).unwrap()];
            assert_eq!(decode(&encode(&one)).as_deref(), Some(&one[..]), "{one:?}");
            for second in 0u16..=255 {
                let two = [u8::try_from(first).unwrap(), u8::try_from(second).unwrap()];
                assert_eq!(decode(&encode(&two)).as_deref(), Some(&two[..]), "{two:?}");
            }
        }
    }

    #[test]
    fn a_float_is_its_shortest_decimal_and_reads_back_to_the_same_bits() {
        for number in [0.0f32, -0.0, 1.0, 15.418, -13.966_396, f32::MIN, f32::MAX] {
            assert_eq!(
                unfloat(&float(number)).map(f32::to_bits),
                Some(number.to_bits())
            );
        }
        assert_eq!(float(1.0), "1.0");
    }

    #[test]
    fn a_float_no_decimal_reads_back_to_is_written_as_its_bits() {
        let payload = f32::from_bits(0x7fc0_0001);
        assert_eq!(float(payload), "0x7fc00001");
        assert_eq!(unfloat("0x7fc00001").map(f32::to_bits), Some(0x7fc0_0001));
    }

    #[test]
    fn a_name_is_ascii_and_starts_with_a_letter_an_underscore_or_a_colon() {
        for name in ["a", "_a", ":a", "CriminalCareerDefs::Shopping", "a-b.c1"] {
            assert!(is_xml_name(name), "{name}");
        }
        for name in ["", "1a", "-a", ".a", "a b", "a<b", "n\u{e4}me"] {
            assert!(!is_xml_name(name), "{name}");
        }
    }

    #[test]
    fn an_escape_this_never_writes_is_refused() {
        assert_eq!(decode("\\q"), None);
        assert_eq!(decode("\\"), None);
        assert_eq!(decode("\\x"), None);
        assert_eq!(decode("\\x0"), None);
        assert_eq!(decode("\\xzz"), None);
        assert_eq!(decode("\\x+1"), None);
    }
}
