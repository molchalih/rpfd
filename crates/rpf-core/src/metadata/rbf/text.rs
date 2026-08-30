//! The escape that lets an arbitrary byte string be XML text.
//!
//! `RBF` string values and raw blobs are **bytes**, and XML text is characters.
//! Three measured facts decide the shape of this:
//!
//! - 1,038 records in the corpus carry a byte at or above `0x80`, and the blobs
//!   holding them are not valid UTF-8. `CodeWalker` routes them through
//!   `Encoding.ASCII` and turns every one into `?`.
//! - 42,368 NUL bytes appear inside blobs, and 42,366 blobs end in one while
//!   5,676 do not. A NUL is not a character XML can carry at all.
//! - Tab, newline and carriage return are rewritten by XML's own attribute-value
//!   and line-end normalisation, so a byte string carrying them cannot survive
//!   as literal text.
//!
//! So the escape is byte-exact rather than character-exact, and it escapes
//! everything XML would otherwise change. The encoder is canonical — it escapes
//! exactly what it must — which is what makes [`decode`] of [`encode`] the
//! identity on every byte string.

/// The escape character, and the one character that always escapes itself.
const ESCAPE: char = '\\';

/// A space at either end of the text.
///
/// Escaped so that a text node made only of XML whitespace is unambiguously
/// indentation and never a blob. Without it `<Name> </Name>` could be either.
const SPACE: u8 = b' ';

/// How an escaped space is written.
const ESCAPED_SPACE: &str = "\\x20";

/// Writes `bytes` as XML text.
///
/// The result is valid UTF-8, contains no character XML has to normalise, and
/// begins and ends with no space.
pub(super) fn encode(bytes: &[u8]) -> String {
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
        // `None` means the input ended part-way through a sequence, so every
        // byte that is left is unusable.
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
/// The escape character never may, because it is what marks the others. `0x7F`
/// never may, because it is legal XML and invisible. Everything else outside
/// XML 1.0's `Char` production never may, which is what excludes the control
/// characters — tab, newline and carriage return included, since XML rewrites
/// all three.
fn literal(character: char) -> bool {
    character != ESCAPE
        && character != '\u{7f}'
        && matches!(character, '\u{20}'..='\u{d7ff}' | '\u{e000}'..='\u{fffd}' | '\u{10000}'..)
}

/// Reads back what [`encode`] wrote.
///
/// Returns `None` if `text` carries a backslash that does not begin `\\` or
/// `\xNN` — an escape this never writes, which a hand edit can still produce.
pub(super) fn decode(text: &str) -> Option<Vec<u8>> {
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

#[cfg(test)]
mod tests {
    use super::{decode, encode};

    #[test]
    fn a_shipped_blob_shows_its_own_trailing_nul() {
        // docs/metadata-encodings.md: `RbfXml` strips the last byte of every
        // blob unconditionally, and 5,676 of 48,042 blobs do not have one to
        // strip. A blob that writes its own bytes cannot reproduce that.
        assert_eq!(encode(b"DES_gasstation01\0"), "DES_gasstation01\\x00");
        assert_eq!(encode(b"DES_gasstation01"), "DES_gasstation01");
    }

    #[test]
    fn a_byte_that_is_not_utf8_survives() {
        // The 1,038 records CodeWalker turns into `?`.
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
    fn an_escape_this_never_writes_is_refused() {
        assert_eq!(decode("\\q"), None);
        assert_eq!(decode("\\"), None);
        assert_eq!(decode("\\x"), None);
        assert_eq!(decode("\\x0"), None);
        assert_eq!(decode("\\xzz"), None);
        assert_eq!(decode("\\x+1"), None);
    }
}
