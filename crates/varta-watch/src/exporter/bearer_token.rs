//! Bearer-token parsing for the Prometheus `/metrics` endpoint.

/// Position of the first `\r\n` byte pair in `buf`.
#[cfg(feature = "prometheus-exporter")]
pub(super) fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

/// Parse `Authorization: Bearer <64hex>` out of a buffered HTTP/1.x
/// request without allocating.  Returns the decoded 32-byte token when
/// the header is present, well-formed, and carries exactly 64 hex
/// characters of token material; returns `None` otherwise.  The header
/// field name is matched case-insensitively per RFC 7230 §3.2.
#[cfg(feature = "prometheus-exporter")]
pub(super) fn parse_authorization_bearer(buf: &[u8]) -> Option<[u8; 32]> {
    // Skip the request line. find_crlf returns the index of '\r'; bump
    // past the '\n' that follows.
    let mut rest = match find_crlf(buf) {
        Some(eol) => &buf[eol + 2..],
        // No CRLF at all — too short to carry a header anyway.
        None => return None,
    };
    while let Some(eol) = find_crlf(rest) {
        let line = &rest[..eol];
        rest = &rest[eol + 2..];
        if line.is_empty() {
            // Empty line == end of headers.
            return None;
        }
        const HDR: &[u8] = b"authorization:";
        if line.len() >= HDR.len() && line[..HDR.len()].eq_ignore_ascii_case(HDR) {
            let mut value = &line[HDR.len()..];
            while let Some(b) = value.first().copied() {
                if b == b' ' || b == b'\t' {
                    value = &value[1..];
                } else {
                    break;
                }
            }
            const BEARER: &[u8] = b"bearer ";
            if value.len() < BEARER.len() {
                return None;
            }
            if !value[..BEARER.len()].eq_ignore_ascii_case(BEARER) {
                return None;
            }
            let mut token_part = &value[BEARER.len()..];
            while let Some(b) = token_part.first().copied() {
                if b == b' ' || b == b'\t' {
                    token_part = &token_part[1..];
                } else {
                    break;
                }
            }
            if token_part.len() < 64 {
                return None;
            }
            return varta_vlp::decode_hex_32(&token_part[..64]).ok();
        }
    }
    None
}
