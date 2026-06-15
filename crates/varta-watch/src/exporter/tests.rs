use std::io::{self, Read, Write as IoWrite};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use varta_vlp::crypto::BearerToken;
use varta_vlp::{DecodeError, Status};

use crate::observer::Event;
use crate::probe_table::{BoundedIndex, Hash32};

use super::bearer_token::parse_authorization_bearer;
use super::http::{drain_read_to_would_block, PROM_DRAIN_READ_CAP};
use super::{
    drop_reason_index, DropReason, Exporter, IterStage, PidRowTable, PromExporter,
    RECOVERY_REFUSED_REASON_LABELS, STAGE_LABELS,
};
// MAX_PROM_IP_STATES and DROP_REASON_LABELS are used in the table-full and
// dropped-label tests; they are private constants in mod.rs.
use super::{DROP_REASON_LABELS, MAX_PROM_IP_STATES};

/// Shared 32-byte bearer token for unit tests.  The bytes are arbitrary
/// (chosen so a casual `xxd` of a capture is obviously synthetic) and
/// the lowercase 64-char hex form is exposed as `TEST_TOKEN_HEX` for
/// tests that need to inject it into an HTTP request.
const TEST_TOKEN: [u8; 32] = [0xab; 32];
const TEST_TOKEN_HEX: &str = "abababababababababababababababababababababababababababababababab";

fn make_token() -> BearerToken {
    BearerToken::from_bytes(TEST_TOKEN)
}

#[test]
fn render_body_sorts_pids_numerically() {
    let mut prom = PromExporter::bind("127.0.0.1:0".parse().unwrap(), make_token()).expect("bind");
    prom.record(&Event::Beat {
        pid: 30,
        status: Status::Ok,
        nonce: 1,
        payload: 0,
        observer_ns: 0,
        origin: crate::peer_cred::BeatOrigin::KernelAttested,
        pid_ns_inode: None,
    })
    .unwrap();
    prom.record(&Event::Beat {
        pid: 2,
        status: Status::Ok,
        nonce: 1,
        payload: 0,
        observer_ns: 0,
        origin: crate::peer_cred::BeatOrigin::KernelAttested,
        pid_ns_inode: None,
    })
    .unwrap();
    prom.record(&Event::Beat {
        pid: 11,
        status: Status::Ok,
        nonce: 1,
        payload: 0,
        observer_ns: 0,
        origin: crate::peer_cred::BeatOrigin::KernelAttested,
        pid_ns_inode: None,
    })
    .unwrap();
    prom.render_body();
    let body = &prom.body_buf;
    let pos2 = body.find("pid=\"2\"").expect("pid 2");
    let pos11 = body.find("pid=\"11\"").expect("pid 11");
    let pos30 = body.find("pid=\"30\"").expect("pid 30");
    assert!(pos2 < pos11 && pos11 < pos30, "sort order broken:\n{body}");
}

#[test]
fn decode_and_io_events_do_not_create_rows() {
    let mut prom = PromExporter::bind("127.0.0.1:0".parse().unwrap(), make_token()).expect("bind");
    prom.record(&Event::Decode(varta_vlp::DecodeError::BadMagic, 0))
        .unwrap();
    prom.record(&Event::Io(io::Error::other("x"), 0)).unwrap();
    assert!(prom.rows.is_empty());
}

#[test]
fn pid_row_table_is_bounded_and_preserves_existing_rows() {
    let mut rows = PidRowTable::with_capacity(2);

    rows.get_mut_or_insert(10).expect("pid 10 row").beats_total = 1;
    rows.get_mut_or_insert(20).expect("pid 20 row").stalls_total = 1;

    assert!(
        rows.get_mut_or_insert(30).is_none(),
        "third pid must be refused when the fixed row table is full"
    );
    assert_eq!(rows.len(), 2);
    assert_eq!(rows.get(10).map(|row| row.beats_total), Some(1));
    assert_eq!(rows.get(20).map(|row| row.stalls_total), Some(1));

    rows.remove(10);
    assert!(
        rows.get_mut_or_insert(30).is_some(),
        "removing an evicted pid must free a row slot"
    );
    assert!(rows.contains_key(&30));
}

#[test]
fn decode_errors_emit_kind_label_for_every_variant_even_at_zero() {
    let mut prom = PromExporter::bind("127.0.0.1:0".parse().unwrap(), make_token()).expect("bind");
    // Bump bad_magic twice, bad_status once, leave bad_version at zero.
    prom.record(&Event::Decode(DecodeError::BadMagic, 0))
        .unwrap();
    prom.record(&Event::Decode(DecodeError::BadMagic, 0))
        .unwrap();
    prom.record(&Event::Decode(DecodeError::BadStatus(0xff), 0))
        .unwrap();

    prom.render_body();
    let body = &prom.body_buf;
    // All three kind series must be present so `absent()` rules don't
    // silently disappear before the first incident of that kind.
    assert!(
        body.contains("varta_decode_errors_total{kind=\"bad_magic\"} 2"),
        "missing or wrong bad_magic series:\n{body}"
    );
    assert!(
        body.contains("varta_decode_errors_total{kind=\"bad_version\"} 0"),
        "missing zero-valued bad_version series:\n{body}"
    );
    assert!(
        body.contains("varta_decode_errors_total{kind=\"bad_status\"} 1"),
        "missing or wrong bad_status series:\n{body}"
    );
}

#[test]
fn non_get_request_returns_405() {
    let mut prom = PromExporter::bind("127.0.0.1:0".parse().unwrap(), make_token()).expect("bind");
    let addr = prom.local_addr().expect("local_addr");
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("read timeout");
    stream
        .write_all(b"POST /metrics HTTP/1.0\r\n\r\n")
        .expect("write");
    // Yield so the kernel can deliver the bytes to the listener's
    // accept queue before serve_pending() runs; under concurrent
    // test load the write→accept race is otherwise observable.
    std::thread::sleep(Duration::from_millis(5));
    prom.serve_pending().expect("serve_pending");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read");
    assert!(
        response.starts_with("HTTP/1.0 405 Method Not Allowed"),
        "expected 405, got: {response}"
    );
    assert!(
        response.contains("Allow: GET"),
        "missing Allow header: {response}"
    );
}

#[test]
fn cleanup_drain_is_byte_bounded() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let addr = listener.local_addr().expect("local_addr");
    let mut client = TcpStream::connect(addr).expect("connect client");
    let (mut server, _) = listener.accept().expect("accept");
    server.set_nonblocking(true).expect("server nonblocking");

    let payload = vec![0xA5; PROM_DRAIN_READ_CAP + 2048];
    client.write_all(&payload).expect("write payload");
    std::thread::sleep(Duration::from_millis(5));

    drain_read_to_would_block(&mut server, Instant::now() + Duration::from_secs(1));

    let mut leftover = [0u8; 1];
    for _ in 0..20 {
        match server.read(&mut leftover) {
            Ok(1) => return,
            Ok(0) => panic!("server unexpectedly reached EOF"),
            Ok(_) => unreachable!("one-byte read cannot return more than one byte"),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(e) => panic!("unexpected read error after bounded drain: {e}"),
        }
    }
    panic!("bounded cleanup drain consumed all queued excess bytes");
}

/// Drive a single GET against the exporter with optional Authorization
/// header; returns the raw response so each test can assert on its
/// status line, headers, and body independently.
fn one_get(prom: &mut PromExporter, addr: SocketAddr, auth: Option<&str>) -> String {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("read timeout");
    let mut req = String::from("GET /metrics HTTP/1.0\r\nHost: localhost\r\n");
    if let Some(a) = auth {
        req.push_str("Authorization: ");
        req.push_str(a);
        req.push_str("\r\n");
    }
    req.push_str("Connection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).expect("write");
    // Retry accepting pending connections in case the TCP connection hasn't
    // reached the accept queue yet (kernel SYN queue -> listen backlog transition).
    for _ in 0..20 {
        std::thread::sleep(Duration::from_millis(5));
        prom.serve_pending().expect("serve_pending");
    }
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read");
    response
}

#[test]
fn metrics_requires_bearer_token() {
    let mut prom = PromExporter::bind("127.0.0.1:0".parse().unwrap(), make_token()).expect("bind");
    let addr = prom.local_addr().expect("local_addr");
    let response = one_get(&mut prom, addr, None);
    assert!(
        response.starts_with("HTTP/1.0 401 Unauthorized"),
        "expected 401 on missing auth, got: {response}"
    );
    assert!(
        response.contains("WWW-Authenticate: Bearer"),
        "missing WWW-Authenticate header: {response}"
    );
    assert_eq!(
        prom.prom_auth_failures_total, 1,
        "prom_auth_failures_total must bump on missing auth"
    );
    assert_eq!(
        prom.frame_auth_failures_total, 0,
        "frame_auth_failures_total must NOT bump on a /metrics bearer failure"
    );
}

#[test]
fn metrics_rejects_wrong_token() {
    let mut prom = PromExporter::bind("127.0.0.1:0".parse().unwrap(), make_token()).expect("bind");
    let addr = prom.local_addr().expect("local_addr");
    let bad = "Bearer 0000000000000000000000000000000000000000000000000000000000000000";
    let response = one_get(&mut prom, addr, Some(bad));
    assert!(
        response.starts_with("HTTP/1.0 401 Unauthorized"),
        "expected 401 on wrong token, got: {response}"
    );
    assert_eq!(
        prom.prom_auth_failures_total, 1,
        "prom_auth_failures_total must bump on wrong token"
    );
}

#[test]
fn metrics_rejects_token_with_trailing_garbage() {
    let mut prom = PromExporter::bind("127.0.0.1:0".parse().unwrap(), make_token()).expect("bind");
    let addr = prom.local_addr().expect("local_addr");
    let bad = format!("Bearer {TEST_TOKEN_HEX}extra");
    let response = one_get(&mut prom, addr, Some(&bad));
    assert!(
        response.starts_with("HTTP/1.0 401 Unauthorized"),
        "expected 401 on token with trailing garbage, got: {response}"
    );
    assert_eq!(
        prom.prom_auth_failures_total, 1,
        "prom_auth_failures_total must bump on malformed token"
    );
}

#[test]
fn metrics_accepts_valid_token() {
    let mut prom = PromExporter::bind("127.0.0.1:0".parse().unwrap(), make_token()).expect("bind");
    let addr = prom.local_addr().expect("local_addr");
    let good = format!("Bearer {TEST_TOKEN_HEX}");
    let response = one_get(&mut prom, addr, Some(&good));
    assert!(
        response.starts_with("HTTP/1.0 200 OK"),
        "expected 200 on valid token, got: {response}"
    );
    assert_eq!(
        prom.prom_auth_failures_total, 0,
        "prom_auth_failures_total must not bump on success"
    );
}

/// Regression: a verbose scraper (large User-Agent / Accept-Encoding /
/// Accept headers) can push the Authorization header past byte 512.  The
/// request buffer must be sized to PROM_REQUEST_CAP (4096), not a fixed 512,
/// so the token is always within the scanned window.
#[test]
fn metrics_accepts_token_after_verbose_headers() {
    use super::PROM_REQUEST_CAP;
    let mut prom = PromExporter::bind("127.0.0.1:0".parse().unwrap(), make_token()).expect("bind");
    let addr = prom.local_addr().expect("local_addr");

    // Build a request whose Authorization header starts after byte 512 by
    // padding with a long (but legal) X-Verbose header.
    let padding = "X".repeat(600);
    let req = format!(
        "GET /metrics HTTP/1.0\r\nHost: localhost\r\nX-Verbose: {padding}\r\nAuthorization: Bearer {TEST_TOKEN_HEX}\r\nConnection: close\r\n\r\n"
    );
    assert!(
        req.find("Authorization:").unwrap() > 512,
        "padding must push Authorization past byte 512 (sanity check)"
    );
    assert!(
        req.len() <= PROM_REQUEST_CAP,
        "request must fit within PROM_REQUEST_CAP"
    );

    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("read timeout");
    stream.write_all(req.as_bytes()).expect("write");
    for _ in 0..20 {
        std::thread::sleep(Duration::from_millis(5));
        prom.serve_pending().expect("serve_pending");
    }
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read response");

    assert!(
        response.starts_with("HTTP/1.0 200 OK"),
        "expected 200 with Authorization past byte 512, got: {response}"
    );
    assert_eq!(
        prom.prom_auth_failures_total, 0,
        "prom_auth_failures_total must not bump when Authorization is past byte 512"
    );
}

/// Regression: `varta_frame_auth_failures_total` (frame PID-spoofing,
/// `Event::AuthFailure`) and `varta_prom_auth_failures_total` (/metrics
/// bearer-token rejection) are two INDEPENDENT counters. They were once a
/// single backing field, so both series rendered the same conflated sum — a
/// stray unauthenticated GET inflated the PID-spoofing alarm and a real
/// frame-spoof inflated the metrics-probing alarm. Drive one of each and
/// assert the two series carry distinct values.
#[test]
fn frame_and_prom_auth_failures_are_independent() {
    let mut prom = PromExporter::bind("127.0.0.1:0".parse().unwrap(), make_token()).expect("bind");
    let addr = prom.local_addr().expect("local_addr");

    // Two frame-level PID-spoofing rejections.
    prom.record(&Event::AuthFailure {
        claimed_pid: 1234,
        observer_ns: 0,
    })
    .unwrap();
    prom.record(&Event::AuthFailure {
        claimed_pid: 5678,
        observer_ns: 0,
    })
    .unwrap();
    assert_eq!(
        prom.frame_auth_failures_total, 2,
        "frame counter must track Event::AuthFailure"
    );
    assert_eq!(
        prom.prom_auth_failures_total, 0,
        "bearer counter must NOT move on a frame auth failure"
    );

    // One /metrics bearer-token rejection (missing Authorization header).
    let response = one_get(&mut prom, addr, None);
    assert!(
        response.starts_with("HTTP/1.0 401 Unauthorized"),
        "expected 401, got: {response}"
    );
    assert_eq!(
        prom.frame_auth_failures_total, 2,
        "frame counter must NOT move on a /metrics bearer failure"
    );
    assert_eq!(
        prom.prom_auth_failures_total, 1,
        "bearer counter must track /metrics rejections"
    );

    // The two rendered series carry the two distinct values, not one sum.
    prom.render_body();
    let body = &prom.body_buf;
    assert!(
        body.contains("varta_frame_auth_failures_total 2"),
        "frame series wrong; body:\n{body}"
    );
    assert!(
        body.contains("varta_prom_auth_failures_total 1"),
        "prom series wrong; body:\n{body}"
    );
}

/// Regression: an unauthenticated (401) or non-GET (405) request must not
/// advance the scrape-freshness window. Before the fix, `serve_pending`
/// committed `last_scrape` for any accepted connection (`served > 0`), so
/// an unauthenticated peer — a stray `curl`, a k8s TCP liveness probe, or
/// a hostile client — could poison the 1-second cache. At startup the next
/// *authorized* scrape within that second was then served an empty
/// `body_buf` (`Content-Length: 0`), starving the legitimate scraper of
/// metrics during exactly the incidents metrics exist to surface.
#[test]
fn unauthorized_request_does_not_poison_scrape_cache() {
    let mut prom = PromExporter::bind("127.0.0.1:0".parse().unwrap(), make_token()).expect("bind");
    let addr = prom.local_addr().expect("local_addr");

    // 1) Unauthenticated GET → 401, no render. Must NOT touch the cache.
    let unauth = one_get(&mut prom, addr, None);
    assert!(
        unauth.starts_with("HTTP/1.0 401 Unauthorized"),
        "expected 401, got: {unauth}"
    );
    assert!(
        prom.last_scrape.is_none(),
        "an unauthenticated (401) request must not advance the scrape-freshness window"
    );
    assert_eq!(
        prom.scrape_skipped_total, 0,
        "a rejected (401) request must not count as a skipped scrape"
    );

    // 2) Authorized GET immediately after — well within PROM_MIN_SCRAPE_INTERVAL.
    //    Because the 401 did not poison the window, this still renders a
    //    fresh, non-empty body instead of serving the empty startup cache.
    let good = format!("Bearer {TEST_TOKEN_HEX}");
    let authed = one_get(&mut prom, addr, Some(&good));
    assert!(
        authed.starts_with("HTTP/1.0 200 OK"),
        "expected 200, got: {authed}"
    );
    let body = authed.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("");
    assert!(
        body.contains("varta_scrape_skipped_total"),
        "authorized scrape after an unauthenticated one must receive a freshly \
         rendered (non-empty) body, not the poisoned empty cache; response:\n{authed}"
    );
    assert!(
        prom.last_scrape.is_some(),
        "an authorized fresh serve must advance the scrape-freshness window"
    );
    assert_eq!(
        prom.scrape_skipped_total, 0,
        "a freshly-rendered authorized serve must not count as a skipped scrape"
    );
}

#[test]
fn metrics_authorization_header_is_case_insensitive() {
    let mut prom = PromExporter::bind("127.0.0.1:0".parse().unwrap(), make_token()).expect("bind");
    let addr = prom.local_addr().expect("local_addr");
    // Lowercase `bearer` and uppercase hex must both succeed.
    let token_upper = TEST_TOKEN_HEX.to_uppercase();
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("read timeout");
    let req = format!(
        "GET /metrics HTTP/1.0\r\nauthorization: bearer {token_upper}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).expect("write");
    std::thread::sleep(Duration::from_millis(5));
    prom.serve_pending().expect("serve_pending");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read");
    assert!(
        response.starts_with("HTTP/1.0 200 OK"),
        "expected 200 with case-insensitive header, got: {response}"
    );
}

#[test]
fn auth_failures_counter_emitted_at_zero_in_body() {
    let mut prom = PromExporter::bind("127.0.0.1:0".parse().unwrap(), make_token()).expect("bind");
    prom.render_body();
    assert!(
        prom.body_buf.contains("varta_prom_auth_failures_total 0"),
        "auth_failures_total must emit at zero; body:\n{}",
        prom.body_buf
    );
}

#[test]
fn parse_authorization_bearer_finds_token_among_many_headers() {
    let req = format!(
        "GET /metrics HTTP/1.0\r\nHost: localhost\r\nX-Foo: bar\r\nAuthorization: Bearer {TEST_TOKEN_HEX}\r\nUser-Agent: prom/2\r\n\r\n"
    );
    let parsed =
        parse_authorization_bearer(req.as_bytes()).expect("token must parse out of headers");
    assert_eq!(parsed, TEST_TOKEN);
}

#[test]
fn parse_authorization_bearer_rejects_non_bearer_scheme() {
    let req = "GET /metrics HTTP/1.0\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\r\n";
    assert!(parse_authorization_bearer(req.as_bytes()).is_none());
}

#[test]
fn parse_authorization_bearer_rejects_short_token() {
    let req = "GET /metrics HTTP/1.0\r\nAuthorization: Bearer abc\r\n\r\n";
    assert!(parse_authorization_bearer(req.as_bytes()).is_none());
}

#[test]
fn parse_authorization_bearer_rejects_trailing_garbage_after_token() {
    let req =
        format!("GET /metrics HTTP/1.0\r\nAuthorization: Bearer {TEST_TOKEN_HEX}extra\r\n\r\n");
    assert!(parse_authorization_bearer(req.as_bytes()).is_none());
}

#[test]
fn parse_authorization_bearer_accepts_trailing_ows_after_token() {
    let req = format!("GET /metrics HTTP/1.0\r\nAuthorization: Bearer {TEST_TOKEN_HEX}\t \r\n\r\n");
    assert_eq!(parse_authorization_bearer(req.as_bytes()), Some(TEST_TOKEN));
}

#[test]
fn record_evicted_pid_removes_row() {
    let mut prom = PromExporter::bind("127.0.0.1:0".parse().unwrap(), make_token()).expect("bind");
    prom.record(&Event::Beat {
        pid: 42,
        status: Status::Ok,
        nonce: 1,
        payload: 0,
        observer_ns: 0,
        origin: crate::peer_cred::BeatOrigin::KernelAttested,
        pid_ns_inode: None,
    })
    .unwrap();
    assert!(prom.rows.contains_key(&42), "row should exist after beat");
    prom.record_evicted_pid(42);
    assert!(
        !prom.rows.contains_key(&42),
        "row should be removed after eviction"
    );
}

#[test]
fn deferred_stall_after_eviction_does_not_recreate_orphan_row() {
    // A stall queued past the per-tick eval budget can arrive after the slot
    // was evicted and its exporter row already drained. The Stall arm must
    // NOT re-create an orphan row for a pid record_evicted_pid will never
    // remove again — it must count it as a refused row instead.
    let mut prom = PromExporter::bind("127.0.0.1:0".parse().unwrap(), make_token()).expect("bind");
    prom.record(&Event::Beat {
        pid: 42,
        status: Status::Ok,
        nonce: 1,
        payload: 0,
        observer_ns: 0,
        origin: crate::peer_cred::BeatOrigin::KernelAttested,
        pid_ns_inode: None,
    })
    .unwrap();
    prom.record_evicted_pid(42);
    assert!(!prom.rows.contains_key(&42), "row removed by eviction");

    prom.record(&Event::Stall {
        pid: 42,
        last_nonce: 1,
        last_ns: 0,
        origin: crate::peer_cred::BeatOrigin::KernelAttested,
        pid_ns_inode: None,
        generation: None,
        observer_ns: 0,
    })
    .unwrap();
    assert!(
        !prom.rows.contains_key(&42),
        "deferred stall must not re-create an orphan row for an evicted pid"
    );
    assert_eq!(
        prom.prom_pid_row_refused_total, 1,
        "missing-row stall is counted as a refused row"
    );
}

#[test]
fn stall_for_live_agent_still_increments_its_existing_row() {
    // Regression guard: a stall for a pid that has a live row (it beat, then
    // went silent) must still increment stalls_total and flip last_status.
    let mut prom = PromExporter::bind("127.0.0.1:0".parse().unwrap(), make_token()).expect("bind");
    prom.record(&Event::Beat {
        pid: 7,
        status: Status::Ok,
        nonce: 1,
        payload: 0,
        observer_ns: 0,
        origin: crate::peer_cred::BeatOrigin::KernelAttested,
        pid_ns_inode: None,
    })
    .unwrap();
    prom.record(&Event::Stall {
        pid: 7,
        last_nonce: 1,
        last_ns: 0,
        origin: crate::peer_cred::BeatOrigin::KernelAttested,
        pid_ns_inode: None,
        generation: None,
        observer_ns: 0,
    })
    .unwrap();
    let row = prom.rows.get(7).expect("live agent keeps its row");
    assert_eq!(row.stalls_total, 1);
    assert_eq!(row.last_status, Some(Status::Stall as u8));
    assert_eq!(prom.prom_pid_row_refused_total, 0);
}

#[test]
fn record_evicted_pid_ignores_unknown_pid() {
    let mut prom = PromExporter::bind("127.0.0.1:0".parse().unwrap(), make_token()).expect("bind");
    // Should not panic when called for a pid that was never tracked.
    prom.record_evicted_pid(99);
    // Verify rows is still empty.
    assert!(prom.rows.is_empty());
}

#[test]
fn record_refuses_new_pid_when_bounded_row_table_is_full() {
    let mut prom = PromExporter::bind("127.0.0.1:0".parse().unwrap(), make_token()).expect("bind");
    prom.rows = PidRowTable::with_capacity(1);
    prom.pid_scratch = Vec::with_capacity(1);

    prom.record(&Event::Beat {
        pid: 1,
        status: Status::Ok,
        nonce: 1,
        payload: 0,
        observer_ns: 0,
        origin: crate::peer_cred::BeatOrigin::KernelAttested,
        pid_ns_inode: None,
    })
    .unwrap();
    prom.record(&Event::Beat {
        pid: 2,
        status: Status::Critical,
        nonce: 1,
        payload: 0,
        observer_ns: 0,
        origin: crate::peer_cred::BeatOrigin::KernelAttested,
        pid_ns_inode: None,
    })
    .unwrap();

    assert!(prom.rows.contains_key(&1));
    assert!(
        !prom.rows.contains_key(&2),
        "failed row admission must not evict an existing pid row"
    );
    assert_eq!(prom.prom_pid_row_refused_total, 1);

    prom.render_body();
    assert!(
        prom.body_buf.contains("varta_prom_pid_row_refused_total 1"),
        "row-table pressure must be observable:\n{}",
        prom.body_buf
    );
}

#[test]
fn self_health_metrics_are_emitted() {
    let mut prom = PromExporter::bind("127.0.0.1:0".parse().unwrap(), make_token()).expect("bind");
    // Add a tracked PID so pids_tracked > 0
    prom.record(&Event::Beat {
        pid: 7,
        status: Status::Ok,
        nonce: 1,
        payload: 0,
        observer_ns: 1,
        origin: crate::peer_cred::BeatOrigin::KernelAttested,
        pid_ns_inode: None,
    })
    .unwrap();
    prom.record_loop_tick();
    prom.render_body();
    let body = &prom.body_buf;
    assert!(
        body.contains("varta_watch_uptime_seconds"),
        "missing varta_watch_uptime_seconds:\n{body}"
    );
    assert!(
        body.contains("varta_watch_last_poll_loop_timestamp_seconds"),
        "missing varta_watch_last_poll_loop_timestamp_seconds:\n{body}"
    );
    assert!(
        body.contains("varta_watch_pids_tracked 1"),
        "missing/incorrect varta_watch_pids_tracked:\n{body}"
    );
    // Uptime should be small (just created)
    let needle = "varta_watch_uptime_seconds 0.";
    assert!(body.contains(needle), "uptime should start near 0:\n{body}");
    // pids_tracked after eviction
    prom.record_evicted_pid(7);
    prom.render_body();
    let body2 = &prom.body_buf;
    assert!(
        body2.contains("varta_watch_pids_tracked 0"),
        "pids_tracked should be 0 after eviction:\n{body2}"
    );
}

/// The dropped-connection metric must emit every label value on every
/// scrape, even at zero — same contract as `varta_decode_errors_total`.
/// `absent()` alert rules and dashboards depend on stable series.
#[test]
fn connections_dropped_emit_every_reason_label_at_zero() {
    let mut prom = PromExporter::bind("127.0.0.1:0".parse().unwrap(), make_token()).expect("bind");
    prom.render_body();
    let body = &prom.body_buf;
    for reason in DROP_REASON_LABELS {
        let series = format!("varta_prom_connections_dropped_total{{reason=\"{reason}\"}} 0");
        assert!(
            body.contains(&series),
            "missing zero-emission for reason={reason}:\n{body}"
        );
    }
}

/// Per-IP token bucket: a single IP exceeding its burst must be denied,
/// and the denial must bump `varta_prom_connections_dropped_total
/// {reason="rate_limit"}`.  Unit-tested directly on `allow_ip` to avoid
/// the flakiness of real TCP-accept loops.
#[test]
fn allow_ip_denies_after_burst_and_records_rate_limit() {
    let mut prom = PromExporter::bind_with_rate_limit(
        "127.0.0.1:0".parse().unwrap(),
        make_token(),
        /* rate_per_sec */ 1,
        /* rate_burst   */ 3,
    )
    .expect("bind");

    let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    let t0 = Instant::now();

    // Burst of 3 consumes all tokens.
    for _ in 0..3 {
        assert!(prom.allow_ip(ip, t0));
    }
    // 4th attempt within the same instant must be denied.
    assert!(!prom.allow_ip(ip, t0));
    let idx = drop_reason_index(DropReason::RateLimit);
    assert_eq!(
        prom.connections_dropped_total[idx], 1,
        "rate_limit drop counter must increment on denial"
    );

    // After enough time, the bucket refills and a new connection passes.
    let t1 = t0 + Duration::from_secs(2);
    assert!(prom.allow_ip(ip, t1));
}

/// `allow_ip` with `rate_burst = 0` must always allow — this is the
/// "no rate limit" escape hatch.  The IP-state map must stay empty.
#[test]
fn allow_ip_burst_zero_is_unlimited() {
    let mut prom = PromExporter::bind_with_rate_limit(
        "127.0.0.1:0".parse().unwrap(),
        make_token(),
        /* rate_per_sec */ 5,
        /* rate_burst   */ 0,
    )
    .expect("bind");
    let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    let t = Instant::now();
    for _ in 0..1000 {
        assert!(prom.allow_ip(ip, t));
    }
    assert!(
        prom.ip_state.is_empty(),
        "burst=0 path must not allocate per-IP state"
    );
}

/// Regression: `rate_per_sec = 0` with a non-zero burst must NOT permanently
/// lock out a steady scraper. A token bucket that never refills would, after
/// the initial burst is spent, deny every subsequent request forever (and
/// `last_seen` updates keep the entry from aging out of the table). A zero
/// refill is treated as the "disabled" sentinel, identical to a zero burst.
#[test]
fn allow_ip_refill_zero_does_not_lock_out() {
    let mut prom = PromExporter::bind_with_rate_limit(
        "127.0.0.1:0".parse().unwrap(),
        make_token(),
        /* rate_per_sec */ 0,
        /* rate_burst   */ 10,
    )
    .expect("bind");
    let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    let t = Instant::now();
    // Far more calls than the configured burst — every one must be allowed,
    // since a zero refill rate disables limiting rather than wedging it.
    for _ in 0..1000 {
        assert!(
            prom.allow_ip(ip, t),
            "rate_per_sec=0 must disable limiting, never lock out"
        );
    }
    assert!(
        prom.ip_state.is_empty(),
        "refill=0 path must not allocate per-IP state"
    );
}

fn prom_probe_cluster_ips(count: usize) -> Vec<IpAddr> {
    let table_size = MAX_PROM_IP_STATES
        .saturating_mul(2)
        .max(2)
        .next_power_of_two();
    let mask = table_size - 1;
    let mut ips = Vec::with_capacity(count);

    for host in 1u32..=0x00ff_ffff {
        let ip = IpAddr::V4(Ipv4Addr::new(
            10,
            ((host >> 16) & 0xff) as u8,
            ((host >> 8) & 0xff) as u8,
            (host & 0xff) as u8,
        ));
        if (ip.hash32() as usize & mask) == 0 {
            ips.push(ip);
            if ips.len() == count {
                return ips;
            }
        }
    }

    panic!("could not find {count} IPs for the same Prometheus probe cluster");
}

/// Probe exhaustion is distinct from ordinary capacity pressure: a 64-slot
/// collision cluster can make `IpStateTable::insert` fail while the table is
/// still far below `MAX_PROM_IP_STATES`. New IPs must fail closed here, or an
/// untracked source gets a fresh burst allowance on every retry.
#[test]
fn allow_ip_probe_exhaustion_fails_closed() {
    let mut prom = PromExporter::bind_with_rate_limit(
        "127.0.0.1:0".parse().unwrap(),
        make_token(),
        /* rate_per_sec */ 1,
        /* rate_burst   */ 1,
    )
    .expect("bind");
    let t0 = Instant::now();
    let cluster = prom_probe_cluster_ips(BoundedIndex::<IpAddr>::MAX_PROBE + 1);

    for ip in cluster.iter().take(BoundedIndex::<IpAddr>::MAX_PROBE) {
        assert!(prom.allow_ip(*ip, t0), "seed IP {ip} should be admitted");
    }
    assert_eq!(prom.ip_state.len(), BoundedIndex::<IpAddr>::MAX_PROBE);

    let refused_ip = cluster[BoundedIndex::<IpAddr>::MAX_PROBE];
    assert!(!prom.allow_ip(refused_ip, t0));
    assert!(
        !prom.allow_ip(refused_ip, t0),
        "retries from an unrecordable IP must not receive fresh buckets"
    );

    let idx = drop_reason_index(DropReason::IpTableFull);
    assert_eq!(
        prom.connections_dropped_total[idx], 2,
        "probe-exhausted insert refusals must be visible as ip_table_full pressure"
    );
    assert_eq!(
        prom.ip_state.len(),
        BoundedIndex::<IpAddr>::MAX_PROBE,
        "failed inserts must not perturb tracked source state"
    );

    prom.render_body();
    assert!(
        prom.body_buf
            .contains("varta_prom_ip_state_probe_exhausted_total 2"),
        "probe-exhaustion metric must expose failed inserts:\n{}",
        prom.body_buf
    );
}

/// Filling the per-IP table past `MAX_PROM_IP_STATES` must force-evict
/// the oldest entry and bump
/// `varta_prom_connections_dropped_total{reason="ip_table_full"}`.
#[test]
fn allow_ip_table_full_force_evicts_and_records() {
    let mut prom = PromExporter::bind_with_rate_limit(
        "127.0.0.1:0".parse().unwrap(),
        make_token(),
        /* rate_per_sec */ 1000,
        /* rate_burst   */ 1000,
    )
    .expect("bind");
    // Insert MAX_PROM_IP_STATES distinct IPs at t0; the (N+1)th must
    // trigger force-eviction.  Use IPv4 within 10.0.0.0/8 to avoid any
    // overlap with the loopback used elsewhere in tests.
    let t0 = Instant::now();
    for i in 0..MAX_PROM_IP_STATES {
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            10,
            ((i >> 16) & 0xff) as u8,
            ((i >> 8) & 0xff) as u8,
            (i & 0xff) as u8,
        ));
        assert!(prom.allow_ip(ip, t0));
    }
    assert_eq!(prom.ip_state.len(), MAX_PROM_IP_STATES);

    // One more IP at the same instant — sweep can't free anything
    // because everyone is fresh, so the oldest gets force-evicted.
    let new_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(11, 0, 0, 1));
    assert!(prom.allow_ip(new_ip, t0));
    assert_eq!(
        prom.ip_state.len(),
        MAX_PROM_IP_STATES,
        "table size must remain capped"
    );
    let idx = drop_reason_index(DropReason::IpTableFull);
    assert!(
        prom.connections_dropped_total[idx] >= 1,
        "ip_table_full drop counter must increment on force-eviction"
    );
}

/// M8: every refusal-reason label must be emitted on the first
/// scrape (even at zero) so `absent()` alert rules stay green.
/// Confirms the `debounce_capacity` label joins the
/// pre-existing `unauthenticated_transport` and `cross_namespace_agent`
/// labels with no gaps.
#[test]
fn recovery_refused_debounce_capacity_label_emitted_at_zero() {
    let mut prom = PromExporter::bind("127.0.0.1:0".parse().unwrap(), make_token()).expect("bind");
    prom.render_body();
    let body = &prom.body_buf;
    for reason in RECOVERY_REFUSED_REASON_LABELS.iter() {
        let needle = format!("varta_recovery_refused_total{{reason=\"{reason}\"}} 0");
        assert!(
            body.contains(&needle),
            "missing first-scrape zero line for reason {reason:?}; body:\n{body}"
        );
    }
    // The new evictions + invariant-violations counters must also
    // emit at zero, mirroring the tracker self-health pattern.
    assert!(
        body.contains("varta_recovery_last_fired_evictions_total 0"),
        "evictions counter missing zero line in first scrape"
    );
    assert!(
        body.contains("varta_recovery_invariant_violations_total 0"),
        "invariant-violations counter missing zero line in first scrape"
    );
}

/// M8: bumping the `RefusedDebounceCapacity` outcome counter must
/// drive both the outcome-label and the refused-reason-label
/// arrays.  Confirms `record_recovery_outcome` is the single
/// entry point for the new variant.
#[test]
fn recovery_refused_debounce_capacity_outcome_drives_counters() {
    let mut prom = PromExporter::bind("127.0.0.1:0".parse().unwrap(), make_token()).expect("bind");
    let outcome = crate::recovery::RecoveryOutcome::RefusedDebounceCapacity { pid: 42 };
    prom.record_recovery_outcome(&outcome, None);
    prom.render_body();
    let body = &prom.body_buf;
    assert!(
        body.contains("varta_recovery_outcomes_total{outcome=\"refused_debounce_capacity\"} 1"),
        "outcome counter must increment under refused_debounce_capacity; body:\n{body}"
    );
    assert!(
        body.contains("varta_recovery_refused_total{reason=\"debounce_capacity\"} 1"),
        "refused-reason counter must increment under debounce_capacity; body:\n{body}"
    );
}

/// The deferred-stall freshness guard surfaces its skips as a distinct,
/// benign outcome label (NOT a `refused_*` safety reason). Confirms the new
/// `SkippedAgentResumed` variant drives only the outcome array and leaves
/// every refused-reason counter at zero.
#[test]
fn recovery_skipped_agent_resumed_outcome_drives_only_outcome_counter() {
    let mut prom = PromExporter::bind("127.0.0.1:0".parse().unwrap(), make_token()).expect("bind");
    let outcome = crate::recovery::RecoveryOutcome::SkippedAgentResumed { pid: 7 };
    prom.record_recovery_outcome(&outcome, None);
    prom.render_body();
    let body = &prom.body_buf;
    assert!(
        body.contains("varta_recovery_outcomes_total{outcome=\"skipped_agent_resumed\"} 1"),
        "outcome counter must increment under skipped_agent_resumed; body:\n{body}"
    );
    // A self-heal is not a structural refusal — no reason counter moves.
    for reason in RECOVERY_REFUSED_REASON_LABELS.iter() {
        let needle = format!("varta_recovery_refused_total{{reason=\"{reason}\"}} 0");
        assert!(
            body.contains(&needle),
            "skipped_agent_resumed must not bump refused reason {reason:?}; body:\n{body}"
        );
    }
}

/// The platform-degraded recovery skip (a `KernelAttested` deferred stall with
/// no start-time generation on credential-only platforms) surfaces under its
/// own `skipped_stall_unverifiable` outcome label — distinct from a confirmed
/// `skipped_pid_recycled` — so operators can see kernel-attested recovery is
/// running recycle-unverifiable on their host. It is a benign safety skip, not
/// a structural refusal, so no `refused_*` reason counter moves.
#[test]
fn recovery_skipped_stall_unverifiable_outcome_drives_only_outcome_counter() {
    let mut prom = PromExporter::bind("127.0.0.1:0".parse().unwrap(), make_token()).expect("bind");
    let outcome = crate::recovery::RecoveryOutcome::SkippedStallUnverifiable { pid: 7 };
    prom.record_recovery_outcome(&outcome, None);
    prom.render_body();
    let body = &prom.body_buf;
    assert!(
        body.contains("varta_recovery_outcomes_total{outcome=\"skipped_stall_unverifiable\"} 1"),
        "outcome counter must increment under skipped_stall_unverifiable; body:\n{body}"
    );
    assert!(
        body.contains("varta_recovery_outcomes_total{outcome=\"skipped_pid_recycled\"} 0"),
        "an unverifiable skip must not be conflated with a confirmed recycle; body:\n{body}"
    );
    for reason in RECOVERY_REFUSED_REASON_LABELS.iter() {
        let needle = format!("varta_recovery_refused_total{{reason=\"{reason}\"}} 0");
        assert!(
            body.contains(&needle),
            "skipped_stall_unverifiable must not bump refused reason {reason:?}; body:\n{body}"
        );
    }
}

#[test]
fn recovery_reaped_outcome_records_duration_metrics() {
    use std::os::unix::process::ExitStatusExt;

    let mut prom = PromExporter::bind("127.0.0.1:0".parse().unwrap(), make_token()).expect("bind");
    let outcome = crate::recovery::RecoveryOutcome::Reaped {
        child_pid: 123,
        status: std::process::ExitStatus::from_raw(0),
        duration_ns: 42_000,
    };

    prom.record_recovery_outcome(&outcome, outcome.duration_ns());
    prom.render_body();
    let body = &prom.body_buf;
    assert!(
        body.contains("varta_recovery_outcomes_total{outcome=\"reaped_zero\"} 1"),
        "reaped_zero outcome counter must increment; body:\n{body}"
    );
    assert!(
        body.contains("varta_recovery_duration_ns_sum 42000"),
        "duration sum must include reaped outcome duration; body:\n{body}"
    );
    assert!(
        body.contains("varta_recovery_duration_count_total 1"),
        "duration count must increment for reaped outcomes; body:\n{body}"
    );
}

/// Every stage label must appear in the rendered body even before any
/// observation has landed (stable-label-set contract). Also verifies the
/// `+Inf` literal (not `inf`) is used for the implicit bucket.
#[test]
fn stage_histogram_emits_all_labels_at_zero_on_first_scrape() {
    let mut prom = PromExporter::bind("127.0.0.1:0".parse().unwrap(), make_token()).expect("bind");
    prom.render_body();
    let body = &prom.body_buf;
    for stage_label in STAGE_LABELS.iter() {
        let inf_key =
            format!("varta_observer_stage_seconds_bucket{{stage=\"{stage_label}\",le=\"+Inf\"}} 0");
        assert!(
            body.contains(&inf_key),
            "stage={stage_label} +Inf bucket missing or non-zero at first scrape; body:\n{body}"
        );
        let count_key = format!("varta_observer_stage_seconds_count{{stage=\"{stage_label}\"}} 0");
        assert!(
            body.contains(&count_key),
            "stage={stage_label} _count missing at first scrape; body:\n{body}"
        );
    }
}

/// A single observation lands in the correct stage bucket and increments
/// the per-stage count and sum.
#[test]
fn stage_histogram_records_observation_in_correct_bucket() {
    let mut prom = PromExporter::bind("127.0.0.1:0".parse().unwrap(), make_token()).expect("bind");
    // Record a 2 ms duration for Poll — should land in le="0.005" bucket.
    prom.record_stage_duration(IterStage::Poll, Duration::from_millis(2));
    prom.render_body();
    let body = &prom.body_buf;
    // le="0.005" bucket for Poll must be cumulative 1.
    assert!(
        body.contains("varta_observer_stage_seconds_bucket{stage=\"poll\",le=\"0.005\"} 1"),
        "Poll 2 ms must land in le=0.005; body:\n{body}"
    );
    // count must be 1.
    assert!(
        body.contains("varta_observer_stage_seconds_count{stage=\"poll\"} 1"),
        "Poll count must be 1; body:\n{body}"
    );
    // Other stages must still have count 0.
    assert!(
        body.contains("varta_observer_stage_seconds_count{stage=\"drain_pending\"} 0"),
        "drain_pending count must remain 0; body:\n{body}"
    );
}

/// Regression (bug-477): a single peer that resets its connection must NOT
/// abort the whole `/metrics` serve loop for the tick. Before the fix, an
/// `ECONNRESET` on a freshly-accepted socket made `serve_one` return `Err`,
/// whose `?` aborted `serve_pending` — skipping the freshness commit and the
/// anti-flood drain and abandoning every connection queued behind the hostile
/// one, so a reset-per-tick attacker could starve legitimate scrapers.
///
/// `serve_one` is now infallible: a reset connection becomes
/// `ServeOutcome::Rejected` and the loop proceeds. This queues a hostile
/// (RST-on-close) connection AHEAD of a legitimate authorized one and asserts
/// the legitimate one is still served within a SINGLE `serve_pending` call.
#[cfg(unix)]
#[test]
fn reset_connection_does_not_abort_serve_loop() {
    use std::os::unix::io::AsRawFd;

    #[repr(C)]
    struct Linger {
        l_onoff: i32,
        l_linger: i32,
    }
    // SO_LINGER {l_onoff=1, l_linger=0}: close(2) sends RST immediately.
    #[cfg(target_os = "linux")]
    const SOL_SOCKET: i32 = 1;
    #[cfg(target_os = "linux")]
    const SO_LINGER: i32 = 13;
    #[cfg(not(target_os = "linux"))]
    const SOL_SOCKET: i32 = 0xffff;
    #[cfg(not(target_os = "linux"))]
    const SO_LINGER: i32 = 0x0080;
    extern "C" {
        fn setsockopt(
            fd: i32,
            level: i32,
            optname: i32,
            optval: *const core::ffi::c_void,
            optlen: u32,
        ) -> i32;
    }

    let mut prom = PromExporter::bind("127.0.0.1:0".parse().unwrap(), make_token()).expect("bind");
    let addr = prom.local_addr().expect("local_addr");

    // Hostile connection A: arm RST-on-close, then write an unread byte so the
    // server's read of the reset socket reliably returns ECONNRESET.
    let mut hostile = TcpStream::connect(addr).expect("connect hostile");
    let lin = Linger {
        l_onoff: 1,
        l_linger: 0,
    };
    let rc = unsafe {
        setsockopt(
            hostile.as_raw_fd(),
            SOL_SOCKET,
            SO_LINGER,
            core::ptr::addr_of!(lin) as *const core::ffi::c_void,
            core::mem::size_of::<Linger>() as u32,
        )
    };
    assert_eq!(rc, 0, "SO_LINGER setsockopt failed");
    hostile.write_all(b"X").expect("write hostile byte");

    // Legit connection B: valid authorized GET, queued behind A, kept open.
    let mut legit = TcpStream::connect(addr).expect("connect legit");
    legit
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("read timeout");
    legit
        .write_all(
            format!(
                "GET /metrics HTTP/1.0\r\nAuthorization: Bearer {TEST_TOKEN_HEX}\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .expect("write legit");

    // Let both reach the listen backlog, then RST A.
    std::thread::sleep(Duration::from_millis(150));
    drop(hostile);
    std::thread::sleep(Duration::from_millis(30));

    // A SINGLE serve loop: with the bug, A's ECONNRESET aborts it before B is
    // served; with the fix, A is Rejected and B is served in the same call.
    let _ = prom.serve_pending();

    let mut response = String::new();
    let _ = legit.read_to_string(&mut response);
    assert!(
        response.starts_with("HTTP/1.0 200"),
        "a legit scraper queued behind a reset connection must still be served \
         in the same serve loop; got: {response:?}"
    );
}
