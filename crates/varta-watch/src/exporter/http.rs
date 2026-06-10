//! HTTP/1.0 serving layer for [`super::PromExporter`].
//!
//! Contains the per-IP rate-limit check (`allow_ip`), the connection-accept
//! loop (`serve_pending`), the single-connection handler (`serve_one`), and
//! the stack-allocated write helpers used by `serve_one`.

#[cfg(feature = "prometheus-exporter")]
use std::io::{self, ErrorKind, Read, Write as IoWrite};
#[cfg(feature = "prometheus-exporter")]
use std::net::{IpAddr, Shutdown, TcpStream};
#[cfg(feature = "prometheus-exporter")]
use std::time::Instant;

#[cfg(feature = "prometheus-exporter")]
use super::{
    drop_reason_index, DropReason, ServeOutcome, MAX_PROM_IP_STATES, PROM_IP_STATE_SWEEP_INTERVAL,
    PROM_IP_STATE_TTL, PROM_MAX_CONNECTIONS_PER_SERVE, PROM_MAX_DRAIN_PER_SERVE,
    PROM_MIN_SCRAPE_INTERVAL, PROM_READ_DEADLINE, PROM_REQUEST_CAP, PROM_WRITE_TIMEOUT,
};

#[cfg(feature = "prometheus-exporter")]
pub(super) const PROM_DRAIN_READ_CAP: usize = 4096;

#[cfg(feature = "prometheus-exporter")]
impl super::PromExporter {
    /// Returns `true` and consumes one token if the source IP has tokens
    /// available; otherwise returns `false`.  Capacity-evicts stale or
    /// (as a last resort) the oldest entry when the table is full, and
    /// bumps the corresponding drop counter so operators can observe
    /// rate-limit vs table-full pressure separately.
    pub(super) fn allow_ip(&mut self, ip: IpAddr, now: Instant) -> bool {
        // A zero burst — or a zero refill rate — means "no per-IP limit";
        // skip the bookkeeping entirely. The `rate_per_sec == 0` case is not
        // merely an optimization: a token bucket that never refills would
        // permanently lock out a steady scraper once its initial burst is
        // spent (and `last_seen` updates on every drop keep the entry from
        // aging out of the table), so a zero refill is treated as the same
        // documented "disabled" sentinel as a zero burst rather than as an
        // unsatisfiable limit.
        if self.rate_burst == 0 || self.rate_per_sec == 0 {
            return true;
        }
        let cap_milli: u32 = self.rate_burst.saturating_mul(1000);
        let refill_per_ms: u32 = self.rate_per_sec; // 1000 milli-tokens / 1000 ms

        // Periodic stale sweep — cheap when the table is sparse, bounded
        // by MAX_PROM_IP_STATES iterations when it isn't.
        if now.duration_since(self.last_ip_sweep) >= PROM_IP_STATE_SWEEP_INTERVAL {
            self.last_ip_sweep = now;
            self.ip_state.evict_older_than(now, PROM_IP_STATE_TTL);
        }

        match self.ip_state.get_mut(ip) {
            Some(st) => {
                let elapsed_ms = now.duration_since(st.last_refill).as_millis() as u64;
                if elapsed_ms > 0 {
                    let add_milli =
                        (elapsed_ms as u128 * refill_per_ms as u128).min(u32::MAX as u128) as u32;
                    st.tokens_milli = st.tokens_milli.saturating_add(add_milli).min(cap_milli);
                    st.last_refill = now;
                }
                st.last_seen = now;
                if st.tokens_milli >= 1000 {
                    st.tokens_milli -= 1000;
                    true
                } else {
                    self.connections_dropped_total[drop_reason_index(DropReason::RateLimit)] = self
                        .connections_dropped_total[drop_reason_index(DropReason::RateLimit)]
                    .saturating_add(1);
                    false
                }
            }
            None => {
                let table_full_idx = drop_reason_index(DropReason::IpTableFull);
                let mut recorded_table_pressure = false;
                if self.ip_state.len() >= MAX_PROM_IP_STATES {
                    // Try to make room by evicting stale entries first.
                    self.ip_state.evict_older_than(now, PROM_IP_STATE_TTL);
                }
                if self.ip_state.len() >= MAX_PROM_IP_STATES {
                    // Still full — force-evict the oldest entry.  Count
                    // the event so a sustained horizontal flood is
                    // observable.
                    if let Some(oldest_ip) = self.ip_state.oldest_ip() {
                        self.ip_state.remove(oldest_ip);
                    }
                    self.connections_dropped_total[table_full_idx] =
                        self.connections_dropped_total[table_full_idx].saturating_add(1);
                    recorded_table_pressure = true;
                }
                // New entry starts with a full bucket minus the one token
                // consumed by this connection. If the bounded index cannot
                // record the source, fail closed; otherwise this IP would get
                // a fresh bucket on every retry and bypass the limiter.
                let tokens_milli = cap_milli.saturating_sub(1000);
                if self
                    .ip_state
                    .insert(
                        ip,
                        super::PromIpState {
                            tokens_milli,
                            last_refill: now,
                            last_seen: now,
                        },
                    )
                    .is_err()
                {
                    if !recorded_table_pressure {
                        self.connections_dropped_total[table_full_idx] =
                            self.connections_dropped_total[table_full_idx].saturating_add(1);
                    }
                    return false;
                }
                true
            }
        }
    }

    /// Accept ready connections on the listener and write a metrics
    /// response back to each. Returns `Ok(())` when the accept queue
    /// drains cleanly; returns the first non-`WouldBlock` error otherwise.
    ///
    /// Service budget per call is bounded by two limits (whichever hits
    /// first): a 100 ms wall-clock deadline and
    /// [`PROM_MAX_CONNECTIONS_PER_SERVE`] accepted connections. Both
    /// exist to prevent a storm of slow scrapers from starving the
    /// observer poll loop (stall detection, I/O polling, reaping).
    ///
    /// After the service budget is exhausted, the exporter enters a
    /// drain phase that accepts and immediately closes up to
    /// [`PROM_MAX_DRAIN_PER_SERVE`] additional connections without
    /// serving them.  This prevents the kernel's accept queue from
    /// building up under a connection flood (hostile client opening
    /// thousands of connections).
    pub fn serve_pending(&mut self) -> io::Result<()> {
        let render_fresh = self
            .last_scrape
            .map_or(true, |last| last.elapsed() >= PROM_MIN_SCRAPE_INTERVAL);
        let serve_deadline = Instant::now() + std::time::Duration::from_millis(100);
        let mut served = 0;
        let mut served_fresh = false;
        let result = loop {
            if Instant::now() >= serve_deadline {
                self.scrape_budget_exhausted_total =
                    self.scrape_budget_exhausted_total.saturating_add(1);
                break Ok(());
            }
            if served >= PROM_MAX_CONNECTIONS_PER_SERVE {
                self.scrape_budget_exhausted_total =
                    self.scrape_budget_exhausted_total.saturating_add(1);
                break Ok(());
            }
            match self.listener.accept() {
                Ok((stream, peer)) => {
                    // Per-IP rate limit applies even before serve-budget
                    // counting: dropping a rate-limited connection costs
                    // an accept(2) + drop(2) but no body render, and does
                    // not consume the 8-conn budget.  This keeps a single
                    // hostile IP from squeezing out legitimate scrapers.
                    if !self.allow_ip(peer.ip(), Instant::now()) {
                        drop(stream);
                        continue;
                    }
                    match self.serve_one(stream, render_fresh)? {
                        ServeOutcome::ServedFresh => served_fresh = true,
                        ServeOutcome::ServedCached => {
                            self.scrape_skipped_total = self.scrape_skipped_total.saturating_add(1);
                        }
                        ServeOutcome::Rejected => {}
                    }
                    served += 1;
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break Ok(()),
                Err(e) => break Err(e),
            }
        };
        // Advance the freshness window only when an authorized client actually
        // received a freshly-rendered body. Keying this on the raw accepted-
        // connection count (`served`) let an unauthenticated 401/405 request —
        // a stray `curl`, a k8s TCP liveness probe, or a hostile peer — commit
        // `last_scrape` with an unchanged (possibly still-empty at startup)
        // `body_buf`, starving the legitimate scraper of fresh-or-any metrics
        // for up to one full scrape interval. `served` is retained only as the
        // per-tick service budget counter above.
        if served_fresh {
            self.last_scrape = Some(Instant::now());
        }
        let mut drained = 0;
        while drained < PROM_MAX_DRAIN_PER_SERVE {
            if Instant::now() >= serve_deadline + std::time::Duration::from_millis(100) {
                break;
            }
            match self.listener.accept() {
                Ok((stream, peer)) => {
                    // Update the IP bucket even on drained connections so a
                    // sustained flooder doesn't get a free pass once the
                    // serve budget is exhausted — its bucket continues to
                    // drain toward 0 and stays there.
                    let _ = self.allow_ip(peer.ip(), Instant::now());
                    drop(stream);
                    drained += 1;
                    self.connections_dropped_total[drop_reason_index(DropReason::Drain)] = self
                        .connections_dropped_total[drop_reason_index(DropReason::Drain)]
                    .saturating_add(1);
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
        result
    }

    fn serve_one(&mut self, mut stream: TcpStream, render_fresh: bool) -> io::Result<ServeOutcome> {
        // Linux accept4(2) with SOCK_CLOEXEC does *not* propagate O_NONBLOCK
        // to the accepted socket — the man page is explicit on this.  Set it
        // unconditionally so the deadline loops below are the actual latency
        // bounds, not a kernel blocking wait.  Do *not* use set_read_timeout /
        // set_write_timeout: those silently re-enable blocking mode.
        stream.set_nonblocking(true)?;
        let deadline = Instant::now() + PROM_READ_DEADLINE;
        // PROM_REQUEST_CAP bytes covers the widest real-world request: a
        // Prometheus request line + Authorization header + verbose user-agent /
        // Accept / Accept-Encoding headers can exceed 512 bytes on some
        // scrapers.  We accumulate across reads so headers split across
        // multiple TCP segments are still contiguous when we scan for
        // `Authorization:`.
        let mut buf = [0u8; PROM_REQUEST_CAP];
        let mut total = 0;
        loop {
            if Instant::now() >= deadline {
                break;
            }
            if total >= buf.len() {
                break;
            }
            match stream.read(&mut buf[total..]) {
                Ok(0) => break,
                Ok(n) => {
                    total += n;
                    if buf[..total].windows(4).any(|w| w == b"\r\n\r\n")
                        || total >= PROM_REQUEST_CAP
                    {
                        break;
                    }
                }
                // The request may not have arrived on a just-accepted
                // non-blocking socket yet. Yield and retry rather than
                // bailing on the first WouldBlock — the deadline check at
                // the loop head is the real latency bound (see the
                // set_nonblocking comment above). Breaking here instead
                // mis-reads a not-yet-arrived request as empty, replies 405,
                // and closes; the request bytes then land in the receive
                // buffer and close(2) emits an RST (macOS/BSD), surfacing as
                // "Connection reset by peer" on the scraper. Mirrors
                // write_all_nonblocking's WouldBlock handling.
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    std::thread::yield_now();
                    continue;
                }
                Err(e) => return Err(e),
            }
        }

        if total < 4 || buf[..4] != *b"GET " {
            let response = b"HTTP/1.0 405 Method Not Allowed\r\nAllow: GET\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            let cleanup_deadline = Instant::now() + PROM_WRITE_TIMEOUT;
            let _ = write_all_nonblocking(&mut stream, response, cleanup_deadline);
            drain_read_to_would_block(&mut stream, cleanup_deadline);
            let _ = stream.shutdown(Shutdown::Write);
            return Ok(ServeOutcome::Rejected);
        }

        // Bearer-token auth.  Header parsing skips the request line and
        // walks CRLF-terminated header fields until either Authorization
        // is found (and its 64-hex Bearer value matches the configured
        // token in constant time) or the headers run out.  All failure
        // paths bump `prom_auth_failures_total` and return 401 without ever
        // touching the response body.
        let authorized = match super::bearer_token::parse_authorization_bearer(&buf[..total]) {
            Some(presented) => varta_vlp::ct_eq(&presented, self.token.as_bytes()),
            None => false,
        };
        if !authorized {
            self.prom_auth_failures_total = self.prom_auth_failures_total.saturating_add(1);
            let response = b"HTTP/1.0 401 Unauthorized\r\nWWW-Authenticate: Bearer realm=\"varta\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            let cleanup_deadline = Instant::now() + PROM_WRITE_TIMEOUT;
            let _ = write_all_nonblocking(&mut stream, response, cleanup_deadline);
            drain_read_to_would_block(&mut stream, cleanup_deadline);
            let _ = stream.shutdown(Shutdown::Write);
            return Ok(ServeOutcome::Rejected);
        }

        if render_fresh {
            self.render_body();
        }
        let body_len = self.body_buf.len();
        let write_deadline = Instant::now() + PROM_WRITE_TIMEOUT;
        // Write headers and body in two parts to avoid allocating a
        // combined response String.
        let _ = write_headers_with_len(&mut stream, body_len, write_deadline);
        let _ = write_all_nonblocking(&mut stream, self.body_buf.as_bytes(), write_deadline);
        drain_read_to_would_block(&mut stream, write_deadline);
        let _ = stream.shutdown(Shutdown::Write);
        // An authorized client was served. `render_fresh` decides whether the
        // body it received was freshly rendered (advances `last_scrape`) or
        // came from the cache (counts as a skipped scrape).
        Ok(if render_fresh {
            ServeOutcome::ServedFresh
        } else {
            ServeOutcome::ServedCached
        })
    }
}

/// Write the HTTP 200 response line and headers (including Content-Length)
/// into `stream` using a stack buffer so no heap allocation occurs on the
/// `/metrics` scrape path.
#[cfg(feature = "prometheus-exporter")]
pub(super) fn write_headers_with_len(
    stream: &mut TcpStream,
    body_len: usize,
    deadline: Instant,
) -> io::Result<()> {
    let mut buf = [0u8; 128];
    let prefix = b"HTTP/1.0 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: ";
    let suffix = b"\r\nConnection: close\r\n\r\n";
    let len_str_len = write_usize(&mut buf[prefix.len()..], body_len);
    let total = prefix.len() + len_str_len + suffix.len();
    buf[..prefix.len()].copy_from_slice(prefix);
    buf[prefix.len() + len_str_len..total].copy_from_slice(suffix);
    write_all_nonblocking(stream, &buf[..total], deadline)
}

/// Write `n` as decimal ASCII into `buf` and return the number of bytes
/// written.
///
/// `usize` on 64-bit can require up to 20 decimal digits.  The caller must
/// ensure `buf` is large enough; the debug assertion catches undersized
/// buffers at test time and has zero overhead in release builds.
#[cfg(feature = "prometheus-exporter")]
fn write_usize(buf: &mut [u8], mut n: usize) -> usize {
    debug_assert!(
        buf.len() >= 20,
        "write_usize: buffer too small ({})",
        buf.len()
    );
    if n == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut pos = buf.len();
    while n > 0 {
        pos -= 1;
        buf[pos] = (n % 10) as u8 + b'0';
        n /= 10;
    }
    let len = buf.len() - pos;
    buf.copy_within(pos.., 0);
    len
}

/// Maximum number of `yield_now()` calls per `write_all_nonblocking`
/// invocation.  At ~100 µs per yield (macOS) and 10 yields this bounds
/// scheduler concessions to ~1 ms, well within the 50 ms
/// [`PROM_WRITE_TIMEOUT`].
#[cfg(feature = "prometheus-exporter")]
const MAX_WRITE_YIELDS: usize = 10;

/// Non-blocking `write_all` with a wall-clock deadline. Returns `Ok(())`
/// whether the full buffer was written or the deadline expired; the caller
/// is responsible for deciding whether a short write is an error.
///
/// On `WouldBlock` the loop yields the thread to the OS scheduler rather
/// than busy-spinning.  To prevent a persistently-full TCP send buffer from
/// starving the observer poll loop, the function yields at most
/// [`MAX_WRITE_YIELDS`] times before giving up on the current buffer.
///
/// `yield_now()` can be surprisingly long on macOS (~100 µs).  With the
/// 50 ms [`PROM_WRITE_TIMEOUT`] a 10-yield budget is safe.
#[cfg(feature = "prometheus-exporter")]
pub(super) fn write_all_nonblocking(
    stream: &mut TcpStream,
    buf: &[u8],
    deadline: Instant,
) -> io::Result<()> {
    let mut written = 0;
    let mut yields = 0;
    while written < buf.len() {
        if Instant::now() >= deadline {
            break;
        }
        match stream.write(&buf[written..]) {
            Ok(0) => break,
            Ok(n) => written += n,
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                if yields >= MAX_WRITE_YIELDS {
                    break;
                }
                yields += 1;
                std::thread::yield_now();
                continue;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Drain a bounded amount of unread data from the peer's send buffer so that
/// `shutdown(SHUT_WR)` usually sends a graceful FIN instead of RST.
///
/// On macOS, calling `shutdown(SHUT_WR)` on a non-blocking socket that has
/// unread data in the receive buffer triggers an RST rather than a TCP FIN.
/// This best-effort non-blocking drain handles normal scrape headers while
/// refusing to spend unbounded poll-loop time on a peer that keeps the socket
/// readable after the response has already been written.
#[cfg(feature = "prometheus-exporter")]
pub(super) fn drain_read_to_would_block(stream: &mut TcpStream, deadline: Instant) {
    let mut buf = [0u8; 128];
    let mut drained = 0usize;
    while drained < PROM_DRAIN_READ_CAP && Instant::now() < deadline {
        let remaining = PROM_DRAIN_READ_CAP - drained;
        let chunk_len = buf.len().min(remaining);
        match stream.read(&mut buf[..chunk_len]) {
            Ok(0) => break,
            Ok(n) => {
                drained += n;
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
            Err(_) => break,
        }
    }
}
