use super::types::Config;

impl Config {
    /// Class-A (compile-time-config) builds replace the long help body with
    /// a neutral one-liner so the binary's `strings` output never carries
    /// flag literals.  The static `pub const` is always linked into the
    /// binary — even when the corresponding code path is `#[cfg]`-gated —
    /// so the only way to keep flag names out of the binary is to keep
    /// them out of the constant body itself.
    #[cfg(feature = "compile-time-config")]
    pub const HELP: &'static str = "varta-watch (compile-time configured; no argv accepted; see \
         book/src/architecture/compile-time-config.md)\n";

    /// Verbatim `--help` text. The acceptance test asserts that every
    /// documented long-flag substring appears in this body.
    #[cfg(not(feature = "compile-time-config"))]
    pub const HELP: &'static str = "\
varta-watch — observe Varta Lifeline Protocol agents over configurable transports.

USAGE:
    varta-watch --socket <PATH> --threshold-ms <MS> [OPTIONS]

REQUIRED:
    --socket <PATH>                Path to bind the observer's UDS.
    --threshold-ms <MS>            Per-pid silence window before a stall is
                                    surfaced (milliseconds).

OPTIONAL:
    --recovery-cmd <TEMPLATE>      Shell fragment run on each unique stall
                                     via the system shell with the stalled
                                     pid passed as $1. SECURITY: the
                                     template body is under full operator
                                     control; never accept it from an
                                     untrusted source. Requires --features
                                     unsafe-shell-recovery at build time.
    --recovery-exec <CMD>          Command and arguments invoked via execvp
                                     on each unique stall. Split on
                                     whitespace into argv; {pid} in any
                                     argument is replaced with the numeric
                                     PID. No shell — metacharacters have
                                     no effect. Mutually exclusive with
                                     --recovery-cmd.
    --recovery-cmd-file <PATH>     Read --recovery-cmd template from a file.
                                     File must be owned by the observer's
                                     UID and mode 0600 or stricter.
                                     Requires --features
                                     unsafe-shell-recovery at build time.
    --recovery-exec-file <PATH>    Read --recovery-exec command from a file
                                     with the same permission requirements
                                     as --recovery-cmd-file.
    --recovery-debounce-ms <MS>    Per-pid debounce window for recovery
                                     invocations (default 1000).
    --recovery-env <KEY=VALUE>     Repeatable. Pass an environment variable
                                     to recovery child processes. When set,
                                     the child's environment is cleared and
                                     only PATH=/usr/bin:/bin plus these
                                     explicit variables are set. Without this
                                     flag the child inherits the observer's
                                     environment.
    --socket-mode <OCTAL>           File mode for the observer socket
                                     (default 0600 — owner-only r/w).
    --export-file <PATH>            Append one tab-separated event line per
                                     observer event to this file.
    --export-file-max-bytes <N>     Rotate export file when its size exceeds
                                     N bytes (keeps up to 5 generations:
                                     PATH.1 .. PATH.5).  Without this flag
                                     the file grows without bound.
    --export-file-sync-every <N>    Force fdatasync(2) on the export file
                                     every N records appended. 0 (default)
                                     disables per-record durability — the
                                     BufWriter is flushed only on clean
                                     shutdown and during rotation, so a
                                     crash can lose up to one BufWriter
                                     worth of events. Non-zero values
                                     trade IO for crash-time durability;
                                     `1` matches the recovery audit log's
                                     per-record guarantee.
    --prom-addr <IP:PORT>          Bind a Prometheus text-format endpoint at
                                    GET /metrics on this address.  Requires
                                    --prom-token-file; /metrics has no
                                    anonymous access.
    --prom-token-file <PATH>       Path to a file containing the 64-hex-char
                                     bearer token enforced on every /metrics
                                     scrape.  File must be mode 0600 or
                                     stricter, owned by the observer UID,
                                     not a symlink.  Required when
                                     --prom-addr is set.  Scrapers must send
                                     'Authorization: Bearer <hex>' to
                                     receive 200; missing/wrong tokens
                                     return 401 and bump
                                     varta_prom_auth_failures_total.
    --shutdown-grace-ms <MS>       Maximum time the daemon spends in
                                     Recovery::drop waiting for outstanding
                                     recovery children to exit after SIGKILL
                                     during shutdown.  Default 5000.  Minimum
                                     100.  systemd unit's TimeoutStopSec
                                     must be at least this value plus ~2
                                     seconds of reap margin.
    --recovery-timeout-ms <MS>     Kill-after deadline for recovery children;
                                     if a child runs longer than this it is
                                     killed via kill(2) (default: none —
                                     child runs until completion).
    --read-timeout-ms <MS>         UDS read timeout per poll call
                                     (default 100).  Bounded so a stalled peer
                                     cannot hold the observer loop indefinitely.
    --tracker-capacity <N>          Maximum number of distinct agent pids
                                      tracked concurrently (default 256).
                                      Beats for new pids beyond this limit are
                                      dropped.
    --eviction-scan-window <N>      Maximum slots scanned per eviction
                                      attempt (default 256). Smaller = lower
                                      per-frame upper bound; a full table
                                      sweep takes ceil(tracker_capacity / N)
                                      calls. Range [1, 4096].
    --tracker-eviction-policy <P>   Eviction policy when tracker is full:
                                      strict (default) evicts only confirmed-
                                      stalled agents; balanced falls back to
                                      evicting the oldest active slot to
                                      prevent capacity-exhaustion attacks.
    --clock-source <MODE>          Kernel clock for stall-threshold
                                     accounting:
                                       monotonic     (default; pauses during
                                                     suspend on Linux/BSD/
                                                     macOS — SRE semantics)
                                       boottime      (Linux only; advances
                                                     through suspend —
                                                     medical/embedded)
                                       monotonic-raw (macOS/iOS only;
                                                     mach_continuous_time;
                                                     advances through sleep —
                                                     macOS equivalent of
                                                     boottime)
                                     See book/src/architecture/safety-profiles.md.
    --shutdown-after-secs <SECS>   Exit cleanly after the given uptime
                                     (used by integration tests).
    --udp-port <PORT>              Bind a UDP listener on this port for
                                     network-based agents (requires --features
                                     udp at build time). Combine with UDS or
                                     use alone.
    --udp-bind-addr <IP>           IP address to bind the UDP listener on.
                                     Defaults to 127.0.0.1 (loopback) when
                                     secure-UDP keys are configured, and
                                     0.0.0.0 when only plaintext UDP is in
                                     play.  A non-loopback secure-UDP bind
                                     requires --i-accept-secure-udp-non-loopback.
                                     Requires --udp-port.
    --key-file <PATH>              Path to a file containing a 64-hex-char
                                     key for secure UDP (requires --features
                                     secure-udp at build time).
    --accepted-key-file <PATH>     Path to a file with one hex key per line
                                     for zero-downtime rotation (requires
                                     --features secure-udp).
    --master-key-file <PATH>       Path to a file containing a 64-hex-char
                                     master key for per-agent key derivation
                                     (requires --features secure-udp).
    --max-beat-rate <N>            Per-pid maximum beat rate in beats/sec.
                                     Beats arriving faster than this rate
                                     from the same pid are dropped.
                                     Default: unlimited.
    --heartbeat-file <PATH>        Write a timestamp + loop-counter line to
                                     this file on every poll iteration.
                                     External watchdogs can monitor the file
                                     mtime to detect observer stalls.
    --self-watchdog-secs <SECS>    Spawn a background thread that (a) calls
                                     process::abort() if the poll loop has
                                     not ticked for longer than SECS seconds
                                     and (b) emits systemd WATCHDOG=1 from
                                     its own cadence.  Catches hung poll
                                     loops AND silent watchdog-thread
                                     deaths (H5 — see
                                     book/src/architecture/observer-liveness.md).
                                     Auto-enabled with a 4 s deadline when
                                     $WATCHDOG_USEC is set by the service
                                     manager.  Minimum 1.
    --hw-watchdog <PATH>           Open a hardware watchdog device (e.g.
                                     /dev/watchdog) and kick it once per
                                     poll iteration. On clean shutdown the
                                     magic-close byte 'V' is written to
                                     disarm the watchdog.
    --prom-rate-limit-per-sec <N>  Per-source-IP refill rate for the
                                     /metrics endpoint token bucket
                                     (default 5).  Scrapes from any single
                                     IP arriving faster than this rate are
                                     accepted and immediately closed
                                     without serving.  Counted as
                                     varta_prom_connections_dropped_total
                                     {reason=\"rate_limit\"}.
    --prom-rate-limit-burst <N>    Maximum burst (and bucket capacity) for
                                     the per-source-IP token bucket
                                     (default 10).  Tune higher only if
                                     legitimate scrapers cluster requests.
    --i-accept-plaintext-udp       UNSAFE: explicitly accept the security
                                     risk of binding an unauthenticated
                                     plaintext UDP listener.  Required
                                     when --udp-port is set and no
                                     --key-file / --master-key-file is
                                     configured.  Build must also include
                                     --features unsafe-plaintext-udp.  NOT
                                     for production / safety-critical use;
                                     any device with network reach to the
                                     bound port can inject heartbeats.
    --i-accept-secure-udp-non-loopback
                                   UNSAFE: explicitly accept the security
                                     risk of binding a secure-UDP listener
                                     to a non-loopback address.  The
                                     per-sender replay-state map carries a
                                     1-deep eviction shadow; an attacker
                                     with ≥1025 spoofable UDP source
                                     addresses can rotate the shadow and
                                     replay one captured frame per target
                                     sender.  Required whenever
                                     --udp-bind-addr is set to any address
                                     other than 127.0.0.0/8 or ::1 while
                                     secure-UDP keys are configured.
                                     Restrict the listener's reach with
                                     firewall rules or a private VLAN
                                     before enabling.  See
                                     book/src/architecture/vlp-transports.md.
    --i-accept-shell-risk          UNSAFE: explicitly accept the security
                                     risk of shell-mode recovery
                                     (--recovery-cmd / --recovery-cmd-file).
                                     Required to use shell-mode at all;
                                     without this flag, only --recovery-exec
                                     / --recovery-exec-file are permitted.
                                     Shell mode spawns the system shell
                                     with root-equivalent process authority
                                     — prefer --recovery-exec for any
                                     production deployment. Build must also
                                     include --features unsafe-shell-recovery.
    --secure-udp-i-accept-recovery-on-unauthenticated-transport
                                   UNSAFE: accept the security risk of
                                     running a recovery command while the
                                     secure-UDP listener is bound.  Secure
                                     UDP authenticates wire bytes but cannot
                                     attest the sending process — a holder
                                     of the AEAD key can forge a beat for
                                     any pid.  Without this flag, combining
                                     --udp-port (with key files) and a
                                     recovery command is rejected at startup.
                                     This flag stamps beats from the secure-
                                     UDP listener as operator-attested so
                                     the runtime recovery gate fires.
    --plaintext-udp-i-accept-recovery-on-unauthenticated-transport
                                   UNSAFE: accept the security risk of
                                     running a recovery command while the
                                     plaintext-UDP listener is bound.
                                     Plaintext UDP has no authentication —
                                     any host can forge any frame.  Without
                                     this flag, combining --udp-port (without
                                     key files) and a recovery command is
                                     rejected at startup.  This flag stamps
                                     beats from the plaintext-UDP listener
                                     as operator-attested so recovery fires.
    --allow-cross-namespace-agents UNSAFE: permit beats and recovery for
                                     agents whose kernel-attested PID
                                     namespace differs from the observer's.
                                     Default behaviour drops cross-namespace
                                     beats at receive and refuses recovery
                                     with reason=cross_namespace_agent. Use
                                     only when agents run with --pid=host or
                                     an out-of-band PID translator is in the
                                     recovery template — otherwise kill(2)
                                     would target the wrong process. Linux
                                     only; no-op on other platforms. See
                                     book/src/architecture/namespaces.md.
    --strict-namespace-check       Treat a cross-namespace agent as a fatal
                                     startup error instead of the default
                                     refuse-recovery behaviour. Useful when
                                     the operator wants the daemon to fail
                                     loudly rather than silently log audit
                                     refusals.
    --recovery-audit-file <PATH>   Append a tab-separated audit record for
                                     every recovery spawn and completion.
                                     Records carry wall-clock + observer
                                     timestamps, agent pid, child pid,
                                     mode, outcome, exit code, signal,
                                     duration, and captured stdio
                                     lengths. The file is created mode
                                     0600.
    --recovery-audit-max-bytes <N> Rotate the audit file after every write
                                     that pushes it above N bytes. Up to
                                     5 generations kept.
    --recovery-audit-sync-every <N> How many records to write between
                                     forced fdatasync(2) calls on the
                                     audit file. Default 1 (sync every
                                     record) — the only IEC 62304
                                     Class C-conforming value. Values >1
                                     emit a startup warning. 0 is
                                     rejected at parse time.
    --recovery-capture-stdio       Capture child stdout/stderr non-
                                     blockingly so its length and
                                     truncation status appear in the audit
                                     record. Off by default — opt in only
                                     when you have a recovery command whose
                                     output is bounded.
    --recovery-capture-bytes <N>   Total combined byte cap (stdout +
                                     stderr) per child when capture is
                                     enabled. Default 4096; max 1048576.
    --iteration-budget-ms <MS>     Soft per-iteration budget for the
                                     observer poll loop. Iterations that
                                     exceed this increment
                                     varta_observer_iteration_budget_exceeded_total
                                     and are visible in the
                                     varta_observer_iteration_seconds
                                     histogram. Advisory only — hard
                                     wedges are caught by
                                     --self-watchdog-secs.  Default 250.
                                     Range [50, 60000].  See
                                     book/src/architecture/observer-liveness.md
                                     for the worst-case derivation.
    --scrape-budget-ms <MS>        Soft per-call budget for serve_pending
                                     (the /metrics serving phase of one
                                     poll iteration). Overruns increment
                                     varta_observer_scrape_budget_exceeded_total
                                     and are visible in
                                     varta_observer_serve_pending_seconds.
                                     Separates scrape-storm alarms from
                                     beat-path slowness. Default 250.
                                     Range [50, 60000].

    -h, --help                     Print this message and exit.
";
}
