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
    --recovery-exec <CMD>          Command and arguments invoked via execvp
                                     on each unique stall. Split on
                                     whitespace into argv; {pid} in any
                                     argument is replaced with the numeric
                                     PID. No shell — metacharacters have
                                     no effect.
    --recovery-exec-file <PATH>    Read --recovery-exec command from a file.
                                     File must be owned by the observer's
                                     UID and mode 0600 or stricter.
    --recovery-debounce-ms <MS>    Per-pid debounce window for recovery
                                     invocations (default 1000).
    --recovery-env <KEY=VALUE>     Repeatable. Pass an environment variable
                                     to recovery child processes. Layered on
                                     top of the base env (cleared by default;
                                     inherited if --recovery-inherit-env is
                                     set).
    --recovery-inherit-env         Inherit the observer's full environment
                                     into recovery child processes (legacy
                                     behaviour). WARNING: any AWS_*,
                                     *_TOKEN, OAuth bearers, or database
                                     URLs in the observer's env will be
                                     visible to recovery subprocesses. The
                                     default (without this flag) is to
                                     clear the child env to PATH=/usr/bin:
                                     /bin plus any explicit --recovery-env
                                     entries. Use --recovery-env KEY=VAL
                                     instead of this flag whenever feasible.
    --socket-mode <OCTAL>           File mode for the observer socket
                                     (default 0600 — owner-only r/w).
    --export-file <PATH>            Append one tab-separated event line per
                                     observer event to this file. Existing
                                     files must be observer-owned, readable
                                     and writable regular files with one hard
                                     link; leaf symlinks are rejected.
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
                                     100, maximum 60000.  systemd unit's
                                     TimeoutStopSec must be at least this
                                     value plus ~2 seconds of reap margin.
    --recovery-timeout-ms <MS>     Kill-after deadline for recovery children;
                                     if a child runs longer than this it is
                                     killed via kill(2) (default: none —
                                     child runs until completion).
    --read-timeout-ms <MS>         UDS read timeout per poll call
                                     (default 100).  Bounded so a stalled peer
                                     cannot hold the observer loop indefinitely;
                                     lower when --self-watchdog-secs is tight.
    --tracker-capacity <N>          Maximum number of distinct agent pids
                                      tracked concurrently (default 256).
                                      Range [1, 4096].
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
    --signal-handler-mode <MODE>   Signal-handler installation path on Linux:
                                       direct  (default) — direct rt_sigaction(2)
                                                syscall; owns the kernel ABI
                                                end-to-end including the x86_64
                                                trampoline. Startup readback +
                                                live SIGUSR1 smoke test verify
                                                correctness before the first
                                                real SIGTERM.
                                       libc    — libc sigaction(3) fallback;
                                                sa_restorer is libc's __restore_rt.
                                                Use when running on a kernel not
                                                yet certified for the direct path.
                                     Ignored on macOS/FreeBSD (libc is the only
                                     option). See
                                     book/src/architecture/signal-install.md.
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
                                     from the same pid are dropped and
                                     counted via varta_rate_limited_total
                                     {reason=\"per_pid\"}.  Default: 100.
                                     Set to 0 to disable.
    --global-beat-rate <N>         Global frame admission cap across all
                                     senders (frames/sec), including
                                     authenticated rejection events.
                                     Defends against per-pid rotation
                                     attacks.  Default: 5000.
                                     Set to 0 to disable.
    --global-beat-burst <N>        Global token-bucket burst capacity.
                                     Default: 10000.
    --uds-rcvbuf-bytes <N>         SO_RCVBUF size requested for the
                                     observer UDS socket (bytes).  Linux
                                     doubles and clamps to rmem_max;
                                     the granted size is surfaced as
                                     varta_observer_uds_rcvbuf_bytes.
                                     Default: 1048576.  Maximum: 2147483647.
                                     Set to 0 to leave the kernel default.
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
                                     manager.  Minimum 1 (0 is rejected;
                                     omit the flag to disable the watchdog).
    --hw-watchdog <PATH>           Open a hardware watchdog device (e.g.
                                     /dev/watchdog) and kick it once per
                                     poll iteration. On clean shutdown the
                                     magic-close byte 'V' is written to
                                     disarm watchdogs that support it. On
                                     supported Linux builds, startup verifies
                                     the watchdog ioctl API, close semantics,
                                     and a >=30 s timeout floor.
    --prom-rate-limit-per-sec <N>  Per-source-IP refill rate for the
                                     /metrics endpoint token bucket
                                     (default 5).  Scrapes from any single
                                     IP arriving faster than this rate are
                                     accepted and immediately closed
                                     without serving.  Counted as
                                     varta_prom_connections_dropped_total
                                     {reason=\"rate_limit\"}.  0 disables
                                     per-IP rate limiting (same as a 0 burst).
    --prom-rate-limit-burst <N>    Maximum burst (and bucket capacity) for
                                     the per-source-IP token bucket
                                     (default 10).  Tune higher only if
                                     legitimate scrapers cluster requests.
    --i-accept-plaintext-udp       UNSAFE: explicitly accept the security
                                     risk of binding an unauthenticated
                                     plaintext UDP listener.  Required
                                     when --udp-port is set and no
                                     --key-file / --accepted-key-file /
                                     --master-key-file is configured.
                                     Build must also include
                                     --features unsafe-plaintext-udp.  NOT
                                     for production / safety-critical use;
                                     any device with network reach to the
                                     bound port can inject heartbeats.
    --i-accept-secure-udp-non-loopback
                                   UNSAFE: explicitly accept the security
                                     risk of binding a secure-UDP listener
                                     to a non-loopback address.  The
                                     per-sender replay-state table is bounded
                                     and fails closed when full; a reachable
                                     network can still deny admission for new
                                     agents with authenticated high-cardinality
                                     traffic.  Required whenever
                                     --udp-bind-addr is set to any address
                                     other than 127.0.0.0/8 or ::1 while
                                     secure-UDP keys are configured.
                                     Restrict the listener's reach with
                                     firewall rules or a private VLAN
                                     before enabling.  See
                                     book/src/architecture/vlp-transports.md.
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
    --audit-fsync-budget-ms <MS>   Soft per-call budget for a single
                                     fdatasync(2) on the audit file. If
                                     one fsync exceeds this, the
                                     remaining records in the current
                                     drain are written-to-BufWriter only
                                     and the fsync is deferred to the
                                     next tick — bounds the worst-case
                                     poll stall on a slow disk to one
                                     fsync per tick. Overruns increment
                                     varta_audit_fsync_budget_exceeded_total.
                                     Default 50. 0 is rejected at parse
                                     time.
    --audit-sync-interval-ms <MS>  Time-based fdatasync cadence in
                                     addition to --recovery-audit-sync-every.
                                     0 (default) disables the time
                                     cadence; with a non-zero value the
                                     drain force-syncs after this many
                                     ms have elapsed since the last
                                     sync. Operators on safety-critical
                                     profiles keep
                                     --recovery-audit-sync-every=1 and
                                     ignore this flag.
    --audit-rotation-budget-ms <MS> Per-tick wall-clock budget for the
                                     audit-log rotation state machine.
                                     Rotation (rename × 5 + reopen +
                                     header + boot record + fsync)
                                     advances incrementally; if a tick
                                     exceeds this budget the state is
                                     preserved and the next tick
                                     resumes. Overruns increment
                                     varta_audit_rotation_budget_exceeded_total.
                                     Default 50. Range 1-250 ms; a value at or
                                     above the Maintenance-stage self-watchdog
                                     abort would let a normal rotation abort a
                                     healthy observer.
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
