# Launch posts — ready to copy/paste

Distribution is the bottleneck, not the product. A landing page does not pull
traffic; these do. Post them where the niche actually reads. Measure GitHub
clones/stars and crates.io / PyPI downloads — not website visits.

**Order to ship (one per day, not all at once):**
1. Show HN (Tue–Thu, ~8–10am ET lands best)
2. r/rust (after HN, link the HN thread if it did well)
3. lobste.rs (`show` tag — only if you have an account in good standing)
4. r/embedded (frame for constrained/no-systemd fleets)

For every thread: **reply fast in the first hour**, stay technical, concede the
1:1-systemd case up front. The pre-written "why not systemd" answer is below.

---

## Show HN

**Title** (74 chars):

```
Show HN: One observer watches thousands of local daemons via 32-byte heartbeats
```

**Body:**

```
A background worker on one of our boxes wedged for ~40 minutes. The process was still "up" — PID alive, no crash, no log line — it just stopped doing work. We found out from a customer, not from the machine. The only liveness signal we had was "the process exists," which is useless when a thread deadlocks or an event loop stalls.

I didn't want to bolt an HTTP server and a /healthz onto every daemon, write a systemd unit per PID, or drag in an orchestrator for processes that all live on one host. So I built a small Rust library + observer.

An agent calls beat(status, payload), which encodes a 32-byte frame on the stack and hands it to send(2) on a non-blocking Unix datagram socket — no allocation after connect, ~1.2µs p99. One observer binary decodes every beat in a single-threaded poll loop, tracks per-PID silence thresholds, runs a debounced recovery command (e.g. systemctl restart) when an agent goes dark, and exports /metrics for the whole fleet. One process watches thousands; each costs 32 bytes a beat.

The production crates have an empty dependency list (no tokio/serde/libc). It runs no_std on bare metal, and there's a build profile that compiles out the HTTP server and arg parser for safety-critical use. Clients exist for Rust/Python/Go/Node/.NET/JVM, all speaking one frozen wire format.

Tradeoffs: it's local-first and niche. For a single process, a systemd unit does this fine. UDP mode exists but recovery is refused for unattested beats.

cargo add varta-client / pip install varta
Observer: curl -fsSL https://varta.sh/install.sh | sh

https://github.com/aramirez087/Varta

Is the single-threaded poll loop the right call, or am I going to regret it at fleet scale?
```

**Your own first comment** (post it right after submitting, to frame the top objection):

```
Expected first question: why not systemd WatchdogSec, a k8s liveness probe, or a /health endpoint? Honestly, for a single long-lived service, systemd's WatchdogSec is the right tool and I'd reach for it first — this isn't trying to replace that. The gap it fills is when you have many processes on one host and the per-process options get expensive: a systemd unit (and sd_notify watchdog wiring) per PID, or an HTTP server + /healthz bolted onto every daemon just to answer "are you actually doing work?", or k8s where you don't have or want a control plane (embedded, edge, non-systemd hosts, inside a container with no orchestrator). Here one observer decodes a 32-byte datagram from each process, so adding the 10,001st watched process costs 32 bytes a beat instead of another unit/endpoint/pod. It's also polyglot — a fleet of Rust/Python/Go/Node workers all report liveness over one frozen wire format instead of each language reinventing a probe — and there's a Class-A build that structurally removes the HTTP server, arg parser, and shell-exec for medical-device-grade use, which a /health endpoint can't give you. If your processes are 1:1 with services on a systemd box, use systemd; this is for the many-local-processes case where that stops scaling.
```

---

## r/rust

**Title:**

```
varta-client: a zero-dependency heartbeat library — one observer watches thousands of local processes over 32-byte datagrams
```

**Body:**

```
Background workers and daemons tend to die or wedge silently. You usually find out downstream — a queue backs up, a customer files a ticket — not from the process itself. The usual fixes are heavy: bolt an HTTP /metrics server onto every process, write a systemd unit per PID, or run something orchestrated. If you just have a lot of local processes on a box (or a small UDP cluster), that's a lot of machinery.

Varta is a smaller answer. A process calls beat() to emit a 32-byte heartbeat over a Unix domain socket. One observer binary (varta-watch) decodes every agent's beats, notices when one goes silent (a stall), runs a debounced recovery command (e.g. systemctl restart foo), and exports Prometheus metrics for the whole fleet. One observer, thousands of agents, one datagram each — no per-process HTTP server, no per-PID unit.

The Rust side is what I want to put in front of this crowd:

    use varta_client::{BeatOutcome, Status, Varta};

    let mut agent = Varta::connect("/tmp/varta.sock")?; // one syscall, sets O_NONBLOCK
    loop {
        match agent.beat(Status::Ok, 0) {
            BeatOutcome::Sent       => {}
            BeatOutcome::Dropped(_) => {} // observer absent or socket full — not an error
            BeatOutcome::Failed(e)  => eprintln!("beat: {e}"),
        }
        // your real work here
    }

What I think is worth a look:

- Empty [dependencies]. The production crates (varta-client, varta-watch) carry a literally empty dependency list — no tokio, no serde, no libc. varta-client depends only on the path-local protocol crate. The one exception is optional, feature-gated ChaCha20-Poly1305 (audited RustCrypto, default-features = false) for the encrypted-UDP transport; the default UDS build pulls in nothing.
- Zero heap allocation on the beat path after connect(). connect() opens the socket (one allocation, up front). Every beat() after that encodes the 32-byte frame into a stack buffer and hands it to send(2). A guard-allocator test in the workspace fails the build if anything on that path allocates.
- Non-blocking by contract. The socket is set non-blocking at connect time, and the code is forbidden from ever calling set_nonblocking(false). WouldBlock becomes BeatOutcome::Dropped, never an error — a missing or slow observer can't stall your hot path. Status is Ok | Degraded | Critical | Stall (the last is observer-synthesized; agents can't emit it).
- The protocol crate is #![no_std] by default. varta-vlp (the wire format) compiles clean on thumbv7m-none-eabi with no alloc, and the optional crypto feature stays no_std-clean. The client crate itself uses std's UnixDatagram, so the no_std story is the protocol, not the client — being precise about that since this crowd will ask.
- Optional panic hook. With features = ["panic-handler"], a panic emits a Critical beat before unwinding, so a crashing agent reports its own death instead of just going quiet.

Honest scope: this is niche and local-first. For a single process you want supervised, a systemd unit is simpler and you should use it — Varta earns its keep when you have many local processes and don't want N HTTP endpoints or N units, or when you're somewhere systemd/k8s isn't (embedded, edge, inside a container with no orchestrator). The wire format (VLP v0.2) is frozen and there are conformance-tested clients in Python, Go, Node, .NET, and JVM, so a polyglot fleet reports liveness uniformly.

Numbers are host-dependent; on an Apple Silicon laptop the harness measures p99 ≈ 916 ns and p50 ≈ 584 ns for the beat path, ~0.055% CPU for 50 agents beating at 1 Hz, and ~3.9 KB of binary-size overhead from linking the client. Re-run the bench on your own hardware before quoting them.

cargo add varta-client. Repo, spec, and benchmark methodology: https://github.com/aramirez087/Varta — MIT/Apache-2.0. Happy to answer questions about the no-alloc enforcement or the wire format.
```

---

## lobste.rs

**Title:**

```
Varta: one observer watches thousands of local processes via 32-byte heartbeats, instead of per-process HTTP or systemd units
```

**Tags:** `rust`, `show`, `networking`

**Intro comment:**

```
A process calls beat() to send a 32-byte datagram over a Unix socket; one observer binary decodes every agent's beats, detects stalls, runs a debounced recovery command, and exports Prometheus metrics for the whole fleet. One observer for thousands of local processes — no per-process HTTP /metrics server and no per-PID systemd unit. I built it because I kept finding out that background daemons had wedged from downstream breakage rather than from the process itself, and the only liveness story short of "add Prometheus to every process" was writing a unit per PID. Honest scope: it's niche and local-first — for one process a systemd unit is simpler; this pays off with many local processes or on hosts without systemd/k8s. Production crates have an empty dependency list, the beat path is zero-alloc after connect, and the wire protocol crate is #![no_std]. https://github.com/aramirez087/Varta
```

---

## r/embedded

**Title:**

```
A no_std heartbeat protocol + tiny observer for liveness and auto-recovery on constrained fleets — no systemd, no HTTP per process
```

**Body:**

```
Sharing a liveness tool aimed at the case where systemd and full orchestration aren't available or aren't worth it: bare metal, edge nodes, RTOS targets, containers with no orchestrator.

The model is deliberately small. A process emits a fixed 32-byte heartbeat frame. An observer process (varta-watch) decodes beats from many agents, detects when one goes silent past a threshold, and fires a debounced recovery command. The wire frame is #[repr(C, align(8))], fixed-layout, little-endian, with a CRC-32C trailer — the kind of thing you can decode on the other side without a parser library.

Why it may fit embedded/constrained work:

- The protocol crate is #![no_std] by default and allocation-free. varta-vlp (encode/decode of the 32-byte frame) compiles clean on thumbv7m-none-eabi and other bare-metal targets with no alloc. Encode/decode operate on [u8; 32] stack arrays. The optional ChaCha20-Poly1305 transport (audited RustCrypto, default-features = false) stays no_std-clean too, so encrypted heartbeats don't force you onto std.
- Tiny footprint. Production crates carry an empty [dependencies] list — no libc, no async runtime, no serde. On the reference host, linking the client adds ~3.9 KB of binary size; the beat path is one stack encode plus one send, measured at sub-microsecond p99 and ~0.055% CPU for 50 agents at 1 Hz (host-dependent — re-measure on your target).
- Watchdog-style recovery for a whole fleet, from one process. One observer tracks per-agent silence thresholds and runs debounced recovery (restart the agent, kick a hardware watchdog path, whatever you wire up) instead of one supervisor per process. The four states are Ok, Degraded, Critical, and Stall (Stall is synthesized by the observer when an agent goes quiet; an agent can't claim it). Transport is a Unix socket locally or UDP for a small cluster of nodes.
- A safety-critical build profile that removes attack surface structurally. There's a Class-A profile (aimed at IEC 62304 Class C / medical-device grade) where Cargo features physically excise the HTTP /metrics server, the argument parser, and shell-based recovery from the binary — not disabled at runtime, absent from the symbol table. CI runs a strings audit that rejects the binary if any HTTP literal, any --flag, or /bin/sh survives. Config in that mode is baked at compile time from a file.

Honest about scope: the client crate that opens the socket uses std's datagram types today, so the fully no_std piece is the protocol/codec (varta-vlp) — you bring your own transport on a bare-metal target, and the frame format is what you reuse. The observer itself is a hosted (Linux/Unix) process; this isn't an on-MCU supervisor. It's most useful where you have a Linux-class edge box running a fleet of local agents and want uniform liveness + recovery + metrics without a unit file or HTTP endpoint per process.

Wire format is frozen (VLP v0.2) with a cross-language conformance suite. Repo, the spec byte-map, and the no_std/safety-profile docs: https://github.com/aramirez087/Varta — MIT/Apache-2.0. Install for the observer is curl -fsSL https://varta.sh/install.sh | sh or cargo install. Glad to get feedback on the no_std boundary or the watchdog/recovery design.
```

---

## Visual assets

- **Social/OG card** — `assets/og.png` (1200×630, source `assets/og.svg`). Already
  wired into the site's `og:image` / `twitter:image`, so every share of
  `varta.sh` and the repo renders the pain-first card with the stall→recovery
  terminal. Regenerate after editing the SVG:
  ```sh
  # wrap + rasterize with headless Chrome (no extra deps)
  printf '<!doctype html><meta charset=utf-8><style>html,body{margin:0}svg{display:block;width:1200px;height:630px}</style>' > /tmp/og.html
  cat assets/og.svg >> /tmp/og.html
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --headless=new \
    --hide-scrollbars --force-device-scale-factor=1 --window-size=1200,630 \
    --screenshot=assets/og.png file:///tmp/og.html
  ```

- **Terminal demo** — `docs/marketing/varta-demo.cast` (asciinema v2) +
  `docs/marketing/varta-demo.gif` (rendered with `agg`). The GIF is embedded in
  the README. For the Show HN, upload the cast for a real player:
  ```sh
  asciinema upload docs/marketing/varta-demo.cast    # → returns an asciinema.org URL
  # or re-render the GIF after editing the cast:
  agg --theme 09090b,f4f4f5,18181b,ff4757,10b981,f59e0b,3b82f6,a855f7,22d3ee,a1a1aa,52525b,ff6b78,34d399,fbbf24,60a5fa,c084fc,67e8f9,f4f4f5 \
      --font-size 18 --idle-time-limit 1.4 docs/marketing/varta-demo.cast docs/marketing/varta-demo.gif
  ```
  Drop the asciinema link in the Show HN body or as a reply — a 20-second
  stall→recovery clip converts far better than prose.

## After you post

- **First 5 real users beat any thread.** DM people who have publicly complained
  about silent daemon deaths / per-process health-check sprawl; offer to help
  them wire it up. One user who depends on it > 100 stars.
- **Watch the right meters:** GitHub Insights → Traffic (clones, unique visitors),
  crates.io download graph, PyPI stats. Website visits are vanity here.
- **Name reality:** "Varta" collides with the battery brand, so search is dead.
  Every post title above carries the meaning in words, not the name. Lean on
  these channels and GitHub, not SEO.
