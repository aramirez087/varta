# Varta Landing Page — Design Spec

## Overview

Single-page static site for GitHub Pages. Zero build step — plain HTML + CSS + minimal vanilla JS. Inspired by the autoskills.dev layout: two-column hero, terminal mockup, stacked sections with thin dividers, retro arcade title. Varta's own identity: heartbeat/pulse motif, systems-level confidence, "cooler project" energy.

## Brand Identity

- **Tagline:** "Zero-overhead health protocol for distributed local agents."
- **Visual metaphor:** Heartbeat / pulse / ECG. Varta = "battery" in Sanskrit — energy, continuity, uptime.
- **Personality:** Technical, precise, confident. Not corporate. Built by systems people for systems people. The kind of project that makes you want to read the source.
- **Differentiation from autoskills:** Varta is a Rust library, not an npm CLI. The terminal mockup shows `varta-watch` output (Prometheus metrics, stall detection) rather than npm install. The pulse/heartbeat visual is unique to Varta.

## Color Palette

Monochrome + neon cyan accent. No other colors except functional status badges.

| Token | Hex | Usage |
|-------|-----|-------|
| `--bg` | `#0a0a0a` | Page background (near-black) |
| `--bg-surface` | `#111111` | Terminal mockup bg, section alternates |
| `--bg-elevated` | `#1a1a1a` | Code blocks, hover states |
| `--border` | `#222222` | Thin section dividers, card borders |
| `--text-primary` | `#e4e4e4` | Headings, body text (off-white, not pure white) |
| `--text-secondary` | `#666666` | Captions, metadata, timestamps |
| `--text-dim` | `#444444` | De-emphasized labels |
| `--accent` | `#22d3ee` | CTAs, highlights, terminal cursor, links (cyan) |
| `--accent-dim` | `#0e7490` | Hover states, borders on focus |
| `--accent-glow` | `rgba(34, 211, 238, 0.15)` | Background glow behind hero terminal |
| `--success` | `#22c55e` | Status `Ok`, `Pass`, `Sent` |
| `--danger` | `#ef4444` | Status `Critical`, `Fail` |
| `--warning` | `#eab308` | Status `Degraded`, `Warn` |

## Typography

| Element | Font | Weight | Size | Notes |
|---------|------|--------|------|-------|
| Title (hero) | `Press Start 2P` (Google Fonts) | 400 | 2.2–3rem | Pixel/retro arcade — only used for "VARTA" wordmark |
| Headings | `Inter` | 700 | 1.8–2.5rem | Clean, geometric, bold |
| Body | `Inter` | 400 | 1.05rem | Readable, comfortable line-height (1.7) |
| Code / terminal | `JetBrains Mono` | 400 | 0.85rem | All code, metrics, terminal output |
| Mono labels | `JetBrains Mono` | 500 | 0.75rem | Badges, section labels, timestamps |

Font strategy: `Press Start 2P` for the hero wordmark only (retro identity). Everything else is Inter + JetBrains Mono — clean, modern, developer-readable. No font variety bloat.

## Layout

Max-width 1100px, left-aligned content, lots of breathing room. Sections separated by thin `1px` horizontal rules (`--border` color), not by background color changes.

```
┌──────────────────────────────────────────────────────────┐
│  NAV BAR                                                  │  ← sticky, minimal
├──────────────────────────────────────────────────────────┤
│                                                           │
│  ┌─────────────────────┐  ┌───────────────────────────┐  │
│  │  VARTA (pixel font)  │  │                           │  │
│  │  One-line tagline    │  │   TERMINAL MOCKUP         │  │
│  │  Sub-headline        │  │   $ varta-watch --socket  │  │
│  │                      │  │   [metrics output]        │  │
│  │  [Get Started]       │  │   [heartbeat line]        │  │
│  │  cargo add varta     │  │                           │  │
│  └─────────────────────┘  └───────────────────────────┘  │
│                                                           │
│─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│  ← thin divider
│                                                           │
│  HOW IT WORKS                                             │
│                                                           │
│  1  Connect       Open a Unix Domain Socket              │
│  2  Beat          Encode 32 bytes, send(2), done         │
│  3  Observe       varta-watch decodes, detects, exports  │
│                                                           │
│─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│
│                                                           │
│  PERFORMANCE                                              │
│                                                           │
│  p99 latency     916 ns       cpu (50 agents)  0.055%    │
│  binary overhead 3.8 KB                                  │
│                                                           │
│─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│
│                                                           │
│  CRATES                                                   │
│                                                           │
│  varta-vlp       Wire protocol — Frame, Status, codec    │
│  varta-client    Agent API — connect, beat, panic hook   │
│  varta-watch     Observer — stall, recovery, Prometheus  │
│                                                           │
│─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│
│                                                           │
│  FOOTER        MIT · GitHub · crates.io                  │
└──────────────────────────────────────────────────────────┘
```

## Sections — Detailed

### 1. Nav Bar

- **Left:** `VARTA` in monospace (JetBrains Mono, 500 weight), cyan accent on the dot or a subtle pulse icon
- **Right:** `Docs` · `Crates` · `GitHub` (icon) — minimal, 3 items max
- Sticky. Transparent at top, gains solid `--bg` + 1px bottom border on scroll.
- Mobile: hamburger or just hide nav links (it's only 3 items, could stay visible).

### 2. Hero — Two Column

**Left column (60%):**
- `VARTA` in `Press Start 2P` pixel font, large (2.5–3rem), with a subtle CSS text-shadow glow in cyan
- Below: tagline in Inter 700: "Zero-overhead health protocol for distributed local agents."
- Below: one-line sub: "32-byte heartbeats over Unix Domain Sockets. No dependencies. No allocations. Sub-microsecond."
- CTA row:
  - Primary: pill-style button with `cargo add varta-client` (copyable on click) — monospace text, cyan border
  - Secondary: `View on GitHub →` text link in cyan

**Right column (40%):**
- Terminal mockup — a styled `<div>` that looks like a terminal window:
  - Title bar: 3 dots (red/yellow/green), centered title `varta-watch`
  - Body: dark `--bg-surface` background, monospace text showing simulated output:
    ```
    $ varta-watch --socket /tmp/varta.sock --threshold-ms 2000
    ▓ listening on /tmp/varta.sock
    ▓ pid 4821 — status: Ok — last beat: 12ms ago
    ▓ pid 4821 — status: Ok — last beat: 8ms ago
    ▓ pid 4821 — ⚠ STALL DETECTED — silence: 2104ms
    ▓ → running recovery: systemctl restart my-agent
    ▓ metrics → http://127.0.0.1:9100/metrics
    ▓_
    ```
  - The last line has a blinking cyan cursor (`--accent`)
  - Subtle `box-shadow` glow in `--accent-glow` around the terminal

**Mobile:** Stack vertically. Terminal mockup goes below the copy, full-width.

### 3. How It Works

Numbered steps, left-aligned. Number badges are cyan circles with white text.

```
1  Connect
   Varta::connect() opens a non-blocking Unix Datagram socket.
   One allocation. That's it.

2  Beat
   agent.beat(Status::Ok, payload) encodes 32 bytes on the stack
   and calls send(2). Returns Sent, Dropped, or Failed.

3  Observe
   varta-watch polls the socket, tracks per-pid state machines,
   detects stalls, runs recovery commands, exports Prometheus metrics.
```

Each step: bold number in cyan circle, step title in Inter 700, description in Inter 400, optional inline code snippet in JetBrains Mono.

Separated from hero by thin `1px` horizontal rule. Large vertical padding (5–6rem) above and below.

### 4. Performance

Three large metrics displayed horizontally (stacked on mobile). Each metric:
- Label in `--text-secondary`, uppercase monospace, small
- Value in `--text-primary`, large (2.5rem), JetBrains Mono 700
- Sublabel in `--text-dim`

```
P99 LATENCY              CPU (50 AGENTS)          BINARY OVERHEAD
  916 ns                    0.055%                    3.8 KB
sub-microsecond           nearly invisible          minimal footprint
```

Numbers count up on scroll-into-view (IntersectionObserver + requestAnimationFrame, ~30 lines of JS).

Footnote in `--text-dim`: "Measured on Apple Silicon · Rust 1.93.1 · varta-bench"

### 5. Crates

Three rows, left-aligned. Each row is a horizontal card:

```
varta-vlp ················································→
32-byte wire protocol — Frame, Status, encode/decode

varta-client ·············································→
Agent API — Varta::connect(), beat(), optional panic hook

varta-watch ··············································→
Observer binary — stall detection, recovery, Prometheus
```

Each row: crate name in JetBrains Mono + cyan, dotted leader line, arrow. Description below in `--text-secondary`. Entire row is clickable, links to the crate's README.

### 6. Footer

Minimal. One line:

```
Varta · MIT License · GitHub · crates.io
```

All in `--text-secondary`, small. GitHub and crates.io are icon-links in cyan on hover. 60px height, thin top border.

## Animations

- **Terminal cursor blink:** CSS `@keyframes blink` on the `_` character in the terminal mockup.
- **Counter animation:** Performance numbers count up from 0 when scrolled into view. ~30 lines vanilla JS with IntersectionObserver.
- **Scroll reveal:** Sections fade-in + slide-up 20px on intersection. CSS `@keyframes` + IntersectionObserver toggle class.
- **No heavy libraries, no parallax, no scroll-jacking.** Subtle and purposeful.

## Responsive Breakpoints

| Breakpoint | Layout |
|------------|--------|
| `> 1024px` | Two-column hero, horizontal metrics, full nav |
| `768–1024px` | Hero columns narrow, metrics stay horizontal |
| `< 768px` | Single column everywhere, hero stacks (copy → terminal), metrics stack vertically, larger touch targets |

## File Structure

```
docs/landing-page/
├── design.md          ← this spec
├── index.html         ← single-page HTML
├── style.css          ← all styles (CSS custom properties for theming)
├── script.js          ← counter animation + scroll reveal + clipboard
└── favicon.svg        ← minimal pulse/heartbeat icon
```

Hosted via GitHub Pages from `docs/landing-page/` (configure in repo settings).

## Implementation Notes

- **No build step.** Just push HTML/CSS/JS and enable Pages.
- **Google Fonts loaded via `<link>`** — `Press Start 2P`, `Inter`, `JetBrains Mono`.
- **CSS custom properties** for the entire palette — easy to tweak later.
- **Syntax highlighting** for the terminal mockup is just `<span>` elements with color classes — no library.
- **Copy-to-clipboard** for the `cargo add` command — ~15 lines of vanilla JS.
- **Favicon:** simple SVG of a heartbeat pulse line in cyan on transparent.

## Non-Goals

- No React, no build step, no npm, no bundler.
- No tracking scripts, no analytics.
- No dark/light mode toggle — dark only.
- No blog, no changelog, no multi-page nav.

## Open Questions

- [ ] Custom domain or `username.github.io/varta`?
- [ ] Should the terminal mockup show real `varta-watch` output or a curated demo?
- [ ] Link to crate READMEs in-repo or to docs.rs (once published)?
