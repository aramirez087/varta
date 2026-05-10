---
session: 04
title: "Docs: README, recovery README, release readiness"
depends_on: [2, 3]
touches:
  - "README.md"
  - "crates/varta-watch/README.md"
  - "docs/architecture/recovery-async-spawn.md"
  - "docs/release/v0.1.0-readiness.md"
  - "docs/roadmap/recovery-async-spawn/**"
parallel_safe: false
produces:
  - "crates/varta-watch/README.md"
  - "docs/release/v0.1.0-readiness.md"
  - "docs/roadmap/recovery-async-spawn/session-04-handoff.md"
model: "sonnet"
---

# Session 04 — Documentation pass

```md
Continue from Session 02, 03 artifacts in
docs/roadmap/recovery-async-spawn/session-02-handoff.md and
docs/roadmap/recovery-async-spawn/session-03-handoff.md.

Mission: bring user-facing docs into sync with the new non-blocking recovery
behaviour. No production-code edits.

Repository anchors:
- README.md (top-level project intro — recovery section if any)
- crates/varta-watch/README.md (binary usage + flag table)
- docs/architecture/recovery-async-spawn.md (Session 01 architecture doc)
- docs/release/v0.1.0-readiness.md (release checklist; B1 was a blocker)

Tasks:
1. Update crates/varta-watch/README.md:
   - Add `--recovery-timeout-ms <MS>` to the flag table with the same
     wording as `Config::HELP`.
   - Replace any "blocking is fine on the cold path" framing with text that
     describes spawn-and-reap semantics. Cite the architecture doc.
   - Add a short "Recovery lifecycle" subsection: spawn → outstanding →
     try_reap each tick → Reaped / Killed / ReapFailed.
2. Update README.md (top-level): if recovery is mentioned, mirror the same
   one-paragraph summary. Otherwise add a single sentence under whichever
   section currently describes varta-watch.
3. Update docs/release/v0.1.0-readiness.md: mark blocker B1 as resolved,
   reference the architecture doc and the four recovery_e2e + two cli_smoke
   tests that gate it. Note any follow-ups (signal-based shutdown, metrics
   counters for kill events) without scoping them into this epic.
4. Cross-check docs/architecture/recovery-async-spawn.md against the actual
   final API in src/recovery.rs and src/config.rs; correct any drift
   introduced by Sessions 02 / 03.
5. Re-run `.wolf/anatomy.md` housekeeping: ensure each new or edited file
   has the right token estimate / description line.

Deliverables:
- All files listed in `produces:` above.
- Updated docs/architecture/recovery-async-spawn.md if it drifted.
- docs/roadmap/recovery-async-spawn/session-04-handoff.md summarising what
  changed in user-facing docs and any open release-readiness items for the
  CI gate to verify.

Quality gates:
- cargo build --workspace          (sanity: docs change does not break)
- cargo fmt --all -- --check
- cargo clippy --workspace -- -D warnings

Exit criteria: README, varta-watch README, release readiness, and
architecture doc all agree on the recovery contract; no broken links; the
release-readiness file no longer lists B1 as open.
```
