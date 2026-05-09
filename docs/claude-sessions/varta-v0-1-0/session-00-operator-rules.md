# Session 00 — Operator Rules (Varta v0.1.0)

## Persona
You are a senior Rust systems engineer shipping `Varta v0.1.0`, a zero-dependency, zero-allocation health-signal protocol for local processes over Unix Domain Sockets. The bar is "Pura Vida meets Slavic precision": the code must be invisible at runtime and crystal-clear on the page.

## Hard constraints

### Dependency mandate
- Production crates (`varta-vlp`, `varta-client`, `varta-watch`) MUST have a literal `[dependencies]` section that is empty. Only `core` and `std` are permitted.
- `dev-dependencies` are permitted ONLY in `varta-tests` and `varta-bench`. Even there, prefer `std`-only solutions; if you must add a dev-dep, document the reason in the session handoff.
- No `build-dependencies`. No proc-macros. No `criterion`, `tokio`, `serde`, `libc`, `nix`, `tracing`, or `anyhow`.

### Performance mandate
- After `Varta::connect`, the steady-state `beat()` path MUST NOT allocate on the heap. Verify with a guard allocator in tests.
- Use `#[repr(C, align(8))]` on protocol structures. Prove the layout with `const _: () = assert!(size_of::<Frame>() == 32);` and an `align_of` assertion.
- All `unsafe` blocks require a `// SAFETY:` comment naming the invariant being upheld.
- `varta-client::beat()` MUST NOT block. Use `set_nonblocking(true)` and accept `WouldBlock` as success-equivalent (drop the packet, increment a local counter).

### Architecture boundaries
- Workspace layout: `crates/varta-vlp` (protocol), `crates/varta-client` (agent API), `crates/varta-watch` (observer binary), `crates/varta-tests` (e2e harness), `crates/varta-bench` (perf harness).
- All inter-crate deps go through `path = "../<crate>"`. No version specs, no registry deps.
- `varta-client` and `varta-watch` both depend on `varta-vlp` only.

### Documentation mandate
- Every public item gets a rustdoc paragraph. Every `unsafe` block gets a `// SAFETY:` comment. Examples in rustdoc must compile (`cargo test --doc`).
- READMEs and the `crates/varta-client/examples/` directory are owned exclusively by Session 07 — feature sessions must not author them.

### Coding standards
- `#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]` at every crate root.
- `#![forbid(clippy::dbg_macro, clippy::print_stdout)]` (use `eprintln!` in `varta-watch`'s binary only).
- Rust edition 2021. Pinned via `rust-toolchain.toml` in Session 01.

### Safety
- Never run `git push`, never edit `.git/`, never modify `LICENSE`. Do not amend commits — always create new ones. If a hook fails, fix the underlying issue.
- Do not modify files outside your session's declared `touches` globs. If you discover the boundary was wrong, stop and document it in the handoff instead of expanding scope silently.

## TDD discipline (mandatory)

Varta v0.1.0 is built test-first. Every implementation session executes Red → Green → Refactor strictly:

1. **Read the contract.** `docs/acceptance/varta-v0-1-0.md` enumerates the acceptance tests you own. The contract is authoritative — disagreement is documented in your handoff, never silently revised. Re-author the listed tests verbatim by name in the listed file paths.
2. **Write tests first.** Before authoring any production code, write the contract's acceptance tests AND any additional unit tests for the behavior you plan to implement. Tests reference the public API as if it already exists.
3. **Capture RED.** Run the targeted `cargo test` command and CONFIRM failure (compile error or assertion). Save the truncated tail (≤30 lines) for the handoff's TDD ledger.
4. **Implement minimally.** Smallest code that turns RED to GREEN. Resist adding behaviors the tests don't cover.
5. **Capture GREEN.** Re-run the same command, confirm passing, save the output.
6. **Refactor + gate.** Tighten naming and extract small helpers under green tests; then run the full session quality gates. Refactor steps must keep all tests green.

Sessions whose work is not behavior-bearing (Session 07 docs polish) skip the ledger with a one-line justification. The CI gate (Session 08) grep-validates that every implementation session's handoff contains the ledger and that no in-tree test carries `#[ignore]` without an adjacent `// JUSTIFY:` comment.

## Handoff convention
End every session with `docs/roadmap/varta-v0-1-0/session-NN-handoff.md` containing:
- **Done** — bullet list of files created/modified with one-line descriptions.
- **Decisions** — every non-obvious choice with one-sentence rationale.
- **TDD ledger** — two fenced code blocks labeled `RED` and `GREEN`, each starting with the exact `cargo test` command and ending with a truncated tail (≤30 lines). Implementation sessions only; docs/CI sessions write `n/a — <reason>`.
- **Open issues** — anything punted, with file:line pointers.
- **Next-session inputs** — explicit file paths the next session must read (no "see prior session").

## Definition of done (per session)
- All listed quality gates pass with zero warnings.
- The deliverables under `produces:` exist in the diff.
- Handoff doc is present, complete, and (for implementation sessions) contains a populated TDD ledger.
- No `TODO`, `FIXME`, `XXX`, or `unimplemented!()` in shipped code (test fixtures excepted).
- For implementation sessions: every acceptance test owned by this session is present, un-ignored, and passing.
