# Supply-Chain Posture

Varta is a safety-critical health-protocol library — the integrity of every
dependency in the resolved graph is part of the safety case. This page
documents the four pillars that defend that boundary and the procedure for
moving them.

## 1. Production crates are dep-free

`varta-client` and `varta-watch` carry **zero** registry dependencies. The
`[dependencies]` section of each crate's `Cargo.toml` is empty; the project
CI fails if a non-empty line ever appears there
(`.github/workflows/ci.yml` → `zero-dep audit (varta-client)` and `zero-dep
audit (varta-watch)`). The only registry deps in the workspace live in
`varta-vlp`, and only when the optional `crypto` feature is enabled.

## 2. Direct crypto deps are exact-pinned

`crates/varta-vlp/Cargo.toml` declares the four optional crypto deps with
exact patch-version constraints:

```toml
chacha20poly1305 = { version = "=0.10.1", default-features = false, optional = true }
hkdf             = { version = "=0.12.4", default-features = false, optional = true }
sha2             = { version = "=0.10.9", default-features = false, optional = true }
zeroize          = { version = "=1.8.2",  default-features = false, optional = true, features = ["derive"] }
```

The `=` prefix forbids caret/tilde resolution. A new minor or patch release
on crates.io cannot flow into a fresh checkout without a reviewable
`Cargo.toml` edit. The resolver, the `Cargo.lock`, and the reviewer's
mental model agree exactly on which version is in use.

## 3. `cargo-deny` audits the transitive graph

`deny.toml` at the repo root configures four checks, gated by CI in the
`supply-chain` job:

| Section        | Policy                                                                                                                  |
| -------------- | ----------------------------------------------------------------------------------------------------------------------- |
| `[advisories]` | `yanked = "deny"`. Any new RUSTSEC advisory or yanked crate in the resolved graph fails CI.                             |
| `[licenses]`   | OSI-permissive only: `MIT`, `Apache-2.0`, `Apache-2.0 WITH LLVM-exception`, `BSD-2/3-Clause`, `ISC`, `Unicode-3.0`, `Zlib`, `Unlicense`. No GPL/LGPL/AGPL fallback. |
| `[bans]`       | `multiple-versions = "deny"`, `wildcards = "deny"`. Explicit `skip = [ getrandom ]` because `rand_core 0.9` and `tempfile 3.x` pull divergent majors in dev-deps only. |
| `[sources]`    | Only `crates-io` is allowed. `unknown-registry` and `unknown-git` are hard-denied — no `[patch.crates-io.git = "..."]` regression vector. |

`cargo-deny` itself is pinned in the CI install step (`cargo install
--locked --version 0.19.6 cargo-deny`); the tool is part of the trusted
compute base. The minimum version is set by the RUSTSEC advisory
database — entries using CVSS:4.0 syntax (e.g. RUSTSEC-2026-0073) fail
to parse on `cargo-deny < 0.19`.

## 4. CI always passes `--locked`

Every `cargo build`, `cargo test`, `cargo clippy`, `cargo run`, and `cargo
miri test` invocation in `.github/workflows/ci.yml` passes `--locked`.
This refuses any build whose resolver wants to update `Cargo.lock`. The
lockfile in `main` is the only one that builds.

The previous CI used the default resolver behaviour, which would silently
regenerate `Cargo.lock` whenever the manifest constraint admitted a newer
release. Combined with caret pins, that path let a compromised
`chacha20poly1305 0.10.99` propagate to a green CI run. The `=` pin plus
`--locked` closes that gap from both sides.

## Dep-bump procedure

To bump any direct crypto dep:

1. Read the upstream changelog for the target version. RustCrypto crates
   ship security-relevant fixes in patch releases — note any CVE refs in
   the PR body.
2. Edit `crates/varta-vlp/Cargo.toml` and change the `=X.Y.Z` constraint
   to the new version.
3. Run `cargo update -p <crate>` to refresh `Cargo.lock`. The lockfile
   change must be committed in the same PR.
4. Run `cargo deny check` locally. License or advisory changes in the
   new release fail this step.
5. Run the full SRE feature lane locally (`cargo test --workspace
   --locked --features '<...>'`). Workspace tests + the `varta-tests`
   end-to-end harness must stay green.
6. Open a PR with title `deps: bump <crate> X.Y.Z → X.Y.W` and link the
   upstream changelog in the body.

The same procedure applies to bumping `cargo-deny` itself — edit the
version in `.github/workflows/ci.yml` and document the change.

## Why not `cargo vet` (yet)

`cargo vet` extends auditing to transitive trust: every crate version
needs an attestation from a trusted reviewer. Compelling, but it
multiplies reviewer burden across the entire dep graph and pulls
Anthropic / Mozilla / Bytecode-Alliance audit imports into the project.
Tracked as a follow-up; `cargo-deny` is the current line.
