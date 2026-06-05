# Distribution checklist (varta.sh)

Use after merging discoverability changes. Traffic for niche infra comes from
**events**, not SEO alone.

## One-time setup

- [ ] Register `varta.sh` in [Plausible](https://plausible.io/) (or set `CLOUDFLARE_BEACON_TOKEN` in repo secrets — see [SITE_ANALYTICS.md](SITE_ANALYTICS.md))
- [ ] Set GitHub repo **Website** field to `https://varta.sh`
- [ ] Submit sitemap in Google Search Console: `https://varta.sh/sitemap.xml`

## Launch posts (pick 1–2)

### Hacker News — Show HN

**Title:** Show HN: Varta – 32-byte process heartbeats, zero deps, sub-µs beat path

**Body bullets:**

- Problem: HTTP `/health` on every agent is heavy; systemd watchdog is per-unit.
- Solution: 32-byte VLP frames over UDS/UDP, one `varta-watch` observer, Prometheus native.
- Proof: benchmark numbers on the site; `cargo add varta-client`.
- Links: https://varta.sh · https://varta.sh/book/guides/

### Lobsters

Tag `rust`, `show`. Same angle; emphasize formal threat model + Class-A safety profile.

### Rust communities

- r/rust weekly project thread
- This Week in Rust (submit PR to TWIR repo with one-liner + link)

## Ongoing

- [ ] Awesome-rust PR (monitoring / observability section)
- [ ] Answer Prometheus/monitoring threads with link to [Prometheus guide](https://varta.sh/book/guides/prometheus-setup.html)
- [ ] crates.io release notes linking to guides when tagging