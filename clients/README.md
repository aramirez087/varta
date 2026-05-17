# Varta clients

This directory holds official, production-grade client libraries for
the Varta health protocol in languages other than Rust. Each language
gets its own subdirectory with independent semver, packaging, and CI.

| Language | Package                                                | Status | Source             |
| -------- | ------------------------------------------------------ | ------ | ------------------ |
| Python   | `pip install varta`                                    | Beta   | [`python/`](python/) |
| Go       | `go get github.com/aramirez087/Varta/clients/go`       | Beta   | [`go/`](go/)       |
| Node.js  | (planned)                                              |        |                    |
| JVM      | (planned)                                              |        |                    |

## Stability model

There are two independent stability contracts:

1. **Wire protocol** — frozen at VLP v0.2, governed by
   [`book/src/spec/`](../book/src/spec/). Any change requires a version
   byte bump and is a breaking change across every client.
2. **Client API** — semver per client, tracked in each client's
   `CHANGELOG.md`. The Python client at 0.1.0 may change its public
   surface without breaking the wire.

## Reference verifiers vs. clients

The verifier-grade implementations under
[`tools/reference-implementations/`](../tools/reference-implementations/)
exist to prove that the spec round-trips in each language against the
canonical JSON test vectors. They are **not** clients — no `connect()`,
no `beat()` loop, no fork-detection, no panic-hook, no transport
abstraction. Production users should use the libraries under this
directory.

## Adding a new language

To port the client to a new language, follow the Python layout as a
template:

```
clients/<lang>/
├── README.md          # quickstart + parity table + non-goals
├── CHANGELOG.md       # independent semver
├── LICENSE            # MIT OR Apache-2.0
├── <packaging file>   # pyproject.toml / go.mod / package.json / ...
├── <module>/          # client source
├── tests/             # conformance + unit + interop
└── examples/          # one file per Rust example
```

CI integration is mandatory: a single job that (a) loads
`tools/vlp-test-vectors.json` and asserts byte-equality, and (b)
spawns the built `varta-watch` binary, drives the client over its
configured transport, scrapes `/metrics`, and asserts the expected
beats. Both gates block PRs.
