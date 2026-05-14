# Installation

Varta is currently in rapid development (post-v0.1.0). While it is not yet published to crates.io, it is designed to be easily included as a path dependency.

## Adding to your Rust project

Add the `varta-client` to your `Cargo.toml`:

```toml
[dependencies.varta-client]
path = "path/to/varta/crates/varta-client"
```

### Optional Features

You can enable specific transport or safety features:

```toml
[dependencies.varta-client]
path = "path/to/varta/crates/varta-client"
features = [
    "panic-handler", # Automatic 'Critical' beat on thread panic
    "udp",           # Support for networked agents
    "secure-udp",    # Encrypted UDP transport (requires crypto deps)
]
```

## Installing the Observer

To build and install the `varta-watch` observer binary:

```bash
cargo install --path crates/varta-watch
```

## Verifying the Toolchain

Varta is pinned to a specific stable toolchain via `rust-toolchain.toml`. We recommend matching this for production builds:

```bash
rustup show
```

The Minimum Supported Rust Version (MSRV) is **1.70.0**.
