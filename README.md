# seatbelt-rs

A small type-safe Rust wrapper for macOS seatbelt API.

## Usage

Build a profile with a fluent builder — pick a default, then chain
`action → operation → filter` rules:

```rust
use seatbelt_rs::{Proto, Sandbox};

let sandbox = Sandbox::deny_by_default()
    .allow().file_read().subpath("/usr")
    .allow().file_write().subpath("/tmp")
    .allow().network_outbound().remote(Proto::Tcp, "*:443")
    .deny().file_read().prefix("/Users")
    .allow().mach_bootstrap();

// Inspect the generated SBPL...
println!("{}", sandbox.to_sbpl());

// ...or apply it to the current process.
sandbox.init()?;
# Ok::<(), seatbelt_rs::Error>(())
```
