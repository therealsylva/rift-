# RIFT — Runtime Integrity Forensics Toolkit

RIFT is an experimental, **non-weaponized** Rust CLI for analyzing memory-safety diagnostics and comparing evidence from controlled vulnerable/patched software builds.

> **Status: v0.3 alpha. Not submission-ready.** Log indicators are not proof that CVE-2026-109618 or CVE-2026-109619 was exploited. No independent CVE reproducer or live vulnerability scanner is included.

## Build and test

```bash
cargo test
cargo build --release
cargo run -- analyze fixtures/synthetic-vulnerable.log
cargo run -- compare fixtures/synthetic-vulnerable.log fixtures/synthetic-patched.log
```

The `fixtures/` files contain **synthetic** diagnostics for software unit tests, not actual PHP2Shell results.

## Commands

- `rift analyze <logfile>`: emit JSON indicators for AddressSanitizer, UBSan and selected memory-safety error strings.
- `rift compare <first-log> <second-log>`: compare sanitizer indicator presence in two user-supplied logs. Output explicitly marks `cve_verified: false`.

No HTTP requests, PHP exploitation, or live target probing is performed.

## Scope and limitations

1. Version and patch status are **not** inferred from filenames.
2. Sanitizer markers are **not** sufficient to attribute findings to any CVE.
3. Differential indicators are not equivalent to a causal patch validation.
4. Only reproducible experiments with controlled builds and captured evidence can support academic conclusions.

## Roadmap

- Introduce independently developed memory-safety regression fixtures grounded in official PHP source patches.
- Capture real build provenance and sanitizer outputs in isolated lab containers.
- Implement evidence manifests, stable JSON schemas and black-box behavioral tests.
- Publish reproducibility instructions and independently validated results.

## CI

GitHub Actions will run `cargo fmt`, `cargo clippy` and `cargo test` for every push and pull request.

## License

MIT.
