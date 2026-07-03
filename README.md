# IOCGuard

A small Rust command-line utility for defensive security operations. Reads a list of domain indicators, validates them, normalizes them, classifies suspicious indicators, and generates a short local report.

## Security Use Case

Security analysts often receive domain indicators from multiple sources (proxy logs, email gateways, DNS logs). Many entries are malformed, allowlisted, or suspicious. IOCGuard automates the triage:
- Normalizes and validates domain syntax
- Rejects malformed entries with clear reasons
- Flags suspicious domains based on simple threat heuristics
- Respects an allowlist to avoid false positives

## Repository Structure

```
iocguard/
├── Cargo.toml
├── README.md
├── data/
│   ├── domains.csv
│   └── allowlist.txt
├── report/              # generated output
├── screenshots/
└── src/
    ├── main.rs          # entry point
    ├── lib.rs           # module exports
    ├── cli.rs           # argument parsing
    ├── domain.rs        # data model + normalization
    ├── validate.rs      # validation + suspicion rules
    └── report.rs        # CSV/summary generation
```

## Docker Compose Execution

```bash
# From the docker-compose environment
cd /workspace/iocguard
cargo run -- validate --input data/domains.csv --allowlist data/allowlist.txt --out report
```

## Validation Rules

A domain is **invalid** if:
- Empty, no dot, length > 253
- Consecutive dots or empty labels
- Label > 63 chars, starts/ends with hyphen
- Contains characters other than lowercase letters, digits, dot, or hyphen

A domain is **suspicious** (if not allowlisted) when:
- Contains `xn--` prefix (IDN homograph)
- TLD is one of: zip, mov, top, xyz, tk
- Contains keywords: login, verify, secure, update, paypa1
- Contains 3 or more hyphens

## Testing and Quality Checks

```bash
cargo test               # 26 unit tests
cargo fmt --check        # formatting check
cargo clippy -- -D warnings  # lint check
```

## Known Limitations

- Suspicion rules are intentionally simple (educational scope)
- CSV parsing does not handle quoted fields with embedded commas
- No external crate dependencies (stdlib only)

## Team

- Med Lemine El Mostapha
