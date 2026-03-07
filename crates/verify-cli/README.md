# mandate-verify

Independent poll verification CLI for the Mandate anonymous voting protocol.

## Overview

`mandate-verify` validates anonymous polls produced by the Mandate system.
It reads a voter registry (XLSX) and a poll bundle (binary), then:

1. **Re-derives** ring member public keys from master keys via HKDF
2. **Cross-validates** the registry against the ring in the bundle
3. **Verifies** every BLSAG ring signature (adaptive parallel)
4. **Checks** KeyImage uniqueness (no double-voting)
5. **Tallies** votes and computes turnout
6. **Exports** a multi-sheet XLSX verification report

## Install

Download pre-built binaries from
[GitHub Releases](../../releases) or build from source:

```bash
cargo install --path crates/verify-cli
```

## Usage

### Offline mode (local files)

```bash
mandate-verify poll \
  --registry voters.xlsx \
  --bundle poll-bundle.bin \
  --output report.xlsx \
  --locale zhs+en
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `--registry` | Voter registry XLSX | required |
| `--bundle` | Poll bundle binary (offline) | — |
| `--server` | gRPC endpoint (online, not yet implemented) | — |
| `--poll-id` | Poll ULID (with `--server`) | — |
| `--poll-key` | Hex poll key (with `--server`) | — |
| `--output` | Report output path | `report.xlsx` |
| `--locale` | Language: `en`, `zhs`, `zht`, `zhs+en`, `zht+en` | `zhs+en` |
| `--parallelism` | Thread count (auto-tuned if omitted) | auto |

### Report output

The exported XLSX contains four sheets:

1. **Verification Summary** — poll metadata, pass/fail checks
2. **Registry Mapping** — voter ↔ ring member correspondence
3. **Vote Details** — per-vote signature status (shuffled order)
4. **Tally Results** — vote counts and percentages per option

## Verification workflow

```
Organization publishes:
  ├── voters.xlsx        (voter registry)
  ├── poll-bundle.bin    (poll data + votes)
  └── report.xlsx        (official report)

Anyone can verify:
  $ mandate-verify poll --registry voters.xlsx --bundle poll-bundle.bin
  → Produces their own report.xlsx
  → Compare with the official report
```

## License

See [LICENSE](../../LICENSE) for details.
