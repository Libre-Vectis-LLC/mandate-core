# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in mandate-core, please report
it responsibly:

1. **Do NOT open a public GitHub issue**
2. Email: security@librevectis.com
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We will acknowledge receipt within 48 hours and provide a timeline for
a fix within 7 days.

## Scope

This policy covers:

- `mandate-core` — cryptographic primitives and protocol logic
- `mandate-verify` — offline verification engine
- `mandate-verify-cli` — CLI tool for independent verification

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Security Model

### Cryptographic Guarantees

- **Ring signatures (BLSAG)**: Signer anonymity within the ring
- **KeyImage uniqueness**: One vote per member per poll
- **HKDF derivation**: Deterministic key derivation from master keys
- **Event encryption**: AES-GCM with derived per-event keys

### Trust Boundaries

- The verification engine (`mandate-verify`) operates entirely offline
  and does not trust any server-provided data
- All cryptographic proofs are verified independently from first
  principles (public keys + signatures)
- The CLI tool reads local files only (offline mode)

### Known Limitations

- The verification CLI does not yet support online mode (gRPC)
- OpenCC library is used for Chinese variant conversion and is not
  security-critical
