# Mandate Anonymous Voting Bounty — Challenger Guide

## 1. Challenge Overview

The **mandate-bounty** CTF is a cryptographic bounty challenge. Your objective: **de-anonymize a ring-signature-based anonymous poll**. You are given a set of public artifacts — a voter registry, a bundle of signed vote events, and aggregate results — and must determine which voter cast which vote.

The challenge tests whether the Mandate anonymous voting protocol provides meaningful anonymity in practice. If you can map every voter to their vote choice, you derive a cryptographic key that decrypts a bounty secret containing a wallet mnemonic and contact information, proving your solution is correct without requiring any trusted third party.

**Only a full break — decrypting the bounty secret — qualifies for the reward.** Partial findings, minor implementation observations, or theoretical weaknesses that do not lead to a complete solution are not eligible for bounty payment in this round.

### Why This Matters

Ring signatures (specifically, BLSAG — Back's Linkable Spontaneous Anonymous Group signatures) are the foundation of Mandate's anonymity guarantee. Each vote is signed by a ring that includes all eligible voters, making it computationally infeasible to determine which ring member actually signed. The bounty challenges you to break this guarantee.

---

## 2. Getting Started

### Obtain the Artifacts

The challenge operator distributes a directory of artifacts. You should receive:

```
artifacts/
├── voters.xlsx
├── poll-bundle.bin
├── results.json
├── encrypted_secret.rage
└── manifest.json
```

### Verify Artifact Integrity

Before starting, verify all artifacts against `manifest.json`, which contains SHA-256 hashes:

```bash
# Example: check voters.xlsx
sha256sum voters.xlsx
# Compare output with the value in manifest.json under "artifacts"."voters.xlsx"
```

Each hash in `manifest.json` is prefixed with `sha256:` followed by the hex-encoded digest.

### Install the CLI Tool

The `mandate-bounty` CLI provides verification commands. Build it from source (requires Rust toolchain):

```bash
cd mandate-core
cp Cargo.standalone.toml Cargo.toml
cargo build --release -p mandate-bounty-cli
# Binary: target/release/mandate-bounty
```

> **Note:** The standalone workspace manifest (`Cargo.standalone.toml`) must be copied into place as `Cargo.toml` before building. A pre-generated `Cargo.lock` is provided for reproducible builds.

Two subcommands are relevant to challengers:

| Command | Purpose |
|---------|---------|
| `mandate-bounty verify-solution` | Verify your solution CSV against the encrypted secret |
| `mandate-bounty derive-identity` | Derive the age public key from your CSV (for intermediate checking) |

---

## 3. Artifact Descriptions

### `voters.xlsx`

An Excel spreadsheet with two columns:

| Column | Description |
|--------|-------------|
| `Name` | Voter display name (Unicode, NFC-normalized) |
| `Public_Key` | Base58-encoded Nazgul (Ristretto25519) public key |

Rows are sorted by `Public_Key` in lexicographic (string) order. This is the authoritative name-to-pubkey registry. Every voter in the poll appears exactly once.

### `poll-bundle.bin`

A Protocol Buffers binary containing a `PollBundle` with the following fields:

- **`poll_event_raw`**: The serialized `PollCreate` event, including the poll question, option definitions, and a BLSAG ring signature over the master ring.
- **`vote_events_raw`**: A list of serialized `VoteCast` events. Each contains a BLSAG ring signature, a `KeyImage` (for double-vote prevention), and the selected option ID. **Vote events are randomly shuffled** — their array index has no correlation with the voter registry order.
- **`ring_member_pubs`**: The list of all ring member public keys (bs58-encoded, sorted). This is the master ring used in the PollCreate signature.
- **`org_id`** / **`poll_ulid`**: Derivation path components used to construct the per-poll signing ring.
- **`poll_key_hex`**: The hex-encoded poll decryption key (`k_poll`), needed to decrypt encrypted poll content (question text, option text) within the events.
- **`option_definitions`**: Human-readable option IDs and text.

### `results.json`

Aggregate vote tally:

```json
{
  "poll_id": "<ULID>",
  "total_votes": 1000,
  "results": {
    "opt-like": 600,
    "opt-unlike": 200,
    "opt-abstain": 200
  }
}
```

This tells you the distribution of votes across options but not who voted for what.

### `encrypted_secret.rage`

An [age](https://age-encryption.org/)-encrypted file. The recipient's x25519 public key is derived from the correct solution CSV via the KDF chain (see Section 6). If you derive the correct key, you can decrypt this file to reveal:

1. A **cryptocurrency wallet mnemonic** controlling a wallet preloaded with 100 USDC
2. **Contact information** for submitting your write-up to claim the remaining 400 USDC

### `manifest.json`

The challenge manifest containing artifact hashes, KDF parameters, and the expected age public key:

```json
{
  "version": 1,
  "git_commit": "<hex>",
  "expected_age_pubkey": "age1...",
  "kdf": {
    "algorithm": "csv-sha3-512-argon2id-age-x25519-v1",
    "salt": "mandate-bounty-v1",
    "m_cost_mib": 4096,
    "t_cost": 120,
    "p_cost": 1
  },
  "documentation": {
    "challenger_guide": "bounty-challenger.zh.md"
  },
  "artifacts": {
    "voters.xlsx": "sha256:<hex>",
    "poll-bundle.bin": "sha256:<hex>",
    "results.json": "sha256:<hex>",
    "encrypted_secret.rage": "sha256:<hex>"
  }
}
```

Critically, `manifest.json` contains:
- The **expected age public key** (`expected_age_pubkey`) — your derived key must match this
- The exact **KDF parameters** under `kdf` (Argon2id memory/time/parallelism costs, salt)
- SHA-256 hashes of all artifacts for integrity verification

---

## 4. Understanding the Cryptography

### BLSAG Ring Signatures

Every `VoteCast` event is signed using a **BLSAG** (Back's Linkable Spontaneous Anonymous Group) signature. BLSAG provides three properties:

1. **Anonymity**: The signature proves that *one* member of the ring signed the message, but does not reveal *which* member. An observer cannot distinguish between any of the N ring members as the actual signer.

2. **Unforgeability**: Only a ring member possessing a valid private key can produce a valid signature. You cannot forge a signature without the secret key.

3. **Linkability via KeyImage**: Each signature includes a `KeyImage` — a deterministic, one-way function of the signer's private key and the signing context. If the same signer signs two messages in the same context, both signatures will share the same `KeyImage`. This prevents double-voting without breaking anonymity.

### Per-Poll Derived Signing Rings

Votes are **not** signed using the master ring directly. Instead, a **per-poll signing ring** is derived deterministically from:

- The organization ID
- The master ring hash
- The poll ULID
- The master ring's public keys

Each voter's signing key is similarly derived per-poll. This means KeyImages are poll-scoped — a voter's KeyImage in one poll cannot be linked to their KeyImage in another poll.

### Signature Modes

The challenge uses two signature storage modes:

- **Archival** (PollCreate): The full ring is embedded in the signature, making it self-contained for verification.
- **Compact** (VoteCast): The ring is referenced by hash. The verifier must reconstruct the ring from the `ring_member_pubs` and derivation parameters provided in the bundle.

### Vote Event Shuffling

After all VoteCast events are generated, they are **shuffled using a CSPRNG** (cryptographically secure pseudorandom number generator). The order of events in `vote_events_raw` is random and carries no information about voter identity or generation order.

---

## 5. Solution Format

Your solution is a **canonical CSV file** mapping each voter to their vote choice. The format is strict — a single bit of deviation will produce a different KDF output and fail verification.

### Specification

- **Encoding**: UTF-8 (no BOM)
- **Line endings**: LF (`\n`) only — no CRLF
- **No trailing newline**: The file must NOT end with `\n`
- **No header row**: Data starts on line 1
- **Format**: One line per voter: `{name},{option_id}`
- **Option values**: Use the machine-readable option **ID** from `option_definitions` in the poll bundle or `results.json` (e.g., `opt-like`, `opt-unlike`, `opt-abstain`).
- **Sort order**: Lines are sorted by the voter's bs58-encoded public key in **lexicographic string order** (the same order as `voters.xlsx`)
- **Name normalization**: All voter names must be **NFC-normalized** Unicode

### Example

Given voters sorted by public key:

| Name | Public_Key | Vote |
|------|-----------|------|
| Alice | `2Qx...` | opt-like |
| Bob | `5Hf...` | opt-abstain |
| Carol | `9Zt...` | opt-unlike |

The canonical CSV would be:

```
Alice,opt-like
Bob,opt-abstain
Carol,opt-unlike
```

(Exactly 3 lines, no trailing newline, LF-separated.)

### Critical Details

- The CSV is sorted by **public key**, not by name. Look up each voter's public key in `voters.xlsx` to determine sort order.
- The option values must be the machine-readable **ID** from `option_definitions` in the poll bundle or `results.json` (e.g., `opt-like`). These are the same IDs used as keys in the `results` object.
- Unicode normalization matters: `e` + combining acute (`U+0301`) and `é` (`U+00E9`) look identical but are different byte sequences. NFC normalization collapses them. Use a Unicode library to ensure NFC form.

---

## 6. KDF Chain

The canonical CSV is transformed into an age x25519 identity through a three-step key derivation chain:

### Step 1: SHA3-512

```
sha3_hash = SHA3-512(csv_bytes)
```

Compute the SHA3-512 digest of the raw CSV bytes. This produces a 64-byte hash.

### Step 2: Argon2id

```
derived_key = Argon2id(
    password = sha3_hash,    # 64 bytes from step 1
    salt     = "mandate-bounty-v1",
    m_cost   = 4 GiB,       # 4,194,304 KiB
    t_cost   = 120,          # 120 iterations
    p_cost   = 1,            # single-threaded
    output   = 32 bytes
)
```

The Argon2id parameters are intentionally expensive:
- **4 GiB memory** makes brute-force impractical even on GPU clusters
- **120 iterations** further increases wall-clock time per attempt
- **1 lane** prevents parallelism advantage

This KDF step ensures that even if the search space is reduced, brute-forcing the remaining combinations is computationally prohibitive.

### Step 3: age Identity Construction

```
identity = age::x25519::Identity::from_secret_bytes(derived_key)
public_key = identity.to_public()  # → "age1..."
```

The 32-byte Argon2id output is used directly as the secret bytes for an age x25519 identity. The corresponding public key is in `manifest.json` under `expected_age_pubkey` — if your derived public key matches, your solution is correct.

### Verification Shortcut

You can check your derived public key without attempting decryption:

```bash
cat your-solution.csv | mandate-bounty derive-identity \
    --voters voters.xlsx \
    --manifest manifest.json
```

This runs the full KDF chain and prints the derived `age1...` public key. Compare it to `expected_age_pubkey` in `manifest.json`. Note that the KDF takes significant time and memory due to the Argon2id parameters.

---

## 7. Verification

### Full Verification

```bash
mandate-bounty verify-solution \
    --csv your-solution.csv \
    --voters voters.xlsx \
    --encrypted encrypted_secret.rage \
    --manifest manifest.json
```

This command:
1. Validates your CSV format (UTF-8, line count, `name,option` structure)
2. Runs the KDF chain (SHA3-512 → Argon2id → age identity)
3. Attempts to decrypt `encrypted_secret.rage` with the derived identity
4. On success: prints the decrypted content (mnemonic + contact info) to stdout
5. On failure: reports `Verification FAILED`

### Common Failure Modes

| Symptom | Likely Cause |
|---------|-------------|
| "CSV line N has 0 commas" | Missing comma separator in a line |
| "CSV line N has empty name field" | Leading comma (empty name) |
| "decryption failed (wrong solution?)" | Incorrect voter-to-vote mapping |
| KDF output key does not match | Sorting error, normalization issue, or wrong option IDs |

### CSV Validation Limits

The verifier enforces:
- Maximum file size: 10 MB
- Maximum line count: 10,000
- Each line must have exactly one comma
- Neither name nor option field may be empty

---

## 8. Attack Surface

This section describes areas where a challenger might look for weaknesses. The challenge is designed to be fair — the cryptography is sound in theory, but implementation and protocol details may introduce exploitable patterns.

### Ring Signature Analysis

- **Signature structure**: Each BLSAG signature contains response scalars, a challenge scalar, and a KeyImage. Examine whether the signature construction leaks information about the signer's position in the ring.
- **KeyImage analysis**: KeyImages are deterministic per-signer-per-poll. While they cannot be directly linked to public keys without the private key, patterns in KeyImage values might reveal structural information.
- **Ring construction**: The per-poll signing ring is derived deterministically. Understand the derivation to verify whether ring member ordering introduces any bias.

### Statistical Analysis

- **Vote distribution vs. voter demographics**: If voter names correlate with demographics or cultural patterns, and vote options have demographic skew, statistical inference might narrow possibilities.
- **Aggregate constraints**: You know the exact vote tally (e.g., 600 / 200 / 200). This constrains the solution space significantly — you are solving a combinatorial assignment problem with known marginals.
- **Combinatorial bounds**: With N voters and K options with known counts, the total solution space is `N! / (n1! * n2! * ... * nk!)`. For large N, this is astronomically large, but structural weaknesses could reduce it.

### Implementation Analysis

- **Event serialization**: VoteCast events are JSON-serialized. Examine whether serialization order, field presence, or formatting reveals information about the signer or generation order.
- **Timestamp and ULID patterns**: Each VoteCast event has its own ULID. ULIDs contain a timestamp component — if events were generated sequentially, the timestamp ordering might correlate with voter ordering before the shuffle.
- **Protobuf encoding**: The poll bundle uses Protocol Buffers. Examine whether field ordering or encoding details in the binary format leak information.

### Cryptographic Primitives

- **Curve operations**: Signatures use Ristretto25519. Examine the specific curve arithmetic implementation for side-channel leaks in the signature data.
- **Random number generation**: The shuffle uses OsRng. If the challenge was generated with a deterministic seed (for reproducibility), the PRNG state might be recoverable.
- **Key derivation determinism**: The per-poll key derivation is deterministic given the inputs. If you can enumerate the derivation for each voter, you can compare derived values against signature components.

### Metadata and Side Channels

- **File metadata**: The XLSX file, protobuf binary, and JSON files may contain creation timestamps, tool version strings, or other metadata.
- **Ordering artifacts**: Despite the CSPRNG shuffle, verify that no secondary ordering (e.g., protobuf field encoding order within each event) correlates with the pre-shuffle order.
- **Encryption metadata**: The age-encrypted file contains recipient metadata. Examine whether the ciphertext structure reveals anything about the plaintext or key.

### What You Can Verify

You have all the tools to independently verify the poll's integrity:

1. **Signature verification**: Every BLSAG signature in the bundle can be verified against the ring. Use the `poll_key_hex` to decrypt poll content and the derivation parameters to reconstruct the per-poll signing ring.
2. **KeyImage uniqueness**: Verify that no two VoteCast events share a KeyImage (no double-voting).
3. **Ring membership**: Verify that every ring member public key in the bundle corresponds to a voter in `voters.xlsx`.
4. **Vote count**: Verify that the number of VoteCast events matches `total_votes` in `results.json`, and that the per-option tallies sum correctly.

---

## Appendix: Quick Reference

### File Format Summary

| File | Format | Encoding |
|------|--------|----------|
| `voters.xlsx` | Office Open XML | Binary |
| `poll-bundle.bin` | Protocol Buffers | Binary |
| `results.json` | JSON | UTF-8 |
| `encrypted_secret.rage` | age encryption | Binary |
| `manifest.json` | JSON | UTF-8 |

### Option IDs

Option IDs are machine-readable identifiers (e.g., `opt-like`, `opt-unlike`, `opt-abstain`). They appear in both `results.json` (as tally keys) and `option_definitions` in the poll bundle. Use exactly these IDs in your canonical CSV.

### Key Algorithms

| Component | Algorithm |
|-----------|-----------|
| Ring signatures | BLSAG (Back's Linkable Spontaneous Anonymous Group, Ristretto25519) |
| Ring consensus hash | BLAKE3-XOF-512 |
| Content hash | SHA3-256 |
| KDF pre-hash | SHA3-512 |
| Memory-hard KDF | Argon2id v1.3 |
| Encryption | age x25519 (X25519 + ChaCha20-Poly1305) |
| Artifact integrity | SHA-256 |
| Public key encoding | Base58 (bs58) |

### Bounty Structure and Claim Procedure

| Component | Amount | Mechanism |
|-----------|--------|-----------|
| Instant proof | 100 USDC | Preloaded in the mnemonic-controlled wallet |
| Write-up reward | 400 USDC | Transferred after write-up verification |
| **Total** | **500 USDC** |
| Challenge period | 14 days |

**Claim procedure (read carefully):**

1. **Decrypt the secret.** A successful solution reveals a wallet mnemonic and contact information.
2. **Transfer the instant reward.** The mnemonic controls a wallet containing 100 USDC. Transfer it to a wallet you control. This is your proof of first-to-solve — the on-chain transfer timestamp is the canonical record.
3. **Submit your write-up.** Contact us using the information in the decrypted secret. Submit a write-up explaining your attack methodology (what worked, what failed, and why).
4. **Receive the write-up reward.** After we verify your write-up, 400 USDC will be sent to **the same wallet that received the 100 USDC in step 2** — not to any other address. This prevents impersonation: only the first solver who moved the 100 USDC can receive the 400 USDC reward.

**Eligibility:**

- **Only a full break qualifies.** You must decrypt the mnemonic. Partial findings, theoretical observations, or issues that do not lead to decryption are not eligible for bounty payment in this round.
- **First solver only.** Only the first person to move the 100 USDC receives the write-up reward.
- **Budget constraint.** Due to limited funding, we cannot guarantee payment for non-solution findings (e.g., minor implementation issues, theoretical weaknesses, or false positives). We appreciate responsible disclosure of any genuine vulnerabilities found during the challenge, but bounty payment is reserved for a complete break.
