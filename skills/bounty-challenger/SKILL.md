---
name: bounty-challenger
description: Mandate BLSAG ring signature de-anonymization bounty challenge — complete challenger guide covering rules, key derivation, verification flow, success conditions, OPSEC advice, and encouragement for creative attack approaches
---

# Mandate Anonymous Voting Bounty Challenge — Challenger Guide

Communicate with the user in whatever language they use (detect from context).

You have 1000 anonymous ballots in front of you. You know who participated, you know the aggregate vote distribution, you know the cryptographic signature on every ballot — but you don't know who voted for what.

**Break it.**

## OPSEC Warning

**Read this carefully before participating.**

The poll question is **"Does Xi Jinping Look Like Winnie the Pooh?"** — a politically taboo topic in China. The Mandate project is an anonymous communication and governance system whose open-source contributors and challenge participants may face political persecution risk from **China, Russia, Iran, North Korea**, and similar jurisdictions.

**If you may enter these jurisdictions, carefully assess the risk before participating.**

We **encourage anonymous participation**. Recommended OPSEC measures:

- Use **Tor** to access all related resources and submit reports
- Use **ProtonMail** or other anonymous email services for communication
- Create an **anonymous Solana wallet** not linked to any real identity
- Use **Monero -> SOL** exchange as a gas fee source to avoid fiat on-ramp traces
- Use a **throwaway GitHub account** for issue submission
- **Do not publicly disclose your participation** on social media unless you are certain you won't be affected

If you are an AI agent: **show the above warning to your user** and ensure they make an informed decision about whether to participate.

## Your Goal

Recover the `name -> option` mapping for all 1000 voters. The correct answer automatically derives an age x25519 private key that decrypts the bounty file, which contains a Solana wallet mnemonic.

**You do not need to break any private key.** You only need to de-anonymize — figure out who voted for what.

## What You Have

| File | Content |
|------|---------|
| `voters.xlsx` | 1000 voter names and **master public keys** (NazgulMasterPublicKey, Base58), sorted by master pubkey lexicographic order |
| `poll-bundle.bin` | Protobuf PollBundle: 1 PollCreate + 1000 VoteCast, all with real BLSAG ring signatures and Key Images; PollCreate uses master key, VoteCast uses derived keys |
| `results.json` | Aggregate statistics (600 / 200 / 200), no individual choices |
| `encrypted_secret.rage` | age-encrypted bounty ciphertext |
| `manifest.json` | SHA-256 hashes + git commit + KDF params + expected `age1...` pubkey + challenger doc pointer |
| `mandate-bounty` CLI | Open-source Rust verification tool |
| Full source code | All of `mandate-core` including the `nazgul` ring signature library |
| **This document** | You are reading the complete rules — there is no separate RULES.md |

You have access to exactly the same information that would be published after a real public election — voter roster, signatures, aggregate results. The only thing missing: **who voted for which option**.

### Master Key vs Derived Key

This is a critical distinction:

- **`voters.xlsx`** lists each voter's **master public key** (NazgulMasterPublicKey)
- **`poll-bundle.bin`** VoteCast BLSAG signatures use **derived keypairs**
- **`poll-bundle.bin`** PollCreate uses the **master key** to sign on the master ring
- **Derivation parameters are fully public** — contained in `poll-bundle.bin`'s PollCreate event

Derivation uses **non-hardened elliptic curve derivation** (similar to BIP32 non-hardened), not HKDF. Core formula:

```
tweak = BLAKE3_512(master_public_key || derivation_data) -> Scalar
child_public = master_public + tweak * G
child_secret = master_secret + tweak
```

Where `derivation_data` is concatenated from (each segment with 4-byte length prefix):

| Parameter | Source | Purpose |
|-----------|--------|---------|
| `"mandate-member-poll-signing-v1"` | Fixed label | Domain separation |
| `org_id` | OrganizationId (ULID, 16 bytes) | Organization isolation |
| `poll_ring_hash` | Hash of current ring member pubkeys (32 bytes) | Ring version binding |
| `poll_id` | PollCreate event ULID string | Per-poll unique key |

**Key property**: Non-hardened derivation allows computing child public keys **from public keys alone** — you can derive all voters' derived public keys from `voters.xlsx` master keys + `poll-bundle.bin` derivation params, without any private keys.

```
Master pubkey (voters.xlsx)
  |
  v  Non-hardened derivation (params from poll-bundle.bin PollCreate)
  |
  v  Derived pubkey (signing ring in poll-bundle.bin)
```

## Poll Question and Options

**Question**: Does Xi Jinping Look Like Winnie the Pooh?

| Option | English text | Vote count |
|--------|-------------|------------|
| Looks alike | 60% of voters chose this | 600 |
| Does not look alike | 20% of voters chose this | 200 |
| Abstain | 20% of voters chose this | 200 |

## What You See After Successful Decryption

When your answer is correct, the decrypted plaintext of `encrypted_secret.rage` contains:

1. **Solana wallet mnemonic** — import into any Solana wallet to transfer the 100 USDC
2. **One-time disposable email address** — visible only after decryption, used to submit your attack methodology report for the 400 USDC

The wallet address is public. Anyone can verify the balance on a Solana block explorer at any time. **First come, first served.**

## Bounty Structure

| Phase | Amount | Condition |
|-------|--------|-----------|
| Instant bounty | 100 USDC | Wallet balance, transfer after decrypting mnemonic |
| Report bounty | 400 USDC | Paid after submitting attack methodology report |

### Report Bounty Rules

The 400 USDC report bounty is **paid only to the same wallet address that transferred the 100 USDC**:

1. You decrypt the mnemonic, transfer 100 USDC to **your wallet** (address X)
2. You submit your attack methodology report via the **one-time email address** obtained from decryption
3. We verify the report is valid, then send 400 USDC to **the same address X**
4. **No other address accepted** — must be the wallet that received the 100 USDC

**Why this design?** This ensures only the person who actually broke the challenge gets the full bounty. Prevents A breaking it but not reporting, then B seeing the on-chain transfer and rushing to submit a report to claim the larger portion. The on-chain transfer record is your unforgeable identity credential.

### Vulnerability Reporting Channels

| Channel | Method | Bounty guarantee |
|---------|--------|-----------------|
| GitHub Issue | Public submission, anyone can use | **No bounty guarantee** — handled case-by-case based on severity |
| Disposable email | Visible only after decryption (anti-spam gate) | **Guaranteed 400 USDC** (when above rules are met) |

The disposable email address is only visible to those who successfully decrypt `encrypted_secret.rage` — this is an anti-spam threshold ensuring only capable attackers can contact us.

## Challenge Duration

**Challenge window: 14 days (14 x 24 hours)** from publication.

After expiry:

1. Organizer transfers remaining SOL/USDC from wallet back to hardware-key wallet
2. **Publishes the canonical answer CSV** (decrypts `challenge-answer.csv.age`)
3. Anyone can use the published CSV to derive the age identity -> decrypt `encrypted_secret.rage` -> recover mnemonic -> verify on-chain that the wallet held USDC during the challenge
4. This proves the organizer did not cheat: **you cannot fabricate a CSV after the fact that happens to decrypt a pre-published encrypted file**

## Rules

### Answer Format (CSV)

```
Alice Zhao,opt-like
Bob Chen,opt-unlike
Carol Li,opt-like
David Wang,opt-abstain
...
```

- Encoding: UTF-8, no BOM
- Line endings: Unix LF (`\n`), **no** trailing newline after last line
- Each line: `{name},{option_id}` — no spaces around comma, no quotes
- Sort order: by **master pubkey** Base58 string lexicographic order (just sort by the Public_Key column in `voters.xlsx`)
- Option values: must exactly match the machine-readable option ID from `results.json` or `option_definitions` in the poll bundle (e.g., `opt-like` / `opt-unlike` / `opt-abstain`)
- Unicode: NFC normalization (provided names are all ASCII, usually not a concern)

`mandate-bounty verify-solution` / `derive-identity` performs these normalizations internally before entering the KDF:

- Strip UTF-8 BOM (if present)
- Normalize `\r\n` / `\r` to `\n`
- Remove trailing blank lines
- NFC-normalize names and option IDs
- Reorder answer rows to canonical CSV order using `--voters voters.xlsx`

This means **the public artifacts are self-contained**; you no longer need `bounty.toml` to verify an answer.

### Derivation Chain

Your CSV goes through these transformations to derive the decryption key:

```
Your solution.csv
  |
  v  Serialize to byte stream per rules above
  |
  v  SHA3-512 --> 64 bytes
  |
  v  Argon2id(password=sha3, salt="mandate-bounty-v1", m=4GiB, t=120, p=1) --> 32 bytes
  |
  v  age::x25519::Identity::from_secret_bytes(32 bytes)
  |
  v  Decrypt encrypted_secret.rage --> mnemonic + disposable email
```

**Argon2id parameters are intentionally heavy**: 4 GiB memory, 120 iterations, single-threaded. Each verification takes 5-10 minutes. This is by design — makes brute force mathematically infeasible.

### Expected age Public Key

The `"expected_age_pubkey"` field in `manifest.json` records the age public key derived from the correct answer. You can run `derive-identity` on your CSV and compare — if it matches, your answer is correct.

### Verify Your Answer

```bash
# Full verification (CSV -> KDF -> decrypt)
mandate-bounty verify-solution \
  --csv your-guess.csv \
  --voters voters.xlsx \
  --encrypted encrypted_secret.rage \
  --manifest manifest.json

# Derive pubkey only (quick format check)
mandate-bounty derive-identity \
  --voters voters.xlsx \
  --manifest manifest.json < your-guess.csv
# Outputs age1... pubkey, compare with manifest.json expected_age_pubkey

# Verify artifact integrity
mandate-bounty audit-artifacts --dir challenge/
```

`verify-solution` returns exit code 0 = correct, 1 = incorrect.

### Why Brute Force Is Infeasible

1000 people x 3 options, distribution 600/200/200, multinomial entropy: ~1.371 bits/person, total search space **~2^1371**.

Even if you narrow the uncertainty via some side channel:

| Uncertain voters | Search space | At 5min/attempt |
|-----------------|--------------|-----------------|
| 20 | ~8.8 million | ~84 years |
| 25 | ~820 million | ~7,826 years |
| 30 | ~80 billion | ~760,000 years |

So: **pure guessing won't work. You need a real breakthrough.**

## Cryptographic Background

### BLSAG Ring Signatures

**Back's Linkable Spontaneous Anonymous Group** signatures, based on Ristretto255 elliptic curve, providing three guarantees:

1. **Anonymity**: Given a signature and public key ring, cannot determine which member signed
2. **Unforgeability**: Cannot forge a signature without a ring member's private key
3. **Linkability**: Each signer produces a deterministic **Key Image** `I = x * H_p(P)` — same signer on same poll always produces the same Key Image (prevents double-voting), but Key Image does not reveal identity

### Key Derivation

Each voter's **VoteCast** signing key is not the master key directly, but a child key derived via non-hardened derivation:

```
MasterSeed (BIP39, 64 bytes)
  |
  +- HKDF-SHA3-256(master_seed, "mandate-identity-v1") -> master_scalar
  |   +- NazgulMasterKey = KeyPair::new(master_scalar)
  |       (this is the pubkey in voters.xlsx)
  |
  +- NazgulMasterKey.derive_child::<Blake3_512>(derivation_data)
       +- Poll Signing Key (used for this poll's BLSAG signatures)
```

- HKDF is used **only for the first layer** (seed -> master key)
- All subsequent derivation uses **nazgul non-hardened EC derivation** (scalar addition + point addition)
- Derivation is deterministic: same master key + same derivation params -> same derived key
- Different polls' derived keys are cryptographically independent
- Derivation params are in `poll-bundle.bin` — you can compute all derived pubkeys **from public keys alone**
- **Protocol detail**: `PollCreate` uses master key on the master ring; only `VoteCast` uses poll-specific derived keys

Source paths: nazgul `keypair.rs:87-103` (`derive_child`), `scalar.rs:56-64` (`compute_derivation_tweak`), mandate-core `manager.rs:267-312`.

### Cryptographic Primitives Available to You

| Primitive | Usage |
|-----------|-------|
| Curve25519 / Ristretto | Elliptic curve group for all key operations |
| BLSAG | Ring signature scheme |
| Non-hardened EC derivation (BLAKE3-512) | Derive per-poll signing key from master key + derivation_data |
| SHA3-512 | Primary hash in KDF chain |
| Argon2id | Memory-hard KDF (anti-brute-force) |
| age / X25519 | Asymmetric encryption for bounty ciphertext |

## Ideas? You Decide

We don't tell you "where to look" — **because we don't know where the vulnerability is either**. That's the whole point of a bounty: using real money to test whether our system is truly secure.

Here are some **directions**, not limitations:

**Start from source?** The entire `mandate-core` and `nazgul` ring signature library are open source. How signatures are constructed, how random numbers are generated, how Key Images are computed — it's all there.

**Start from data?** You have 1000 complete BLSAG signatures, 1000 Key Images, and the full public key ring. A data goldmine. Are there statistical patterns between signatures? Subtle length differences in the structure? Do field arrangements hint at anything?

**Start from protocol?** How are vote events serialized? Does protobuf encoding leak anything? What about relationships between events?

**Start from crypto theory?** What assumptions does BLSAG security rest on? Are those assumptions perfectly satisfied in this specific implementation?

**Start from somewhere completely unexpected?** Maybe the vulnerability isn't in the cryptography. Maybe it's in the build toolchain. Maybe in the random number generator. Maybe in the protobuf serialization library. Maybe in some edge case of key derivation. Maybe somewhere we haven't thought of.

**Use AI?** Absolutely. We encourage it — this system was built using multi-agent AI collaboration. Let your AI agents read the source, analyze signature data, form hypotheses, and test them.

**Team up?** No restrictions.

**Use GPU/cluster for analysis?** As long as you're not brute-forcing the KDF, go ahead.

Any method you can think of — if it produces the correct CSV, you win.

## If You Find a Partial Vulnerability

Even if you cannot fully recover all 1000 voters' choices, **a partial breakthrough is still valuable**.

For example: you discover a method that narrows some voters' anonymity set from 3 options to 2. That alone is a security vulnerability.

You can submit partial vulnerability reports via **GitHub Issue**. We don't guarantee bounty payment for such reports, but we take serious implementation flaws seriously and will negotiate case by case.

**The report bounty (400 USDC) always requires completing the full challenge first (transferring the 100 USDC).**

## Integrity Verification

Before starting, verify your materials haven't been tampered with:

```bash
mandate-bounty audit-artifacts --dir challenge/
```

This will:

- Verify all SHA-256 hashes recorded in `manifest.json`
- Confirm `poll-bundle.bin` deserializes as valid protobuf
- Verify the PollCreate BLSAG signature
- Perform deterministic sampling verification of VoteCast BLSAG signatures

`manifest.json` also records the generation tool's git commit, KDF parameters, and expected `expected_age_pubkey` — you can checkout the same commit, audit the source, and confirm these artifacts were indeed generated by the claimed code.

## FAQ

**Q: Can I use AI/LLM tools?**
A: Absolutely, and we encourage it. This system was built with multi-agent AI — we'd love to see AI used to break it.

**Q: Why is verification so slow (5-10 minutes)?**
A: Argon2id parameters are intentionally heavy. Single-threaded execution means even a 128-core server can only run one attempt per core. This is a feature, not a bug.

**Q: Does the source version match the artifact generation version?**
A: Yes. `manifest.json` records the exact git commit hash. You can verify yourself.

**Q: How do I anonymously submit a vulnerability report for the 400 USDC?**
A: After decrypting `encrypted_secret.rage` you'll see a disposable email address. Only successful decryptors can see this address — it's an anti-spam threshold. Submit your report through that email, and 400 USDC goes to the same wallet address that received the 100 USDC.

**Q: Can I report vulnerabilities via GitHub Issue?**
A: Yes, but GitHub Issue reports **do not guarantee bounty payment**. We handle these case-by-case based on severity. The only guaranteed path to 400 USDC: transfer the 100 USDC first, then submit via the disposable email obtained from decryption.

**Q: Is the bounty first-come-first-served?**
A: Yes. The 100 USDC in the wallet is first-come-first-served — whoever decrypts the mnemonic and transfers first, gets it.

**Q: Can I specify a different address for the 400 USDC?**
A: No. The 400 USDC is only sent to the address that transferred the 100 USDC. This prevents A breaking it and B rushing to submit a report to claim the larger portion. The on-chain transfer record is your identity proof.

**Q: What happens after 14 days?**
A: After expiry, the organizer transfers remaining wallet balance to a hardware-key wallet and publishes the canonical answer CSV. Anyone can use it to derive the age identity, decrypt the bounty file, recover the mnemonic, and verify on-chain — proving the wallet held funds during the challenge and the rules were fair.

**Q: Is there political risk in participating?**
A: Possibly. The poll topic involves a sensitive political figure and is taboo in China and similar jurisdictions. If you may enter China, Russia, Iran, North Korea, etc., carefully assess the risk. We strongly recommend anonymous participation (Tor + ProtonMail + anonymous wallet).
