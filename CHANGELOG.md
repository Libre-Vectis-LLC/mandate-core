dcc705da9c38f85864894b7f041f68150ff4462d
- Trimmed TODO backlog by removing completed P0 items and restating remaining work at P1/P2.
- Standardized hash policy to prefer SHA3-256 (use SHA3-512 only when digest length is strictly needed); aligns helpers/tests/docs tasks accordingly.
b72575f6618cab6df9f74b41d6c6b5e2a82d0dcc
- Introduced `hashing` module with SHA3-256 as default and optional SHA3-512, covering byte, ciphertext, and nazgul ring consensus hashes.
- Removed blake3 dependency; pinned nazgul to master (0808e847) to leverage production ring hashing and ordering invariants.
- Added deterministic tests for SHA3 helpers and order-invariant ring hashing; no API surface changes elsewhere.
