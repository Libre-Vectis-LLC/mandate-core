# Contributing to mandate-core

Thank you for considering contributing to mandate-core! This document
outlines the process for contributing to this project.

## Getting Started

1. Fork the repository
2. Clone your fork and set up the development environment
3. Create a feature branch: `git checkout -b feat/your-feature`

## Development Setup

```bash
# Install Rust (stable)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install just (command runner)
cargo install just

# Build all crates
cargo build --workspace

# Run tests
cargo test --workspace --all-features
```

### Dependencies

- Rust stable (1.75+)
- OpenCC library (for i18n Chinese variant conversion)
  - Ubuntu/Debian: `sudo apt-get install libopencc-dev`
  - macOS: `brew install opencc`

## Code Style

- Follow `rustfmt` defaults (run `cargo fmt --all` before committing)
- All clippy warnings are errors (`-D warnings`)
- Comments and documentation in English
- Use `thiserror` for error types in libraries
- Prefer `bs58` encoding over base64 (see encoding standards)

## Pull Request Process

1. Ensure your code compiles without warnings: `cargo clippy --workspace --all-features`
2. Run the full test suite: `cargo test --workspace --all-features`
3. Update documentation if you changed public APIs
4. Write a clear PR description explaining the change

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(verify): add support for batch verification
fix(crypto): handle edge case in HKDF derivation
docs: update verification workflow diagram
```

## Security

If you discover a security vulnerability, please report it responsibly.
See [SECURITY.md](SECURITY.md) for details. **Do not open a public issue
for security vulnerabilities.**

## License

By contributing, you agree that your contributions will be licensed under
the Apache License 2.0.
