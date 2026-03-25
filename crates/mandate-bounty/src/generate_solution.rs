//! Solution generation: random keypairs and vote assignments.
//!
//! Produces a [`SolutionBundle`] containing one keypair per voter and a
//! Fisher-Yates shuffled vote assignment that exactly satisfies the per-option
//! counts declared in the bounty config.

use nazgul::keypair::KeyPair;
use nazgul::traits::LocalByteConvertible;
use rand::seq::SliceRandom;
use rand::{CryptoRng, Rng};

use crate::config::BountyConfig;
use crate::solution_bundle::{SolutionBundle, SolutionEntry, VoterPrivateKey};

/// Generate a random solution: keypairs + vote assignments.
///
/// Uses the provided RNG (`OsRng` for production, `StdRng` for tests).
/// The caller must validate the config and names before calling this.
pub fn generate_solution<R: Rng + CryptoRng>(
    config: &BountyConfig,
    names: &[String],
    rng: &mut R,
) -> anyhow::Result<SolutionBundle> {
    let total = config.voters.total as usize;
    anyhow::ensure!(
        names.len() == total,
        "name count ({}) does not match voters.total ({total})",
        names.len()
    );

    // 1. Generate one keypair per voter.
    let mut keypairs = Vec::with_capacity(total);
    for _ in 0..total {
        keypairs.push(KeyPair::generate(rng));
    }

    // 2. Build the vote assignment array and shuffle it.
    let mut assignments: Vec<&str> = Vec::with_capacity(total);
    for opt in &config.poll.options {
        for _ in 0..opt.count {
            assignments.push(&opt.text_en);
        }
    }
    assignments.shuffle(rng);

    // 3. Assemble the solution entries and private key list.
    let mut solution = Vec::with_capacity(total);
    let mut voter_private_keys = Vec::with_capacity(total);

    for (i, kp) in keypairs.iter().enumerate() {
        let pubkey_bs58 = kp.public().to_base58();

        let scalar = kp
            .secret()
            .ok_or_else(|| anyhow::anyhow!("generated keypair at index {i} has no secret key"))?;
        let scalar_bs58 = scalar.to_base58();

        solution.push(SolutionEntry {
            pubkey_bs58: pubkey_bs58.clone(),
            name: names[i].clone(),
            option: assignments[i].to_owned(),
        });

        voter_private_keys.push(VoterPrivateKey {
            pubkey_bs58,
            scalar_bs58,
        });
    }

    Ok(SolutionBundle {
        version: 1,
        solution,
        voter_private_keys,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use std::collections::{HashMap, HashSet};

    /// Build a small test config (10 voters, 3 options: 5/3/2).
    fn test_config() -> BountyConfig {
        let toml_str = r#"
[challenge]
version = 1

[poll]
org_id = "test-org"
poll_ulid = "01TEST000000000000000000"
title_zh = "test-zh"
title_en = "Test Poll"

[[poll.options]]
id = "opt-a"
text_zh = "a-zh"
text_en = "Option A"
count = 5

[[poll.options]]
id = "opt-b"
text_zh = "b-zh"
text_en = "Option B"
count = 3

[[poll.options]]
id = "opt-c"
text_zh = "c-zh"
text_en = "Option C"
count = 2

[voters]
total = 10
names_file = "test.txt"
normalization = "NFC"

[kdf]
salt = "test-salt"
m_cost_mib = 64
t_cost = 1
p_cost = 1

[bounty]
total_usdc = 100
instant_usdc = 50
report_usdc = 50
challenge_days = 7
"#;
        toml::from_str(toml_str).expect("test config should parse")
    }

    fn test_names(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("Voter {i}")).collect()
    }

    #[test]
    fn test_generate_solution_correct_counts() {
        let config = test_config();
        let names = test_names(10);
        let mut rng = StdRng::seed_from_u64(42);

        let bundle = generate_solution(&config, &names, &mut rng).expect("should succeed");

        // Tally option assignments.
        let mut counts: HashMap<&str, u32> = HashMap::new();
        for entry in &bundle.solution {
            *counts.entry(entry.option.as_str()).or_default() += 1;
        }

        assert_eq!(counts.get("Option A"), Some(&5));
        assert_eq!(counts.get("Option B"), Some(&3));
        assert_eq!(counts.get("Option C"), Some(&2));
    }

    #[test]
    fn test_generate_solution_unique_pubkeys() {
        let config = test_config();
        let names = test_names(10);
        let mut rng = StdRng::seed_from_u64(123);

        let bundle = generate_solution(&config, &names, &mut rng).expect("should succeed");

        let pubkeys: HashSet<&str> = bundle
            .solution
            .iter()
            .map(|e| e.pubkey_bs58.as_str())
            .collect();
        assert_eq!(pubkeys.len(), 10, "all pubkeys must be distinct");

        // Private key pubkeys must match solution pubkeys.
        let priv_pubkeys: HashSet<&str> = bundle
            .voter_private_keys
            .iter()
            .map(|k| k.pubkey_bs58.as_str())
            .collect();
        assert_eq!(
            pubkeys, priv_pubkeys,
            "pubkeys must match between solution and private keys"
        );
    }

    #[test]
    fn test_generate_solution_deterministic() {
        let config = test_config();
        let names = test_names(10);

        let mut rng1 = StdRng::seed_from_u64(999);
        let bundle1 = generate_solution(&config, &names, &mut rng1).expect("should succeed");

        let mut rng2 = StdRng::seed_from_u64(999);
        let bundle2 = generate_solution(&config, &names, &mut rng2).expect("should succeed");

        // Same seed must produce identical pubkeys and assignments.
        for (a, b) in bundle1.solution.iter().zip(bundle2.solution.iter()) {
            assert_eq!(a.pubkey_bs58, b.pubkey_bs58);
            assert_eq!(a.name, b.name);
            assert_eq!(a.option, b.option);
        }
        for (a, b) in bundle1
            .voter_private_keys
            .iter()
            .zip(bundle2.voter_private_keys.iter())
        {
            assert_eq!(a.scalar_bs58, b.scalar_bs58);
        }
    }

    #[test]
    fn test_generate_solution_different_seeds() {
        let config = test_config();
        let names = test_names(10);

        let mut rng1 = StdRng::seed_from_u64(1);
        let bundle1 = generate_solution(&config, &names, &mut rng1).expect("should succeed");

        let mut rng2 = StdRng::seed_from_u64(2);
        let bundle2 = generate_solution(&config, &names, &mut rng2).expect("should succeed");

        // Different seeds should produce different pubkeys.
        let different = bundle1
            .solution
            .iter()
            .zip(bundle2.solution.iter())
            .any(|(a, b)| a.pubkey_bs58 != b.pubkey_bs58);
        assert!(different, "different seeds must produce different output");
    }
}
