//! Vote tallying logic.
//!
//! Aggregates votes by option ID and computes vote shares.

use std::collections::BTreeMap;

/// A single option's tally result.
#[derive(Debug, Clone, PartialEq)]
pub struct OptionTally {
    /// The option identifier.
    pub option_id: String,
    /// Human-readable option text.
    pub option_text: String,
    /// Number of votes for this option.
    pub votes: usize,
    /// Vote share as a fraction (0.0..=1.0).
    pub share: f64,
}

/// Complete tally of a poll.
#[derive(Debug, Clone)]
pub struct TallyResult {
    /// Per-option tallies, sorted by option_id.
    pub options: Vec<OptionTally>,
    /// Total number of votes counted.
    pub total_votes: usize,
}

/// A single vote's decoded choice.
#[derive(Debug, Clone)]
pub struct VoteChoice {
    /// The option this vote was cast for.
    pub option_id: String,
    /// Human-readable option text (for display).
    pub option_text: String,
}

/// Tally votes by option.
///
/// Takes a list of decoded vote choices and aggregates them into a
/// [`TallyResult`] with per-option counts and vote shares.
pub fn tally_votes(choices: &[VoteChoice]) -> TallyResult {
    let total = choices.len();

    // Aggregate by option_id, preserving option_text from first occurrence.
    let mut counts: BTreeMap<&str, (usize, &str)> = BTreeMap::new();
    for choice in choices {
        let entry = counts
            .entry(choice.option_id.as_str())
            .or_insert((0, choice.option_text.as_str()));
        entry.0 += 1;
    }

    let options = counts
        .into_iter()
        .map(|(id, (votes, text))| OptionTally {
            option_id: id.to_string(),
            option_text: text.to_string(),
            votes,
            share: if total > 0 {
                votes as f64 / total as f64
            } else {
                0.0
            },
        })
        .collect();

    TallyResult {
        options,
        total_votes: total,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_tally() {
        let choices = vec![
            VoteChoice {
                option_id: "a".into(),
                option_text: "Candidate A".into(),
            },
            VoteChoice {
                option_id: "b".into(),
                option_text: "Candidate B".into(),
            },
            VoteChoice {
                option_id: "a".into(),
                option_text: "Candidate A".into(),
            },
            VoteChoice {
                option_id: "a".into(),
                option_text: "Candidate A".into(),
            },
        ];

        let result = tally_votes(&choices);
        assert_eq!(result.total_votes, 4);
        assert_eq!(result.options.len(), 2);

        let opt_a = result.options.iter().find(|o| o.option_id == "a").unwrap();
        assert_eq!(opt_a.votes, 3);
        assert!((opt_a.share - 0.75).abs() < f64::EPSILON);

        let opt_b = result.options.iter().find(|o| o.option_id == "b").unwrap();
        assert_eq!(opt_b.votes, 1);
        assert!((opt_b.share - 0.25).abs() < f64::EPSILON);
    }

    #[test]
    fn test_empty_votes() {
        let choices: Vec<VoteChoice> = Vec::new();
        let result = tally_votes(&choices);
        assert_eq!(result.total_votes, 0);
        assert!(result.options.is_empty());
    }

    #[test]
    fn test_single_option() {
        let choices = vec![
            VoteChoice {
                option_id: "yes".into(),
                option_text: "Yes".into(),
            },
            VoteChoice {
                option_id: "yes".into(),
                option_text: "Yes".into(),
            },
        ];

        let result = tally_votes(&choices);
        assert_eq!(result.total_votes, 2);
        assert_eq!(result.options.len(), 1);
        assert!((result.options[0].share - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_many_options_with_zero() {
        // Simulate a poll where one option got zero votes:
        // Options a, b, c — only a and c receive votes.
        let choices = vec![
            VoteChoice {
                option_id: "a".into(),
                option_text: "Option A".into(),
            },
            VoteChoice {
                option_id: "c".into(),
                option_text: "Option C".into(),
            },
            VoteChoice {
                option_id: "a".into(),
                option_text: "Option A".into(),
            },
        ];

        let result = tally_votes(&choices);
        assert_eq!(result.total_votes, 3);
        // "b" never voted for, so it won't appear in results.
        // This is correct: zero-vote options are not in the vote stream.
        assert_eq!(result.options.len(), 2);
    }

    #[test]
    fn test_shares_sum_to_one() {
        let choices = vec![
            VoteChoice {
                option_id: "x".into(),
                option_text: "X".into(),
            },
            VoteChoice {
                option_id: "y".into(),
                option_text: "Y".into(),
            },
            VoteChoice {
                option_id: "z".into(),
                option_text: "Z".into(),
            },
            VoteChoice {
                option_id: "x".into(),
                option_text: "X".into(),
            },
            VoteChoice {
                option_id: "y".into(),
                option_text: "Y".into(),
            },
        ];

        let result = tally_votes(&choices);
        let total_share: f64 = result.options.iter().map(|o| o.share).sum();
        assert!(
            (total_share - 1.0).abs() < 1e-10,
            "shares should sum to 1.0, got {total_share}"
        );
    }

    // -----------------------------------------------------------------------
    // Golden-value test: exact share values for known split
    // -----------------------------------------------------------------------

    #[test]
    fn test_golden_tally_two_one_split() {
        // 3 votes split 2:1 -> 66.67%:33.33% (exact: 2/3 and 1/3)
        let choices = vec![
            VoteChoice {
                option_id: "yes".into(),
                option_text: "Yes".into(),
            },
            VoteChoice {
                option_id: "yes".into(),
                option_text: "Yes".into(),
            },
            VoteChoice {
                option_id: "no".into(),
                option_text: "No".into(),
            },
        ];

        let result = tally_votes(&choices);
        assert_eq!(result.total_votes, 3);
        assert_eq!(result.options.len(), 2);

        let opt_no = result
            .options
            .iter()
            .find(|o| o.option_id == "no")
            .expect("should have 'no' option");
        let opt_yes = result
            .options
            .iter()
            .find(|o| o.option_id == "yes")
            .expect("should have 'yes' option");

        // Exact floating point comparison: 2/3 and 1/3
        assert!(
            (opt_yes.share - 2.0 / 3.0).abs() < f64::EPSILON,
            "yes share should be 2/3, got {}",
            opt_yes.share
        );
        assert!(
            (opt_no.share - 1.0 / 3.0).abs() < f64::EPSILON,
            "no share should be 1/3, got {}",
            opt_no.share
        );
        assert_eq!(opt_yes.votes, 2);
        assert_eq!(opt_no.votes, 1);
    }

    #[test]
    fn test_golden_tally_even_three_way_split() {
        // 3 votes across 3 options -> each gets 1/3
        let choices = vec![
            VoteChoice {
                option_id: "a".into(),
                option_text: "A".into(),
            },
            VoteChoice {
                option_id: "b".into(),
                option_text: "B".into(),
            },
            VoteChoice {
                option_id: "c".into(),
                option_text: "C".into(),
            },
        ];

        let result = tally_votes(&choices);
        assert_eq!(result.total_votes, 3);
        assert_eq!(result.options.len(), 3);

        for opt in &result.options {
            assert_eq!(opt.votes, 1);
            assert!(
                (opt.share - 1.0 / 3.0).abs() < f64::EPSILON,
                "each option should get 1/3, got {}",
                opt.share
            );
        }
    }

    #[test]
    fn test_golden_tally_unanimous() {
        // All votes for one option -> 100% share
        let choices: Vec<VoteChoice> = (0..10)
            .map(|_| VoteChoice {
                option_id: "only".into(),
                option_text: "The Only Choice".into(),
            })
            .collect();

        let result = tally_votes(&choices);
        assert_eq!(result.total_votes, 10);
        assert_eq!(result.options.len(), 1);
        assert_eq!(result.options[0].votes, 10);
        assert!((result.options[0].share - 1.0).abs() < f64::EPSILON);
    }

    // -----------------------------------------------------------------------
    // Edge case: option_text from first occurrence is preserved
    // -----------------------------------------------------------------------

    #[test]
    fn test_option_text_from_first_occurrence() {
        let choices = vec![
            VoteChoice {
                option_id: "opt1".into(),
                option_text: "First text".into(),
            },
            VoteChoice {
                option_id: "opt1".into(),
                option_text: "Different text same id".into(),
            },
        ];

        let result = tally_votes(&choices);
        assert_eq!(result.options[0].option_text, "First text");
    }

    // -----------------------------------------------------------------------
    // Edge case: many options (stress)
    // -----------------------------------------------------------------------

    #[test]
    fn test_many_options_shares_sum_to_one() {
        // 100 votes across 20 options
        let choices: Vec<VoteChoice> = (0..100)
            .map(|i| VoteChoice {
                option_id: format!("opt-{}", i % 20),
                option_text: format!("Option {}", i % 20),
            })
            .collect();

        let result = tally_votes(&choices);
        assert_eq!(result.total_votes, 100);
        assert_eq!(result.options.len(), 20);

        let total_share: f64 = result.options.iter().map(|o| o.share).sum();
        assert!(
            (total_share - 1.0).abs() < 1e-10,
            "shares should sum to 1.0 even with many options, got {total_share}"
        );

        // Each option should have 5 votes (100 / 20)
        for opt in &result.options {
            assert_eq!(opt.votes, 5);
            assert!((opt.share - 0.05).abs() < f64::EPSILON);
        }
    }
}
