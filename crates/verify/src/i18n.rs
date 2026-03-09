//! Internationalization support for verification reports.
//!
//! Static strings (sheet headers, labels, status text) are manually translated
//! in three languages (Simplified Chinese, English, Traditional Chinese) to
//! avoid OpenCC political terminology issues critical for overseas parliaments.
//!
//! Dynamic content (poll questions, option text) uses OpenCC `S2TWP` runtime
//! conversion because it is user-authored general prose.

use std::fmt;
use std::str::FromStr;

/// Errors produced by the i18n module.
#[derive(Debug, thiserror::Error)]
pub enum I18nError {
    /// An unrecognized language code was provided.
    #[error("unknown language code: {0}")]
    UnknownLanguage(String),

    /// An invalid locale string was provided.
    #[error("invalid locale string: {0}")]
    InvalidLocale(String),

    /// OpenCC conversion failed.
    #[cfg(feature = "opencc")]
    #[error("opencc conversion failed: {0}")]
    OpenccError(String),
}

// ---------------------------------------------------------------------------
// Language
// ---------------------------------------------------------------------------

/// Supported languages for verification reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Language {
    /// Simplified Chinese
    Zhs,
    /// English
    En,
    /// Traditional Chinese (static strings manually translated)
    Zht,
}

impl fmt::Display for Language {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Language::Zhs => write!(f, "zhs"),
            Language::En => write!(f, "en"),
            Language::Zht => write!(f, "zht"),
        }
    }
}

impl FromStr for Language {
    type Err = I18nError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "zhs" | "zh-cn" | "zh_cn" => Ok(Language::Zhs),
            "en" => Ok(Language::En),
            "zht" | "zh-tw" | "zh_tw" => Ok(Language::Zht),
            other => Err(I18nError::UnknownLanguage(other.to_owned())),
        }
    }
}

// ---------------------------------------------------------------------------
// Locale
// ---------------------------------------------------------------------------

/// Output locale: either a single language or bilingual (dual-column headers).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Locale {
    /// Single-language output.
    Single(Language),
    /// Bilingual output with primary and secondary languages.
    Bilingual(Language, Language),
}

impl Locale {
    /// Parse a locale string such as `"zhs"`, `"en"`, `"zhs+en"`, `"zht+en"`.
    pub fn parse(s: &str) -> Result<Self, I18nError> {
        if let Some((left, right)) = s.split_once('+') {
            let primary = Language::from_str(left.trim())?;
            let secondary = Language::from_str(right.trim())?;
            if primary == secondary {
                return Err(I18nError::InvalidLocale(format!(
                    "bilingual locale must have two different languages: {s}"
                )));
            }
            Ok(Locale::Bilingual(primary, secondary))
        } else {
            Ok(Locale::Single(Language::from_str(s.trim())?))
        }
    }

    /// Return the languages contained in this locale.
    pub fn languages(&self) -> Vec<Language> {
        match self {
            Locale::Single(lang) => vec![*lang],
            Locale::Bilingual(a, b) => vec![*a, *b],
        }
    }
}

impl fmt::Display for Locale {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Locale::Single(lang) => write!(f, "{lang}"),
            Locale::Bilingual(a, b) => write!(f, "{a}+{b}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Translation keys and static translation table
// ---------------------------------------------------------------------------

/// Translation keys for verification report strings.
///
/// Each variant maps to a human-readable label used in XLSX sheets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TranslationKey {
    // Sheet names
    VerificationSummary,
    RegistryMapping,
    TallyResults,
    VoteAudit,
    Charts,
    NotVoted,

    // Headers — summary
    PollTitle,
    PollId,
    OrgId,
    CreatedAt,
    Deadline,
    RingSize,
    VotesCast,
    Turnout,
    SignaturesVerified,
    KeyImagesUnique,
    RegistryMatches,

    // Headers — registry
    VoterInfo,
    MasterPubKey,
    DerivedPubKey,

    // Headers — vote audit
    KeyImageBs58,
    VoteChoice,
    RevokedColumn,

    // Headers — revocation audit
    RevocationAudit,
    RevokedStatus,
    SignatureValid,
    RevokedYes,
    RevokedNo,

    // Headers — tally
    OptionId,
    OptionText,
    Votes,
    Share,
    Total,

    // Status values
    Yes,
    No,
}

/// Return the static translation for a given key and language.
///
/// All translations are manually curated to avoid OpenCC political terminology
/// issues (e.g., "network" = \u{7f51}\u{7edc} in Mainland vs \u{7db2}\u{8def} in Taiwan).
pub fn translate(key: TranslationKey, language: Language) -> &'static str {
    use Language::*;
    use TranslationKey::*;

    match (key, language) {
        // --- Sheet names ---
        (VerificationSummary, Zhs) => "\u{9a8c}\u{8bc1}\u{6458}\u{8981}",
        (VerificationSummary, En) => "Verification Summary",
        (VerificationSummary, Zht) => "\u{9a57}\u{8b49}\u{6458}\u{8981}",

        (RegistryMapping, Zhs) => "\u{767b}\u{8bb0}\u{6620}\u{5c04}",
        (RegistryMapping, En) => "Registry Mapping",
        (RegistryMapping, Zht) => "\u{767b}\u{8a18}\u{5c0d}\u{6620}",

        (TallyResults, Zhs) => "\u{8ba1}\u{7968}\u{7ed3}\u{679c}",
        (TallyResults, En) => "Tally Results",
        (TallyResults, Zht) => "\u{8a08}\u{7968}\u{7d50}\u{679c}",

        (VoteAudit, Zhs) => "\u{6295}\u{7968}\u{5ba1}\u{8ba1}",
        (VoteAudit, En) => "Vote Audit",
        (VoteAudit, Zht) => "\u{6295}\u{7968}\u{5be9}\u{8a08}",

        (Charts, Zhs) => "\u{56fe}\u{8868}",
        (Charts, En) => "Charts",
        (Charts, Zht) => "\u{5716}\u{8868}",

        // NotVoted = "\u{672a}\u{6295}\u{7968}"
        (NotVoted, Zhs) => "\u{672a}\u{6295}\u{7968}",
        (NotVoted, En) => "Not Voted",
        (NotVoted, Zht) => "\u{672a}\u{6295}\u{7968}",

        // --- Summary headers ---
        (PollTitle, Zhs) => "\u{6295}\u{7968}\u{6807}\u{9898}",
        (PollTitle, En) => "Poll Title",
        (PollTitle, Zht) => "\u{6295}\u{7968}\u{6a19}\u{984c}",

        (PollId, Zhs) => "\u{6295}\u{7968}ID",
        (PollId, En) => "Poll ID",
        (PollId, Zht) => "\u{6295}\u{7968}ID",

        (OrgId, Zhs) => "\u{7ec4}\u{7ec7}ID",
        (OrgId, En) => "Organization ID",
        (OrgId, Zht) => "\u{7d44}\u{7e54}ID",

        (CreatedAt, Zhs) => "\u{521b}\u{5efa}\u{65f6}\u{95f4}",
        (CreatedAt, En) => "Created At",
        (CreatedAt, Zht) => "\u{5efa}\u{7acb}\u{6642}\u{9593}",

        (Deadline, Zhs) => "\u{622a}\u{6b62}\u{65f6}\u{95f4}",
        (Deadline, En) => "Deadline",
        (Deadline, Zht) => "\u{622a}\u{6b62}\u{6642}\u{9593}",

        (RingSize, Zhs) => "\u{73af}\u{5927}\u{5c0f}",
        (RingSize, En) => "Ring Size",
        (RingSize, Zht) => "\u{74b0}\u{5927}\u{5c0f}",

        (VotesCast, Zhs) => "\u{5df2}\u{6295}\u{7968}\u{6570}",
        (VotesCast, En) => "Votes Cast",
        (VotesCast, Zht) => "\u{5df2}\u{6295}\u{7968}\u{6578}",

        (Turnout, Zhs) => "\u{6295}\u{7968}\u{7387}",
        (Turnout, En) => "Turnout",
        (Turnout, Zht) => "\u{6295}\u{7968}\u{7387}",

        (SignaturesVerified, Zhs) => "\u{7b7e}\u{540d}\u{9a8c}\u{8bc1}",
        (SignaturesVerified, En) => "Signatures Verified",
        (SignaturesVerified, Zht) => "\u{7c3d}\u{540d}\u{9a57}\u{8b49}",

        (KeyImagesUnique, Zhs) => "\u{5bc6}\u{94a5}\u{6620}\u{50cf}\u{552f}\u{4e00}",
        (KeyImagesUnique, En) => "Key Images Unique",
        (KeyImagesUnique, Zht) => "\u{91d1}\u{9470}\u{6620}\u{50cf}\u{552f}\u{4e00}",

        (RegistryMatches, Zhs) => "\u{767b}\u{8bb0}\u{5339}\u{914d}",
        (RegistryMatches, En) => "Registry Matches",
        (RegistryMatches, Zht) => "\u{767b}\u{8a18}\u{5339}\u{914d}",

        // --- Vote detail headers ---
        (VoterInfo, Zhs) => "\u{6295}\u{7968}\u{4eba}\u{4fe1}\u{606f}",
        (VoterInfo, En) => "Voter Info",
        (VoterInfo, Zht) => "\u{6295}\u{7968}\u{4eba}\u{8cc7}\u{8a0a}",

        (MasterPubKey, Zhs) => "\u{4e3b}\u{516c}\u{94a5}",
        (MasterPubKey, En) => "Master Public Key",
        (MasterPubKey, Zht) => "\u{4e3b}\u{516c}\u{9470}",

        (DerivedPubKey, Zhs) => "\u{6d3e}\u{751f}\u{516c}\u{94a5}",
        (DerivedPubKey, En) => "Derived Public Key",
        (DerivedPubKey, Zht) => "\u{884d}\u{751f}\u{516c}\u{9470}",

        // --- Vote audit headers ---
        (KeyImageBs58, Zhs) => "\u{5bc6}\u{94a5}\u{6620}\u{50cf} (bs58)",
        (KeyImageBs58, En) => "Key Image (bs58)",
        (KeyImageBs58, Zht) => "\u{91d1}\u{9470}\u{6620}\u{50cf} (bs58)",

        (VoteChoice, Zhs) => "\u{6295}\u{7968}\u{9009}\u{9879}",
        (VoteChoice, En) => "Vote Choice",
        (VoteChoice, Zht) => "\u{6295}\u{7968}\u{9078}\u{9805}",

        // Revoked column in Vote Audit
        (RevokedColumn, Zhs) => "\u{5df2}\u{64a4}\u{9500}",
        (RevokedColumn, En) => "Revoked",
        (RevokedColumn, Zht) => "\u{5df2}\u{64a4}\u{92b7}",

        // --- Revocation audit headers ---
        (RevocationAudit, Zhs) => "\u{64a4}\u{9500}\u{5ba1}\u{8ba1}",
        (RevocationAudit, En) => "Revocation Audit",
        (RevocationAudit, Zht) => "\u{64a4}\u{92b7}\u{5be9}\u{8a08}",

        (RevokedStatus, Zhs) => "\u{64a4}\u{9500}\u{72b6}\u{6001}",
        (RevokedStatus, En) => "Revocation Status",
        (RevokedStatus, Zht) => "\u{64a4}\u{92b7}\u{72c0}\u{614b}",

        (SignatureValid, Zhs) => "\u{7b7e}\u{540d}\u{6709}\u{6548}",
        (SignatureValid, En) => "Signature Valid",
        (SignatureValid, Zht) => "\u{7c3d}\u{540d}\u{6709}\u{6548}",

        (RevokedYes, Zhs) => "\u{5df2}\u{64a4}\u{9500}",
        (RevokedYes, En) => "Yes",
        (RevokedYes, Zht) => "\u{5df2}\u{64a4}\u{92b7}",

        (RevokedNo, Zhs) => "\u{672a}\u{64a4}\u{9500}",
        (RevokedNo, En) => "No",
        (RevokedNo, Zht) => "\u{672a}\u{64a4}\u{92b7}",

        // --- Tally headers ---
        (OptionId, Zhs) => "\u{9009}\u{9879}ID",
        (OptionId, En) => "Option ID",
        (OptionId, Zht) => "\u{9078}\u{9805}ID",

        (OptionText, Zhs) => "\u{9009}\u{9879}\u{6587}\u{672c}",
        (OptionText, En) => "Option Text",
        (OptionText, Zht) => "\u{9078}\u{9805}\u{6587}\u{5b57}",

        (Votes, Zhs) => "\u{7968}\u{6570}",
        (Votes, En) => "Votes",
        (Votes, Zht) => "\u{7968}\u{6578}",

        (Share, Zhs) => "\u{5360}\u{6bd4}",
        (Share, En) => "Share",
        (Share, Zht) => "\u{4f54}\u{6bd4}",

        (Total, Zhs) => "\u{5408}\u{8ba1}",
        (Total, En) => "Total",
        (Total, Zht) => "\u{5408}\u{8a08}",

        // --- Status values ---
        (Yes, Zhs) => "\u{662f}",
        (Yes, En) => "Yes",
        (Yes, Zht) => "\u{662f}",

        (No, Zhs) => "\u{5426}",
        (No, En) => "No",
        (No, Zht) => "\u{5426}",
    }
}

/// All translation keys, useful for exhaustive iteration in tests.
pub const ALL_KEYS: &[TranslationKey] = &[
    TranslationKey::VerificationSummary,
    TranslationKey::RegistryMapping,
    TranslationKey::TallyResults,
    TranslationKey::VoteAudit,
    TranslationKey::Charts,
    TranslationKey::NotVoted,
    TranslationKey::PollTitle,
    TranslationKey::PollId,
    TranslationKey::OrgId,
    TranslationKey::CreatedAt,
    TranslationKey::Deadline,
    TranslationKey::RingSize,
    TranslationKey::VotesCast,
    TranslationKey::Turnout,
    TranslationKey::SignaturesVerified,
    TranslationKey::KeyImagesUnique,
    TranslationKey::RegistryMatches,
    TranslationKey::VoterInfo,
    TranslationKey::MasterPubKey,
    TranslationKey::DerivedPubKey,
    TranslationKey::KeyImageBs58,
    TranslationKey::VoteChoice,
    TranslationKey::RevokedColumn,
    TranslationKey::RevocationAudit,
    TranslationKey::RevokedStatus,
    TranslationKey::SignatureValid,
    TranslationKey::RevokedYes,
    TranslationKey::RevokedNo,
    TranslationKey::OptionId,
    TranslationKey::OptionText,
    TranslationKey::Votes,
    TranslationKey::Share,
    TranslationKey::Total,
    TranslationKey::Yes,
    TranslationKey::No,
];

/// All supported languages.
pub const ALL_LANGUAGES: &[Language] = &[Language::Zhs, Language::En, Language::Zht];

// ---------------------------------------------------------------------------
// OpenCC: Simplified Chinese -> Traditional Chinese (dynamic content)
// ---------------------------------------------------------------------------

/// Convert Simplified Chinese text to Traditional Chinese (Taiwan Standard
/// with Taiwanese idioms) using OpenCC `S2TWP` configuration.
///
/// Used for dynamic user-authored content (poll questions, option text) where
/// OpenCC conversion is acceptable. Static UI strings use manually curated
/// translations instead.
///
/// Requires the `opencc` feature.
#[cfg(feature = "opencc")]
pub fn convert_zhs_to_zht(text: &str) -> Result<String, I18nError> {
    let opencc = opencc_rust::OpenCC::new(opencc_rust::DefaultConfig::S2TWP)
        .map_err(|e| I18nError::OpenccError(e.to_string()))?;
    Ok(opencc.convert(text))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_keys_return_non_empty_for_all_languages() {
        for &key in ALL_KEYS {
            for &lang in ALL_LANGUAGES {
                let translation = translate(key, lang);
                assert!(
                    !translation.is_empty(),
                    "translation for {key:?} in {lang} must not be empty"
                );
            }
        }
    }

    #[test]
    fn test_english_translations_are_ascii() {
        for &key in ALL_KEYS {
            let translation = translate(key, Language::En);
            assert!(
                translation.is_ascii(),
                "English translation for {key:?} should be ASCII, got: {translation}"
            );
        }
    }

    #[test]
    fn test_chinese_translations_are_not_ascii() {
        // Chinese translations should contain non-ASCII characters
        // (some keys like PollId contain "ID" which is ASCII, so we check
        // that the string contains at least one non-ASCII char)
        for &key in ALL_KEYS {
            for &lang in &[Language::Zhs, Language::Zht] {
                let translation = translate(key, lang);
                let has_non_ascii = !translation.is_ascii();
                assert!(
                    has_non_ascii,
                    "Chinese ({lang}) translation for {key:?} should contain non-ASCII characters, got: {translation}"
                );
            }
        }
    }

    #[test]
    fn test_language_display_roundtrip() {
        for &lang in ALL_LANGUAGES {
            let s = lang.to_string();
            let parsed: Language = s.parse().expect("should parse back");
            assert_eq!(lang, parsed);
        }
    }

    #[test]
    fn test_language_from_str_aliases() {
        assert_eq!(Language::from_str("zh-cn").unwrap(), Language::Zhs);
        assert_eq!(Language::from_str("zh_cn").unwrap(), Language::Zhs);
        assert_eq!(Language::from_str("ZHS").unwrap(), Language::Zhs);
        assert_eq!(Language::from_str("zh-tw").unwrap(), Language::Zht);
        assert_eq!(Language::from_str("zh_tw").unwrap(), Language::Zht);
        assert_eq!(Language::from_str("ZHT").unwrap(), Language::Zht);
        assert_eq!(Language::from_str("EN").unwrap(), Language::En);
    }

    #[test]
    fn test_language_from_str_invalid() {
        assert!(Language::from_str("fr").is_err());
        assert!(Language::from_str("").is_err());
        assert!(Language::from_str("xyz").is_err());
    }

    #[test]
    fn test_locale_parse_single() {
        assert_eq!(Locale::parse("zhs").unwrap(), Locale::Single(Language::Zhs));
        assert_eq!(Locale::parse("en").unwrap(), Locale::Single(Language::En));
        assert_eq!(Locale::parse("zht").unwrap(), Locale::Single(Language::Zht));
    }

    #[test]
    fn test_locale_parse_bilingual() {
        assert_eq!(
            Locale::parse("zhs+en").unwrap(),
            Locale::Bilingual(Language::Zhs, Language::En)
        );
        assert_eq!(
            Locale::parse("zht+en").unwrap(),
            Locale::Bilingual(Language::Zht, Language::En)
        );
        assert_eq!(
            Locale::parse("en+zhs").unwrap(),
            Locale::Bilingual(Language::En, Language::Zhs)
        );
    }

    #[test]
    fn test_locale_parse_with_whitespace() {
        assert_eq!(
            Locale::parse(" zhs + en ").unwrap(),
            Locale::Bilingual(Language::Zhs, Language::En)
        );
        assert_eq!(
            Locale::parse(" zht ").unwrap(),
            Locale::Single(Language::Zht)
        );
    }

    #[test]
    fn test_locale_parse_same_language_error() {
        assert!(Locale::parse("en+en").is_err());
        assert!(Locale::parse("zhs+zhs").is_err());
    }

    #[test]
    fn test_locale_parse_invalid() {
        assert!(Locale::parse("fr").is_err());
        assert!(Locale::parse("zhs+fr").is_err());
        assert!(Locale::parse("").is_err());
    }

    #[test]
    fn test_locale_display_roundtrip() {
        let cases = [
            Locale::Single(Language::Zhs),
            Locale::Single(Language::En),
            Locale::Single(Language::Zht),
            Locale::Bilingual(Language::Zhs, Language::En),
            Locale::Bilingual(Language::Zht, Language::En),
        ];
        for locale in &cases {
            let s = locale.to_string();
            let parsed = Locale::parse(&s).expect("should parse back");
            assert_eq!(*locale, parsed);
        }
    }

    #[test]
    fn test_locale_languages() {
        assert_eq!(Locale::Single(Language::En).languages(), vec![Language::En]);
        assert_eq!(
            Locale::Bilingual(Language::Zhs, Language::En).languages(),
            vec![Language::Zhs, Language::En]
        );
    }

    #[cfg(feature = "opencc")]
    #[test]
    fn test_opencc_convert_zhs_to_zht() {
        let result =
            convert_zhs_to_zht("\u{51c9}\u{98ce}\u{6709}\u{8baf}").expect("opencc should succeed");
        assert_eq!(result, "\u{6dbc}\u{98a8}\u{6709}\u{8a0a}");
    }

    #[cfg(feature = "opencc")]
    #[test]
    fn test_opencc_convert_empty_string() {
        let result = convert_zhs_to_zht("").expect("opencc should succeed on empty string");
        assert_eq!(result, "");
    }

    #[cfg(feature = "opencc")]
    #[test]
    fn test_opencc_convert_ascii_passthrough() {
        let result =
            convert_zhs_to_zht("Hello World").expect("opencc should succeed on ASCII input");
        assert_eq!(result, "Hello World");
    }

    #[cfg(feature = "opencc")]
    #[test]
    fn test_opencc_convert_mixed_content() {
        let result = convert_zhs_to_zht("\u{9009}\u{9879}A: \u{7f51}\u{7edc}\u{6295}\u{7968}")
            .expect("opencc should succeed on mixed content");
        // OpenCC S2TWP converts \u{9009}\u{9879} -> \u{9078}\u{9805}, \u{7f51}\u{7edc} -> \u{7db2}\u{8def}, \u{6295}\u{7968} stays
        assert!(result.contains("\u{9078}\u{9805}"));
        assert!(result.contains("\u{7db2}\u{8def}"));
        assert!(result.contains("\u{6295}\u{7968}"));
    }

    #[test]
    fn test_all_keys_count() {
        // Ensure ALL_KEYS matches the number of TranslationKey variants.
        // Update this if you add new keys.
        assert_eq!(ALL_KEYS.len(), 35);
    }

    // -----------------------------------------------------------------------
    // Edge: each language produces distinct translations for most keys
    // -----------------------------------------------------------------------

    #[test]
    fn test_zhs_and_zht_differ_for_at_least_some_keys() {
        // Simplified and Traditional Chinese should differ for keys that
        // contain characters with distinct traditional forms.
        let mut differ_count = 0;
        for &key in ALL_KEYS {
            let zhs = translate(key, Language::Zhs);
            let zht = translate(key, Language::Zht);
            if zhs != zht {
                differ_count += 1;
            }
        }
        assert!(
            differ_count > 0,
            "at least some ZHS and ZHT translations should differ"
        );
    }

    // -----------------------------------------------------------------------
    // Edge: locale with aliases (zh-cn, zh_tw)
    // -----------------------------------------------------------------------

    #[test]
    fn test_locale_parse_with_aliases() {
        assert_eq!(
            Locale::parse("zh-cn+zh-tw").unwrap(),
            Locale::Bilingual(Language::Zhs, Language::Zht)
        );
        assert_eq!(
            Locale::parse("zh_cn").unwrap(),
            Locale::Single(Language::Zhs)
        );
    }

    // -----------------------------------------------------------------------
    // OpenCC: Unicode characters preserved
    // -----------------------------------------------------------------------

    #[cfg(feature = "opencc")]
    #[test]
    fn test_opencc_preserves_emoji_and_special() {
        let input = "\u{6295}\u{7968} 🗳️ \u{6d4b}\u{8bd5}";
        let result = convert_zhs_to_zht(input).expect("opencc should handle emoji");
        // Emoji should pass through, Chinese characters should convert
        assert!(result.contains("🗳️"));
        assert!(result.contains("\u{6295}\u{7968}"));
    }

    // -----------------------------------------------------------------------
    // Locale display format
    // -----------------------------------------------------------------------

    #[test]
    fn test_locale_display_format() {
        assert_eq!(Locale::Single(Language::En).to_string(), "en");
        assert_eq!(
            Locale::Bilingual(Language::Zhs, Language::En).to_string(),
            "zhs+en"
        );
    }
}
