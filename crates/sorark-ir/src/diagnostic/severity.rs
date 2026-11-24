//! Severity, confidence, and category taxonomies for SORARK findings.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Severity level of a SORARK diagnostic finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Warning,
    Error,
}

impl Severity {
    /// Returns the lowercase canonical label (`info`, `warning`, `error`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }

    /// Maps SORARK severity to the SARIF v2.1.0 `level` string (`note`, `warning`, `error`).
    #[must_use]
    pub const fn sarif_level(self) -> &'static str {
        match self {
            Self::Info => "note",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }

    /// Maps SORARK severity to the GitHub Actions workflow command level (`notice`, `warning`, `error`).
    #[must_use]
    pub const fn github_command(self) -> &'static str {
        match self {
            Self::Info => "notice",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }

    /// Parses a severity level case-insensitively (`info`, `warning`/`warn`, `error`/`err`).
    #[must_use]
    pub fn from_str_ignore_case(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "info" | "note" => Some(Self::Info),
            "warning" | "warn" => Some(Self::Warning),
            "error" | "err" => Some(Self::Error),
            _ => None,
        }
    }
}

impl FromStr for Severity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_str_ignore_case(s).ok_or_else(|| {
            format!("Invalid severity `{s}` (expected `info`, `warning`, or `error`)")
        })
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Confidence level of a static or binary analysis finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl Confidence {
    /// Returns the lowercase canonical label (`low`, `medium`, `high`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// High-level rule taxonomy for SORARK checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleCategory {
    StorageSafety,
    StateArchival,
    UpgradeAuth,
    StorageCompatibility,
    AbiCompatibility,
    ResourceBudget,
}

impl RuleCategory {
    /// Returns the kebab-case identifier for this rule category.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StorageSafety => "storage-safety",
            Self::StateArchival => "state-archival",
            Self::UpgradeAuth => "upgrade-auth",
            Self::StorageCompatibility => "storage-compatibility",
            Self::AbiCompatibility => "abi-compatibility",
            Self::ResourceBudget => "resource-budget",
        }
    }
}

impl fmt::Display for RuleCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
