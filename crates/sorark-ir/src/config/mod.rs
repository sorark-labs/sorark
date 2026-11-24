//! Workspace configuration (`sorark.toml`) and Stellar Mainnet archival constants.

mod limits;

pub use limits::{
    DEFAULT_WASM_WARN_BYTES, MAINNET_LEDGER_ENTRY_MAX_BYTES, MAINNET_MAX_ENTRY_TTL,
    MAINNET_MIN_PERSISTENT_ENTRY_TTL, MAINNET_MIN_TEMP_ENTRY_TTL,
};

use crate::diagnostic::{Diagnostic, Severity};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use thiserror::Error;

/// Errors that can occur when reading or parsing `sorark.toml`.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Failed to read configuration file `{path}`: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("Failed to parse TOML in `{path}`: {source}")]
    Toml {
        path: String,
        #[source]
        source: toml::de::Error,
    },
}

/// Per-rule configuration override under `[rules.<RULE_ID>]` in `sorark.toml`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RuleOverride {
    /// Custom severity override (`"info"`, `"warning"`, or `"error"`).
    pub severity: Option<Severity>,
    /// Optional toggle to enable or disable the rule (`true` / `false`).
    pub enabled: Option<bool>,
}

/// Workspace or project configuration loaded from `sorark.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SorarkConfig {
    /// Minimum allowed TTL extension target for persistent/instance entries.
    pub min_persistent_ttl: u32,
    /// Minimum allowed TTL extension target for temporary entries.
    pub min_temp_ttl: u32,
    /// Maximum allowed TTL extension target (Mainnet default: `3,110,400` ledgers).
    pub max_entry_ttl: u32,
    /// Compiled `.wasm` size threshold (in bytes) that triggers a warning.
    pub wasm_warn_bytes: usize,
    /// Compiled `.wasm` size hard ceiling (in bytes) that triggers an error.
    pub wasm_max_bytes: usize,
    /// Maximum recommended initial WASM linear memory pages (64 KiB each; default: 16 pages / 1 MiB).
    pub wasm_max_initial_memory_pages: u64,
    /// Maximum recommended exported WASM symbol count (default: 64).
    pub wasm_max_exports: usize,
    /// Serialized XDR byte size threshold for a fixed-size `#[contracttype]` struct/tuple
    /// above which `ARK-FOOT-001` emits a warning (default: `4096` bytes / 4 KiB).
    pub struct_warn_xdr_bytes: usize,
    /// List of rule IDs disabled globally (e.g. `["ARK-UPG-002"]`).
    pub disabled_rules: Vec<String>,
    /// Directory or file path substrings to exclude when scanning directories.
    pub exclude_paths: Vec<String>,
    /// Treat warnings as errors in CLI exit code calculation.
    pub fail_on_warnings: bool,
    /// Per-rule overrides mapped by rule ID (`[rules.ARK-STOR-002]`).
    pub rules: HashMap<String, RuleOverride>,
}

impl Default for SorarkConfig {
    fn default() -> Self {
        Self {
            min_persistent_ttl: MAINNET_MIN_PERSISTENT_ENTRY_TTL,
            min_temp_ttl: MAINNET_MIN_TEMP_ENTRY_TTL,
            max_entry_ttl: MAINNET_MAX_ENTRY_TTL,
            wasm_warn_bytes: DEFAULT_WASM_WARN_BYTES,
            wasm_max_bytes: MAINNET_LEDGER_ENTRY_MAX_BYTES,
            wasm_max_initial_memory_pages: 16,
            wasm_max_exports: 64,
            struct_warn_xdr_bytes: 4096,
            disabled_rules: Vec::new(),
            exclude_paths: vec!["target".to_string(), ".git".to_string()],
            fail_on_warnings: false,
            rules: HashMap::new(),
        }
    }
}

impl SorarkConfig {
    /// Loads a [`SorarkConfig`] from a TOML file on disk.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path_ref = path.as_ref();
        let raw = std::fs::read_to_string(path_ref).map_err(|source| ConfigError::Io {
            path: path_ref.display().to_string(),
            source,
        })?;
        Self::from_toml_str(&raw, &path_ref.display().to_string())
    }

    /// Parses a [`SorarkConfig`] from a raw TOML string.
    pub fn from_toml_str(raw: &str, label: &str) -> Result<Self, ConfigError> {
        toml::from_str(raw).map_err(|source| ConfigError::Toml {
            path: label.to_string(),
            source,
        })
    }

    /// Looks up a [`RuleOverride`] case-insensitively by `rule_id`.
    #[must_use]
    pub fn rule_override(&self, rule_id: &str) -> Option<&RuleOverride> {
        self.rules
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(rule_id))
            .map(|(_, v)| v)
    }

    /// Returns `true` if `rule_id` is enabled under this configuration.
    #[must_use]
    pub fn is_rule_enabled(&self, rule_id: &str) -> bool {
        if self
            .disabled_rules
            .iter()
            .any(|r| r.eq_ignore_ascii_case(rule_id))
        {
            return false;
        }
        if let Some(ov) = self.rule_override(rule_id)
            && ov.enabled == Some(false)
        {
            return false;
        }
        true
    }

    /// Returns the effective [`Severity`] for `rule_id`, applying any `[rules.<RULE_ID>]` override.
    #[must_use]
    pub fn effective_severity(&self, rule_id: &str, default_severity: Severity) -> Severity {
        self.rule_override(rule_id)
            .and_then(|ov| ov.severity)
            .unwrap_or(default_severity)
    }

    /// Applies any configured `[rules.<RULE_ID>] severity = "..."` overrides in place.
    pub fn apply_severity_overrides(&self, diagnostics: &mut [Diagnostic]) {
        for diag in diagnostics {
            if let Some(ov) = self.rule_override(&diag.rule_id)
                && let Some(sev) = ov.severity
            {
                diag.severity = sev;
            }
        }
    }

    /// Returns the set of disabled rule IDs normalized to uppercase.
    #[must_use]
    pub fn disabled_rule_set(&self) -> HashSet<String> {
        let mut set: HashSet<String> = self
            .disabled_rules
            .iter()
            .map(|r| r.to_ascii_uppercase())
            .collect();
        for (k, v) in &self.rules {
            if v.enabled == Some(false) {
                set.insert(k.to_ascii_uppercase());
            }
        }
        set
    }

    /// Generates a documented starter `sorark.toml` template.
    #[must_use]
    pub fn default_toml_template() -> &'static str {
        r#"# SORARK Configuration (sorark.toml)
# Stellar Mainnet State Archival & Resource Limits

# Minimum persistent/instance TTL in ledgers (Mainnet default: 4096 ledgers / ~5.6 hours)
min_persistent_ttl = 4096

# Minimum temporary entry TTL in ledgers (Mainnet default: 16 ledgers / ~80 seconds)
min_temp_ttl = 16

# Maximum entry TTL in ledgers (Mainnet default: 3,110,400 ledgers / ~180 days)
max_entry_ttl = 3110400

# Compiled WASM size thresholds in bytes (48 KiB warning, 64 KiB hard limit)
wasm_warn_bytes = 49152
wasm_max_bytes = 65536

# Treat warnings as non-zero exit codes in CI
fail_on_warnings = false

# Disable specific rule IDs if needed (e.g. ["ARK-UPG-002"])
disabled_rules = []

# Paths to skip during recursive workspace scans
exclude_paths = ["target", ".git"]

# Optional per-rule severity or enablement overrides:
# [rules.ARK-STOR-002]
# severity = "error"
"#
    }
}
