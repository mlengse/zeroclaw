//! Configuration schema types for the isolated Herdr-Sulur harness (`[harness]` / `[harness.sulur]`).

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use zeroclaw_macros::{ConfigEnum, Configurable};

/// Top-level `[harness]` configuration block.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, Configurable)]
#[cfg_attr(feature = "schema-export", derive(schemars::JsonSchema))]
#[prefix = "harness"]
pub struct HarnessConfig {
    /// Sulur persistent memory bridge & Herdr-compatible PTY harness (`[harness.sulur]`).
    #[serde(default)]
    #[nested]
    pub sulur: SulurHarnessConfig,
}

/// Sidecar discovery and bootstrap behavior for `sulur-server`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, ConfigEnum,
)]
#[cfg_attr(feature = "schema-export", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum SidecarMode {
    /// Discover `<db>.daemon.json` first; spawn detached `sulur-server start` if absent or stale.
    #[default]
    ManagedSidecar,
    /// Only connect to an externally managed `sulur-server` daemon (fail loud and spool if absent).
    ExternalOnly,
}

/// Top-level configuration block `[harness.sulur]` in ZeroClaw config.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Configurable)]
#[cfg_attr(feature = "schema-export", derive(schemars::JsonSchema))]
#[prefix = "harness.sulur"]
pub struct SulurHarnessConfig {
    /// Master switch for the Herdr-Sulur harness (`default: true`).
    #[serde(default = "default_true_flag")]
    pub enabled: bool,
    /// Canonical directory path of the shared Akar database owned by `sulur-server`.
    #[serde(default = "default_db_path")]
    pub db_path: PathBuf,
    /// Optional override for the `sulur-server` executable path (defaults to `"sulur-server"` on PATH).
    #[serde(default)]
    pub sulur_server_bin: Option<PathBuf>,
    /// Whether ZeroClaw spawns `sulur-server start` if `<db>.daemon.json` is absent.
    #[serde(default)]
    pub sidecar_mode: SidecarMode,
    /// Default Sulur project scope when workspace scope cannot be auto-inferred (`"shared"` fallback).
    #[serde(default = "default_scope")]
    pub default_scope: String,
    /// Directory scanned for declarative `.toml` agent profiles (`default: distribution/agent-detection`).
    #[serde(default = "default_detection_dir")]
    pub agent_detection_dir: PathBuf,
    /// TCP connection timeout in milliseconds (`default: 500`).
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    /// Per-RPC request deadline in milliseconds (`default: 1500`; write timeouts spill to spool).
    #[serde(default = "default_request_timeout_ms")]
    pub request_timeout_ms: u64,
    /// Pre-turn `briefing` + `multi_recall` formatting budgets (`[harness.sulur.briefing_budget]`).
    #[serde(default)]
    #[nested]
    pub briefing_budget: BriefingBudgetConfig,
    /// Explicit channel flags matching 6-channel recall (`[harness.sulur.recall_channels]`).
    #[serde(default)]
    #[nested]
    pub recall_channels: RecallChannelFlags,
    /// Lossless `.spool.jsonl` fallback settings (`[harness.sulur.spool]`).
    #[serde(default)]
    #[nested]
    pub spool: SpoolConfig,
    /// Idle `dream_task` + `wiki_sync` trigger settings (`[harness.sulur.dream_trigger]`).
    #[serde(default)]
    #[nested]
    pub dream_trigger: DreamTriggerConfig,
    /// Default approval timeout in seconds in Discord (`default: 900`).
    #[serde(default = "default_approval_timeout_secs")]
    pub approval_timeout_secs: u64,
}

impl Default for SulurHarnessConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            db_path: default_db_path(),
            sulur_server_bin: None,
            sidecar_mode: SidecarMode::default(),
            default_scope: default_scope(),
            agent_detection_dir: default_detection_dir(),
            connect_timeout_ms: default_connect_timeout_ms(),
            request_timeout_ms: default_request_timeout_ms(),
            briefing_budget: BriefingBudgetConfig::default(),
            recall_channels: RecallChannelFlags::default(),
            spool: SpoolConfig::default(),
            dream_trigger: DreamTriggerConfig::default(),
            approval_timeout_secs: default_approval_timeout_secs(),
        }
    }
}

/// Pre-turn `briefing` + `multi_recall` token/character formatting budgets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Configurable)]
#[cfg_attr(feature = "schema-export", derive(schemars::JsonSchema))]
#[prefix = "harness.sulur.briefing_budget"]
pub struct BriefingBudgetConfig {
    /// Hard total character budget for injected `[Memory context]` block (`default: 3500`).
    #[serde(default = "default_max_total_chars")]
    pub max_total_chars: usize,
    /// Budget allocated to `sulur-server` `briefing` op (`default: 2000`).
    #[serde(default = "default_briefing_chars")]
    pub briefing_chars: usize,
    /// Maximum ranked hits pulled from 6-channel `multi_recall` (`default: 6`).
    #[serde(default = "default_recall_limit")]
    pub max_recall_items: usize,
    /// Include active pending handoffs & unread cross-project messages in preamble (`default: true`).
    #[serde(default = "default_true_flag")]
    pub include_handoff: bool,
}

impl Default for BriefingBudgetConfig {
    fn default() -> Self {
        Self {
            max_total_chars: default_max_total_chars(),
            briefing_chars: default_briefing_chars(),
            max_recall_items: default_recall_limit(),
            include_handoff: true,
        }
    }
}

/// Documented toggles aligned with `sulur_core::recall::config::{ChannelKind, OptionalSwitches}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Configurable)]
#[cfg_attr(feature = "schema-export", derive(schemars::JsonSchema))]
#[prefix = "harness.sulur.recall_channels"]
pub struct RecallChannelFlags {
    /// Lexical BM25 full-text search channel (`default: true`).
    #[serde(default = "default_true_flag")]
    pub lexical: bool,
    /// Dense vector semantic similarity channel (`default: true`).
    #[serde(default = "default_true_flag")]
    pub semantic: bool,
    /// Named-entity graph lookup channel (`default: true`).
    #[serde(default = "default_true_flag")]
    pub entity: bool,
    /// Temporal recency & episode sequence channel (`default: true`).
    #[serde(default = "default_true_flag")]
    pub temporal: bool,
    /// Graph proximity traversal channel (`default: true`).
    #[serde(default = "default_true_flag")]
    pub graph_proximity: bool,
    /// Optional late-interaction reranking switch (`default: false`).
    #[serde(default)]
    pub late_interaction: bool,
    /// Optional dream-augmented synthesis channel (`default: false`).
    #[serde(default)]
    pub dream_augmented: bool,
    /// Optional multi-hop propagation switch (`default: false`).
    #[serde(default)]
    pub propagation: bool,
    /// Request per-channel score explanation trace (`explain = true`) for observability.
    #[serde(default)]
    pub explain: bool,
}

impl Default for RecallChannelFlags {
    fn default() -> Self {
        Self {
            lexical: true,
            semantic: true,
            entity: true,
            temporal: true,
            graph_proximity: true,
            late_interaction: false,
            dream_augmented: false,
            propagation: false,
            explain: false,
        }
    }
}

/// Lossless `.spool.jsonl` fallback settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Configurable)]
#[cfg_attr(feature = "schema-export", derive(schemars::JsonSchema))]
#[prefix = "harness.sulur.spool"]
pub struct SpoolConfig {
    /// Override canonical `<normalized_db_path>.spool.jsonl` path when set.
    #[serde(default)]
    pub override_path: Option<PathBuf>,
    /// Maximum local spool size before raising a high-priority Discord warning (`default: 64 MiB`).
    #[serde(default = "default_max_spool_bytes")]
    pub max_spool_bytes: u64,
}

impl Default for SpoolConfig {
    fn default() -> Self {
        Self {
            override_path: None,
            max_spool_bytes: default_max_spool_bytes(),
        }
    }
}

/// Idle `dream_task` + `wiki_sync` trigger settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Configurable)]
#[cfg_attr(feature = "schema-export", derive(schemars::JsonSchema))]
#[prefix = "harness.sulur.dream_trigger"]
pub struct DreamTriggerConfig {
    /// Enable idle Dream Engine consolidation triggers (`default: true`).
    #[serde(default = "default_true_flag")]
    pub enabled: bool,
    /// Consecutive seconds with all sessions idle before triggering (`default: 300`).
    #[serde(default = "default_idle_debounce_secs")]
    pub idle_debounce_secs: u64,
    /// Whether to invoke wire op `wiki_sync` after `dream_control(action="run")` (`default: true`).
    #[serde(default = "default_true_flag")]
    pub run_wiki_sync: bool,
    /// Optional OKF v0.2 wiki export directory passed to wire `wiki_sync`.
    #[serde(default)]
    pub wiki_dir: Option<PathBuf>,
}

impl Default for DreamTriggerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            idle_debounce_secs: default_idle_debounce_secs(),
            run_wiki_sync: true,
            wiki_dir: None,
        }
    }
}

const fn default_true_flag() -> bool {
    true
}

fn default_db_path() -> PathBuf {
    PathBuf::from("~/.sulur/memory.db")
}

fn default_scope() -> String {
    "shared".to_string()
}

fn default_detection_dir() -> PathBuf {
    PathBuf::from("distribution/agent-detection")
}

const fn default_connect_timeout_ms() -> u64 {
    500
}

const fn default_request_timeout_ms() -> u64 {
    1_500
}

const fn default_approval_timeout_secs() -> u64 {
    900
}

const fn default_max_total_chars() -> usize {
    3_500
}

const fn default_briefing_chars() -> usize {
    2_000
}

const fn default_recall_limit() -> usize {
    6
}

const fn default_max_spool_bytes() -> u64 {
    64 * 1024 * 1024
}

const fn default_idle_debounce_secs() -> u64 {
    300
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn harness_config_defaults_and_toml_overrides() {
        let defaults: HarnessConfig = toml::from_str("").expect("empty toml parses with defaults");
        assert!(defaults.sulur.enabled);
        assert_eq!(defaults.sulur.sidecar_mode, SidecarMode::ManagedSidecar);
        assert_eq!(defaults.sulur.briefing_budget.max_total_chars, 3_500);
        assert_eq!(defaults.sulur.spool.max_spool_bytes, 64 * 1024 * 1024);

        let custom: HarnessConfig = toml::from_str(
            r#"
[sulur]
enabled = false
sidecar_mode = "external_only"
approval_timeout_secs = 120
"#,
        )
        .expect("override toml parses");
        assert!(!custom.sulur.enabled);
        assert_eq!(custom.sulur.sidecar_mode, SidecarMode::ExternalOnly);
        assert_eq!(custom.sulur.approval_timeout_secs, 120);
        assert_eq!(custom.sulur.default_scope, "shared");
    }
}
