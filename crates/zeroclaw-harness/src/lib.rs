//! Isolated Herdr-Sulur native harness for ZeroClaw.
//!
//! Encapsulates declarative CLI agent detection (`detector`), cross-platform headless
//! PTY orchestration (`pty_runner`), out-of-process `sulur-server` wire connectivity
//! (`sulur_bridge`), deterministic turn lifecycle hooks (`lifecycle_hooks`), and
//! Discord command/approval bridging (`discord_commands`).
//!
//! Strictly adheres to Constitution Principles VII–XI:
//! - Zero `ghostty-vt` or graphical terminal crates.
//! - Zero `akar-*` / `sulur-*` in-process linkage.
//! - Dependencies flow strictly inward toward `zeroclaw-api`, `zeroclaw-config`, and `zeroclaw-log`.

pub mod detector;
pub mod discord_commands;
pub mod lifecycle_hooks;
pub mod pty_runner;
pub mod sulur_bridge;

use std::path::PathBuf;
use thiserror::Error;

/// Typed domain error enum for `zeroclaw-harness` (Constitution Principle VI).
#[derive(Debug, Error)]
pub enum HarnessError {
    /// Failed to parse or validate a declarative agent detection TOML profile.
    #[error("invalid agent detection profile `{profile}`: {reason}")]
    InvalidProfile { profile: String, reason: String },

    /// Failed to compile a regex / line_regex matcher inside a detection rule.
    #[error("invalid regex in profile `{profile}` rule `{rule}`: {source}")]
    InvalidRuleRegex {
        profile: String,
        rule: String,
        #[source]
        source: regex::Error,
    },

    /// Unsupported detection region specifier.
    #[error("invalid region specification `{0}`")]
    InvalidRegionSpec(String),

    /// Cross-platform PTY spawn, read, write, or resize failure.
    #[error("pty failure for session `{session_id}`: {reason}")]
    Pty { session_id: String, reason: String },

    /// Attempted to resolve an approval prompt that was already processed or expired.
    #[error("approval prompt `{prompt_id}` already processed")]
    ApprovalAlreadyProcessed { prompt_id: String },

    /// Out-of-process `sulur-server` daemon unavailable or failed wire handshake.
    #[error("sulur daemon unavailable: {reason}")]
    DaemonUnavailable { reason: String },

    /// Wire protocol RPC returned an explicit failure or exceeded framing limits.
    #[error("sulur wire error: {reason}")]
    Wire { reason: String },

    /// Local filesystem I/O failure (profile read, spool append, worktree probe).
    #[error("harness i/o error at `{path}`: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Convenience result alias for harness operations.
pub type HarnessResult<T> = Result<T, HarnessError>;

/// Thin lifecycle hook contract invoked from `zeroclaw-runtime` under `#[cfg(feature = "herdr-sulur-harness")]`.
#[async_trait::async_trait]
pub trait HarnessLifecycleHooks: Send + Sync {
    /// Ensure session scope initialization and sidecar readiness before turns begin.
    async fn on_session_start(&self, _scope: &str, _session_id: &str) -> HarnessResult<()> {
        Ok(())
    }

    /// Assemble deterministic pre-turn memory context bounded by `[harness.sulur.briefing_budget]`.
    async fn on_before_turn(
        &self,
        _scope: &str,
        _session_id: &str,
        _prompt: &str,
    ) -> HarnessResult<Option<String>> {
        Ok(None)
    }

    /// Persist post-turn execution summary / patches or fall back to `.spool.jsonl`.
    async fn on_after_turn(
        &self,
        _scope: &str,
        _session_id: &str,
        _summary: &str,
    ) -> HarnessResult<()> {
        Ok(())
    }

    /// Check whether all managed sessions are quiescent and trigger idle consolidation when eligible.
    async fn on_idle(&self) -> HarnessResult<()> {
        Ok(())
    }
}

/// Default harness lifecycle handle wired into `zeroclaw-runtime` when `herdr-sulur-harness` is enabled.
#[derive(Debug, Default, Clone)]
pub struct HarnessLifecycle {
    enabled: bool,
}

impl HarnessLifecycle {
    /// Construct a new [`HarnessLifecycle`] handle from config toggle state.
    #[must_use]
    pub const fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    /// Whether the Herdr-Sulur harness is enabled in configuration.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }
}

#[async_trait::async_trait]
impl HarnessLifecycleHooks for HarnessLifecycle {}
