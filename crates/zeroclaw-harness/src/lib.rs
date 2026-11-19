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

use std::path::{Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;
use zeroclaw_config::harness::SulurHarnessConfig;

pub use lifecycle_hooks::{SulurLifecycleManager, SulurWireMemory};
pub use sulur_bridge::SulurBridge;

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

    /// Assemble deterministic pre-turn memory context for an explicit active `workspace_path`.
    async fn on_before_turn_with_workspace(
        &self,
        scope: &str,
        session_id: &str,
        _workspace_path: &Path,
        prompt: &str,
    ) -> HarnessResult<Option<String>> {
        self.on_before_turn(scope, session_id, prompt).await
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
    manager: Option<Arc<SulurLifecycleManager>>,
}

impl HarnessLifecycle {
    /// Construct a new [`HarnessLifecycle`] handle from config toggle state.
    #[must_use]
    pub fn new(enabled: bool) -> Self {
        if enabled {
            Self::from_config(&SulurHarnessConfig::default())
        } else {
            Self {
                enabled: false,
                manager: None,
            }
        }
    }

    /// Construct a [`HarnessLifecycle`] bound to an explicit [`SulurHarnessConfig`].
    #[must_use]
    pub fn from_config(config: &SulurHarnessConfig) -> Self {
        if !config.enabled {
            return Self {
                enabled: false,
                manager: None,
            };
        }
        let bridge = Arc::new(SulurBridge::new(config.clone()));
        let manager = Arc::new(SulurLifecycleManager::new(bridge));
        Self {
            enabled: true,
            manager: Some(manager),
        }
    }

    /// Construct a [`HarnessLifecycle`] wrapping a shared [`SulurLifecycleManager`].
    #[must_use]
    pub fn with_manager(manager: Arc<SulurLifecycleManager>) -> Self {
        Self {
            enabled: true,
            manager: Some(manager),
        }
    }

    /// Whether the Herdr-Sulur harness is enabled in configuration.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Borrow the underlying [`SulurLifecycleManager`] when enabled.
    #[must_use]
    pub fn manager(&self) -> Option<&Arc<SulurLifecycleManager>> {
        self.manager.as_ref()
    }
}

#[async_trait::async_trait]
impl HarnessLifecycleHooks for HarnessLifecycle {
    async fn on_session_start(&self, scope: &str, session_id: &str) -> HarnessResult<()> {
        match &self.manager {
            Some(mgr) => mgr.on_session_start(scope, session_id).await,
            None => Ok(()),
        }
    }

    async fn on_before_turn(
        &self,
        scope: &str,
        session_id: &str,
        prompt: &str,
    ) -> HarnessResult<Option<String>> {
        match &self.manager {
            Some(mgr) => mgr.on_before_turn(scope, session_id, prompt).await,
            None => Ok(None),
        }
    }

    async fn on_before_turn_with_workspace(
        &self,
        scope: &str,
        session_id: &str,
        workspace_path: &Path,
        prompt: &str,
    ) -> HarnessResult<Option<String>> {
        match &self.manager {
            Some(mgr) => {
                mgr.on_before_turn_with_workspace(scope, session_id, workspace_path, prompt)
                    .await
            }
            None => Ok(None),
        }
    }

    async fn on_after_turn(
        &self,
        scope: &str,
        session_id: &str,
        summary: &str,
    ) -> HarnessResult<()> {
        match &self.manager {
            Some(mgr) => mgr.on_after_turn(scope, session_id, summary).await,
            None => Ok(()),
        }
    }

    async fn on_idle(&self) -> HarnessResult<()> {
        match &self.manager {
            Some(mgr) => mgr.on_idle().await,
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn harness_lifecycle_from_config_constructs_manager_when_enabled() {
        let disabled_cfg = SulurHarnessConfig {
            enabled: false,
            ..Default::default()
        };
        let disabled = HarnessLifecycle::from_config(&disabled_cfg);
        assert!(!disabled.is_enabled());
        assert!(disabled.manager().is_none());

        let enabled_cfg = SulurHarnessConfig {
            enabled: true,
            ..Default::default()
        };
        let enabled = HarnessLifecycle::from_config(&enabled_cfg);
        assert!(enabled.is_enabled());
        assert!(enabled.manager().is_some());
    }

    #[tokio::test]
    async fn harness_lifecycle_disabled_hooks_are_noop() {
        let hooks: Arc<dyn HarnessLifecycleHooks> = Arc::new(HarnessLifecycle::new(false));
        hooks
            .on_session_start("scope", "sess-1")
            .await
            .expect("on_session_start");
        let pre = hooks
            .on_before_turn_with_workspace("scope", "sess-1", Path::new("."), "hello")
            .await
            .expect("on_before_turn_with_workspace");
        assert!(pre.is_none());
        hooks
            .on_after_turn("scope", "sess-1", "done")
            .await
            .expect("on_after_turn");
        hooks.on_idle().await.expect("on_idle");
    }
}
