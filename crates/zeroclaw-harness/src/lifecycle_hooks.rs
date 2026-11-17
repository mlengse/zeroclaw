//! Deterministic Pre-Turn, Post-Turn, Cross-Tool Handoff, and Idle Dream lifecycle
//! interceptors backed by [`crate::sulur_bridge::SulurBridge`].
//!
//! Exposes [`SulurWireMemory`] (implementing [`zeroclaw_api::memory_traits::Memory`]) and
//! [`SulurLifecycleManager`] (`inject_context`, `record_turn`, `maybe_trigger_dream`).

use crate::sulur_bridge::{
    CasPatchOperation, CrossToolHandoffPayload, LifecycleSpoolRecord, SulurBridge,
    extract_recall_lines,
};
use crate::{HarnessLifecycleHooks, HarnessResult};
use async_trait::async_trait;
use serde_json::json;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroclaw_api::attribution::{Attributable, MemoryKind as AttrMemoryKind, Role};
use zeroclaw_api::memory_traits::{
    Memory, MemoryCategory, MemoryEntry, normalize_recent_recall_query,
};

/// Result bundle from deterministic pre-turn memory injection (`inject_context`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InjectedMemoryContext {
    /// Bounded `[Memory context] ... [/Memory context]` block prepended to agent turns.
    pub formatted_block: String,
    /// Handoff ticket claimed from Zed IDE / local CLI if one matched this scope.
    pub claimed_handoff: Option<CrossToolHandoffPayload>,
    /// Popped unread cross-project message count surfaced in the preamble.
    pub popped_messages: usize,
    /// Number of recall hits included.
    pub recall_hits: usize,
}

/// Native [`Memory`] trait backend talking to out-of-process `sulur-server` via [`SulurBridge`].
#[derive(Debug, Clone)]
pub struct SulurWireMemory {
    bridge: Arc<SulurBridge>,
    scope: String,
    alias: String,
}

impl SulurWireMemory {
    /// Construct a new [`SulurWireMemory`] scoped to `scope`.
    #[must_use]
    pub fn new(bridge: Arc<SulurBridge>, scope: impl Into<String>) -> Self {
        Self {
            bridge,
            scope: scope.into(),
            alias: "sulur-wire".to_string(),
        }
    }

    /// Borrow the underlying [`SulurBridge`].
    #[must_use]
    pub fn bridge(&self) -> &Arc<SulurBridge> {
        &self.bridge
    }
}

impl Attributable for SulurWireMemory {
    fn role(&self) -> Role {
        Role::Memory(AttrMemoryKind::Plugin)
    }

    fn alias(&self) -> &str {
        &self.alias
    }
}

#[async_trait]
impl Memory for SulurWireMemory {
    fn name(&self) -> &str {
        "sulur-wire"
    }

    async fn store(
        &self,
        key: &str,
        content: &str,
        category: MemoryCategory,
        session_id: Option<&str>,
    ) -> anyhow::Result<()> {
        let sess = session_id.unwrap_or("default");
        let label = format!("{category}:{key}");
        self.bridge
            .remember_or_spool(content, &self.scope, &label, sess, None)
            .await
            .map_err(anyhow::Error::from)?;
        Ok(())
    }

    async fn recall(
        &self,
        query: &str,
        limit: usize,
        session_id: Option<&str>,
        _since: Option<&str>,
        _until: Option<&str>,
    ) -> anyhow::Result<Vec<MemoryEntry>> {
        let norm_query = normalize_recent_recall_query(query);
        let effective_query = if norm_query.is_empty() {
            "project summary"
        } else {
            norm_query
        };
        let explain = self.bridge.config().recall_channels.explain;
        let resp = self
            .bridge
            .recall(
                effective_query,
                Some(&self.scope),
                limit.max(1),
                true,
                explain,
            )
            .await
            .map_err(anyhow::Error::from)?;

        let rows = extract_recall_lines(&resp);
        let now_ts = chrono::Utc::now().to_rfc3339();
        Ok(rows
            .into_iter()
            .take(limit)
            .map(|r| {
                let id = r.get("id").cloned().unwrap_or_default();
                let label = r
                    .get("label")
                    .cloned()
                    .unwrap_or_else(|| "sulur".to_string());
                let content = r.get("content").cloned().unwrap_or_default();
                let score = r.get("score").and_then(|s| s.parse::<f64>().ok());
                MemoryEntry {
                    id: id.clone(),
                    key: label,
                    content,
                    category: MemoryCategory::Core,
                    timestamp: now_ts.clone(),
                    session_id: session_id.map(str::to_string),
                    score,
                    namespace: self.scope.clone(),
                    importance: None,
                    superseded_by: None,
                    kind: None,
                    pinned: false,
                    tenant_id: None,
                    principal_id: None,
                    agent_alias: None,
                    agent_id: None,
                }
            })
            .collect())
    }

    async fn get(&self, key: &str) -> anyhow::Result<Option<MemoryEntry>> {
        let hits = self.recall(key, 1, None, None, None).await?;
        Ok(hits
            .into_iter()
            .next()
            .filter(|e| e.key == key || e.id == key))
    }

    async fn list(
        &self,
        _category: Option<&MemoryCategory>,
        session_id: Option<&str>,
    ) -> anyhow::Result<Vec<MemoryEntry>> {
        self.recall("project context", 10, session_id, None, None)
            .await
    }

    async fn forget(&self, _key: &str) -> anyhow::Result<bool> {
        anyhow::bail!("forget is disabled on SulurWireMemory; use Sulur retention/supersede tools")
    }

    async fn forget_for_agent(&self, _key: &str, _agent_id: &str) -> anyhow::Result<bool> {
        anyhow::bail!("forget_for_agent is disabled on SulurWireMemory")
    }

    async fn count(&self) -> anyhow::Result<usize> {
        let resp = self
            .bridge
            .call_op(crate::sulur_bridge::WireRequest {
                op: Some("stats".to_string()),
                ..Default::default()
            })
            .await
            .map_err(anyhow::Error::from)?;
        let approx = resp.stats.map_or(0, |s| {
            usize::try_from(s.total_queries).unwrap_or(usize::MAX)
        });
        Ok(approx)
    }

    async fn health_check(&self) -> bool {
        self.bridge.ensure_daemon().await.is_ok()
    }

    async fn store_with_agent(
        &self,
        key: &str,
        content: &str,
        category: MemoryCategory,
        session_id: Option<&str>,
        namespace: Option<&str>,
        importance: Option<f64>,
        agent_id: Option<&str>,
    ) -> anyhow::Result<()> {
        let target_scope = namespace.unwrap_or(&self.scope);
        let label = format!("{category}:{key}");
        self.bridge
            .remember(
                content,
                target_scope,
                &label,
                session_id,
                agent_id,
                importance.unwrap_or(0.85),
            )
            .await
            .map(|_| ())
            .map_err(anyhow::Error::from)
    }

    async fn recall_for_agents(
        &self,
        _allowed_agent_ids: &[&str],
        query: &str,
        limit: usize,
        session_id: Option<&str>,
        since: Option<&str>,
        until: Option<&str>,
    ) -> anyhow::Result<Vec<MemoryEntry>> {
        self.recall(query, limit, session_id, since, until).await
    }
}

/// High-level deterministic turn & idle orchestrator combining [`SulurBridge`] with configured budgets.
#[derive(Debug, Clone)]
pub struct SulurLifecycleManager {
    bridge: Arc<SulurBridge>,
    last_activity_ms: Arc<std::sync::atomic::AtomicU64>,
}

impl SulurLifecycleManager {
    /// Wrap a [`SulurBridge`] in a [`SulurLifecycleManager`].
    #[must_use]
    pub fn new(bridge: Arc<SulurBridge>) -> Self {
        Self {
            bridge,
            last_activity_ms: Arc::new(std::sync::atomic::AtomicU64::new(now_epoch_ms())),
        }
    }

    /// Borrow underlying [`SulurBridge`].
    #[must_use]
    pub fn bridge(&self) -> &Arc<SulurBridge> {
        &self.bridge
    }

    /// Record recent turn/session activity so idle dream debounce resets.
    pub fn touch_activity(&self) {
        self.last_activity_ms
            .store(now_epoch_ms(), std::sync::atomic::Ordering::Relaxed);
    }

    /// Override recorded activity epoch milliseconds (primarily for deterministic idle debounce tests).
    pub fn set_last_activity_ms_for_test(&self, epoch_ms: u64) {
        self.last_activity_ms
            .store(epoch_ms, std::sync::atomic::Ordering::Relaxed);
    }

    /// Execute deterministic Pre-Turn memory assembly (`T019` + `T020`):
    /// `briefing` + `handoff_list`/`handoff_accept` + `message_pop` + multi-channel `recall`.
    ///
    /// Bounded strictly by `briefing_budget.max_total_chars` (`3500` chars default).
    ///
    /// # Errors
    /// Propagates [`crate::HarnessError::DaemonUnavailable`] (Fail Loud) when `sulur-server` cannot
    /// be reached; never fabricates empty memory silently when an active prompt requires context.
    pub async fn inject_context(
        &self,
        scope: &str,
        session_id: &str,
        workspace_path: &Path,
        prompt: &str,
    ) -> HarnessResult<InjectedMemoryContext> {
        self.touch_activity();
        let cfg = self.bridge.config();
        let budget = &cfg.briefing_budget;
        let recall_flags = &cfg.recall_channels;

        let effective_scope = if scope.trim().is_empty() {
            cfg.default_scope.as_str()
        } else {
            scope
        };

        // Ensure daemon up front (fail loud on ExternalOnly outage per Principle III).
        self.bridge.ensure_daemon().await?;

        let mut sections = Vec::<String>::new();
        let mut claimed_handoff: Option<CrossToolHandoffPayload> = None;
        let mut popped_messages = 0_usize;

        if budget.include_handoff {
            if let Ok(offered) = self
                .bridge
                .handoff_list(effective_scope, "offered", workspace_path)
                .await
                && let Some(first_ticket) = offered.first()
                && let Some(ref ticket_id) = first_ticket.ticket_id
                && let Ok(claimed) = self
                    .bridge
                    .handoff_accept(ticket_id, session_id, workspace_path)
                    .await
            {
                let steps = claimed.unblocked_next_steps.join("; ");
                let files = claimed.modified_files.join(", ");
                sections.push(format!(
                    "### Active Handoff ({})\n- From: {} ({})\n- Milestone: {}\n- Next: {}\n- Files: {}",
                    ticket_id,
                    claimed.source_session_id,
                    claimed.workspace_path.display(),
                    claimed.milestone,
                    steps,
                    files
                ));
                claimed_handoff = Some(claimed);
            }

            if let Ok(Some(msg)) = self.bridge.message_pop("discord").await {
                popped_messages += 1;
                sections.push(format!(
                    "### Incoming Cross-Surface Message ({} -> {})\n{}",
                    msg.from_scope, msg.to_scope, msg.body
                ));
            }
        }

        if let Ok(briefing_md) = self
            .bridge
            .briefing(effective_scope, Some(session_id), budget.briefing_chars)
            .await
            && !briefing_md.trim().is_empty()
        {
            sections.push(format!(
                "### Project Briefing\n{}",
                truncate_chars(&briefing_md, budget.briefing_chars)
            ));
        }

        // Execute multi-channel recall if any core channel is enabled.
        let any_channel_enabled = recall_flags.lexical
            || recall_flags.semantic
            || recall_flags.entity
            || recall_flags.temporal
            || recall_flags.graph_proximity
            || recall_flags.late_interaction
            || recall_flags.dream_augmented
            || recall_flags.propagation;

        let mut recall_hits = 0_usize;
        if any_channel_enabled && budget.max_recall_items > 0 && !prompt.trim().is_empty() {
            let enhanced =
                recall_flags.semantic || recall_flags.graph_proximity || recall_flags.entity;
            if let Ok(resp) = self
                .bridge
                .recall(
                    prompt,
                    Some(effective_scope),
                    budget.max_recall_items,
                    enhanced,
                    recall_flags.explain,
                )
                .await
            {
                let lines = extract_recall_lines(&resp);
                if !lines.is_empty() {
                    let mut recall_buf = String::from("### Multi-Channel Recall\n");
                    for item in lines.iter().take(budget.max_recall_items) {
                        recall_hits += 1;
                        let line_content = item.get("content").map_or("", String::as_str);
                        let channel = item.get("channel").map_or("recall", String::as_str);
                        let score = item.get("score").map_or("", String::as_str);
                        let single = format!(
                            "- [{channel} {score}] {}\n",
                            truncate_chars(line_content.trim(), 280)
                        );
                        recall_buf.push_str(&single);
                    }
                    sections.push(recall_buf.trim_end().to_string());
                }
            }
        }

        let formatted_block = if sections.is_empty() {
            String::new()
        } else {
            let joined = format!(
                "[Memory context]\n{}\n[/Memory context]\n",
                sections.join("\n\n")
            );
            truncate_chars(&joined, budget.max_total_chars)
        };

        Ok(InjectedMemoryContext {
            formatted_block,
            claimed_handoff,
            popped_messages,
            recall_hits,
        })
    }

    /// Execute deterministic Post-Turn capture (`T023`):
    /// sanitizes & redacts tokens/secrets, records summary (`remember`) and optional structured
    /// `CasPatchOperation` diffs, falling back atomically to `.spool.jsonl` on timeout/outage.
    ///
    /// # Errors
    /// Fails loudly on explicit CAS precondition conflict (`expected_content_hash`/`expected_revision_id`),
    /// or if both wire write and `.spool.jsonl` write fail.
    pub async fn record_turn(
        &self,
        scope: &str,
        session_id: &str,
        profile: Option<&str>,
        summary: &str,
        cas_patches: &[CasPatchOperation],
        modified_files: &[String],
    ) -> HarnessResult<()> {
        self.touch_activity();
        let effective_scope = if scope.trim().is_empty() {
            self.bridge.config().default_scope.as_str()
        } else {
            scope
        };

        let files_suffix = if modified_files.is_empty() {
            String::new()
        } else {
            format!("\nModified files: {}", modified_files.join(", "))
        };
        let combined = format!("{summary}{files_suffix}");
        if !combined.trim().is_empty() {
            let _wrote_wire = self
                .bridge
                .remember_or_spool(
                    &combined,
                    effective_scope,
                    "turn:summary",
                    session_id,
                    profile,
                )
                .await?;
        }

        for patch in cas_patches {
            let scrubbed_content = self.bridge.scrub_untrusted_text(&patch.content).await;
            let mut sanitized_patch = patch.clone();
            sanitized_patch.content = scrubbed_content;

            match self.bridge.patch(&sanitized_patch).await {
                Ok(_) => {}
                Err(crate::HarnessError::Wire { reason })
                    if reason.contains("cas")
                        || reason.contains("revision")
                        || reason.contains("hash")
                        || reason.contains("precondition") =>
                {
                    // Explicit CAS precondition conflict -> Fail Loud rather than silently overwrite.
                    return Err(crate::HarnessError::Wire { reason });
                }
                Err(_) => {
                    let rec = LifecycleSpoolRecord::new(
                        session_id,
                        effective_scope,
                        "CasPatch",
                        0,
                        now_epoch_ms(),
                        json!({
                            "memory_id": sanitized_patch.memory_id,
                            "operation": sanitized_patch.operation,
                            "section_heading": sanitized_patch.section_heading,
                            "content": sanitized_patch.content,
                        }),
                    );
                    self.bridge.append_spool(rec).await?;
                }
            }
        }

        Ok(())
    }

    /// Trigger 7-phase Dream Engine consolidation & `wiki_sync` export (`T024`)
    /// ONLY when every active managed session is idle for at least `idle_debounce_secs` (`300s`).
    ///
    /// Returns `Ok(true)` if dream consolidation ran, `Ok(false)` if suppressed due to active turns
    /// or disabled trigger config.
    ///
    /// # Errors
    /// Propagates wire errors when `dream_control(run)` fails on an active daemon.
    pub async fn maybe_trigger_dream(
        &self,
        session_idle_durations_ms: &[Option<u64>],
    ) -> HarnessResult<bool> {
        let dream_cfg = &self.bridge.config().dream_trigger;
        if !dream_cfg.enabled || session_idle_durations_ms.is_empty() {
            return Ok(false);
        }

        let required_ms = dream_cfg.idle_debounce_secs.saturating_mul(1_000);
        let all_quiescent = session_idle_durations_ms
            .iter()
            .all(|maybe_idle| maybe_idle.is_some_and(|ms| ms >= required_ms));
        if !all_quiescent {
            return Ok(false);
        }

        let _dream_resp = self.bridge.dream_control("run").await?;

        if dream_cfg.run_wiki_sync {
            let wiki_dir = dream_cfg
                .wiki_dir
                .clone()
                .unwrap_or_else(|| Path::new(&self.bridge.normalized_db()).join("wiki"));
            let _ = self.bridge.wiki_sync("export", &wiki_dir).await?;
        }

        Ok(true)
    }
}

#[async_trait]
impl HarnessLifecycleHooks for SulurLifecycleManager {
    async fn on_session_start(&self, _scope: &str, _session_id: &str) -> HarnessResult<()> {
        let _ = self.bridge.ensure_daemon().await?;
        Ok(())
    }

    async fn on_before_turn(
        &self,
        scope: &str,
        session_id: &str,
        prompt: &str,
    ) -> HarnessResult<Option<String>> {
        let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
        self.on_before_turn_with_workspace(scope, session_id, &cwd, prompt)
            .await
    }

    async fn on_before_turn_with_workspace(
        &self,
        scope: &str,
        session_id: &str,
        workspace_path: &Path,
        prompt: &str,
    ) -> HarnessResult<Option<String>> {
        let injected = self
            .inject_context(scope, session_id, workspace_path, prompt)
            .await?;
        if injected.formatted_block.is_empty() {
            Ok(None)
        } else {
            Ok(Some(injected.formatted_block))
        }
    }

    async fn on_after_turn(
        &self,
        scope: &str,
        session_id: &str,
        summary: &str,
    ) -> HarnessResult<()> {
        self.record_turn(scope, session_id, None, summary, &[], &[])
            .await
    }

    async fn on_idle(&self) -> HarnessResult<()> {
        let last_ms = self
            .last_activity_ms
            .load(std::sync::atomic::Ordering::Relaxed);
        let idle_ms = now_epoch_ms().saturating_sub(last_ms);
        let _triggered = self.maybe_trigger_dream(&[Some(idle_ms)]).await?;
        Ok(())
    }
}

fn truncate_chars(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    text.chars().take(max_chars).collect()
}

fn now_epoch_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(u64::MAX)
}
