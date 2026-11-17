//! Discord Gateway Safeguard Approval bridge, thread-isolated [`SessionRegistry`] with
//! `git worktree` helpers, and canonical `/agent`, `/session`, `/handoff` command router.
//!
//! Operates strictly through `zeroclaw_api::channel::Channel` inward trait boundaries
//! without modifying or importing `zeroclaw-channels`.

use crate::lifecycle_hooks::SulurLifecycleManager;
use crate::pty_runner::{
    HarnessSessionPhase, PtyControlCommand, PtyEvent, PtySessionState, SelectedAgentRuntime,
};
use crate::sulur_bridge::CrossToolHandoffPayload;
use crate::{HarnessError, HarnessResult};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc};
use zeroclaw_api::channel::{
    ApprovalSource, Channel, ChannelApprovalRequest, ChannelApprovalResponse, SendMessage,
};

/// Declarative descriptor exported as `"slash"`-tagged skill metadata for `DiscordSlashCommandResolver`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashSkillDescriptor {
    pub name: String,
    pub description: String,
    pub tags: Vec<String>,
    pub options: Vec<SlashOptionDescriptor>,
}

/// Option metadata inside [`SlashSkillDescriptor`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashOptionDescriptor {
    pub name: String,
    pub kind: String,
    pub description: String,
    pub required: bool,
    pub choices: Vec<String>,
}

/// Canonical command vocabulary parsed from both Discord `/cmd` slash syntax and `!cmd` prefixes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HarnessCommand {
    /// `/agent <opencode|agy|zeroclaw-native>` (`native` accepted as alias).
    Agent {
        runtime: SelectedAgentRuntime,
        /// Optional explicit confirmation mode when switching mid-turn (`confirm_cancel` | `queue`).
        mid_turn_policy: Option<MidTurnSwitchPolicy>,
    },
    /// `/session <create|switch|worktree|list|stop> [target]`.
    Session(SessionSubcommand),
    /// `/handoff <create|claim|status> [arg]`.
    Handoff(HandoffSubcommand),
}

/// Deterministic behavior options when `/agent` is invoked while a turn is in flight (`U2`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MidTurnSwitchPolicy {
    /// Gracefully terminate the running sub-agent via `CancellationToken`/`Terminate` and switch now.
    ConfirmCancelAndSwitch,
    /// Finish current turn cleanly and switch before the next user prompt.
    QueueNextTurn,
}

/// Subcommands under `/session`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionSubcommand {
    Create { path_or_name: Option<String> },
    Switch { target: String },
    Worktree { branch: String },
    List,
    Stop { session_id: Option<String> },
}

/// Subcommands under `/handoff`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandoffSubcommand {
    Create { milestone: Option<String> },
    Claim { ticket_id: Option<String> },
    Status,
}

/// Result returned when processing `/agent` on a live session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentSwitchOutcome {
    SwitchedNow {
        session_id: String,
        runtime: SelectedAgentRuntime,
    },
    QueuedForNextTurn {
        session_id: String,
        runtime: SelectedAgentRuntime,
    },
    ConfirmationRequired {
        session_id: String,
        current_phase: HarnessSessionPhase,
        requested: SelectedAgentRuntime,
        prompt_message: String,
    },
}

/// Generate the built-in `"slash"`-tagged skill descriptors consumed by `DiscordSlashCommandResolver`.
#[must_use]
pub fn harness_slash_skill_descriptors() -> Vec<SlashSkillDescriptor> {
    vec![
        SlashSkillDescriptor {
            name: "agent".to_string(),
            description:
                "Switch coding runtime for this thread (opencode, agy, or zeroclaw-native)"
                    .to_string(),
            tags: vec!["slash".to_string()],
            options: vec![
                SlashOptionDescriptor {
                    name: "runtime".to_string(),
                    kind: "string".to_string(),
                    description: "Target runtime".to_string(),
                    required: true,
                    choices: vec![
                        "opencode".to_string(),
                        "agy".to_string(),
                        "zeroclaw-native".to_string(),
                        "native".to_string(),
                    ],
                },
                SlashOptionDescriptor {
                    name: "mode".to_string(),
                    kind: "string".to_string(),
                    description: "Mid-turn switch policy (confirm-cancel or queue)".to_string(),
                    required: false,
                    choices: vec!["confirm-cancel".to_string(), "queue".to_string()],
                },
            ],
        },
        SlashSkillDescriptor {
            name: "session".to_string(),
            description: "Manage thread-isolated sessions and git worktrees".to_string(),
            tags: vec!["slash".to_string()],
            options: vec![
                SlashOptionDescriptor {
                    name: "action".to_string(),
                    kind: "string".to_string(),
                    description: "Session action".to_string(),
                    required: true,
                    choices: vec![
                        "create".to_string(),
                        "switch".to_string(),
                        "worktree".to_string(),
                        "list".to_string(),
                        "stop".to_string(),
                    ],
                },
                SlashOptionDescriptor {
                    name: "target".to_string(),
                    kind: "string".to_string(),
                    description: "Branch name, directory, or session id".to_string(),
                    required: false,
                    choices: vec![],
                },
            ],
        },
        SlashSkillDescriptor {
            name: "handoff".to_string(),
            description:
                "Transfer or claim coding session continuity across Zed IDE / CLI / Discord"
                    .to_string(),
            tags: vec!["slash".to_string()],
            options: vec![
                SlashOptionDescriptor {
                    name: "action".to_string(),
                    kind: "string".to_string(),
                    description: "Handoff action".to_string(),
                    required: true,
                    choices: vec![
                        "create".to_string(),
                        "claim".to_string(),
                        "status".to_string(),
                    ],
                },
                SlashOptionDescriptor {
                    name: "detail".to_string(),
                    kind: "string".to_string(),
                    description: "Optional milestone summary or ticket id".to_string(),
                    required: false,
                    choices: vec![],
                },
            ],
        },
    ]
}

/// Parse `/agent`, `!agent`, `/session`, `!session`, `/handoff`, or `!handoff` text cleanly.
///
/// # Errors
/// Returns [`HarnessError::InvalidProfile`] when command syntax or subcommand arguments are invalid.
pub fn parse_harness_command(input: &str) -> HarnessResult<Option<HarnessCommand>> {
    let trimmed = input.trim();
    let body = if let Some(rest) = trimmed.strip_prefix('/') {
        rest
    } else if let Some(rest) = trimmed.strip_prefix('!') {
        rest
    } else {
        return Ok(None);
    };

    let parts: Vec<&str> = body.split_whitespace().collect();
    let Some(&cmd) = parts.first() else {
        return Ok(None);
    };

    match cmd.to_ascii_lowercase().as_str() {
        "agent" => {
            let Some(&raw_rt) = parts.get(1) else {
                return Err(HarnessError::InvalidProfile {
                    profile: "discord:/agent".to_string(),
                    reason: "usage: /agent <opencode|agy|zeroclaw-native> [confirm-cancel|queue]"
                        .to_string(),
                });
            };
            let runtime = match raw_rt.to_ascii_lowercase().as_str() {
                "native" | "zeroclaw-native" | "zeroclaw" => SelectedAgentRuntime::NativeZeroClaw,
                other => SelectedAgentRuntime::DeclarativeCli(other.to_string()),
            };
            let mid_turn_policy = match parts.get(2).map(|s| s.to_ascii_lowercase()).as_deref() {
                None => None,
                Some("confirm-cancel" | "cancel" | "force") => {
                    Some(MidTurnSwitchPolicy::ConfirmCancelAndSwitch)
                }
                Some("queue" | "next") => Some(MidTurnSwitchPolicy::QueueNextTurn),
                Some(other) => {
                    return Err(HarnessError::InvalidProfile {
                        profile: "discord:/agent".to_string(),
                        reason: format!(
                            "unknown mid-turn policy `{other}`; expected `confirm-cancel` or `queue`"
                        ),
                    });
                }
            };
            Ok(Some(HarnessCommand::Agent {
                runtime,
                mid_turn_policy,
            }))
        }
        "session" => {
            let sub = parts.get(1).map(|s| s.to_ascii_lowercase());
            let arg = parts.get(2..).and_then(|s| {
                let joined = s.join(" ");
                if joined.trim().is_empty() {
                    None
                } else {
                    Some(joined)
                }
            });
            let parsed = match sub.as_deref() {
                Some("create" | "new") => SessionSubcommand::Create { path_or_name: arg },
                Some("switch") => SessionSubcommand::Switch {
                    target: arg.ok_or_else(|| HarnessError::InvalidProfile {
                        profile: "discord:/session".to_string(),
                        reason: "usage: /session switch <session_id_or_thread>".to_string(),
                    })?,
                },
                Some("worktree") => SessionSubcommand::Worktree {
                    branch: arg.ok_or_else(|| HarnessError::InvalidProfile {
                        profile: "discord:/session".to_string(),
                        reason: "usage: /session worktree <branch>".to_string(),
                    })?,
                },
                Some("list") | None => SessionSubcommand::List,
                Some("stop") => SessionSubcommand::Stop { session_id: arg },
                Some(other) => {
                    return Err(HarnessError::InvalidProfile {
                        profile: "discord:/session".to_string(),
                        reason: format!(
                            "unknown /session subcommand `{other}`; expected create|switch|worktree|list|stop"
                        ),
                    });
                }
            };
            Ok(Some(HarnessCommand::Session(parsed)))
        }
        "handoff" => {
            let sub = parts.get(1).map(|s| s.to_ascii_lowercase());
            let detail = parts.get(2..).and_then(|s| {
                let joined = s.join(" ");
                if joined.trim().is_empty() {
                    None
                } else {
                    Some(joined)
                }
            });
            let parsed = match sub.as_deref() {
                Some("create" | "send") => HandoffSubcommand::Create { milestone: detail },
                Some("claim" | "accept") => HandoffSubcommand::Claim { ticket_id: detail },
                Some("status") | None => HandoffSubcommand::Status,
                Some(other) => {
                    return Err(HarnessError::InvalidProfile {
                        profile: "discord:/handoff".to_string(),
                        reason: format!(
                            "unknown /handoff subcommand `{other}`; expected create|claim|status"
                        ),
                    });
                }
            };
            Ok(Some(HarnessCommand::Handoff(parsed)))
        }
        _ => Ok(None),
    }
}

/// Strip `:thread` suffix from a Discord channel recipient so Safeguard prompts land on the root channel
/// cleanly per `spec.md` Assumptions and `DiscordChannel::request_approval_attributed`.
#[must_use]
pub fn normalize_discord_root_recipient(recipient: &str) -> String {
    match recipient.split_once(":thread") {
        Some((root, _)) => root.to_string(),
        None => recipient.to_string(),
    }
}

/// Registered session entry tracked per Discord channel/thread.
#[derive(Debug, Clone)]
struct RegistryRecord {
    state: PtySessionState,
    pending_runtime_switch: Option<SelectedAgentRuntime>,
    control_tx: Option<mpsc::Sender<PtyControlCommand>>,
}

/// Thread-isolated registry binding Discord recipients to [`PtySessionState`] and optional git worktrees.
#[derive(Debug, Default, Clone)]
pub struct SessionRegistry {
    sessions: Arc<RwLock<HashMap<String, RegistryRecord>>>,
    active_by_recipient: Arc<RwLock<HashMap<String, String>>>,
}

impl SessionRegistry {
    /// Construct an empty [`SessionRegistry`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register or replace a managed session bound to `channel_recipient`.
    pub fn register_session(
        &self,
        state: PtySessionState,
        control_tx: Option<mpsc::Sender<PtyControlCommand>>,
    ) {
        let sid = state.session_id.clone();
        let recipient = state.channel_recipient.clone();
        {
            let mut map = self.sessions.write();
            map.insert(
                sid.clone(),
                RegistryRecord {
                    state,
                    pending_runtime_switch: None,
                    control_tx,
                },
            );
        }
        self.active_by_recipient.write().insert(recipient, sid);
    }

    /// Resolve the active session snapshot for a Discord recipient (`channel_id` or `channel_id:thread_id`).
    #[must_use]
    pub fn active_session_for(&self, recipient: &str) -> Option<PtySessionState> {
        let sid = self.active_by_recipient.read().get(recipient)?.clone();
        self.sessions.read().get(&sid).map(|r| r.state.clone())
    }

    /// Switch which session ID a Discord recipient targets.
    ///
    /// # Errors
    /// Returns [`HarnessError::InvalidProfile`] when `session_id` is unknown.
    pub fn switch_recipient_session(&self, recipient: &str, session_id: &str) -> HarnessResult<()> {
        if !self.sessions.read().contains_key(session_id) {
            return Err(HarnessError::InvalidProfile {
                profile: "session_registry".to_string(),
                reason: format!("unknown session `{session_id}`"),
            });
        }
        self.active_by_recipient
            .write()
            .insert(recipient.to_string(), session_id.to_string());
        Ok(())
    }

    /// Snapshot all tracked sessions.
    #[must_use]
    pub fn list_sessions(&self) -> Vec<PtySessionState> {
        self.sessions
            .read()
            .values()
            .map(|rec| rec.state.clone())
            .collect()
    }

    /// Update tracked [`HarnessSessionPhase`] cleanly (e.g., on `PtyEvent::PhaseChanged` or crash settle).
    pub fn update_phase(&self, session_id: &str, phase: HarnessSessionPhase) {
        let mut sessions = self.sessions.write();
        if let Some(rec) = sessions.get_mut(session_id) {
            rec.state.phase = phase;
            if matches!(
                phase,
                HarnessSessionPhase::CompletedIdle | HarnessSessionPhase::Idle
            ) && let Some(queued_rt) = rec.pending_runtime_switch.take()
            {
                rec.state.selected_runtime = queued_rt;
            }
        }
    }

    /// Compute idle elapsed milliseconds for each registered session (used by `maybe_trigger_dream`).
    #[must_use]
    pub fn idle_durations_ms(&self, now_ms: u64) -> Vec<Option<u64>> {
        self.sessions
            .read()
            .values()
            .map(|rec| match rec.state.phase {
                HarnessSessionPhase::Idle | HarnessSessionPhase::CompletedIdle => {
                    Some(now_ms.saturating_sub(rec.state.last_state_change_at_ms))
                }
                _ => None,
            })
            .collect()
    }

    /// Request runtime switch (`/agent ...`) for `recipient`, enforcing explicit confirmation or queueing
    /// when a turn is in flight (`Thinking` | `Streaming` | `AwaitingApproval`).
    ///
    /// # Errors
    /// Returns [`HarnessError::InvalidProfile`] if `recipient` has no active session.
    pub async fn switch_agent_runtime(
        &self,
        recipient: &str,
        requested: SelectedAgentRuntime,
        policy: Option<MidTurnSwitchPolicy>,
    ) -> HarnessResult<AgentSwitchOutcome> {
        let (sid, phase, ctrl_tx) = {
            let sid = self
                .active_by_recipient
                .read()
                .get(recipient)
                .cloned()
                .ok_or_else(|| HarnessError::InvalidProfile {
                    profile: "discord:/agent".to_string(),
                    reason: format!("no active session bound to `{recipient}`"),
                })?;
            let sessions = self.sessions.read();
            let rec = sessions
                .get(&sid)
                .ok_or_else(|| HarnessError::InvalidProfile {
                    profile: "discord:/agent".to_string(),
                    reason: format!("missing session record `{sid}`"),
                })?;
            (sid, rec.state.phase, rec.control_tx.clone())
        };

        if !phase.is_active() {
            if let Some(rec) = self.sessions.write().get_mut(&sid) {
                rec.state.selected_runtime = requested.clone();
                rec.pending_runtime_switch = None;
            }
            return Ok(AgentSwitchOutcome::SwitchedNow {
                session_id: sid,
                runtime: requested,
            });
        }

        match policy {
            Some(MidTurnSwitchPolicy::ConfirmCancelAndSwitch) => {
                if let Some(tx) = ctrl_tx {
                    let _ = tx.send(PtyControlCommand::Terminate).await;
                }
                if let Some(rec) = self.sessions.write().get_mut(&sid) {
                    rec.state.selected_runtime = requested.clone();
                    rec.pending_runtime_switch = None;
                }
                Ok(AgentSwitchOutcome::SwitchedNow {
                    session_id: sid,
                    runtime: requested,
                })
            }
            Some(MidTurnSwitchPolicy::QueueNextTurn) => {
                if let Some(rec) = self.sessions.write().get_mut(&sid) {
                    rec.pending_runtime_switch = Some(requested.clone());
                }
                Ok(AgentSwitchOutcome::QueuedForNextTurn {
                    session_id: sid,
                    runtime: requested,
                })
            }
            None => Ok(AgentSwitchOutcome::ConfirmationRequired {
                session_id: sid,
                current_phase: phase,
                requested: requested.clone(),
                prompt_message: format!(
                    "Session is currently `{phase:?}`. Re-run with `confirm-cancel` to terminate active turn and switch to `{requested:?}`, or `queue` to switch after completion."
                ),
            }),
        }
    }

    /// Execute `/handoff create` (persisting [`CrossToolHandoffPayload`] to Sulur) or
    /// `/handoff claim` against [`SulurLifecycleManager`].
    ///
    /// # Errors
    /// Propagates wire errors or missing session errors.
    pub async fn handle_handoff_command(
        &self,
        recipient: &str,
        sub: HandoffSubcommand,
        sulur: &SulurLifecycleManager,
    ) -> HarnessResult<String> {
        let sess =
            self.active_session_for(recipient)
                .ok_or_else(|| HarnessError::InvalidProfile {
                    profile: "discord:/handoff".to_string(),
                    reason: format!("no active session bound to `{recipient}`"),
                })?;

        match sub {
            HandoffSubcommand::Create { milestone } => {
                let agent_name = match &sess.selected_runtime {
                    SelectedAgentRuntime::NativeZeroClaw => "zeroclaw-native".to_string(),
                    SelectedAgentRuntime::DeclarativeCli(id) => id.clone(),
                };
                let payload = CrossToolHandoffPayload {
                    ticket_id: None,
                    scope: sess.sulur_scope.clone(),
                    source_session_id: sess.session_id.clone(),
                    source_agent: agent_name,
                    target_harness: Some("zed".to_string()),
                    workspace_path: sess.workspace_path.clone(),
                    git_branch: sess.worktree_branch.clone(),
                    milestone: milestone
                        .unwrap_or_else(|| "Handed off from Discord session".to_string()),
                    unblocked_next_steps: vec!["Continue in Zed IDE or terminal".to_string()],
                    modified_files: Vec::new(),
                    status: "offered".to_string(),
                    created_at: 0,
                    claimed_at: None,
                };
                let created = sulur.bridge().handoff_begin(&payload).await?;
                Ok(format!(
                    "Created handoff ticket `{}` for scope `{}`",
                    created.ticket_id.unwrap_or_else(|| "pending".to_string()),
                    created.scope
                ))
            }
            HandoffSubcommand::Claim { ticket_id } => {
                let target_id = if let Some(id) = ticket_id {
                    id
                } else {
                    let offered = sulur
                        .bridge()
                        .handoff_list(&sess.sulur_scope, "offered", &sess.workspace_path)
                        .await?;
                    offered
                        .first()
                        .and_then(|t| t.ticket_id.clone())
                        .ok_or_else(|| HarnessError::Wire {
                            reason: "no offered handoff ticket available to claim".to_string(),
                        })?
                };
                let claimed = sulur
                    .bridge()
                    .handoff_accept(&target_id, &sess.session_id, &sess.workspace_path)
                    .await?;
                Ok(format!(
                    "Claimed handoff `{}`: {}",
                    claimed.ticket_id.unwrap_or(target_id),
                    claimed.milestone
                ))
            }
            HandoffSubcommand::Status => {
                let offered = sulur
                    .bridge()
                    .handoff_list(&sess.sulur_scope, "offered", &sess.workspace_path)
                    .await?;
                Ok(format!(
                    "{} offered handoff ticket(s) in scope `{}`",
                    offered.len(),
                    sess.sulur_scope
                ))
            }
        }
    }
}

/// Create an isolated `git worktree` directory on branch `branch` (creating branch `-b` when new).
///
/// # Errors
/// Returns [`HarnessError::Io`] or [`HarnessError::Pty`] on git invocation failure.
pub async fn create_git_worktree(
    repo_root: &Path,
    worktree_dir: &Path,
    branch: &str,
) -> HarnessResult<PathBuf> {
    let repo = repo_root.to_path_buf();
    let wt = worktree_dir.to_path_buf();
    let br = branch.to_string();

    tokio::task::spawn_blocking(move || {
        if let Some(parent) = wt.parent() {
            std::fs::create_dir_all(parent).map_err(|source| HarnessError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        let wt_str = wt.to_string_lossy().into_owned();
        // Try attaching existing branch first; fall back to `-b <branch>`.
        let out = Command::new("git")
            .args([
                "-C",
                &repo.to_string_lossy(),
                "worktree",
                "add",
                &wt_str,
                &br,
            ])
            .output()
            .map_err(|source| HarnessError::Io {
                path: repo.clone(),
                source,
            })?;
        if out.status.success() {
            return Ok(wt);
        }

        let create_new = Command::new("git")
            .args([
                "-C",
                &repo.to_string_lossy(),
                "worktree",
                "add",
                "-b",
                &br,
                &wt_str,
            ])
            .output()
            .map_err(|source| HarnessError::Io { path: repo, source })?;
        if !create_new.status.success() {
            return Err(HarnessError::Pty {
                session_id: br,
                reason: format!(
                    "git worktree add failed: {}",
                    String::from_utf8_lossy(&create_new.stderr)
                ),
            });
        }
        Ok(wt)
    })
    .await
    .map_err(|err| HarnessError::Pty {
        session_id: "git-worktree".to_string(),
        reason: format!("worktree task panicked: {err}"),
    })?
}

/// Remove an isolated `git worktree` when a thread session finishes.
///
/// # Errors
/// Returns [`HarnessError::Io`] or [`HarnessError::Pty`] on git invocation failure.
pub async fn remove_git_worktree(repo_root: &Path, worktree_dir: &Path) -> HarnessResult<()> {
    let repo = repo_root.to_path_buf();
    let wt = worktree_dir.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let out = Command::new("git")
            .args([
                "-C",
                &repo.to_string_lossy(),
                "worktree",
                "remove",
                "--force",
                &wt.to_string_lossy(),
            ])
            .output()
            .map_err(|source| HarnessError::Io { path: repo, source })?;
        if !out.status.success() {
            return Err(HarnessError::Pty {
                session_id: "git-worktree".to_string(),
                reason: format!(
                    "git worktree remove failed: {}",
                    String::from_utf8_lossy(&out.stderr)
                ),
            });
        }
        Ok(())
    })
    .await
    .map_err(|err| HarnessError::Pty {
        session_id: "git-worktree".to_string(),
        reason: format!("worktree remove task panicked: {err}"),
    })?
}

/// Bridge live [`PtyEvent`] notifications to ZeroClaw's [`Channel`] Safeguard approval API (`T026`)
/// and Discord crash-restart notifications.
///
/// Exits cleanly when the broadcast `events` channel closes.
pub async fn run_discord_event_bridge(
    channel: Arc<dyn Channel>,
    channel_recipient: String,
    scope: String,
    control_tx: mpsc::Sender<PtyControlCommand>,
    mut events: broadcast::Receiver<PtyEvent>,
    registry: Option<SessionRegistry>,
    sulur: Option<Arc<SulurLifecycleManager>>,
) {
    let root_recipient = normalize_discord_root_recipient(&channel_recipient);

    loop {
        match events.recv().await {
            Ok(PtyEvent::PhaseChanged { session_id, to, .. }) => {
                if let Some(ref reg) = registry {
                    reg.update_phase(&session_id, to);
                }
            }
            Ok(PtyEvent::ApprovalRequested {
                session_id,
                payload,
            }) => {
                let req = ChannelApprovalRequest {
                    tool_name: payload.tool_or_command_hint.clone(),
                    arguments_summary: payload.matched_excerpt.clone(),
                    raw_arguments: None,
                    position: None,
                };
                let timeout = Duration::from_secs(payload.timeout_secs.max(1));
                let decision = channel
                    .request_approval_attributed_with_timeout(&root_recipient, &req, timeout)
                    .await;

                let (approved, decided_by, custom_response, timed_out) = match decision {
                    Ok(Some(resp)) => match resp.response {
                        ChannelApprovalResponse::Approve
                        | ChannelApprovalResponse::AlwaysApprove => {
                            (true, resp.decided_by, None, false)
                        }
                        ChannelApprovalResponse::DenyWithEdit { replacement } => {
                            (true, resp.decided_by, Some(replacement.into_bytes()), false)
                        }
                        ChannelApprovalResponse::Deny => {
                            let is_timeout = matches!(resp.source, ApprovalSource::TimedOut);
                            (false, resp.decided_by, None, is_timeout)
                        }
                    },
                    Ok(None) | Err(_) => (false, None, None, false),
                };

                let _ = control_tx
                    .send(PtyControlCommand::ResolveApproval {
                        prompt_id: payload.prompt_id,
                        approved,
                        decided_by,
                        custom_response,
                    })
                    .await;

                if timed_out {
                    let msg = SendMessage::new(
                        format!(
                            "Approval prompt timed out for session `{session_id}` — action rejected and session returned to idle."
                        ),
                        channel_recipient.clone(),
                    );
                    let _ = channel.send(&msg).await;
                    if let Some(ref reg) = registry {
                        reg.update_phase(&session_id, HarnessSessionPhase::CompletedIdle);
                    }
                }
            }
            Ok(PtyEvent::Exited {
                session_id,
                exit_code,
                tail_excerpt,
            }) => {
                let crashed = exit_code.is_some_and(|code| code != 0) || exit_code.is_none();
                if let Some(ref mgr) = sulur {
                    let summary = format!(
                        "Sub-agent session `{session_id}` exited ({exit_code:?}): {tail_excerpt}"
                    );
                    let _ = mgr
                        .record_turn(&scope, &session_id, None, &summary, &[], &[])
                        .await;
                }
                if let Some(ref reg) = registry {
                    reg.update_phase(&session_id, HarnessSessionPhase::CompletedIdle);
                }
                if crashed {
                    let notice = SendMessage::new(
                        format!(
                            "⚠️ Sub-agent session `{session_id}` terminated unexpectedly (exit code: {exit_code:?}).\n**One-Click Restart**: invoke `/session create` or reply `!session create` to relaunch.\n```\n{tail_excerpt}\n```"
                        ),
                        channel_recipient.clone(),
                    );
                    let _ = channel.send(&notice).await;
                }
            }
            Ok(PtyEvent::OutputChunk { .. }) => {}
            Err(broadcast::error::RecvError::Lagged(_)) => continue,
            Err(broadcast::error::RecvError::Closed) => break,
        }
    }
}
