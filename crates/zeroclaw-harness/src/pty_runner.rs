//! Cross-platform asynchronous PTY runner and dual-channel harness state machine.
//!
//! Bridges `portable_pty::native_pty_system()` (`ConPTY` on Windows, `openpty` on Unix)
//! via `tokio::task::spawn_blocking` I/O pumps into bounded Tokio channels, driving
//! [`HarnessStateMachine`] with strict `IPC > Regex` precedence and debounce suppression.

use crate::detector::{
    truncate_chars_tail, AnsiStripRingBuffer, CompiledAgentProfile, HerdrIpcListener,
    IpcStateMessage, RawDetectedState, MAX_EXCERPT_CHARS,
};
use crate::{HarnessError, HarnessResult};
use parking_lot::RwLock;
use portable_pty::{native_pty_system, ChildKiller, CommandBuilder, MasterPty, PtySize};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use zeroclaw_api::lifecycle::LifecycleActivity;

/// Bounded capacity for outbound [`PtyEvent`] broadcast listeners.
const EVENT_BROADCAST_CAPACITY: usize = 256;

/// Bounded capacity for inbound [`PtyControlCommand`] requests.
const CONTROL_CHANNEL_CAPACITY: usize = 64;

/// Bounded capacity for raw PTY stdout/stderr chunks flowing from `spawn_blocking`.
const RAW_READ_CHANNEL_CAPACITY: usize = 128;

/// High-level harness session state exposed to Discord & Lifecycle Hooks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HarnessSessionPhase {
    /// Sub-agent initialized or idle awaiting user prompt.
    Idle,
    /// Sub-agent processing request / reasoning before visible text generation.
    Thinking,
    /// Sub-agent actively emitting text or progress updates.
    Streaming,
    /// Sub-agent blocked waiting for explicit Discord operator approval/choice.
    AwaitingApproval,
    /// Turn cleanly finished and debounced idle; eligible for post-turn & dream triggers.
    CompletedIdle,
    /// Sub-agent process exited unexpectedly or was terminated.
    Terminated { exit_code: Option<i32> },
}

impl HarnessSessionPhase {
    /// Exact mapping onto ZeroClaw core lifecycle vocabulary (FR-005).
    #[must_use]
    pub const fn to_lifecycle_activity(self) -> LifecycleActivity {
        match self {
            Self::Idle => LifecycleActivity::Idle,
            Self::Thinking => LifecycleActivity::Turn,
            Self::Streaming => LifecycleActivity::Tool,
            Self::AwaitingApproval => LifecycleActivity::Approval,
            Self::CompletedIdle | Self::Terminated { .. } => LifecycleActivity::Finished,
        }
    }

    /// True if the session is actively working or awaiting approval (not quiescent).
    #[must_use]
    pub const fn is_active(self) -> bool {
        matches!(self, Self::Thinking | Self::Streaming | Self::AwaitingApproval)
    }
}

/// Debounce state for stabilizing noisy TUI redraws into `CompletedIdle`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PendingIdleConfirmation {
    pub first_seen_at_ms: u64,
    pub last_checked_at_ms: u64,
    pub confirmations: u8,
}

/// Captured details extracted when `detector.rs` enters `AwaitingApproval`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalPromptPayload {
    /// Unique monotonic ID used for idempotent first-click resolution.
    pub prompt_id: String,
    /// ID of the matching rule or `"ipc:permission.asked"`.
    pub rule_id: String,
    /// Bounded stripped context excerpt (up to 1,200 chars) rendered in Discord card.
    pub matched_excerpt: String,
    /// Parsed command or file target hint if detected, else agent display name.
    pub tool_or_command_hint: String,
    /// Detection source (`IpcPush` or `PtyRegex`).
    pub source: DetectionSourceKind,
    /// Unix epoch milliseconds when blocked state began.
    pub detected_at_ms: u64,
    /// Expiration window in seconds (`default: 900` = 15 min).
    pub timeout_secs: u64,
}

/// Source channel that triggered a session state transition or approval prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionSourceKind {
    IpcPush,
    PtyRegex,
    ProcessExit,
}

/// Active sub-agent selection per Discord thread or channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectedAgentRuntime {
    NativeZeroClaw,
    /// External declarative CLI profile ID (`"opencode"`, `"agy"`, or custom `.toml`).
    DeclarativeCli(String),
}

/// Canonical runtime record for one managed coding session (bound to a Discord thread/channel).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PtySessionState {
    pub session_id: String,
    /// Discord target identifier (e.g., `<channel_id>:<thread_id>` or `<channel_id>`).
    pub channel_recipient: String,
    /// Selected runtime (Native ZeroClaw or external CLI agent ID).
    pub selected_runtime: SelectedAgentRuntime,
    /// Canonical Sulur project scope string (e.g., `"ws:memory:zeroclaw"`).
    pub sulur_scope: String,
    /// Working directory or isolated git worktree bound to this session.
    pub workspace_path: PathBuf,
    /// Git branch/worktree name if managed via `/session worktree`.
    pub worktree_branch: Option<String>,
    /// OS PID of the spawned sub-agent process when running.
    pub pid: Option<u32>,
    /// Current state machine phase.
    pub phase: HarnessSessionPhase,
    /// Pending debounce tracker during Working -> CompletedIdle transition.
    pub pending_idle: Option<PendingIdleConfirmation>,
    /// Active blocking approval prompt awaiting Discord button click, if any.
    pub active_approval: Option<ApprovalPromptPayload>,
    /// Unix epoch ms timestamps for timeout/idle accounting.
    pub started_at_ms: u64,
    pub last_output_at_ms: u64,
    pub last_state_change_at_ms: u64,
}

/// Inbound commands sent to a running PTY worker via `tokio::sync::mpsc::Sender<PtyControlCommand>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PtyControlCommand {
    /// Inject a user prompt or follow-up text into PTY stdin.
    WriteInput(Vec<u8>),
    /// Resolve an active `AwaitingApproval` gate (must match `active_approval.prompt_id`).
    ResolveApproval {
        prompt_id: String,
        approved: bool,
        decided_by: Option<String>,
        custom_response: Option<Vec<u8>>,
    },
    /// Resize ConPTY / Unix PTY viewport (`rows x cols`).
    Resize { rows: u16, cols: u16 },
    /// Gracefully terminate the sub-agent process (`interrupt_sequence`, then wait/kill).
    Terminate,
}

/// Outbound events emitted by PTY worker over `tokio::sync::broadcast` / `mpsc`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum PtyEvent {
    OutputChunk {
        session_id: String,
        stripped_text: String,
        timestamp_ms: u64,
    },
    PhaseChanged {
        session_id: String,
        from: HarnessSessionPhase,
        to: HarnessSessionPhase,
        reason: String,
        timestamp_ms: u64,
    },
    ApprovalRequested {
        session_id: String,
        payload: ApprovalPromptPayload,
    },
    Exited {
        session_id: String,
        exit_code: Option<i32>,
        tail_excerpt: String,
    },
}

/// Normalize interactive PTY stdin line endings cleanly (`\n` -> `\r\n` without doubling existing `\r\n` or bare `\r`).
#[must_use]
pub fn normalize_pty_stdin(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() + 4);
    let mut prev_cr = false;
    for &b in input {
        if b == b'\n' && !prev_cr {
            out.push(b'\r');
        }
        out.push(b);
        prev_cr = b == b'\r';
    }
    out
}

/// Deterministic dual-channel (`IPC > Regex`) harness session state machine.
///
/// Decoupled from OS PTY handles so both live PTY tasks and deterministic unit tests
/// can drive exact millisecond timestamps without sleeping.
pub struct HarnessStateMachine {
    session_id: String,
    profile: CompiledAgentProfile,
    ring: AnsiStripRingBuffer,
    phase: HarnessSessionPhase,
    pending_idle: Option<PendingIdleConfirmation>,
    active_approval: Option<ApprovalPromptPayload>,
    ipc_blocked: bool,
    started_at_ms: u64,
    last_output_at_ms: u64,
    last_state_change_at_ms: u64,
    approval_timeout_secs: u64,
}

impl HarnessStateMachine {
    /// Construct a new session state machine bound to `profile`.
    #[must_use]
    pub fn new(
        session_id: String,
        profile: CompiledAgentProfile,
        started_at_ms: u64,
        approval_timeout_secs: u64,
    ) -> Self {
        Self {
            session_id,
            profile,
            ring: AnsiStripRingBuffer::new(),
            phase: HarnessSessionPhase::Idle,
            pending_idle: None,
            active_approval: None,
            ipc_blocked: false,
            started_at_ms,
            last_output_at_ms: started_at_ms,
            last_state_change_at_ms: started_at_ms,
            approval_timeout_secs,
        }
    }

    /// Current session phase.
    #[must_use]
    pub const fn phase(&self) -> HarnessSessionPhase {
        self.phase
    }

    /// Pending idle confirmation tracker when debouncing noisy redraws.
    #[must_use]
    pub const fn pending_idle(&self) -> Option<PendingIdleConfirmation> {
        self.pending_idle
    }

    /// Active blocking approval prompt, if awaiting operator input.
    #[must_use]
    pub const fn active_approval(&self) -> Option<&ApprovalPromptPayload> {
        self.active_approval.as_ref()
    }

    /// Bounded ANSI-stripped line ring buffer.
    #[must_use]
    pub const fn buffer(&self) -> &AnsiStripRingBuffer {
        &self.ring
    }

    /// Drain pending terminal DSR/DA replies needed by ConPTY/Unix VT handshakes.
    pub fn take_terminal_responses(&mut self) -> Vec<Vec<u8>> {
        self.ring.take_terminal_responses()
    }

    /// Last timestamp PTY output arrived.
    #[must_use]
    pub const fn last_output_at_ms(&self) -> u64 {
        self.last_output_at_ms
    }

    /// Last timestamp `phase` transitioned.
    #[must_use]
    pub const fn last_state_change_at_ms(&self) -> u64 {
        self.last_state_change_at_ms
    }

    /// Notify state machine that user input was written into PTY stdin.
    pub fn on_input_sent(&mut self, now_ms: u64) -> Vec<PtyEvent> {
        if matches!(self.phase, HarnessSessionPhase::Terminated { .. }) {
            return Vec::new();
        }
        self.pending_idle = None;
        if matches!(
            self.phase,
            HarnessSessionPhase::Idle | HarnessSessionPhase::CompletedIdle
        ) {
            return self.transition(HarnessSessionPhase::Thinking, "user_input", now_ms);
        }
        Vec::new()
    }

    /// Consume raw PTY bytes, emit stripped `OutputChunk`, and evaluate regex rules unless masked by IPC.
    pub fn on_pty_bytes(&mut self, bytes: &[u8], now_ms: u64) -> Vec<PtyEvent> {
        let mut events = Vec::new();
        if bytes.is_empty() || matches!(self.phase, HarnessSessionPhase::Terminated { .. }) {
            return events;
        }

        self.last_output_at_ms = now_ms;
        let stripped = self.ring.push_bytes_delta(bytes);
        if !stripped.is_empty() {
            events.push(PtyEvent::OutputChunk {
                session_id: self.session_id.clone(),
                stripped_text: stripped,
                timestamp_ms: now_ms,
            });
        }

        // Strict `IPC > Regex`: never let lower-priority PTY output clear an IPC-asserted block.
        if self.ipc_blocked {
            return events;
        }

        if let Some(matched) = self.profile.evaluate_buffer(&self.ring) {
            match matched.state {
                RawDetectedState::Blocked => {
                    self.pending_idle = None;
                    let same_rule = self
                        .active_approval
                        .as_ref()
                        .is_some_and(|a| a.rule_id == matched.rule_id);
                    if !same_rule {
                        let payload = ApprovalPromptPayload {
                            prompt_id: uuid::Uuid::now_v7().to_string(),
                            rule_id: matched.rule_id.clone(),
                            matched_excerpt: matched.matched_excerpt,
                            tool_or_command_hint: self.infer_hint(),
                            source: DetectionSourceKind::PtyRegex,
                            detected_at_ms: now_ms,
                            timeout_secs: self.approval_timeout_secs,
                        };
                        self.active_approval = Some(payload.clone());
                        events.extend(self.transition(
                            HarnessSessionPhase::AwaitingApproval,
                            &format!("pty_rule:{}", matched.rule_id),
                            now_ms,
                        ));
                        events.push(PtyEvent::ApprovalRequested {
                            session_id: self.session_id.clone(),
                            payload,
                        });
                    }
                }
                RawDetectedState::Working => {
                    self.pending_idle = None;
                    if self.phase != HarnessSessionPhase::AwaitingApproval {
                        let next_phase = match matched.subphase.as_deref() {
                            Some("streaming") => HarnessSessionPhase::Streaming,
                            _ => HarnessSessionPhase::Thinking,
                        };
                        events.extend(self.transition(
                            next_phase,
                            &format!("pty_rule:{}", matched.rule_id),
                            now_ms,
                        ));
                    }
                }
                RawDetectedState::Idle => {
                    if self.phase.is_active() {
                        events.extend(self.advance_idle_debounce(now_ms));
                    }
                }
            }
        }

        events
    }

    /// Apply structured out-of-band IPC state update (`IPC > Regex` precedence).
    pub fn on_ipc_message(&mut self, msg: &IpcStateMessage, now_ms: u64) -> Vec<PtyEvent> {
        if matches!(self.phase, HarnessSessionPhase::Terminated { .. }) {
            return Vec::new();
        }
        let mut events = Vec::new();
        match msg.state {
            RawDetectedState::Blocked => {
                self.ipc_blocked = true;
                self.pending_idle = None;
                let rule_id = format!("ipc:{}", msg.event);
                let excerpt = msg
                    .detail
                    .as_deref()
                    .map(|d| truncate_chars_tail(d, MAX_EXCERPT_CHARS))
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| {
                        truncate_chars_tail(&self.ring.lines_snapshot().join("\n"), MAX_EXCERPT_CHARS)
                    });
                let payload = ApprovalPromptPayload {
                    prompt_id: uuid::Uuid::now_v7().to_string(),
                    rule_id: rule_id.clone(),
                    matched_excerpt: excerpt,
                    tool_or_command_hint: msg
                        .detail
                        .clone()
                        .unwrap_or_else(|| self.infer_hint()),
                    source: DetectionSourceKind::IpcPush,
                    detected_at_ms: now_ms,
                    timeout_secs: self.approval_timeout_secs,
                };
                self.active_approval = Some(payload.clone());
                events.extend(self.transition(
                    HarnessSessionPhase::AwaitingApproval,
                    &rule_id,
                    now_ms,
                ));
                events.push(PtyEvent::ApprovalRequested {
                    session_id: self.session_id.clone(),
                    payload,
                });
            }
            RawDetectedState::Working => {
                self.ipc_blocked = false;
                self.pending_idle = None;
                self.active_approval = None;
                let target = if self.phase == HarnessSessionPhase::Streaming {
                    HarnessSessionPhase::Streaming
                } else {
                    HarnessSessionPhase::Thinking
                };
                events.extend(self.transition(target, &format!("ipc:{}", msg.event), now_ms));
            }
            RawDetectedState::Idle => {
                self.ipc_blocked = false;
                self.active_approval = None;
                if now_ms.saturating_sub(self.started_at_ms) >= self.profile.profile.startup_grace_ms
                {
                    self.pending_idle = None;
                    events.extend(self.transition(
                        HarnessSessionPhase::CompletedIdle,
                        &format!("ipc:{}", msg.event),
                        now_ms,
                    ));
                } else {
                    events.extend(self.advance_idle_debounce(now_ms));
                }
            }
        }
        events
    }

    /// Periodic debounce check (`100 ms` x `3` ticks, `cap 700 ms`, `startup_grace 3000 ms`).
    pub fn on_tick(&mut self, now_ms: u64) -> Vec<PtyEvent> {
        if !matches!(
            self.phase,
            HarnessSessionPhase::Thinking | HarnessSessionPhase::Streaming
        ) {
            return Vec::new();
        }
        if now_ms.saturating_sub(self.started_at_ms) < self.profile.profile.startup_grace_ms {
            return Vec::new();
        }

        // If any working or blocked rule currently matches, cancel idle confirmation.
        if let Some(matched) = self.profile.evaluate_buffer(&self.ring)
            && matches!(
                matched.state,
                RawDetectedState::Working | RawDetectedState::Blocked
            )
        {
            self.pending_idle = None;
            return Vec::new();
        }

        self.advance_idle_debounce(now_ms)
    }

    /// Idempotently resolve an active [`ApprovalPromptPayload`], returning exact PTY stdin bytes to write.
    ///
    /// # Errors
    /// Returns [`HarnessError::ApprovalAlreadyProcessed`] if `active_approval` is absent or mismatches `prompt_id`.
    pub fn resolve_approval(
        &mut self,
        prompt_id: &str,
        approved: bool,
        custom_response: Option<&[u8]>,
        now_ms: u64,
    ) -> HarnessResult<(Vec<u8>, Vec<PtyEvent>)> {
        let Some(active) = &self.active_approval else {
            return Err(HarnessError::ApprovalAlreadyProcessed {
                prompt_id: prompt_id.to_string(),
            });
        };
        if active.prompt_id != prompt_id {
            return Err(HarnessError::ApprovalAlreadyProcessed {
                prompt_id: prompt_id.to_string(),
            });
        }

        self.active_approval = None;
        self.ipc_blocked = false;
        self.pending_idle = None;
        self.ring.advance_detection_floor();

        let stdin_bytes = if let Some(custom) = custom_response {
            let mut normalized = normalize_pty_stdin(custom);
            if !normalized.ends_with(b"\r") && !normalized.ends_with(b"\n") {
                normalized.push(b'\r');
            }
            normalized
        } else if approved {
            self.profile
                .profile
                .approval_inputs
                .approve_sequence
                .as_bytes()
                .to_vec()
        } else {
            self.profile
                .profile
                .approval_inputs
                .reject_sequence
                .as_bytes()
                .to_vec()
        };

        let reason = if approved {
            "approval_granted"
        } else {
            "approval_rejected"
        };
        let events = self.transition(HarnessSessionPhase::Thinking, reason, now_ms);
        Ok((stdin_bytes, events))
    }

    /// Mark session terminated upon child process exit and emit [`PtyEvent::Exited`].
    pub fn on_process_exit(&mut self, exit_code: Option<i32>, now_ms: u64) -> Vec<PtyEvent> {
        self.pending_idle = None;
        self.active_approval = None;
        self.ipc_blocked = false;

        let mut events = self.transition(
            HarnessSessionPhase::Terminated { exit_code },
            "process_exit",
            now_ms,
        );
        let tail_excerpt =
            truncate_chars_tail(&self.ring.lines_snapshot().join("\n"), MAX_EXCERPT_CHARS);
        events.push(PtyEvent::Exited {
            session_id: self.session_id.clone(),
            exit_code,
            tail_excerpt,
        });
        events
    }

    fn advance_idle_debounce(&mut self, now_ms: u64) -> Vec<PtyEvent> {
        let cfg = self.profile.profile.idle_debounce;
        let updated = match self.pending_idle {
            None => PendingIdleConfirmation {
                first_seen_at_ms: now_ms,
                last_checked_at_ms: now_ms,
                confirmations: 1,
            },
            Some(mut pending) => {
                if now_ms.saturating_sub(pending.last_checked_at_ms) >= cfg.recheck_ms {
                    pending.confirmations = pending.confirmations.saturating_add(1);
                    pending.last_checked_at_ms = now_ms;
                }
                pending
            }
        };

        let elapsed = now_ms.saturating_sub(updated.first_seen_at_ms);
        if updated.confirmations >= cfg.confirmations || elapsed >= cfg.cap_ms {
            self.pending_idle = None;
            return self.transition(HarnessSessionPhase::CompletedIdle, "idle_debounced", now_ms);
        }

        self.pending_idle = Some(updated);
        Vec::new()
    }

    fn transition(
        &mut self,
        to: HarnessSessionPhase,
        reason: &str,
        now_ms: u64,
    ) -> Vec<PtyEvent> {
        if self.phase == to {
            return Vec::new();
        }
        let from = self.phase;
        self.phase = to;
        self.last_state_change_at_ms = now_ms;
        vec![PtyEvent::PhaseChanged {
            session_id: self.session_id.clone(),
            from,
            to,
            reason: reason.to_string(),
            timestamp_ms: now_ms,
        }]
    }

    fn infer_hint(&self) -> String {
        self.ring
            .lines_snapshot()
            .iter()
            .rev()
            .find(|line| !line.trim().is_empty())
            .map(|line| truncate_chars_tail(line.trim(), 120))
            .unwrap_or_else(|| self.profile.profile.id.clone())
    }
}

/// Configuration parameters for spawning a managed sub-agent inside an OS PTY.
#[derive(Debug, Clone)]
pub struct PtySpawnConfig {
    pub session_id: String,
    pub channel_recipient: String,
    pub sulur_scope: String,
    pub workspace_path: PathBuf,
    pub worktree_branch: Option<String>,
    pub program: String,
    pub args: Vec<String>,
    pub extra_env: BTreeMap<String, String>,
    pub rows: u16,
    pub cols: u16,
    pub approval_timeout_secs: u64,
    pub profile: CompiledAgentProfile,
}

/// Live handle owning control channels, event subscriptions, and graceful shutdown for a spawned PTY.
pub struct PtySessionHandle {
    state: Arc<RwLock<PtySessionState>>,
    control_tx: mpsc::Sender<PtyControlCommand>,
    event_tx: broadcast::Sender<PtyEvent>,
    ipc_endpoint: Option<String>,
    cancel: CancellationToken,
}

impl PtySessionHandle {
    /// Spawn a child CLI process inside the platform native PTY (`ConPTY` or `openpty`)
    /// and launch non-blocking reader, IPC listener, and debounce supervisor tasks.
    ///
    /// # Errors
    /// Returns [`HarnessError::Pty`] if PTY allocation or child process spawning fails,
    /// or [`HarnessError::Io`] if binding the optional IPC listener fails.
    pub fn spawn(config: PtySpawnConfig) -> HarnessResult<Self> {
        let cancel = CancellationToken::new();
        let started_at_ms = now_epoch_ms();

        // Bind optional Herdr out-of-band IPC listener (`OpenCode v2`) BEFORE child spawn.
        let mut ipc_listener = if config.profile.profile.ipc_plugin.is_some() {
            Some(HerdrIpcListener::bind(&config.session_id, cancel.child_token())?)
        } else {
            None
        };
        let ipc_endpoint = ipc_listener
            .as_ref()
            .map(|l| l.endpoint_path().to_string());

        let pty_system = native_pty_system();
        let pair = pty_system
            .openpty(PtySize {
                rows: config.rows.max(4),
                cols: config.cols.max(20),
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|err| HarnessError::Pty {
                session_id: config.session_id.clone(),
                reason: err.to_string(),
            })?;

        let mut cmd = CommandBuilder::new(&config.program);
        for arg in &config.profile.profile.default_args {
            cmd.arg(arg);
        }
        for arg in &config.args {
            cmd.arg(arg);
        }
        cmd.cwd(&config.workspace_path);
        for (k, v) in &config.profile.profile.env {
            cmd.env(k, v);
        }
        for (k, v) in &config.extra_env {
            cmd.env(k, v);
        }
        if let (Some(ipc_cfg), Some(endpoint)) = (&config.profile.profile.ipc_plugin, &ipc_endpoint)
        {
            cmd.env(&ipc_cfg.env_flag, "1");
            cmd.env(&ipc_cfg.socket_env_var, endpoint);
            cmd.env(&ipc_cfg.pane_id_env_var, &config.session_id);
        }

        let child = pair
            .slave
            .spawn_command(cmd)
            .map_err(|err| HarnessError::Pty {
                session_id: config.session_id.clone(),
                reason: err.to_string(),
            })?;
        // Critical: drop slave handle immediately in parent so child exit closes master reader with EOF.
        drop(pair.slave);

        let pid = child.process_id();
        let killer = child.clone_killer();
        let reader = pair
            .master
            .try_clone_reader()
            .map_err(|err| HarnessError::Pty {
                session_id: config.session_id.clone(),
                reason: format!("failed cloning PTY reader: {err}"),
            })?;
        let writer = pair
            .master
            .take_writer()
            .map_err(|err| HarnessError::Pty {
                session_id: config.session_id.clone(),
                reason: format!("failed acquiring PTY writer: {err}"),
            })?;

        let master = Arc::new(parking_lot::Mutex::new(pair.master));
        let writer = Arc::new(parking_lot::Mutex::new(writer));
        let killer = Arc::new(parking_lot::Mutex::new(killer));
        let (exit_tx, exit_rx) = oneshot::channel::<Option<i32>>();
        spawn_blocking_child_waiter(child, exit_tx);

        let initial_state = PtySessionState {
            session_id: config.session_id.clone(),
            channel_recipient: config.channel_recipient,
            selected_runtime: SelectedAgentRuntime::DeclarativeCli(config.profile.profile.id.clone()),
            sulur_scope: config.sulur_scope,
            workspace_path: config.workspace_path,
            worktree_branch: config.worktree_branch,
            pid,
            phase: HarnessSessionPhase::Idle,
            pending_idle: None,
            active_approval: None,
            started_at_ms,
            last_output_at_ms: started_at_ms,
            last_state_change_at_ms: started_at_ms,
        };
        let state = Arc::new(RwLock::new(initial_state));

        let (control_tx, control_rx) = mpsc::channel(CONTROL_CHANNEL_CAPACITY);
        let (event_tx, _event_rx) = broadcast::channel(EVENT_BROADCAST_CAPACITY);
        let (raw_tx, raw_rx) = mpsc::channel::<Vec<u8>>(RAW_READ_CHANNEL_CAPACITY);

        spawn_blocking_reader(reader, raw_tx, config.session_id.clone());

        let supervisor_args = SupervisorContext {
            session_id: config.session_id,
            profile: config.profile,
            approval_timeout_secs: config.approval_timeout_secs,
            started_at_ms,
            state: Arc::clone(&state),
            master,
            writer,
            killer,
            exit_rx,
            control_rx,
            raw_rx,
            event_tx: event_tx.clone(),
            cancel: cancel.child_token(),
        };
        let _supervisor = ::zeroclaw_spawn::spawn!(async move {
            run_supervisor(supervisor_args, &mut ipc_listener).await;
        });

        Ok(Self {
            state,
            control_tx,
            event_tx,
            ipc_endpoint,
            cancel,
        })
    }

    /// Sender handle for injecting prompts, resolving approvals, resizing, or terminating.
    #[must_use]
    pub fn control_sender(&self) -> mpsc::Sender<PtyControlCommand> {
        self.control_tx.clone()
    }

    /// Subscribe to stripped output chunks, phase transitions, approval prompts, and exit events.
    #[must_use]
    pub fn subscribe_events(&self) -> broadcast::Receiver<PtyEvent> {
        self.event_tx.subscribe()
    }

    /// Snapshot the current [`PtySessionState`].
    #[must_use]
    pub fn state_snapshot(&self) -> PtySessionState {
        self.state.read().clone()
    }

    /// Out-of-band IPC socket/pipe path exported when the profile configures `ipc_plugin`.
    #[must_use]
    pub fn ipc_endpoint(&self) -> Option<&str> {
        self.ipc_endpoint.as_deref()
    }

    /// Trigger graceful cancellation of this session's supervisor and IPC listener.
    pub fn shutdown(&self) {
        self.cancel.cancel();
    }
}

fn spawn_blocking_reader(
    mut reader: Box<dyn Read + Send>,
    raw_tx: mpsc::Sender<Vec<u8>>,
    session_id: String,
) {
    tokio::task::spawn_blocking(move || {
        let mut buf = [0_u8; 4096];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if raw_tx.blocking_send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
                Err(err) => {
                    ::zeroclaw_log::record!(
                        DEBUG,
                        ::zeroclaw_log::Event::new(
                            "harness.pty.read",
                            ::zeroclaw_log::Action::Fail,
                        )
                        .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                        .with_attrs(::serde_json::json!({
                            "session_id": session_id,
                            "err": err.to_string(),
                        })),
                        "pty blocking reader ended"
                    );
                    break;
                }
            }
        }
    });
}

fn spawn_blocking_child_waiter(
    mut child: Box<dyn portable_pty::Child + Send + Sync>,
    exit_tx: oneshot::Sender<Option<i32>>,
) {
    tokio::task::spawn_blocking(move || {
        let code = child
            .wait()
            .ok()
            .and_then(|status| i32::try_from(status.exit_code()).ok());
        let _ = exit_tx.send(code);
    });
}

struct SupervisorContext {
    session_id: String,
    profile: CompiledAgentProfile,
    approval_timeout_secs: u64,
    started_at_ms: u64,
    state: Arc<RwLock<PtySessionState>>,
    master: Arc<parking_lot::Mutex<Box<dyn MasterPty + Send>>>,
    writer: Arc<parking_lot::Mutex<Box<dyn Write + Send>>>,
    killer: Arc<parking_lot::Mutex<Box<dyn ChildKiller + Send + Sync>>>,
    exit_rx: oneshot::Receiver<Option<i32>>,
    control_rx: mpsc::Receiver<PtyControlCommand>,
    raw_rx: mpsc::Receiver<Vec<u8>>,
    event_tx: broadcast::Sender<PtyEvent>,
    cancel: CancellationToken,
}

async fn run_supervisor(
    mut ctx: SupervisorContext,
    ipc_listener: &mut Option<HerdrIpcListener>,
) {
    let recheck_ms = ctx.profile.profile.idle_debounce.recheck_ms.max(25);
    let mut ticker = tokio::time::interval(Duration::from_millis(recheck_ms));
    let mut sm = HarnessStateMachine::new(
        ctx.session_id.clone(),
        ctx.profile.clone(),
        ctx.started_at_ms,
        ctx.approval_timeout_secs,
    );

    let mut master = Some(ctx.master);
    let mut writer = Some(ctx.writer);
    let mut exit_rx = ctx.exit_rx;
    let known_exit_code: Option<i32>;

    loop {
        tokio::select! {
            () = ctx.cancel.cancelled() => {
                if let Some(ref w) = writer {
                    let interrupt = ctx.profile.profile.approval_inputs.interrupt_sequence.as_bytes().to_vec();
                    let _ = write_pty_blocking(Arc::clone(w), interrupt).await;
                }
                let _ = kill_child_blocking(Arc::clone(&ctx.killer)).await;
                drop(writer.take());
                drop(master.take());
                known_exit_code = tokio::time::timeout(Duration::from_millis(500), &mut exit_rx)
                    .await
                    .ok()
                    .and_then(|res| res.ok())
                    .flatten();
                break;
            }
            chunk = ctx.raw_rx.recv() => match chunk {
                Some(bytes) => {
                    let events = sm.on_pty_bytes(&bytes, now_epoch_ms());
                    if let Some(ref w) = writer {
                        for reply in sm.take_terminal_responses() {
                            let _ = write_pty_blocking(Arc::clone(w), reply).await;
                        }
                    }
                    sync_and_broadcast(&ctx.state, &ctx.event_tx, &sm, events);
                }
                None => {
                    drop(writer.take());
                    drop(master.take());
                    known_exit_code = tokio::time::timeout(Duration::from_millis(500), &mut exit_rx)
                        .await
                        .ok()
                        .and_then(|res| res.ok())
                        .flatten();
                    break;
                }
            },
            exit_res = &mut exit_rx => {
                known_exit_code = exit_res.ok().flatten();
                // Drain buffered output before dropping master (essential on Windows ConPTY:
                // conhost holds the output pipe open until ClosePseudoConsole / MasterPty drop).
                drain_raw_output(&mut ctx.raw_rx, &mut sm, &ctx.state, &ctx.event_tx, Duration::from_millis(80)).await;
                drop(writer.take());
                drop(master.take());
                drain_raw_output(&mut ctx.raw_rx, &mut sm, &ctx.state, &ctx.event_tx, Duration::from_millis(120)).await;
                break;
            }
            ipc_msg = recv_ipc_optional(ipc_listener) => {
                if let Some(msg) = ipc_msg {
                    let events = sm.on_ipc_message(&msg, now_epoch_ms());
                    sync_and_broadcast(&ctx.state, &ctx.event_tx, &sm, events);
                }
            }
            cmd = ctx.control_rx.recv() => match cmd {
                Some(PtyControlCommand::WriteInput(raw)) => {
                    if let Some(ref w) = writer {
                        let normalized = normalize_pty_stdin(&raw);
                        if let Err(err) = write_pty_blocking(Arc::clone(w), normalized).await {
                            ::zeroclaw_log::record!(
                                WARN,
                                ::zeroclaw_log::Event::new(
                                    "harness.pty.write_stdin",
                                    ::zeroclaw_log::Action::Fail,
                                )
                                .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                                .with_attrs(::serde_json::json!({
                                    "session_id": ctx.session_id,
                                    "err": err.to_string(),
                                })),
                                "failed writing PTY stdin"
                            );
                        } else {
                            let events = sm.on_input_sent(now_epoch_ms());
                            sync_and_broadcast(&ctx.state, &ctx.event_tx, &sm, events);
                        }
                    }
                }
                Some(PtyControlCommand::ResolveApproval { prompt_id, approved, custom_response, .. }) => {
                    match sm.resolve_approval(&prompt_id, approved, custom_response.as_deref(), now_epoch_ms()) {
                        Ok((bytes, events)) => {
                            if let Some(ref w) = writer
                                && let Err(err) = write_pty_blocking(Arc::clone(w), bytes).await
                            {
                                ::zeroclaw_log::record!(
                                    WARN,
                                    ::zeroclaw_log::Event::new(
                                        "harness.pty.write_approval",
                                        ::zeroclaw_log::Action::Fail,
                                    )
                                    .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                                    .with_attrs(::serde_json::json!({
                                        "session_id": ctx.session_id,
                                        "err": err.to_string(),
                                    })),
                                    "failed writing approval bytes to PTY"
                                );
                            }
                            sync_and_broadcast(&ctx.state, &ctx.event_tx, &sm, events);
                        }
                        Err(err) => {
                            ::zeroclaw_log::record!(
                                DEBUG,
                                ::zeroclaw_log::Event::new(
                                    "harness.pty.resolve_approval",
                                    ::zeroclaw_log::Action::Skip,
                                )
                                .with_attrs(::serde_json::json!({
                                    "session_id": ctx.session_id,
                                    "err": err.to_string(),
                                })),
                                "ignored duplicate/stale approval"
                            );
                        }
                    }
                }
                Some(PtyControlCommand::Resize { rows, cols }) => {
                    if let Some(ref m) = master {
                        let m_clone = Arc::clone(m);
                        let _ = tokio::task::spawn_blocking(move || {
                            let guard = m_clone.lock();
                            guard.resize(PtySize {
                                rows: rows.max(4),
                                cols: cols.max(20),
                                pixel_width: 0,
                                pixel_height: 0,
                            })
                        }).await;
                    }
                }
                Some(PtyControlCommand::Terminate) => {
                    if let Some(ref w) = writer {
                        let interrupt = ctx.profile.profile.approval_inputs.interrupt_sequence.as_bytes().to_vec();
                        let _ = write_pty_blocking(Arc::clone(w), interrupt).await;
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    let _ = kill_child_blocking(Arc::clone(&ctx.killer)).await;
                    drop(writer.take());
                    drop(master.take());
                    known_exit_code = tokio::time::timeout(Duration::from_millis(500), &mut exit_rx)
                        .await
                        .ok()
                        .and_then(|res| res.ok())
                        .flatten();
                    break;
                }
                None => {}
            },
            _ = ticker.tick() => {
                let events = sm.on_tick(now_epoch_ms());
                sync_and_broadcast(&ctx.state, &ctx.event_tx, &sm, events);
            }
        }
    }

    let events = sm.on_process_exit(known_exit_code, now_epoch_ms());
    sync_and_broadcast(&ctx.state, &ctx.event_tx, &sm, events);
}

async fn drain_raw_output(
    raw_rx: &mut mpsc::Receiver<Vec<u8>>,
    sm: &mut HarnessStateMachine,
    state: &Arc<RwLock<PtySessionState>>,
    event_tx: &broadcast::Sender<PtyEvent>,
    budget: Duration,
) {
    let deadline = tokio::time::sleep(budget);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            () = &mut deadline => break,
            chunk = raw_rx.recv() => match chunk {
                Some(bytes) => {
                    let events = sm.on_pty_bytes(&bytes, now_epoch_ms());
                    sync_and_broadcast(state, event_tx, sm, events);
                }
                None => break,
            }
        }
    }
}

async fn recv_ipc_optional(ipc_listener: &mut Option<HerdrIpcListener>) -> Option<IpcStateMessage> {
    match ipc_listener {
        Some(listener) => listener.receiver_mut().recv().await,
        None => std::future::pending().await,
    }
}

fn sync_and_broadcast(
    state: &Arc<RwLock<PtySessionState>>,
    event_tx: &broadcast::Sender<PtyEvent>,
    sm: &HarnessStateMachine,
    events: Vec<PtyEvent>,
) {
    {
        let mut guard = state.write();
        guard.phase = sm.phase();
        guard.pending_idle = sm.pending_idle();
        guard.active_approval = sm.active_approval().cloned();
        guard.last_output_at_ms = sm.last_output_at_ms();
        guard.last_state_change_at_ms = sm.last_state_change_at_ms();
    }
    for ev in events {
        let _ = event_tx.send(ev);
    }
}

async fn write_pty_blocking(
    writer: Arc<parking_lot::Mutex<Box<dyn Write + Send>>>,
    bytes: Vec<u8>,
) -> std::io::Result<()> {
    tokio::task::spawn_blocking(move || {
        let mut guard = writer.lock();
        guard.write_all(&bytes)?;
        guard.flush()
    })
    .await
    .map_err(std::io::Error::other)?
}

async fn kill_child_blocking(
    killer: Arc<parking_lot::Mutex<Box<dyn ChildKiller + Send + Sync>>>,
) -> std::io::Result<()> {
    tokio::task::spawn_blocking(move || {
        let mut guard = killer.lock();
        guard.kill()
    })
    .await
    .map_err(std::io::Error::other)?
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
