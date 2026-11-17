//! Integration tests for Discord Safeguard approvals, slash/prefix command router,
//! thread-isolated `SessionRegistry`, `git worktree` helpers, mid-turn `/agent` switch policies,
//! timeout fallback, crash one-click restart, and `/handoff` round-trips (`T029`).

use parking_lot::Mutex;
use serde_json::{Value, json};
use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use zeroclaw_api::attribution::{Attributable, ChannelKind, Role};
use zeroclaw_api::channel::{
    ApprovalSource, AttributedApprovalResponse, Channel, ChannelApprovalRequest,
    ChannelApprovalResponse, ChannelMessage, SendMessage,
};
use zeroclaw_config::harness::{
    BriefingBudgetConfig, DreamTriggerConfig, RecallChannelFlags, SidecarMode, SpoolConfig,
    SulurHarnessConfig,
};
use zeroclaw_harness::HarnessError;
use zeroclaw_harness::detector::CompiledProfileRegistry;
use zeroclaw_harness::discord_commands::{
    AgentSwitchOutcome, HandoffSubcommand, HarnessCommand, MidTurnSwitchPolicy, SessionRegistry,
    SessionSubcommand, create_git_worktree, harness_slash_skill_descriptors,
    normalize_discord_root_recipient, parse_harness_command, remove_git_worktree,
    run_discord_event_bridge,
};
use zeroclaw_harness::lifecycle_hooks::SulurLifecycleManager;
use zeroclaw_harness::pty_runner::{
    DetectionSourceKind, HarnessSessionPhase, HarnessStateMachine, PtyControlCommand,
    PtySessionHandle, PtySessionState, PtySpawnConfig, SelectedAgentRuntime,
};
use zeroclaw_harness::sulur_bridge::{
    MAX_FRAME_SIZE, SidecarDescriptor, SulurBridge, WIRE_PROTOCOL_TAG, WireRequest, WireResponse,
    normalize_db_path, sidecar_path,
};

const TEST_TOKEN: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

fn detection_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("zeroclaw root")
        .join("distribution/agent-detection")
}

fn test_sulur_config(db_dir: &Path) -> SulurHarnessConfig {
    SulurHarnessConfig {
        enabled: true,
        db_path: db_dir.to_path_buf(),
        sulur_server_bin: None,
        sidecar_mode: SidecarMode::ExternalOnly,
        default_scope: "ws:memory:zeroclaw".to_string(),
        agent_detection_dir: detection_dir(),
        connect_timeout_ms: 500,
        request_timeout_ms: 1_500,
        briefing_budget: BriefingBudgetConfig::default(),
        recall_channels: RecallChannelFlags::default(),
        spool: SpoolConfig::default(),
        dream_trigger: DreamTriggerConfig::default(),
        approval_timeout_secs: 900,
    }
}

#[derive(Debug, Clone)]
enum ScriptedApproval {
    Respond(AttributedApprovalResponse),
    DelayThenTimeout(Duration),
}

struct MockDiscordChannel {
    alias: String,
    sent_messages: Arc<Mutex<Vec<SendMessage>>>,
    approval_requests: Arc<Mutex<Vec<(String, ChannelApprovalRequest)>>>,
    scripted_approvals: Arc<Mutex<VecDeque<ScriptedApproval>>>,
}

impl MockDiscordChannel {
    fn new(scripted: Vec<ScriptedApproval>) -> Self {
        Self {
            alias: "discord-test".to_string(),
            sent_messages: Arc::new(Mutex::new(Vec::new())),
            approval_requests: Arc::new(Mutex::new(Vec::new())),
            scripted_approvals: Arc::new(Mutex::new(scripted.into())),
        }
    }

    fn sent_messages(&self) -> Vec<SendMessage> {
        self.sent_messages.lock().clone()
    }

    fn approval_requests(&self) -> Vec<(String, ChannelApprovalRequest)> {
        self.approval_requests.lock().clone()
    }
}

impl Attributable for MockDiscordChannel {
    fn role(&self) -> Role {
        Role::Channel(ChannelKind::Discord)
    }

    fn alias(&self) -> &str {
        &self.alias
    }
}

#[async_trait::async_trait]
impl Channel for MockDiscordChannel {
    fn name(&self) -> &str {
        "discord"
    }

    async fn send(&self, message: &SendMessage) -> anyhow::Result<()> {
        self.sent_messages.lock().push(message.clone());
        Ok(())
    }

    async fn listen(&self, _tx: mpsc::Sender<ChannelMessage>) -> anyhow::Result<()> {
        Ok(())
    }

    async fn request_approval(
        &self,
        _recipient: &str,
        _request: &ChannelApprovalRequest,
    ) -> anyhow::Result<Option<ChannelApprovalResponse>> {
        Ok(None)
    }

    async fn request_approval_attributed_with_timeout(
        &self,
        recipient: &str,
        request: &ChannelApprovalRequest,
        timeout: Duration,
    ) -> anyhow::Result<Option<AttributedApprovalResponse>> {
        self.approval_requests
            .lock()
            .push((recipient.to_string(), request.clone()));

        let next = self.scripted_approvals.lock().pop_front();
        match next {
            Some(ScriptedApproval::Respond(resp)) => Ok(Some(resp)),
            Some(ScriptedApproval::DelayThenTimeout(wait_for)) => {
                if wait_for > timeout {
                    tokio::time::sleep(timeout).await;
                    Ok(Some(AttributedApprovalResponse::from_runtime(
                        ChannelApprovalResponse::Deny,
                        ApprovalSource::TimedOut,
                    )))
                } else {
                    tokio::time::sleep(wait_for).await;
                    Ok(Some(AttributedApprovalResponse::from_runtime(
                        ChannelApprovalResponse::Deny,
                        ApprovalSource::TimedOut,
                    )))
                }
            }
            None => Ok(None),
        }
    }
}

async fn spawn_mock_sulur_server(
    db_path: &Path,
) -> (u16, Arc<Mutex<Vec<WireRequest>>>, oneshot::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock sulur-server");
    let port = listener.local_addr().expect("local addr").port();
    let recorded = Arc::new(Mutex::new(Vec::<WireRequest>::new()));
    let recorded_clone = Arc::clone(&recorded);
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

    let sc_path = sidecar_path(&db_path.to_string_lossy());
    let descriptor = SidecarDescriptor {
        pid: std::process::id(),
        port,
        host: "127.0.0.1".to_string(),
        token: TEST_TOKEN.to_string(),
        db_path: normalize_db_path(&db_path.to_string_lossy()),
        protocol: WIRE_PROTOCOL_TAG.to_string(),
        started_at: 1_763_210_000.0,
    };
    std::fs::write(
        &sc_path,
        serde_json::to_string_pretty(&descriptor).expect("serialize descriptor"),
    )
    .expect("write .daemon.json");

    zeroclaw_spawn::spawn!(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                accepted = listener.accept() => {
                    let Ok((mut stream, _)) = accepted else { break; };
                    let rec = Arc::clone(&recorded_clone);
                    zeroclaw_spawn::spawn!(async move {
                        let mut len_buf = [0_u8; 4];
                        if stream.read_exact(&mut len_buf).await.is_err() {
                            return;
                        }
                        let len = usize::try_from(u32::from_le_bytes(len_buf)).unwrap_or(0);
                        if len == 0 || len > MAX_FRAME_SIZE {
                            return;
                        }
                        let mut body = vec![0_u8; len];
                        if stream.read_exact(&mut body).await.is_err() {
                            return;
                        }
                        let Ok(req) = serde_json::from_slice::<WireRequest>(&body) else {
                            return;
                        };
                        rec.lock().push(req.clone());
                        let resp = build_mock_sulur_response(&req);
                        let bytes = serde_json::to_vec(&resp).unwrap_or_default();
                        let _ = stream
                            .write_all(&(u32::try_from(bytes.len()).unwrap_or(0)).to_le_bytes())
                            .await;
                        let _ = stream.write_all(&bytes).await;
                        let _ = stream.flush().await;
                    });
                }
            }
        }
    });

    (port, recorded, shutdown_tx)
}

fn build_mock_sulur_response(req: &WireRequest) -> WireResponse {
    let cols = vec![
        "ticket_id".into(),
        "scope".into(),
        "milestone".into(),
        "unblocked_next_steps".into(),
        "modified_files".into(),
        "status".into(),
        "offered_by".into(),
        "claimed_by".into(),
        "created_at".into(),
        "claimed_at".into(),
    ];

    match req.op.as_deref() {
        Some("ping") => WireResponse {
            success: true,
            message: Some("pong".into()),
            error_message: None,
            column_names: vec![],
            rows: vec![],
            stats: None,
            results: None,
            explanation: None,
        },
        Some("remember") => WireResponse {
            success: true,
            message: Some("recorded".into()),
            error_message: None,
            column_names: vec![],
            rows: vec![],
            stats: None,
            results: None,
            explanation: None,
        },
        Some("handoff_begin") => WireResponse {
            success: true,
            message: None,
            error_message: None,
            column_names: cols,
            rows: vec![vec![
                Some(Value::String("hf_discord_01".into())),
                Some(Value::String("ws:memory:zeroclaw".into())),
                Some(Value::String(
                    req.params
                        .as_ref()
                        .and_then(|p| p.get("milestone"))
                        .and_then(Value::as_str)
                        .unwrap_or("Handed off")
                        .into(),
                )),
                Some(Value::String(r#"["Open in Zed IDE"]"#.into())),
                Some(Value::String("[]".into())),
                Some(Value::String("offered".into())),
                Some(Value::String("opencode".into())),
                None,
                Some(json!(1_763_210_100_i64)),
                None,
            ]],
            stats: None,
            results: None,
            explanation: None,
        },
        Some("handoff_list") => WireResponse {
            success: true,
            message: None,
            error_message: None,
            column_names: cols,
            rows: vec![vec![
                Some(Value::String("hf_zed_09".into())),
                Some(Value::String("ws:memory:zeroclaw".into())),
                Some(Value::String("Resume Zed refactor in Discord".into())),
                Some(Value::String(r#"["Run cargo test"]"#.into())),
                Some(Value::String(r#"["discord_commands.rs"]"#.into())),
                Some(Value::String("offered".into())),
                Some(Value::String("zed".into())),
                None,
                Some(json!(1_763_210_050_i64)),
                None,
            ]],
            stats: None,
            results: None,
            explanation: None,
        },
        Some("handoff_accept") => WireResponse {
            success: true,
            message: None,
            error_message: None,
            column_names: cols,
            rows: vec![vec![
                Some(Value::String("hf_zed_09".into())),
                Some(Value::String("ws:memory:zeroclaw".into())),
                Some(Value::String("Resume Zed refactor in Discord".into())),
                Some(Value::String(r#"["Run cargo test"]"#.into())),
                Some(Value::String(r#"["discord_commands.rs"]"#.into())),
                Some(Value::String("claimed".into())),
                Some(Value::String("zed".into())),
                Some(Value::String("sess-thread-1".into())),
                Some(json!(1_763_210_050_i64)),
                Some(json!(1_763_210_200_i64)),
            ]],
            stats: None,
            results: None,
            explanation: None,
        },
        _ => WireResponse {
            success: true,
            message: None,
            error_message: None,
            column_names: vec![],
            rows: vec![],
            stats: None,
            results: None,
            explanation: None,
        },
    }
}

fn mock_approval_pty_command() -> (String, Vec<String>) {
    #[cfg(windows)]
    {
        let script = concat!(
            "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new(); ",
            "Write-Host (\"$([char]27)[36mThinking... esc to interrupt$([char]27)[0m\"); ",
            "Start-Sleep -Milliseconds 80; ",
            "Write-Host (\"$([char]0x25B3) Permission required: edit main.rs\"); ",
            "$ans = [Console]::In.ReadLine(); ",
            "if ($ans -eq 'y') { Write-Host 'DISCORD_BRIDGE_APPROVED_OK' } else { Write-Host ('DENIED:' + $ans) }"
        );
        (
            "powershell.exe".to_string(),
            vec![
                "-NoLogo".to_string(),
                "-NoProfile".to_string(),
                "-Command".to_string(),
                script.to_string(),
            ],
        )
    }
    #[cfg(unix)]
    {
        let script = r#"printf "\033[36mThinking... esc to interrupt\033[0m\n"; sleep 0.08; printf "△ Permission required: edit main.rs\n"; IFS= read -r ans; if [ "$ans" = "y" ]; then printf "DISCORD_BRIDGE_APPROVED_OK\n"; else printf "DENIED:%s\n" "$ans"; fi"#;
        (
            "/bin/sh".to_string(),
            vec!["-c".to_string(), script.to_string()],
        )
    }
}

fn sample_session_state(
    session_id: &str,
    recipient: &str,
    runtime: SelectedAgentRuntime,
    phase: HarnessSessionPhase,
    workspace: &Path,
) -> PtySessionState {
    PtySessionState {
        session_id: session_id.to_string(),
        channel_recipient: recipient.to_string(),
        selected_runtime: runtime,
        sulur_scope: "ws:memory:zeroclaw".to_string(),
        workspace_path: workspace.to_path_buf(),
        worktree_branch: None,
        pid: None,
        phase,
        pending_idle: None,
        active_approval: None,
        started_at_ms: 1_000,
        last_output_at_ms: 1_000,
        last_state_change_at_ms: 1_000,
    }
}

#[tokio::test]
async fn approval_roundtrip_bridges_thread_to_root_channel_under_one_second() {
    let registry_profiles =
        CompiledProfileRegistry::load_from_dir(&detection_dir()).expect("load profiles");
    let opencode = registry_profiles
        .resolve("opencode")
        .expect("opencode")
        .clone();
    let (program, args) = mock_approval_pty_command();

    let handle = PtySessionHandle::spawn(PtySpawnConfig {
        session_id: "disc-sess-approve".to_string(),
        channel_recipient: "123456:thread-999".to_string(),
        sulur_scope: "ws:memory:zeroclaw".to_string(),
        workspace_path: std::env::temp_dir(),
        worktree_branch: None,
        program,
        args,
        extra_env: BTreeMap::new(),
        rows: 24,
        cols: 80,
        approval_timeout_secs: 60,
        profile: opencode,
    })
    .expect("spawn PTY");

    let channel = Arc::new(MockDiscordChannel::new(vec![ScriptedApproval::Respond(
        AttributedApprovalResponse::operator(ChannelApprovalResponse::Approve),
    )]));
    let session_registry = SessionRegistry::new();
    session_registry.register_session(handle.state_snapshot(), Some(handle.control_sender()));

    let mut observer_rx = handle.subscribe_events();
    let bridge_rx = handle.subscribe_events();
    let bridge_channel: Arc<dyn Channel> = Arc::clone(&channel) as Arc<dyn Channel>;
    let bridge_registry = session_registry.clone();
    let ctrl = handle.control_sender();

    let bridge_task = zeroclaw_spawn::spawn!(async move {
        run_discord_event_bridge(
            bridge_channel,
            "123456:thread-999".to_string(),
            "ws:memory:zeroclaw".to_string(),
            ctrl,
            bridge_rx,
            Some(bridge_registry),
            None,
        )
        .await;
    });

    let mut approval_requested_at: Option<Instant> = None;
    let mut roundtrip_elapsed: Option<Duration> = None;
    let mut saw_approved_ok = false;

    let deadline = tokio::time::sleep(Duration::from_secs(10));
    tokio::pin!(deadline);

    loop {
        tokio::select! {
            () = &mut deadline => panic!("timed out waiting for Discord approval bridge roundtrip"),
            ev = observer_rx.recv() => match ev {
                Ok(zeroclaw_harness::pty_runner::PtyEvent::ApprovalRequested { .. }) => {
                    approval_requested_at = Some(Instant::now());
                }
                Ok(zeroclaw_harness::pty_runner::PtyEvent::OutputChunk { stripped_text, .. }) => {
                    if stripped_text.contains("DISCORD_BRIDGE_APPROVED_OK") {
                        saw_approved_ok = true;
                        if let Some(t0) = approval_requested_at {
                            roundtrip_elapsed = Some(t0.elapsed());
                        }
                    }
                }
                Ok(zeroclaw_harness::pty_runner::PtyEvent::Exited { exit_code, .. }) => {
                    assert_eq!(exit_code, Some(0));
                    break;
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
    }

    drop(handle);
    let _ = tokio::time::timeout(Duration::from_secs(2), bridge_task).await;

    assert!(
        saw_approved_ok,
        "PTY did not observe DISCORD_BRIDGE_APPROVED_OK"
    );
    let elapsed = roundtrip_elapsed.expect("approval latency measured");
    assert!(
        elapsed < Duration::from_secs(1),
        "SC-005 breach: approval round-trip took {elapsed:?}"
    );

    let reqs = channel.approval_requests();
    assert_eq!(reqs.len(), 1);
    assert_eq!(
        reqs[0].0, "123456",
        "Safeguard prompt must strip `:thread` suffix and target root channel"
    );
    assert!(
        reqs[0].1.arguments_summary.contains("Permission required"),
        "expected excerpt forwarded in ChannelApprovalRequest"
    );
}

#[tokio::test]
async fn duplicate_resolve_approval_is_idempotent_with_approval_already_processed() {
    let registry_profiles =
        CompiledProfileRegistry::load_from_dir(&detection_dir()).expect("load profiles");
    let opencode = registry_profiles
        .resolve("opencode")
        .expect("opencode")
        .clone();
    let mut sm = HarnessStateMachine::new("idemp-1".into(), opencode, 1_000, 900);

    let events = sm.on_pty_bytes(
        b"\xe2\x96\xb3 Permission required: write Cargo.toml\n",
        1_100,
    );
    let prompt_id = events
        .iter()
        .find_map(|ev| match ev {
            zeroclaw_harness::pty_runner::PtyEvent::ApprovalRequested { payload, .. } => {
                Some(payload.prompt_id.clone())
            }
            _ => None,
        })
        .expect("approval prompt emitted");

    let (bytes, _) = sm
        .resolve_approval(&prompt_id, true, None, 1_200)
        .expect("first resolve succeeds");
    assert_eq!(bytes, b"y\r");

    let dup_err = sm
        .resolve_approval(&prompt_id, true, None, 1_250)
        .expect_err("second click must fail cleanly");
    assert!(
        matches!(dup_err, HarnessError::ApprovalAlreadyProcessed { .. }),
        "expected ApprovalAlreadyProcessed, got {dup_err:?}"
    );
}

#[tokio::test]
async fn timeout_notice_and_crash_one_click_restart_reach_discord_and_sulur() {
    let temp = TempDir::new().expect("temp dir");
    let db_dir = temp.path().join("sulur-db");
    std::fs::create_dir_all(&db_dir).expect("create db dir");
    let (_port, recorded, shutdown_tx) = spawn_mock_sulur_server(&db_dir).await;

    let sulur_cfg = test_sulur_config(&db_dir);
    let mgr = Arc::new(SulurLifecycleManager::new(Arc::new(SulurBridge::new(
        sulur_cfg,
    ))));

    let channel = Arc::new(MockDiscordChannel::new(vec![
        ScriptedApproval::DelayThenTimeout(Duration::from_millis(20)),
    ]));
    let session_registry = SessionRegistry::new();
    let sess = sample_session_state(
        "crash-sess-1",
        "chan-77:thread-5",
        SelectedAgentRuntime::DeclarativeCli("opencode".into()),
        HarnessSessionPhase::AwaitingApproval,
        temp.path(),
    );
    session_registry.register_session(sess, None);

    let (ctrl_tx, mut ctrl_rx) = mpsc::channel::<PtyControlCommand>(8);
    let (ev_tx, ev_rx) = tokio::sync::broadcast::channel(16);

    let bridge_channel: Arc<dyn Channel> = Arc::clone(&channel) as Arc<dyn Channel>;
    let bridge_registry = session_registry.clone();
    let bridge_mgr = Arc::clone(&mgr);

    let bridge_task = zeroclaw_spawn::spawn!(async move {
        run_discord_event_bridge(
            bridge_channel,
            "chan-77:thread-5".to_string(),
            "ws:memory:zeroclaw".to_string(),
            ctrl_tx,
            ev_rx,
            Some(bridge_registry),
            Some(bridge_mgr),
        )
        .await;
    });

    ev_tx
        .send(zeroclaw_harness::pty_runner::PtyEvent::ApprovalRequested {
            session_id: "crash-sess-1".into(),
            payload: zeroclaw_harness::pty_runner::ApprovalPromptPayload {
                prompt_id: "prm-timeout-1".into(),
                rule_id: "permission_box".into(),
                matched_excerpt: "Permission required".into(),
                tool_or_command_hint: "opencode".into(),
                source: DetectionSourceKind::PtyRegex,
                detected_at_ms: 1_000,
                timeout_secs: 1,
            },
        })
        .expect("send approval request");

    let resolved_cmd = tokio::time::timeout(Duration::from_secs(2), ctrl_rx.recv())
        .await
        .expect("timed out waiting for ResolveApproval")
        .expect("control command received");
    assert!(matches!(
        resolved_cmd,
        PtyControlCommand::ResolveApproval {
            approved: false,
            ..
        }
    ));

    // Wait briefly for timeout notice and phase transition before sending crash exit.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        session_registry
            .active_session_for("chan-77:thread-5")
            .expect("session tracked")
            .phase,
        HarnessSessionPhase::CompletedIdle
    );

    ev_tx
        .send(zeroclaw_harness::pty_runner::PtyEvent::Exited {
            session_id: "crash-sess-1".into(),
            exit_code: Some(42),
            tail_excerpt: "panic: segmentation fault in subagent".into(),
        })
        .expect("send exited event");
    drop(ev_tx);

    let _ = tokio::time::timeout(Duration::from_secs(3), bridge_task).await;

    let sent = channel.sent_messages();
    assert!(
        sent.iter().any(|m| m.recipient == "chan-77:thread-5"
            && m.content.contains("Approval prompt timed out")),
        "missing timeout notice in {sent:#?}"
    );
    assert!(
        sent.iter().any(|m| m.recipient == "chan-77:thread-5"
            && m.content.contains("**One-Click Restart**")
            && m.content.contains("/session create")),
        "missing One-Click Restart notice in {sent:#?}"
    );

    let wire_reqs = recorded.lock().clone();
    assert!(
        wire_reqs.iter().any(|r| {
            r.op.as_deref() == Some("remember")
                && (r.query.contains("terminated") || r.query.contains("exited"))
        }),
        "crash exit failed to log summary to Sulur: {wire_reqs:#?}"
    );

    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn command_parser_slash_descriptors_mid_turn_policies_worktree_and_handoff_work() {
    // 1. Slash skill descriptors
    let descriptors = harness_slash_skill_descriptors();
    let names: Vec<&str> = descriptors.iter().map(|d| d.name.as_str()).collect();
    assert_eq!(names, vec!["agent", "session", "handoff"]);
    assert!(
        descriptors
            .iter()
            .all(|d| d.tags.contains(&"slash".to_string()))
    );

    // 2. Canonical `/cmd` and `!cmd` parity
    assert_eq!(
        parse_harness_command("/agent opencode").expect("parse"),
        parse_harness_command("!agent opencode").expect("parse")
    );
    assert_eq!(
        parse_harness_command("/agent zeroclaw-native queue").expect("parse"),
        Some(HarnessCommand::Agent {
            runtime: SelectedAgentRuntime::NativeZeroClaw,
            mid_turn_policy: Some(MidTurnSwitchPolicy::QueueNextTurn),
        })
    );
    assert_eq!(
        parse_harness_command("!session worktree feat/harness-40").expect("parse"),
        Some(HarnessCommand::Session(SessionSubcommand::Worktree {
            branch: "feat/harness-40".into()
        }))
    );
    assert_eq!(
        parse_harness_command("/handoff create Phase 4 done").expect("parse"),
        Some(HarnessCommand::Handoff(HandoffSubcommand::Create {
            milestone: Some("Phase 4 done".into())
        }))
    );
    assert!(
        parse_harness_command("hello normal prompt")
            .expect("non-cmd")
            .is_none()
    );
    assert!(parse_harness_command("/agent").is_err());
    assert_eq!(
        normalize_discord_root_recipient("999000:thread-123"),
        "999000"
    );

    // 3. Thread isolation & mid-turn `/agent` switch policy
    let temp = TempDir::new().expect("temp");
    let reg = SessionRegistry::new();
    let (ctrl_tx, mut ctrl_rx) = mpsc::channel::<PtyControlCommand>(4);
    reg.register_session(
        sample_session_state(
            "s-thread-a",
            "chan:thread-a",
            SelectedAgentRuntime::DeclarativeCli("opencode".into()),
            HarnessSessionPhase::Thinking,
            temp.path(),
        ),
        Some(ctrl_tx),
    );
    reg.register_session(
        sample_session_state(
            "s-thread-b",
            "chan:thread-b",
            SelectedAgentRuntime::DeclarativeCli("agy".into()),
            HarnessSessionPhase::Idle,
            temp.path(),
        ),
        None,
    );

    // Unconfirmed mid-turn switch requests explicit confirmation
    let confirm = reg
        .switch_agent_runtime(
            "chan:thread-a",
            SelectedAgentRuntime::DeclarativeCli("agy".into()),
            None,
        )
        .await
        .expect("switch");
    assert!(matches!(
        confirm,
        AgentSwitchOutcome::ConfirmationRequired { .. }
    ));

    // Queued mid-turn switch applies on `CompletedIdle` without touching thread-b
    let queued = reg
        .switch_agent_runtime(
            "chan:thread-a",
            SelectedAgentRuntime::NativeZeroClaw,
            Some(MidTurnSwitchPolicy::QueueNextTurn),
        )
        .await
        .expect("queue");
    assert!(matches!(
        queued,
        AgentSwitchOutcome::QueuedForNextTurn { .. }
    ));
    assert_eq!(
        reg.active_session_for("chan:thread-a")
            .expect("a")
            .selected_runtime,
        SelectedAgentRuntime::DeclarativeCli("opencode".into())
    );
    reg.update_phase("s-thread-a", HarnessSessionPhase::CompletedIdle);
    assert_eq!(
        reg.active_session_for("chan:thread-a")
            .expect("a")
            .selected_runtime,
        SelectedAgentRuntime::NativeZeroClaw
    );

    // Confirm-cancel mid-turn sends `Terminate` immediately
    reg.update_phase("s-thread-a", HarnessSessionPhase::Streaming);
    let cancelled = reg
        .switch_agent_runtime(
            "chan:thread-a",
            SelectedAgentRuntime::DeclarativeCli("agy".into()),
            Some(MidTurnSwitchPolicy::ConfirmCancelAndSwitch),
        )
        .await
        .expect("confirm cancel");
    assert!(matches!(cancelled, AgentSwitchOutcome::SwitchedNow { .. }));
    assert_eq!(
        ctrl_rx.try_recv().expect("terminate sent"),
        PtyControlCommand::Terminate
    );
    assert_eq!(
        reg.active_session_for("chan:thread-b")
            .expect("b unchanged")
            .selected_runtime,
        SelectedAgentRuntime::DeclarativeCli("agy".into())
    );

    // 4. Isolated `git worktree` create & remove on temporary git repository
    let repo_dir = temp.path().join("repo");
    std::fs::create_dir_all(&repo_dir).expect("mkdir repo");
    assert!(
        Command::new("git")
            .args(["init"])
            .current_dir(&repo_dir)
            .output()
            .expect("git init")
            .status
            .success()
    );
    let commit_out = Command::new("git")
        .args([
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.com",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--allow-empty",
            "-m",
            "chore(test): seed initial commit for git worktree isolation test",
        ])
        .current_dir(&repo_dir)
        .output()
        .expect("git commit");
    assert!(
        commit_out.status.success(),
        "git commit failed: {}",
        String::from_utf8_lossy(&commit_out.stderr)
    );
    let wt_dir = temp.path().join("wt-thread-a");
    let created_wt = create_git_worktree(&repo_dir, &wt_dir, "feat/thread-a")
        .await
        .expect("create git worktree");
    assert!(created_wt.join(".git").exists());
    remove_git_worktree(&repo_dir, &wt_dir)
        .await
        .expect("remove git worktree");
    assert!(!wt_dir.exists());

    // 5. `/handoff create` and `/handoff claim` against mock Sulur TCP wire
    let db_dir = temp.path().join("sulur-handoff-db");
    std::fs::create_dir_all(&db_dir).expect("mkdir db");
    let (_port, recorded, shutdown_tx) = spawn_mock_sulur_server(&db_dir).await;
    let mgr = SulurLifecycleManager::new(Arc::new(SulurBridge::new(test_sulur_config(&db_dir))));

    let created_msg = reg
        .handle_handoff_command(
            "chan:thread-b",
            HandoffSubcommand::Create {
                milestone: Some("Ready for Zed review".into()),
            },
            &mgr,
        )
        .await
        .expect("handoff create");
    assert!(created_msg.contains("hf_discord_01"));

    let claimed_msg = reg
        .handle_handoff_command(
            "chan:thread-b",
            HandoffSubcommand::Claim { ticket_id: None },
            &mgr,
        )
        .await
        .expect("handoff claim");
    assert!(claimed_msg.contains("hf_zed_09"));

    let ops: Vec<Option<String>> = recorded.lock().iter().map(|r| r.op.clone()).collect();
    assert!(ops.contains(&Some("handoff_begin".into())));
    assert!(ops.contains(&Some("handoff_list".into())));
    assert!(ops.contains(&Some("handoff_accept".into())));

    let _ = shutdown_tx.send(());
}
