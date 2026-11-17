//! TDD state machine tests for dual-channel `IPC > Regex`, debounce suppression,
//! OpenCode v2 and `agy` CLI transitions, and memory-bounded ANSI bursting (`T014`).

use std::path::PathBuf;
use zeroclaw_api::lifecycle::LifecycleActivity;
use zeroclaw_harness::HarnessError;
use zeroclaw_harness::detector::{
    CompiledProfileRegistry, IpcStateMessage, MAX_EXCERPT_CHARS, MAX_RING_BYTES, MAX_RING_LINES,
    RawDetectedState,
};
use zeroclaw_harness::pty_runner::{
    DetectionSourceKind, HarnessSessionPhase, HarnessStateMachine, PtyEvent,
};

fn detection_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("zeroclaw root")
        .join("distribution/agent-detection")
}

#[test]
fn maps_session_phases_to_zeroclaw_lifecycle_activity() {
    assert_eq!(
        HarnessSessionPhase::Idle.to_lifecycle_activity(),
        LifecycleActivity::Idle
    );
    assert_eq!(
        HarnessSessionPhase::Thinking.to_lifecycle_activity(),
        LifecycleActivity::Turn
    );
    assert_eq!(
        HarnessSessionPhase::Streaming.to_lifecycle_activity(),
        LifecycleActivity::Tool
    );
    assert_eq!(
        HarnessSessionPhase::AwaitingApproval.to_lifecycle_activity(),
        LifecycleActivity::Approval
    );
    assert_eq!(
        HarnessSessionPhase::CompletedIdle.to_lifecycle_activity(),
        LifecycleActivity::Finished
    );
    assert_eq!(
        HarnessSessionPhase::Terminated { exit_code: Some(1) }.to_lifecycle_activity(),
        LifecycleActivity::Finished
    );
}

#[test]
fn suppresses_false_idle_until_debounce_and_startup_grace_elapse() {
    let registry = CompiledProfileRegistry::load_from_dir(&detection_dir()).expect("load profiles");
    let opencode = registry.resolve("opencode").expect("opencode").clone();

    let mut sm = HarnessStateMachine::new("sess-debounce".into(), opencode, 0, 900);
    assert_eq!(sm.phase(), HarnessSessionPhase::Idle);

    // Trigger active working state at t = 100 ms
    let events = sm.on_pty_bytes(b"\x1b[36mesc to interrupt\x1b[0m\r\n", 100);
    assert_eq!(sm.phase(), HarnessSessionPhase::Thinking);
    assert!(events.iter().any(|e| matches!(
        e,
        PtyEvent::PhaseChanged {
            to: HarnessSessionPhase::Thinking,
            ..
        }
    )));

    // Within startup_grace_ms (3000ms), clear ring to non-working lines and tick 3x100ms:
    // MUST stay Thinking (never settle CompletedIdle prematurely inside 3000ms startup grace).
    for _ in 0..64 {
        sm.on_pty_bytes(b"ordinary output line without spinner\r\n", 500);
    }
    for tick_t in [600_u64, 700, 800, 900, 1_500] {
        sm.on_tick(tick_t);
        assert_eq!(
            sm.phase(),
            HarnessSessionPhase::Thinking,
            "must remain active within 3000ms startup grace at t={tick_t}"
        );
    }

    // Past startup grace (t = 3_100): re-arm working hint then let it disappear cleanly.
    sm.on_pty_bytes(
        b"progress: \xE2\x96\xA0\xE2\x96\xA0\xE2\x96\xA0\xE2\x96\xA0\r\n",
        3_100,
    );
    assert_eq!(sm.phase(), HarnessSessionPhase::Streaming);

    // Flush the 64 lines so no working rule matches anymore.
    for _ in 0..64 {
        sm.on_pty_bytes(b"done writing line\r\n", 3_200);
    }

    // 1st check -> PendingIdleConfirmation(1)
    sm.on_tick(3_300);
    assert_eq!(sm.phase(), HarnessSessionPhase::Streaming);
    assert_eq!(sm.pending_idle().map(|p| p.confirmations), Some(1));

    // 2nd check -> PendingIdleConfirmation(2)
    sm.on_tick(3_400);
    assert_eq!(sm.phase(), HarnessSessionPhase::Streaming);
    assert_eq!(sm.pending_idle().map(|p| p.confirmations), Some(2));

    // Mid-debounce flicker: working indicator returns -> cancels pending idle!
    sm.on_pty_bytes(b"esc to interrupt\r\n", 3_450);
    assert_eq!(sm.pending_idle(), None);
    assert_eq!(sm.phase(), HarnessSessionPhase::Thinking);

    // Clear lines again and run 3 consecutive 100ms ticks cleanly -> settles to CompletedIdle!
    for _ in 0..64 {
        sm.on_pty_bytes(b"final summary line\r\n", 3_500);
    }
    sm.on_tick(3_600);
    sm.on_tick(3_700);
    assert_eq!(sm.phase(), HarnessSessionPhase::Thinking);
    let settled = sm.on_tick(3_800);
    assert_eq!(sm.phase(), HarnessSessionPhase::CompletedIdle);
    assert!(settled.iter().any(|e| matches!(
        e,
        PtyEvent::PhaseChanged {
            to: HarnessSessionPhase::CompletedIdle,
            ..
        }
    )));
}

#[test]
fn ipc_push_precedes_pty_regex_and_idempotently_resolves_approval() {
    let registry = CompiledProfileRegistry::load_from_dir(&detection_dir()).expect("load profiles");
    let opencode = registry.resolve("opencode").expect("opencode").clone();
    let mut sm = HarnessStateMachine::new("sess-opencode".into(), opencode, 0, 900);

    // Child emits PTY working text AND buffered working state
    sm.on_pty_bytes(b"Thinking... esc to interrupt\r\n", 200);
    assert_eq!(sm.phase(), HarnessSessionPhase::Thinking);

    // IPC permission.asked arrives while PTY still only shows working text -> IPC > Regex wins!
    let ipc = IpcStateMessage {
        pane_id: "sess-opencode".into(),
        state: RawDetectedState::Blocked,
        event: "permission.asked".into(),
        ts: Some(500),
        detail: Some("Run `cargo test -p zeroclaw-harness`?".into()),
        agent_session_id: None,
    };
    let events = sm.on_ipc_message(&ipc, 500);
    assert_eq!(sm.phase(), HarnessSessionPhase::AwaitingApproval);

    let payload = sm
        .active_approval()
        .expect("active approval populated")
        .clone();
    assert_eq!(payload.source, DetectionSourceKind::IpcPush);
    assert_eq!(payload.rule_id, "ipc:permission.asked");
    assert!(
        events
            .iter()
            .any(|e| matches!(e, PtyEvent::ApprovalRequested { .. }))
    );

    // First approval resolution sends OpenCode approve_sequence "y\r"
    let (bytes, res_events) = sm
        .resolve_approval(&payload.prompt_id, true, None, 600)
        .expect("first approval succeeds");
    assert_eq!(bytes, b"y\r");
    assert_eq!(sm.phase(), HarnessSessionPhase::Thinking);
    assert!(sm.active_approval().is_none());
    assert!(res_events.iter().any(|e| matches!(
        e,
        PtyEvent::PhaseChanged {
            from: HarnessSessionPhase::AwaitingApproval,
            to: HarnessSessionPhase::Thinking,
            ..
        }
    )));

    // Duplicate resolution with same prompt_id fails idempotently
    let dup = sm.resolve_approval(&payload.prompt_id, true, None, 650);
    assert!(matches!(
        dup,
        Err(HarnessError::ApprovalAlreadyProcessed { .. })
    ));
}

#[test]
fn agy_non_ipc_profile_detects_bottom_region_and_caps_excerpt_and_ring() {
    let registry = CompiledProfileRegistry::load_from_dir(&detection_dir()).expect("load profiles");
    let agy = registry.resolve("agy").expect("agy").clone();
    let mut sm = HarnessStateMachine::new("sess-agy".into(), agy, 0, 900);

    // Flood > 256 KiB of heavy ANSI output first
    for i in 0..1_500 {
        let chunk = format!(
            "\x1b[38;5;45magy step {i:04}: {}\x1b[0m\r\n",
            "y".repeat(256)
        );
        sm.on_pty_bytes(chunk.as_bytes(), 1_000);
    }
    assert!(sm.buffer().line_count() <= MAX_RING_LINES);
    assert!(sm.buffer().total_bytes() <= MAX_RING_BYTES);

    // Spinner triggers working (Streaming subphase)
    sm.on_pty_bytes(b"\xE2\xA0\x8B Editing pty_runner.rs\r\n", 1_200);
    assert_eq!(sm.phase(), HarnessSessionPhase::Streaming);

    // Long prompt context + bottom 2 lines matching permission_prompt (`navigate` + `tab amend`)
    let long_ctx = format!("command: {}\r\n", "z".repeat(2_000));
    sm.on_pty_bytes(long_ctx.as_bytes(), 1_300);
    sm.on_pty_bytes(
        b"\xE2\x86\x91/\xE2\x86\x93 Navigate \xc2\xb7 tab Amend \xc2\xb7 ctrl+g edit\r\nesc to cancel\r\n",
        1_350,
    );
    assert_eq!(sm.phase(), HarnessSessionPhase::AwaitingApproval);

    let payload = sm.active_approval().expect("agy approval active").clone();
    assert_eq!(payload.source, DetectionSourceKind::PtyRegex);
    assert_eq!(payload.rule_id, "permission_prompt");
    assert!(payload.matched_excerpt.chars().count() <= MAX_EXCERPT_CHARS);

    // Rejecting agy sends Escape (`\u{001b}`)
    let (bytes, _) = sm
        .resolve_approval(&payload.prompt_id, false, None, 1_400)
        .expect("reject agy succeeds");
    assert_eq!(bytes, b"\x1b");
}

#[test]
fn resolved_blocker_in_ring_does_not_retrigger_on_trailing_output_and_rearms_for_new_prompt() {
    let registry = CompiledProfileRegistry::load_from_dir(&detection_dir()).expect("load profiles");
    let opencode = registry.resolve("opencode").expect("opencode").clone();
    let mut sm = HarnessStateMachine::new("sess-retrigger".into(), opencode, 0, 900);

    let ev1 = sm.on_pty_bytes(b"Thinking...\r\n\xE2\x96\xB3 Permission required\r\n", 100);
    assert_eq!(sm.phase(), HarnessSessionPhase::AwaitingApproval);
    assert!(
        ev1.iter()
            .any(|e| matches!(e, PtyEvent::ApprovalRequested { .. }))
    );
    let prompt_id = sm
        .active_approval()
        .expect("active approval")
        .prompt_id
        .clone();

    let (stdin_bytes, _) = sm
        .resolve_approval(&prompt_id, true, None, 200)
        .expect("resolve first approval");
    assert_eq!(stdin_bytes, b"y\r");
    assert_eq!(sm.phase(), HarnessSessionPhase::Thinking);

    // Trailing echo/output still leaves the old `△ Permission required` line inside the 64-line window,
    // yet must NOT re-trigger AwaitingApproval.
    let trailing = sm.on_pty_bytes(b"y\r\nAPPROVED_OK\r\n\r\n\r\n", 250);
    assert_eq!(sm.phase(), HarnessSessionPhase::Thinking);
    assert!(
        !trailing
            .iter()
            .any(|e| matches!(e, PtyEvent::ApprovalRequested { .. })),
        "stale blocker in retained ring must not re-trigger: {trailing:?}"
    );
    assert!(
        sm.buffer()
            .lines_snapshot()
            .iter()
            .any(|l| l.contains("Permission required")),
        "history snapshot remains preserved for tail_excerpt"
    );

    // A genuinely new blocker emitted later must still trigger a fresh prompt.
    let ev2 = sm.on_pty_bytes(b"\xE2\x96\xB3 Permission required: second edit\r\n", 300);
    assert_eq!(sm.phase(), HarnessSessionPhase::AwaitingApproval);
    assert!(
        ev2.iter()
            .any(|e| matches!(e, PtyEvent::ApprovalRequested { .. }))
    );
}

#[test]
fn opencode_and_agy_detection_meets_250ms_latency_budget() {
    let registry = CompiledProfileRegistry::load_from_dir(&detection_dir()).expect("load profiles");
    let opencode = registry.resolve("opencode").expect("opencode").clone();
    let agy = registry.resolve("agy").expect("agy").clone();

    let start = std::time::Instant::now();
    for i in 0..50_u64 {
        let mut sm_oc = HarnessStateMachine::new(format!("oc-lat-{i}"), opencode.clone(), 0, 900);
        sm_oc.on_pty_bytes(b"\x1b[36mThinking... esc to interrupt\x1b[0m\r\n", 100);
        assert_eq!(sm_oc.phase(), HarnessSessionPhase::Thinking);
        sm_oc.on_pty_bytes(b"\xE2\x96\xB3 Permission required: git status\r\n", 150);
        assert_eq!(sm_oc.phase(), HarnessSessionPhase::AwaitingApproval);

        let mut sm_agy = HarnessStateMachine::new(format!("agy-lat-{i}"), agy.clone(), 0, 900);
        sm_agy.on_pty_bytes(b"\xE2\xA0\x8B Inspecting cargo workspace\r\n", 100);
        assert_eq!(sm_agy.phase(), HarnessSessionPhase::Streaming);
        sm_agy.on_pty_bytes(
            b"\xE2\x86\x91/\xE2\x86\x93 Navigate \xc2\xb7 tab Amend\r\nesc to cancel\r\n",
            150,
        );
        assert_eq!(sm_agy.phase(), HarnessSessionPhase::AwaitingApproval);
    }
    let avg_pair_latency = start.elapsed() / 50;
    assert!(
        avg_pair_latency < std::time::Duration::from_millis(250),
        "state detection exceeded 250ms SLA (SC-002): {avg_pair_latency:?}"
    );
}

#[test]
fn terminated_session_settles_to_completed_idle_for_restart() {
    let registry = CompiledProfileRegistry::load_from_dir(&detection_dir()).expect("load profiles");
    let agy = registry.resolve("agy").expect("agy").clone();
    let mut sm = HarnessStateMachine::new("sess-crash-1".into(), agy, 0, 900);

    sm.on_pty_bytes(b"\xE2\xA0\x8B Building target\r\n", 100);
    assert_eq!(sm.phase(), HarnessSessionPhase::Streaming);

    let exit_events = sm.on_process_exit(Some(101), 450);
    assert_eq!(
        sm.phase(),
        HarnessSessionPhase::Terminated {
            exit_code: Some(101)
        }
    );
    assert!(exit_events.iter().any(|e| matches!(
        e,
        PtyEvent::Exited {
            exit_code: Some(101),
            ..
        }
    )));

    // After recording failed-turn diagnostic, harness settles back to CompletedIdle so
    // one-click Discord restart can inject the next turn cleanly.
    let settled = sm.settle_completed_idle_after_exit(480);
    assert_eq!(sm.phase(), HarnessSessionPhase::CompletedIdle);
    assert_eq!(
        sm.phase().to_lifecycle_activity(),
        LifecycleActivity::Finished
    );
    assert!(settled.iter().any(|e| matches!(
        e,
        PtyEvent::PhaseChanged {
            from: HarnessSessionPhase::Terminated {
                exit_code: Some(101)
            },
            to: HarnessSessionPhase::CompletedIdle,
            ..
        }
    )));

    let restarted = sm.on_input_sent(500);
    assert_eq!(sm.phase(), HarnessSessionPhase::Thinking);
    assert!(restarted.iter().any(|e| matches!(
        e,
        PtyEvent::PhaseChanged {
            from: HarnessSessionPhase::CompletedIdle,
            to: HarnessSessionPhase::Thinking,
            ..
        }
    )));
}

#[tokio::test]
async fn live_herdr_ipc_listener_drives_opencode_state_machine() {
    use tokio::io::AsyncWriteExt;
    use tokio_util::sync::CancellationToken;
    use zeroclaw_harness::detector::HerdrIpcListener;

    let registry = CompiledProfileRegistry::load_from_dir(&detection_dir()).expect("load profiles");
    let opencode = registry.resolve("opencode").expect("opencode").clone();
    let cancel = CancellationToken::new();
    let mut listener = HerdrIpcListener::bind("ipc-e2e-1", cancel.clone()).expect("bind IPC");
    let endpoint = listener.endpoint_path().to_string();

    let writer_task = zeroclaw_spawn::spawn!(async move {
        #[cfg(windows)]
        let mut client = {
            use tokio::net::windows::named_pipe::ClientOptions;
            loop {
                match ClientOptions::new().open(&endpoint) {
                    Ok(c) => break c,
                    Err(_) => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
                }
            }
        };
        #[cfg(unix)]
        let mut client = tokio::net::UnixStream::connect(&endpoint)
            .await
            .expect("connect unix ipc");

        client
            .write_all(
                br#"{"pane_id":"ipc-e2e-1","state":"blocked","event":"permission.asked","detail":"Write file src/lib.rs?"}
"#,
            )
            .await
            .expect("write blocked ipc");
        client
            .write_all(
                br#"{"pane_id":"ipc-e2e-1","state":"idle","event":"session.idle"}
"#,
            )
            .await
            .expect("write idle ipc");
        client.flush().await.expect("flush ipc");
    });

    let msg_blocked = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        listener.receiver_mut().recv(),
    )
    .await
    .expect("timeout receiving blocked IPC")
    .expect("blocked IPC message");

    let msg_idle = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        listener.receiver_mut().recv(),
    )
    .await
    .expect("timeout receiving idle IPC")
    .expect("idle IPC message");

    writer_task.await.expect("writer task");

    let mut sm = HarnessStateMachine::new("ipc-e2e-1".into(), opencode, 0, 900);
    let ev1 = sm.on_ipc_message(&msg_blocked, 200);
    assert_eq!(sm.phase(), HarnessSessionPhase::AwaitingApproval);
    assert!(ev1.iter().any(|e| matches!(
        e,
        PtyEvent::ApprovalRequested { payload, .. } if payload.source == DetectionSourceKind::IpcPush
    )));

    sm.on_ipc_message(&msg_idle, 3_500);
    assert_eq!(sm.phase(), HarnessSessionPhase::CompletedIdle);
    cancel.cancel();
}

#[test]
fn parses_herdr_json_rpc_report_agent_and_session_envelopes() {
    use zeroclaw_harness::detector::{normalize_herdr_socket_env, normalize_windows_pipe_path};

    // Windows Named Pipe normalization prevents \\.\pipe\\\.\pipe\ duplication.
    assert_eq!(
        normalize_windows_pipe_path(r"zeroclaw-herdr-1"),
        r"\\.\pipe\zeroclaw-herdr-1"
    );
    assert_eq!(
        normalize_windows_pipe_path(r"\\.\pipe\\\.\pipe\zeroclaw-herdr-1"),
        r"\\.\pipe\zeroclaw-herdr-1"
    );
    let env_val = normalize_herdr_socket_env(r"\\.\pipe\zeroclaw-herdr-1");
    #[cfg(windows)]
    assert_eq!(env_val, "zeroclaw-herdr-1");
    #[cfg(not(windows))]
    assert_eq!(env_val, r"\\.\pipe\zeroclaw-herdr-1");

    // Native Herdr JSON-RPC pane.report_agent (working / blocked / idle + agent_session_id)
    let working = IpcStateMessage::parse_ndjson_line(
        r#"{"id":"herdr:opencode:1","method":"pane.report_agent","params":{"pane_id":"pane-42","source":"herdr:opencode","agent":"opencode","seq":101,"state":"working","agent_session_id":"oc-sess-9"}}"#,
    )
    .expect("parse working json-rpc");
    assert_eq!(working.pane_id, "pane-42");
    assert_eq!(working.state, RawDetectedState::Working);
    assert_eq!(working.event, "pane.report_agent");
    assert_eq!(working.agent_session_id.as_deref(), Some("oc-sess-9"));

    let blocked = IpcStateMessage::parse_ndjson_line(
        r#"{"id":"herdr:opencode:2","method":"pane.report_agent","params":{"pane_id":"pane-42","state":"blocked","agent_session_id":"oc-sess-9"}}"#,
    )
    .expect("parse blocked json-rpc");
    assert_eq!(blocked.state, RawDetectedState::Blocked);

    let session_only = IpcStateMessage::parse_ndjson_line(
        r#"{"id":"herdr:opencode:3","method":"pane.report_agent_session","params":{"pane_id":"pane-42","agent_session_id":"oc-sess-10"}}"#,
    )
    .expect("parse session json-rpc");
    assert_eq!(session_only.event, "pane.report_agent_session");
    assert_eq!(session_only.agent_session_id.as_deref(), Some("oc-sess-10"));

    // Mid-turn pane.report_agent_session MUST NOT drop an active session to CompletedIdle.
    let registry = CompiledProfileRegistry::load_from_dir(&detection_dir()).expect("load profiles");
    let opencode = registry.resolve("opencode").expect("opencode").clone();
    let mut sm = HarnessStateMachine::new("pane-42".into(), opencode, 0, 900);
    sm.on_ipc_message(&working, 100);
    assert_eq!(sm.phase(), HarnessSessionPhase::Thinking);
    let sess_ev = sm.on_ipc_message(&session_only, 5_000);
    assert!(sess_ev.is_empty());
    assert_eq!(sm.phase(), HarnessSessionPhase::Thinking);
}
