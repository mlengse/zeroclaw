//! Cross-platform PTY spawn, ANSI-stripped streaming, interactive approval stdin injection,
//! resize, and clean termination smoke tests (`T014` — ConPTY on Windows, openpty on Unix).

use std::path::PathBuf;
use std::time::Duration;
use zeroclaw_harness::detector::CompiledProfileRegistry;
use zeroclaw_harness::pty_runner::{
    HarnessSessionPhase, PtyControlCommand, PtyEvent, PtySessionHandle, PtySpawnConfig,
};

fn detection_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("zeroclaw root")
        .join("distribution/agent-detection")
}

fn mock_cli_command() -> (String, Vec<String>) {
    #[cfg(windows)]
    {
        let script = r#"[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new(); [Console]::WriteLine("`e[36mThinking... esc to interrupt`e[0m"); Start-Sleep -Milliseconds 120; [Console]::WriteLine(([char]0x25B3) + " Permission required"); $ans = [Console]::In.ReadLine(); if ($ans -eq "y") { [Console]::WriteLine("APPROVED_OK") } else { [Console]::WriteLine("REJECTED:" + $ans) }"#;
        // Fallback escape sequence `[char]27` compatible with both Windows PowerShell 5.1 and pwsh 7+:
        let script = script.replace("`e", "$([char]27)");
        let _ = script; // constructed cleanly below
        let ps_script = concat!(
            "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new(); ",
            "Write-Host (\"$([char]27)[36mThinking... esc to interrupt$([char]27)[0m\"); ",
            "Start-Sleep -Milliseconds 120; ",
            "Write-Host (\"$([char]0x25B3) Permission required\"); ",
            "$ans = [Console]::In.ReadLine(); ",
            "if ($ans -eq 'y') { Write-Host 'APPROVED_OK' } else { Write-Host ('REJECTED:' + $ans) }"
        );
        (
            "powershell.exe".to_string(),
            vec![
                "-NoLogo".to_string(),
                "-NoProfile".to_string(),
                "-Command".to_string(),
                ps_script.to_string(),
            ],
        )
    }
    #[cfg(unix)]
    {
        (
            "/bin/sh".to_string(),
            vec![
                "-c".to_string(),
                r#"printf "\033[36mThinking... esc to interrupt\033[0m\n"; sleep 0.12; printf "△ Permission required\n"; IFS= read -r ans; if [ "$ans" = "y" ]; then printf "APPROVED_OK\n"; else printf "REJECTED:%s\n" "$ans"; fi"#.to_string(),
            ],
        )
    }
}

#[tokio::test]
async fn spawns_mock_cli_in_real_pty_and_roundtrips_approval_to_exit() {
    let registry = CompiledProfileRegistry::load_from_dir(&detection_dir()).expect("load profiles");
    let opencode = registry.resolve("opencode").expect("opencode").clone();
    let (program, args) = mock_cli_command();

    let handle = PtySessionHandle::spawn(PtySpawnConfig {
        session_id: "pty-smoke-1".to_string(),
        channel_recipient: "discord:12345".to_string(),
        sulur_scope: "ws:memory:zeroclaw".to_string(),
        workspace_path: std::env::temp_dir(),
        worktree_branch: None,
        program,
        args,
        extra_env: Default::default(),
        rows: 24,
        cols: 80,
        approval_timeout_secs: 60,
        profile: opencode,
    })
    .expect("spawn PTY session");

    let ctrl = handle.control_sender();
    let mut events = handle.subscribe_events();

    let mut saw_working = false;
    let mut saw_approval = false;
    let mut saw_approved_ok = false;
    let mut exited_cleanly = false;
    let mut trace_log = Vec::<String>::new();

    let deadline = tokio::time::sleep(Duration::from_secs(10));
    tokio::pin!(deadline);

    loop {
        tokio::select! {
            () = &mut deadline => {
                panic!(
                    "timed out waiting for cross-platform PTY roundtrip; state={:?}; trace={trace_log:#?}",
                    handle.state_snapshot()
                );
            }
            ev = events.recv() => match ev {
                Ok(PtyEvent::PhaseChanged { from, to, reason, .. }) => {
                    trace_log.push(format!("PhaseChanged: {from:?} -> {to:?} ({reason})"));
                    if matches!(to, HarnessSessionPhase::Thinking | HarnessSessionPhase::Streaming) {
                        saw_working = true;
                    }
                }
                Ok(PtyEvent::ApprovalRequested { payload, .. }) => {
                    trace_log.push(format!("ApprovalRequested: {} ({})", payload.prompt_id, payload.rule_id));
                    saw_approval = true;
                    // Resize viewport mid-session then approve via ResolveApproval -> writes "y\r"
                    ctrl.send(PtyControlCommand::Resize { rows: 36, cols: 120 })
                        .await
                        .expect("send resize");
                    ctrl.send(PtyControlCommand::ResolveApproval {
                        prompt_id: payload.prompt_id,
                        approved: true,
                        decided_by: Some("test-operator".to_string()),
                        custom_response: None,
                    })
                    .await
                    .expect("send resolve approval");
                }
                Ok(PtyEvent::OutputChunk { stripped_text, .. }) => {
                    trace_log.push(format!("OutputChunk: {stripped_text:?}"));
                    assert!(
                        !stripped_text.contains('\x1b'),
                        "PTY output chunk must be ANSI-stripped: {stripped_text:?}"
                    );
                    if stripped_text.contains("APPROVED_OK") {
                        saw_approved_ok = true;
                    }
                }
                Ok(PtyEvent::Exited { exit_code, tail_excerpt, .. }) => {
                    trace_log.push(format!("Exited({exit_code:?}): {tail_excerpt:?}"));
                    assert_eq!(exit_code, Some(0), "trace={trace_log:#?}");
                    exited_cleanly = true;
                    break;
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    trace_log.push(format!("Lagged({n})"));
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    trace_log.push("Closed".to_string());
                    break;
                }
            }
        }
    }

    assert!(saw_working, "expected Thinking/Streaming transition");
    assert!(saw_approval, "expected ApprovalRequested event");
    assert!(saw_approved_ok, "expected child to observe injected y\\r and print APPROVED_OK");
    assert!(exited_cleanly, "expected clean child exit");
}

#[tokio::test]
async fn spawns_fast_shell_echo_and_exits_cleanly() {
    let registry = CompiledProfileRegistry::load_from_dir(&detection_dir()).expect("load profiles");
    let opencode = registry.resolve("opencode").expect("opencode").clone();
    #[cfg(windows)]
    let (program, args) = (
        "cmd.exe".to_string(),
        vec!["/D".into(), "/Q".into(), "/C".into(), "echo esc to interrupt & echo HELLO_PTY".into()],
    );
    #[cfg(unix)]
    let (program, args) = (
        "/bin/sh".to_string(),
        vec!["-c".into(), "echo 'esc to interrupt'; echo HELLO_PTY".into()],
    );

    let handle = PtySessionHandle::spawn(PtySpawnConfig {
        session_id: "pty-echo-1".to_string(),
        channel_recipient: "discord:echo".to_string(),
        sulur_scope: "ws:memory:zeroclaw".to_string(),
        workspace_path: std::env::temp_dir(),
        worktree_branch: None,
        program,
        args,
        extra_env: Default::default(),
        rows: 24,
        cols: 80,
        approval_timeout_secs: 60,
        profile: opencode,
    })
    .expect("spawn fast shell");

    let mut events = handle.subscribe_events();
    let mut chunks = String::new();
    let mut exited = false;
    let deadline = tokio::time::sleep(Duration::from_secs(5));
    tokio::pin!(deadline);

    loop {
        tokio::select! {
            () = &mut deadline => panic!("echo timed out; state={:?}; chunks={chunks:?}", handle.state_snapshot()),
            ev = events.recv() => match ev {
                Ok(PtyEvent::OutputChunk { stripped_text, .. }) => chunks.push_str(&stripped_text),
                Ok(PtyEvent::Exited { exit_code, .. }) => {
                    assert_eq!(exit_code, Some(0));
                    exited = true;
                    break;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                _ => {}
            }
        }
    }
    assert!(exited, "expected clean exit; chunks={chunks:?}");
    assert!(chunks.contains("HELLO_PTY"), "missing HELLO_PTY in {chunks:?}");
}

#[tokio::test]
async fn terminates_long_running_pty_session_cleanly() {
    let registry = CompiledProfileRegistry::load_from_dir(&detection_dir()).expect("load profiles");
    let agy = registry.resolve("agy").expect("agy").clone();
    #[cfg(windows)]
    let (program, args) = (
        "cmd.exe".to_string(),
        vec![
            "/D".into(),
            "/Q".into(),
            "/C".into(),
            "ping -n 30 127.0.0.1 >nul".into(),
        ],
    );
    #[cfg(unix)]
    let (program, args) = (
        "/bin/sh".to_string(),
        vec!["-c".into(), "sleep 30".into()],
    );

    let handle = PtySessionHandle::spawn(PtySpawnConfig {
        session_id: "pty-term-1".to_string(),
        channel_recipient: "discord:term".to_string(),
        sulur_scope: "ws:memory:zeroclaw".to_string(),
        workspace_path: std::env::temp_dir(),
        worktree_branch: None,
        program,
        args,
        extra_env: Default::default(),
        rows: 24,
        cols: 80,
        approval_timeout_secs: 60,
        profile: agy,
    })
    .expect("spawn sleeper");

    let ctrl = handle.control_sender();
    let mut events = handle.subscribe_events();
    tokio::time::sleep(Duration::from_millis(80)).await;
    ctrl.send(PtyControlCommand::Terminate)
        .await
        .expect("send terminate");

    let mut exited = false;
    let deadline = tokio::time::sleep(Duration::from_secs(5));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            () = &mut deadline => panic!("terminate timed out; state={:?}", handle.state_snapshot()),
            ev = events.recv() => match ev {
                Ok(PtyEvent::Exited { .. }) => {
                    exited = true;
                    break;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                _ => {}
            }
        }
    }
    assert!(exited, "expected clean termination Exited event");
}
