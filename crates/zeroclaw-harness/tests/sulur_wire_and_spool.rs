//! Integration tests for `sulur_bridge.rs` & `lifecycle_hooks.rs` (`T025`):
//! - Sidecar discovery (`.daemon.json`) & `ExternalOnly` fail-loud
//! - `inject_context()` (`briefing`, `handoff_accept`, `message_pop`, multi-channel `recall`) + `< 500ms` p95 (`SC-003`)
//! - `record_turn()` secret/token scrubbing (`C2`), CAS precondition fail-loud, & `.spool.jsonl` fallback (`4096`-line cap)
//! - `SulurWireMemory` trait impl & `maybe_trigger_dream()` idle gate + `wiki_sync`

use serde_json::{Value, json};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use zeroclaw_api::memory_traits::{Memory, MemoryCategory};
use zeroclaw_config::harness::{
    BriefingBudgetConfig, DreamTriggerConfig, RecallChannelFlags, SidecarMode, SpoolConfig,
    SulurHarnessConfig,
};
use zeroclaw_harness::HarnessError;
use zeroclaw_harness::lifecycle_hooks::{SulurLifecycleManager, SulurWireMemory};
use zeroclaw_harness::sulur_bridge::{
    CasPatchOperation, LifecycleSpoolRecord, MAX_FRAME_SIZE, MAX_SPOOL_LINES, SidecarDescriptor,
    SulurBridge, WIRE_PROTOCOL_TAG, WireRequest, WireResponse, canonical_spool_path,
    normalize_db_path, sidecar_path,
};

const TEST_TOKEN: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

fn test_config(db_dir: &std::path::Path, mode: SidecarMode) -> SulurHarnessConfig {
    SulurHarnessConfig {
        enabled: true,
        db_path: db_dir.to_path_buf(),
        sulur_server_bin: None,
        sidecar_mode: mode,
        default_scope: "ws:memory:zeroclaw".to_string(),
        agent_detection_dir: std::path::PathBuf::from("distribution/agent-detection"),
        connect_timeout_ms: 500,
        request_timeout_ms: 1_500,
        briefing_budget: BriefingBudgetConfig::default(),
        recall_channels: RecallChannelFlags::default(),
        spool: SpoolConfig::default(),
        dream_trigger: DreamTriggerConfig {
            enabled: true,
            idle_debounce_secs: 2,
            run_wiki_sync: true,
            wiki_dir: Some(db_dir.join("wiki")),
        },
        approval_timeout_secs: 900,
    }
}

async fn spawn_mock_sulur_server(
    db_path: &std::path::Path,
    cas_conflict_on_patch: bool,
) -> (
    u16,
    Arc<Mutex<Vec<WireRequest>>>,
    tokio::sync::oneshot::Sender<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock sulur-server");
    let port = listener.local_addr().expect("local addr").port();
    let recorded = Arc::new(Mutex::new(Vec::<WireRequest>::new()));
    let recorded_clone = Arc::clone(&recorded);
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

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
                        if req.token.as_deref() != Some(TEST_TOKEN) {
                            let err_resp = WireResponse {
                                success: false,
                                message: None,
                                error_message: Some("invalid token".to_string()),
                                column_names: vec![],
                                rows: vec![],
                                stats: None,
                                results: None,
                                explanation: None,
                            };
                            let bytes = serde_json::to_vec(&err_resp).unwrap_or_default();
                            let _ = stream.write_all(&(u32::try_from(bytes.len()).unwrap_or(0)).to_le_bytes()).await;
                            let _ = stream.write_all(&bytes).await;
                            return;
                        }

                        rec.lock().await.push(req.clone());
                        let resp = build_mock_response(&req, cas_conflict_on_patch);
                        let bytes = serde_json::to_vec(&resp).unwrap_or_default();
                        let _ = stream.write_all(&(u32::try_from(bytes.len()).unwrap_or(0)).to_le_bytes()).await;
                        let _ = stream.write_all(&bytes).await;
                        let _ = stream.flush().await;
                    });
                }
            }
        }
    });

    (port, recorded, shutdown_tx)
}

fn build_mock_response(req: &WireRequest, cas_conflict_on_patch: bool) -> WireResponse {
    let ok = |msg: Option<&str>| WireResponse {
        success: true,
        message: msg.map(str::to_string),
        error_message: None,
        column_names: vec![],
        rows: vec![],
        stats: None,
        results: None,
        explanation: None,
    };

    match req.op.as_deref() {
        Some("ping") => ok(Some("pong")),
        Some("briefing") => ok(Some(
            "## Workspace Rules\n- Zero ghostty-vt\n- Keep diff <= 30 lines",
        )),
        Some("handoff_list") => WireResponse {
            success: true,
            message: None,
            error_message: None,
            column_names: vec![
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
            ],
            rows: vec![vec![
                Some(Value::String("hf_zed_01".into())),
                Some(Value::String("ws:memory:zeroclaw".into())),
                Some(Value::String("Implement Fase 3 bridge".into())),
                Some(Value::String(r#"["Verify wire tests"]"#.into())),
                Some(Value::String(r#"["sulur_bridge.rs"]"#.into())),
                Some(Value::String("offered".into())),
                Some(Value::String("zed:local-1".into())),
                None,
                Some(json!(1_763_210_000_i64)),
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
            column_names: vec![
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
            ],
            rows: vec![vec![
                Some(Value::String("hf_zed_01".into())),
                Some(Value::String("ws:memory:zeroclaw".into())),
                Some(Value::String("Implement Fase 3 bridge".into())),
                Some(Value::String(r#"["Verify wire tests"]"#.into())),
                Some(Value::String(r#"["sulur_bridge.rs"]"#.into())),
                Some(Value::String("claimed".into())),
                Some(Value::String("zed:local-1".into())),
                Some(Value::String("discord-sess-1".into())),
                Some(json!(1_763_210_000_i64)),
                Some(json!(1_763_210_050_i64)),
            ]],
            stats: None,
            results: None,
            explanation: None,
        },
        Some("message_pop") => WireResponse {
            success: true,
            message: None,
            error_message: None,
            column_names: vec![
                "message_id".into(),
                "from_scope".into(),
                "to_scope".into(),
                "target_harness".into(),
                "body".into(),
                "evidence".into(),
                "status".into(),
                "created_at".into(),
                "claimed_at".into(),
            ],
            rows: vec![vec![
                Some(Value::String("019a0000-0000-7000-8000-000000000001".into())),
                Some(Value::String("ws:memory:sulur".into())),
                Some(Value::String("ws:memory:zeroclaw".into())),
                Some(Value::String("discord".into())),
                Some(Value::String(
                    "Zed IDE finished editing sulur-mcp proxy".into(),
                )),
                Some(Value::String("[]".into())),
                Some(Value::String("claimed".into())),
                Some(json!(1_763_210_000_i64)),
                Some(json!(1_763_210_010_i64)),
            ]],
            stats: None,
            results: None,
            explanation: None,
        },
        Some("recall") => WireResponse {
            success: true,
            message: None,
            error_message: None,
            column_names: vec![
                "id".into(),
                "label".into(),
                "content".into(),
                "score".into(),
                "similarity".into(),
                "channel".into(),
            ],
            rows: vec![],
            stats: None,
            results: Some(vec![
                json!({"memory_id": 11, "label": "arch", "body": "Single-writer sulur-server via akar-json-v1", "score": 0.94, "channel": "semantic"}),
                json!({"memory_id": 12, "label": "pty", "body": "portable-pty replaces ghostty-vt", "score": 0.88, "channel": "lexical"}),
            ]),
            explanation: None,
        },
        Some("remember") => WireResponse {
            success: true,
            message: None,
            error_message: None,
            column_names: vec!["id".into()],
            rows: vec![vec![Some(json!(101_i64))]],
            stats: None,
            results: None,
            explanation: None,
        },
        Some("patch") => {
            if cas_conflict_on_patch {
                WireResponse {
                    success: false,
                    message: None,
                    error_message: Some(
                        "patch failed: precondition_failed stale revision_id".into(),
                    ),
                    column_names: vec![],
                    rows: vec![],
                    stats: None,
                    results: None,
                    explanation: None,
                }
            } else {
                ok(Some("patched"))
            }
        }
        Some("dream_control") => ok(Some("dream cycle completed in 12 ms")),
        Some("wiki_sync") => ok(Some("Exported 2 wiki documents")),
        Some("stats") => WireResponse {
            success: true,
            message: None,
            error_message: None,
            column_names: vec![],
            rows: vec![],
            stats: Some(zeroclaw_harness::sulur_bridge::ServerStats {
                num_clients: 2,
                total_queries: 7,
                uptime_secs: 42,
                db_path: "mock".into(),
                pid: 1,
            }),
            results: None,
            explanation: None,
        },
        other => WireResponse {
            success: false,
            message: None,
            error_message: Some(format!("Unknown operation: {other:?}")),
            column_names: vec![],
            rows: vec![],
            stats: None,
            results: None,
            explanation: None,
        },
    }
}

#[tokio::test]
async fn external_only_fails_loud_when_daemon_missing_and_discovers_msys_paths() {
    let norm = normalize_db_path("/c/tmp/sulur-db");
    if cfg!(windows) {
        assert_eq!(norm, r"C:\tmp\sulur-db");
    }

    let tmp = TempDir::new().expect("tempdir");
    let cfg = test_config(tmp.path(), SidecarMode::ExternalOnly);
    let bridge = SulurBridge::new(cfg);

    let err = bridge
        .ensure_daemon()
        .await
        .expect_err("ExternalOnly with no .daemon.json must fail loud");
    assert!(matches!(err, HarnessError::DaemonUnavailable { .. }));
}

#[tokio::test]
async fn inject_context_assembles_handoff_message_briefing_recall_within_500ms_p95() {
    let tmp = TempDir::new().expect("tempdir");
    let (_port, recorded, shutdown) = spawn_mock_sulur_server(tmp.path(), false).await;

    let cfg = test_config(tmp.path(), SidecarMode::ExternalOnly);
    let bridge = Arc::new(SulurBridge::new(cfg));
    let mgr = SulurLifecycleManager::new(Arc::clone(&bridge));

    let first = mgr
        .inject_context(
            "ws:memory:zeroclaw",
            "discord-sess-1",
            tmp.path(),
            "How does sulur bridge prevent akar.lock contention?",
        )
        .await
        .expect("inject_context succeeds");

    assert!(first.formatted_block.starts_with("[Memory context]"));
    assert!(first.formatted_block.contains("Implement Fase 3 bridge"));
    assert!(
        first
            .formatted_block
            .contains("Zed IDE finished editing sulur-mcp proxy")
    );
    assert!(first.formatted_block.contains("Zero ghostty-vt"));
    assert!(first.formatted_block.contains("Single-writer sulur-server"));
    assert!(first.formatted_block.chars().count() <= 3_500);
    assert_eq!(first.popped_messages, 1);
    assert_eq!(first.recall_hits, 2);
    assert_eq!(
        first.claimed_handoff.and_then(|h| h.ticket_id).as_deref(),
        Some("hf_zed_01")
    );

    // Measure 20 iterations -> verify p95 < 500ms (SC-003).
    let mut latencies = Vec::with_capacity(20);
    for _ in 0..20 {
        let t0 = Instant::now();
        let _ = mgr
            .inject_context(
                "ws:memory:zeroclaw",
                "discord-sess-1",
                tmp.path(),
                "recall check",
            )
            .await
            .expect("inject_context iteration");
        latencies.push(t0.elapsed());
    }
    latencies.sort();
    let p95 = latencies[18];
    assert!(
        p95 < Duration::from_millis(500),
        "inject_context p95 exceeded 500ms SLA (SC-003): {p95:?}"
    );

    let ops: Vec<String> = recorded
        .lock()
        .await
        .iter()
        .filter_map(|r| r.op.clone())
        .collect();
    assert!(ops.contains(&"ping".to_string()));
    assert!(ops.contains(&"handoff_list".to_string()));
    assert!(ops.contains(&"handoff_accept".to_string()));
    assert!(ops.contains(&"message_pop".to_string()));
    assert!(ops.contains(&"briefing".to_string()));
    assert!(ops.contains(&"recall".to_string()));

    let _ = shutdown.send(());
}

#[tokio::test]
async fn record_turn_redacts_secrets_spools_on_outage_and_enforces_4096_cap() {
    let tmp = TempDir::new().expect("tempdir");
    let (_port, recorded, shutdown) = spawn_mock_sulur_server(tmp.path(), true).await;

    let cfg = test_config(tmp.path(), SidecarMode::ExternalOnly);
    let bridge = Arc::new(SulurBridge::new(cfg.clone()));
    let mgr = SulurLifecycleManager::new(Arc::clone(&bridge));
    bridge.ensure_daemon().await.expect("connect mock daemon");

    // Verify secret scrubbing before wire dispatch (`C2`) AND CAS conflict fail-loud:
    let dirty_summary = format!(
        "Executed task with Bearer super_secret_bearer_token, sk-abcdefgh1234567890, and daemon token {TEST_TOKEN}"
    );
    let cas_err = mgr
        .record_turn(
            "ws:memory:zeroclaw",
            "discord-sess-2",
            Some("opencode"),
            &dirty_summary,
            &[CasPatchOperation {
                memory_id: 42,
                operation: "replace_section".into(),
                section_heading: "Decisions".into(),
                section_order: Some(1),
                content: "Token should not leak: sk-xyz9876543210abcdef".into(),
                expected_content_hash: Some("stale".into()),
                expected_revision_id: Some(1),
                actor_role: "editor".into(),
            }],
            &["src/sulur_bridge.rs".into()],
        )
        .await
        .expect_err("CAS conflict must fail loud");
    assert!(matches!(cas_err, HarnessError::Wire { .. }));

    {
        let log = recorded.lock().await;
        let payload_text: String = log
            .iter()
            .filter(|r| matches!(r.op.as_deref(), Some("remember") | Some("patch")))
            .map(|r| format!("{} {:?}", r.query, r.params))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !payload_text.contains(TEST_TOKEN),
            "daemon token leaked into remembered memory content!"
        );
        assert!(
            !payload_text.contains("super_secret_bearer_token"),
            "bearer token leaked!"
        );
        assert!(
            !payload_text.contains("sk-abcdefgh1234567890"),
            "API key leaked!"
        );
        assert!(
            !payload_text.contains("sk-xyz9876543210abcdef"),
            "API key leaked in patch!"
        );
        assert!(payload_text.contains("[REDACTED]"));
    }

    // Drop mock server -> test lossless .spool.jsonl fallback & secret redaction offline!
    let _ = shutdown.send(());
    tokio::time::sleep(Duration::from_millis(50)).await;
    // Remove daemon descriptor so ensure_daemon detects outage immediately:
    let _ = std::fs::remove_file(sidecar_path(&tmp.path().to_string_lossy()));

    mgr.record_turn(
        "ws:memory:zeroclaw",
        "discord-sess-2",
        Some("agy"),
        "Offline turn Bearer offline_secret_token completed",
        &[],
        &["src/lifecycle_hooks.rs".into()],
    )
    .await
    .expect("offline turn must spool losslessly without failing");

    assert_eq!(bridge.pending_spool_count().await, 1);
    let sp_path = canonical_spool_path(
        &normalize_db_path(&cfg.db_path.to_string_lossy()),
        &cfg.spool,
    );
    let sp_raw = std::fs::read_to_string(&sp_path).expect("read .spool.jsonl");
    assert!(!sp_raw.contains("offline_secret_token"));
    assert!(sp_raw.contains("[REDACTED]"));
    let parsed: LifecycleSpoolRecord =
        serde_json::from_str(sp_raw.trim()).expect("parse spool json");
    assert_eq!(parsed.event_type, "PostTurnSummary");
    assert!(!parsed.ingest_key.is_empty());

    // Pre-fill spool to MAX_SPOOL_LINES (4096) and verify cap rejection rather than unbounded growth:
    let bulk_rec =
        LifecycleSpoolRecord::new("s", "ws", "PostTurnSummary", 99, 1, json!({"ok": true}));
    let line = format!("{}\n", serde_json::to_string(&bulk_rec).expect("json"));
    let mut bulk = String::with_capacity(line.len() * MAX_SPOOL_LINES);
    for _ in 0..MAX_SPOOL_LINES {
        bulk.push_str(&line);
    }
    std::fs::write(&sp_path, bulk).expect("seed 4096 lines");
    let cap_err = bridge
        .append_spool(bulk_rec)
        .await
        .expect_err("4097th spool record must hit MAX_SPOOL_LINES safety cap");
    assert!(matches!(cap_err, HarnessError::Wire { .. }));

    // Verify deterministic deduplication keys differ cleanly across distinct turns:
    let keys: HashSet<String> = (0_u64..10)
        .map(|seq| {
            LifecycleSpoolRecord::new("s1", "ws", "PostTurnSummary", seq, seq, json!({"seq": seq}))
                .ingest_key
        })
        .collect();
    assert_eq!(keys.len(), 10);
}

#[tokio::test]
async fn sulur_wire_memory_and_idle_dream_gate_behave_deterministically() {
    let tmp = TempDir::new().expect("tempdir");
    let (_port, recorded, shutdown) = spawn_mock_sulur_server(tmp.path(), false).await;

    let cfg = test_config(tmp.path(), SidecarMode::ExternalOnly);
    let bridge = Arc::new(SulurBridge::new(cfg));
    let memory = SulurWireMemory::new(Arc::clone(&bridge), "ws:memory:zeroclaw");
    let mgr = SulurLifecycleManager::new(Arc::clone(&bridge));

    assert_eq!(memory.name(), "sulur-wire");
    assert!(memory.health_check().await);
    memory
        .store(
            "arch_decision",
            "Use portable-pty",
            MemoryCategory::Core,
            Some("s1"),
        )
        .await
        .expect("store works");
    let hits = memory
        .recall("portable-pty", 5, Some("s1"), None, None)
        .await
        .expect("recall works");
    assert_eq!(hits.len(), 2);
    assert!(memory.forget("arch_decision").await.is_err());

    // Dream gate MUST suppress if any session is still active (`None`) or under `idle_debounce_secs` (2000ms):
    assert!(
        !mgr.maybe_trigger_dream(&[Some(3_000), None])
            .await
            .expect("active session suppresses dream")
    );
    assert!(
        !mgr.maybe_trigger_dream(&[Some(1_500)])
            .await
            .expect("under debounce suppresses dream")
    );

    // Once all sessions are quiescent >= 2000ms -> dream_control(run) + wiki_sync(export) fire:
    let triggered = mgr
        .maybe_trigger_dream(&[Some(2_500), Some(4_000)])
        .await
        .expect("all idle triggers dream");
    assert!(triggered);

    let ops: Vec<String> = recorded
        .lock()
        .await
        .iter()
        .filter_map(|r| r.op.clone())
        .collect();
    assert!(ops.contains(&"dream_control".to_string()));
    assert!(ops.contains(&"wiki_sync".to_string()));

    let _ = shutdown.send(());
}
