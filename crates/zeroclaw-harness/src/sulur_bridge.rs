//! Native out-of-process `sulur-server` TCP wire bridge (`akar-json-v1`), sidecar daemon
//! discovery/bootstrapping, and lossless `.spool.jsonl` fallback queue.
//!
//! Strictly communicates over loopback TCP (`sulur-server`'s `akar-json-v1` framing) so ZeroClaw
//! (`MIT OR Apache-2.0`) never links `sulur-*` or `akar-*` (`GPLv3`) in-process and never acquires
//! a competing `akar.lock`.

use crate::{HarnessError, HarnessResult};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use zeroclaw_config::harness::{SidecarMode, SpoolConfig, SulurHarnessConfig};

/// Expected wire protocol tag announced by `<db>.daemon.json`.
pub const WIRE_PROTOCOL_TAG: &str = "akar-json-v1";

/// Hard frame size ceiling matching `sulur/crates/sulur-server/src/wire/envelope.rs` (`128 MiB`).
pub const MAX_FRAME_SIZE: usize = 128 * 1024 * 1024;

/// Maximum queued NDJSON records permitted in `<normalized_db_path>.spool.jsonl`.
pub const MAX_SPOOL_LINES: usize = 4_096;

/// Exact JSON schema written by `sulur/crates/sulur-server/src/sidecar.rs`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SidecarDescriptor {
    pub pid: u32,
    pub port: u16,
    pub host: String,
    pub token: String,
    pub db_path: String,
    pub protocol: String,
    pub started_at: f64,
}

/// Canonical outbound request envelope mirroring `sulur/crates/sulur-server/src/wire/envelope.rs`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct WireRequest {
    pub query: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub op: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Map<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
}

/// Canonical inbound response envelope mirroring `sulur/crates/sulur-server/src/wire/envelope.rs`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WireResponse {
    pub success: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    #[serde(default)]
    pub column_names: Vec<String>,
    #[serde(default)]
    pub rows: Vec<Vec<Option<Value>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stats: Option<ServerStats>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub results: Option<Vec<Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub explanation: Option<Value>,
}

/// Server telemetry returned by `"stats"` op.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerStats {
    pub num_clients: usize,
    pub total_queries: u64,
    pub uptime_secs: u64,
    pub db_path: String,
    pub pid: u32,
}

/// Continuity payload exchanged between ZeroClaw Discord sessions and Zed IDE / local CLI via Sulur.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossToolHandoffPayload {
    #[serde(default)]
    pub ticket_id: Option<String>,
    pub scope: String,
    pub source_session_id: String,
    pub source_agent: String,
    #[serde(default)]
    pub target_harness: Option<String>,
    pub workspace_path: PathBuf,
    #[serde(default)]
    pub git_branch: Option<String>,
    pub milestone: String,
    pub unblocked_next_steps: Vec<String>,
    #[serde(default)]
    pub modified_files: Vec<String>,
    #[serde(default = "default_handoff_status")]
    pub status: String,
    #[serde(default)]
    pub created_at: i64,
    #[serde(default)]
    pub claimed_at: Option<i64>,
}

fn default_handoff_status() -> String {
    "offered".to_string()
}

/// Cross-project / cross-surface agent message (`message_send` / `list` / `pop` / `cancel`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossProjectMessageWire {
    pub message_id: String,
    pub from_scope: String,
    pub to_scope: String,
    pub target_harness: String,
    pub body: String,
    #[serde(default)]
    pub evidence: Vec<MessageEvidenceRef>,
    #[serde(default = "default_msg_status")]
    pub status: String,
    #[serde(default)]
    pub created_at: i64,
    #[serde(default)]
    pub claimed_at: Option<i64>,
}

fn default_msg_status() -> String {
    "pending".to_string()
}

/// Evidence attachment linked to a [`CrossProjectMessageWire`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageEvidenceRef {
    #[serde(rename = "type")]
    pub kind: String,
    pub value: String,
}

/// CAS-protected memory page section update mapped to wire op `"patch"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CasPatchOperation {
    pub memory_id: i64,
    pub operation: String,
    pub section_heading: String,
    #[serde(default)]
    pub section_order: Option<u32>,
    pub content: String,
    #[serde(default)]
    pub expected_content_hash: Option<String>,
    #[serde(default)]
    pub expected_revision_id: Option<i64>,
    pub actor_role: String,
}

/// Canonical NDJSON record appended to `<normalized_db_path>.spool.jsonl` on timeout/outage.
/// Matches `SpoolDrainer::drain_file` (`sulur/crates/sulur-server/src/spool.rs`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LifecycleSpoolRecord {
    pub ingest_key: String,
    pub event_type: String,
    pub scope: String,
    pub session_id: String,
    pub recorded_at_ms: u64,
    pub payload: Value,
}

impl LifecycleSpoolRecord {
    /// Construct a deduplicated spool record with a deterministic SHA-256 `ingest_key`.
    #[must_use]
    pub fn new(
        session_id: impl Into<String>,
        scope: impl Into<String>,
        event_type: impl Into<String>,
        turn_seq: u64,
        recorded_at_ms: u64,
        payload: Value,
    ) -> Self {
        let session_id = session_id.into();
        let scope = scope.into();
        let event_type = event_type.into();
        let canonical = serde_json::to_string(&payload).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(session_id.as_bytes());
        hasher.update(b":");
        hasher.update(turn_seq.to_le_bytes());
        hasher.update(b":");
        hasher.update(event_type.as_bytes());
        hasher.update(b":");
        hasher.update(canonical.as_bytes());
        let digest = hex::encode(hasher.finalize());
        Self {
            ingest_key: digest,
            event_type,
            scope,
            session_id,
            recorded_at_ms,
            payload,
        }
    }
}

/// Normalize a DB path identically to `sulur-server/src/sidecar.rs::normalize_db_path`.
#[must_use]
pub fn normalize_db_path(db_path: &str) -> String {
    let trimmed = db_path.trim();
    let expanded = if let Some(rest) = trimmed.strip_prefix("~/") {
        dirs_home_join(rest)
    } else if trimmed == "~" {
        dirs_home_join("")
    } else {
        trimmed.to_string()
    };

    let chars: Vec<char> = expanded.chars().collect();
    let normalized =
        if chars.len() >= 3 && chars[0] == '/' && chars[2] == '/' && chars[1].is_ascii_alphabetic()
        {
            format!("{}:{}", chars[1].to_ascii_uppercase(), &expanded[2..])
        } else if chars.len() >= 5
            && chars[1] == ':'
            && chars[2] == '/'
            && chars[3].is_ascii_alphabetic()
            && chars[4] == '/'
        {
            format!("{}{}", &expanded[..2], &expanded[4..])
        } else {
            expanded
        };

    let is_win_abs = normalized.len() >= 2
        && normalized.as_bytes()[0].is_ascii_alphabetic()
        && normalized.as_bytes()[1] == b':';

    if is_win_abs {
        return normalized.replace('/', "\\");
    }
    let path = Path::new(&normalized);
    if path.is_absolute() {
        return normalized;
    }
    std::path::absolute(path)
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .into_owned()
}

fn dirs_home_join(suffix: &str) -> String {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from);
    match home {
        Some(base) if suffix.is_empty() => base.to_string_lossy().into_owned(),
        Some(base) => base.join(suffix).to_string_lossy().into_owned(),
        None => format!("~/{suffix}"),
    }
}

/// Canonical `.daemon.json` descriptor path for `db_path`.
#[must_use]
pub fn sidecar_path(db_path: &str) -> PathBuf {
    PathBuf::from(format!("{}.daemon.json", normalize_db_path(db_path)))
}

/// Resolve canonical `.spool.jsonl` path (respecting `override_path` if set).
#[must_use]
pub fn canonical_spool_path(db_path: &str, spool_cfg: &SpoolConfig) -> PathBuf {
    if let Some(ref custom) = spool_cfg.override_path {
        return custom.clone();
    }
    PathBuf::from(format!("{}.spool.jsonl", normalize_db_path(db_path)))
}

/// Compiled secret & control-character scrubber (`Constitution Tech & Security Constraints`).
fn secret_patterns() -> &'static [Regex] {
    static PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        [
            r"(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*",
            r"\bsk-[A-Za-z0-9]{16,}\b",
            r"\bgh[pousr]_[A-Za-z0-9]{20,}\b",
            r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
            r"\\\\\.\\pipe\\zeroclaw-herdr-[^\s]+",
            r"/tmp/zc-herdr-[^\s]+\.sock",
        ]
        .into_iter()
        .filter_map(|pat| Regex::new(pat).ok())
        .collect()
    })
}

/// Sanitize untrusted PTY/Discord text and strip any daemon tokens, socket paths, or common secrets
/// BEFORE persistence to wire `remember`/`patch` or `.spool.jsonl` (`C2`).
#[must_use]
pub fn sanitize_and_redact_text(raw: &str, extra_secrets: &[&str]) -> String {
    let mut cleaned: String = raw
        .chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .collect();

    for secret in extra_secrets {
        let trimmed = secret.trim();
        if !trimmed.is_empty() && trimmed.len() >= 4 {
            cleaned = cleaned.replace(trimmed, "[REDACTED]");
        }
    }

    for re in secret_patterns() {
        cleaned = re.replace_all(&cleaned, "[REDACTED]").into_owned();
    }

    if let Ok(herdr_sock) = std::env::var("HERDR_SOCKET_PATH")
        && !herdr_sock.trim().is_empty()
    {
        cleaned = cleaned.replace(herdr_sock.trim(), "[REDACTED_SOCKET]");
    }

    cleaned
}

/// Encode `req` into a 4-byte LE length-prefixed JSON frame (`MAX_FRAME_SIZE` bounded).
///
/// # Errors
/// Returns [`HarnessError::Wire`] if JSON serialization fails or exceeds `MAX_FRAME_SIZE`.
pub fn encode_wire_frame(req: &WireRequest) -> HarnessResult<Vec<u8>> {
    let payload = serde_json::to_vec(req).map_err(|err| HarnessError::Wire {
        reason: format!("failed serializing WireRequest: {err}"),
    })?;
    if payload.len() > MAX_FRAME_SIZE {
        return Err(HarnessError::Wire {
            reason: format!("wire request frame exceeds {MAX_FRAME_SIZE} bytes"),
        });
    }
    let len_u32 = u32::try_from(payload.len()).map_err(|_| HarnessError::Wire {
        reason: "wire frame length overflows u32".to_string(),
    })?;
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&len_u32.to_le_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

/// Send a single length-prefixed `WireRequest` over loopback TCP and decode `WireResponse`.
///
/// # Errors
/// Returns [`HarnessError::DaemonUnavailable`] on TCP connect/I/O failure, or
/// [`HarnessError::Wire`] on timeout, framing overflow, or invalid response JSON.
pub async fn send_wire_frame(
    host: &str,
    port: u16,
    req: &WireRequest,
    connect_timeout: Duration,
    request_timeout: Duration,
) -> HarnessResult<WireResponse> {
    let frame = encode_wire_frame(req)?;
    let addr = format!("{host}:{port}");

    let fut = async move {
        let mut stream = tokio::time::timeout(connect_timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| HarnessError::DaemonUnavailable {
                reason: format!("TCP connect timeout to sulur-server at {addr}"),
            })?
            .map_err(|err| HarnessError::DaemonUnavailable {
                reason: format!("TCP connect error to sulur-server at {addr}: {err}"),
            })?;

        stream
            .write_all(&frame)
            .await
            .map_err(|err| HarnessError::DaemonUnavailable {
                reason: format!("failed writing wire request to {addr}: {err}"),
            })?;
        stream
            .flush()
            .await
            .map_err(|err| HarnessError::DaemonUnavailable {
                reason: format!("failed flushing wire request to {addr}: {err}"),
            })?;

        let mut len_buf = [0_u8; 4];
        stream
            .read_exact(&mut len_buf)
            .await
            .map_err(|err| HarnessError::Wire {
                reason: format!("failed reading response frame length from {addr}: {err}"),
            })?;
        let resp_len =
            usize::try_from(u32::from_le_bytes(len_buf)).map_err(|_| HarnessError::Wire {
                reason: "wire frame length conversion overflow".to_string(),
            })?;
        if resp_len == 0 || resp_len > MAX_FRAME_SIZE {
            return Err(HarnessError::Wire {
                reason: format!("invalid response frame size: {resp_len}"),
            });
        }

        let mut body = vec![0_u8; resp_len];
        stream
            .read_exact(&mut body)
            .await
            .map_err(|err| HarnessError::Wire {
                reason: format!("failed reading response body from {addr}: {err}"),
            })?;
        serde_json::from_slice::<WireResponse>(&body).map_err(|err| HarnessError::Wire {
            reason: format!("malformed WireResponse JSON: {err}"),
        })
    };

    tokio::time::timeout(request_timeout, fut)
        .await
        .map_err(|_| HarnessError::Wire {
            reason: format!(
                "sulur-server RPC timed out after {} ms",
                request_timeout.as_millis()
            ),
        })?
}

/// Out-of-process wire client & lossless spool manager for `sulur-server`.
#[derive(Clone)]
pub struct SulurBridge {
    config: SulurHarnessConfig,
    sidecar: Arc<RwLock<Option<SidecarDescriptor>>>,
    client_name: String,
    turn_counter: Arc<std::sync::atomic::AtomicU64>,
}

impl std::fmt::Debug for SulurBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SulurBridge")
            .field("db_path", &self.config.db_path)
            .field("sidecar_mode", &self.config.sidecar_mode)
            .field("client_name", &self.client_name)
            .finish()
    }
}

impl SulurBridge {
    /// Construct a new [`SulurBridge`] bound to `config`.
    #[must_use]
    pub fn new(config: SulurHarnessConfig) -> Self {
        Self {
            config,
            sidecar: Arc::new(RwLock::new(None)),
            client_name: "zeroclaw-harness".to_string(),
            turn_counter: Arc::new(std::sync::atomic::AtomicU64::new(1)),
        }
    }

    /// Borrow underlying config.
    #[must_use]
    pub const fn config(&self) -> &SulurHarnessConfig {
        &self.config
    }

    /// Canonical normalized DB path string.
    #[must_use]
    pub fn normalized_db(&self) -> String {
        normalize_db_path(&self.config.db_path.to_string_lossy())
    }

    /// Canonical `.spool.jsonl` path.
    #[must_use]
    pub fn spool_path(&self) -> PathBuf {
        canonical_spool_path(&self.normalized_db(), &self.config.spool)
    }

    /// Attach a pre-known [`SidecarDescriptor`] (primarily for tests targeting mock daemons).
    pub async fn set_sidecar_for_test(&self, descriptor: SidecarDescriptor) {
        let mut guard = self.sidecar.write().await;
        *guard = Some(descriptor);
    }

    /// Discover `<normalized_db>.daemon.json`, probe `"ping"`, and optionally auto-boot
    /// a detached `sulur-server` child when `sidecar_mode == SidecarMode::ManagedSidecar`.
    ///
    /// # Errors
    /// Fails loudly (`HarnessError::DaemonUnavailable`) when unreachable/stale in `ExternalOnly` mode
    /// or when managed startup does not become healthy within 5 seconds.
    pub async fn ensure_daemon(&self) -> HarnessResult<SidecarDescriptor> {
        if let Some(existing) = self.sidecar.read().await.clone()
            && self.probe_ping(&existing).await.is_ok()
        {
            return Ok(existing);
        }

        let sc_path = sidecar_path(&self.normalized_db());
        if let Ok(Some(desc)) = read_sidecar_descriptor(sc_path.clone()).await
            && desc.protocol == WIRE_PROTOCOL_TAG
            && !desc.token.trim().is_empty()
            && self.probe_ping(&desc).await.is_ok()
        {
            *self.sidecar.write().await = Some(desc.clone());
            return Ok(desc);
        }

        if self.config.sidecar_mode == SidecarMode::ExternalOnly {
            return Err(HarnessError::DaemonUnavailable {
                reason: format!(
                    "no responsive `{WIRE_PROTOCOL_TAG}` daemon found at {} (`ExternalOnly` mode)",
                    sc_path.display()
                ),
            });
        }

        let bin = self
            .config
            .sulur_server_bin
            .clone()
            .unwrap_or_else(|| PathBuf::from("sulur-server"));
        let norm_db = self.normalized_db();
        spawn_detached_sulur_server(bin, norm_db).await?;

        // Poll `<db>.daemon.json` + ping with exponential backoff (`100ms -> 2000ms`, ~5s ceiling).
        let mut backoff_ms = 100_u64;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while tokio::time::Instant::now() < deadline {
            if let Ok(Some(desc)) = read_sidecar_descriptor(sc_path.clone()).await
                && desc.protocol == WIRE_PROTOCOL_TAG
                && !desc.token.trim().is_empty()
                && self.probe_ping(&desc).await.is_ok()
            {
                *self.sidecar.write().await = Some(desc.clone());
                return Ok(desc);
            }
            tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
            backoff_ms = (backoff_ms * 2).min(2_000);
        }

        Err(HarnessError::DaemonUnavailable {
            reason: format!(
                "timed out waiting for `sulur-server` sidecar `{}` to answer ping",
                sc_path.display()
            ),
        })
    }

    async fn probe_ping(&self, desc: &SidecarDescriptor) -> HarnessResult<()> {
        let req = WireRequest {
            op: Some("ping".to_string()),
            client_name: Some(self.client_name.clone()),
            token: Some(desc.token.clone()),
            ..WireRequest::default()
        };
        let resp = send_wire_frame(
            &desc.host,
            desc.port,
            &req,
            Duration::from_millis(self.config.connect_timeout_ms.max(50)),
            Duration::from_millis(self.config.request_timeout_ms.max(100)),
        )
        .await?;
        if resp.success && resp.message.as_deref() == Some("pong") {
            Ok(())
        } else {
            Err(HarnessError::DaemonUnavailable {
                reason: resp
                    .error_message
                    .unwrap_or_else(|| "ping rejected by sulur-server".to_string()),
            })
        }
    }

    /// Execute a raw wire operation with active sidecar token injection.
    ///
    /// # Errors
    /// Propagates [`HarnessError::DaemonUnavailable`] or [`HarnessError::Wire`] on failure or `success == false`.
    pub async fn call_op(&self, mut req: WireRequest) -> HarnessResult<WireResponse> {
        let desc = self.ensure_daemon().await?;
        req.client_name = Some(self.client_name.clone());
        req.token = Some(desc.token.clone());

        let resp = send_wire_frame(
            &desc.host,
            desc.port,
            &req,
            Duration::from_millis(self.config.connect_timeout_ms.max(50)),
            Duration::from_millis(self.config.request_timeout_ms.max(100)),
        )
        .await;

        match resp {
            Ok(r) if r.success => Ok(r),
            Ok(r) => Err(HarnessError::Wire {
                reason: r
                    .error_message
                    .unwrap_or_else(|| "sulur-server returned success=false".to_string()),
            }),
            Err(err) => {
                // Invalidate cached descriptor if transport failed so next call re-discovers.
                if matches!(err, HarnessError::DaemonUnavailable { .. }) {
                    *self.sidecar.write().await = None;
                }
                Err(err)
            }
        }
    }

    /// Sanitize & redact a string using any currently loaded daemon token + compiled secret rules.
    pub async fn scrub_untrusted_text(&self, raw: &str) -> String {
        let active_token = self.sidecar.read().await.as_ref().map(|d| d.token.clone());
        match active_token {
            Some(tok) => sanitize_and_redact_text(raw, &[tok.as_str()]),
            None => sanitize_and_redact_text(raw, &[]),
        }
    }

    /// Invoke `"briefing"` wire op returning rendered markdown + continuity notice.
    ///
    /// # Errors
    /// Propagates transport or wire errors.
    pub async fn briefing(
        &self,
        scope: &str,
        session_id: Option<&str>,
        budget: usize,
    ) -> HarnessResult<String> {
        let mut params = Map::new();
        params.insert("scope".to_string(), json!(scope));
        params.insert("budget".to_string(), json!(budget));
        if let Some(sess) = session_id {
            params.insert("session_id".to_string(), json!(sess));
        }
        let resp = self
            .call_op(WireRequest {
                op: Some("briefing".to_string()),
                params: Some(params),
                ..WireRequest::default()
            })
            .await?;
        Ok(resp.message.unwrap_or_default())
    }

    /// Invoke `"recall"` wire op with explicit parameters matching `wire/mod.rs:handle_recall`.
    ///
    /// # Errors
    /// Propagates transport or wire errors.
    pub async fn recall(
        &self,
        query: &str,
        scope: Option<&str>,
        limit: usize,
        enhanced: bool,
        explain: bool,
    ) -> HarnessResult<WireResponse> {
        let mut params = Map::new();
        params.insert("limit".to_string(), json!(limit.max(1)));
        params.insert("enhanced".to_string(), json!(enhanced));
        params.insert("explain".to_string(), json!(explain));
        params.insert("include_expired".to_string(), json!(false));
        params.insert("include_superseded".to_string(), json!(false));
        if let Some(sc) = scope.filter(|s| !s.trim().is_empty()) {
            params.insert("scope".to_string(), json!(sc));
        }
        self.call_op(WireRequest {
            op: Some("recall".to_string()),
            query: query.to_string(),
            params: Some(params),
            ..WireRequest::default()
        })
        .await
    }

    /// Persist a sanitized memory entry via `"remember"`, returning created memory ID.
    ///
    /// # Errors
    /// Returns [`HarnessError::DaemonUnavailable`] or [`HarnessError::Wire`] when `sulur-server` rejects/times out.
    pub async fn remember(
        &self,
        content: &str,
        scope: &str,
        label: &str,
        session_id: Option<&str>,
        profile: Option<&str>,
        salience: f64,
    ) -> HarnessResult<i64> {
        let scrubbed = self.scrub_untrusted_text(content).await;
        let mut params = Map::new();
        params.insert("label".to_string(), json!(label));
        params.insert("salience".to_string(), json!(salience));
        params.insert("scope".to_string(), json!(scope));
        params.insert("tier".to_string(), json!("episodic"));
        params.insert("protected".to_string(), json!(false));
        if let Some(sess) = session_id {
            params.insert("session_id".to_string(), json!(sess));
        }
        if let Some(prof) = profile {
            params.insert("profile".to_string(), json!(prof));
        }

        let resp = self
            .call_op(WireRequest {
                op: Some("remember".to_string()),
                query: scrubbed,
                params: Some(params),
                ..WireRequest::default()
            })
            .await?;

        let id = resp
            .rows
            .first()
            .and_then(|row| row.first())
            .and_then(|cell| cell.as_ref())
            .and_then(Value::as_i64)
            .unwrap_or(0);
        Ok(id)
    }

    /// Apply a CAS-guarded section update via `"patch"`.
    ///
    /// # Errors
    /// Returns [`HarnessError::Wire`] explicitly on stale `expected_content_hash`/`expected_revision_id` (Fail Loud).
    pub async fn patch(&self, op: &CasPatchOperation) -> HarnessResult<WireResponse> {
        let scrubbed_content = self.scrub_untrusted_text(&op.content).await;
        let mut params = Map::new();
        params.insert("memory_id".to_string(), json!(op.memory_id));
        params.insert("operation".to_string(), json!(op.operation));
        params.insert("section_heading".to_string(), json!(op.section_heading));
        if let Some(order) = op.section_order {
            params.insert("section_order".to_string(), json!(order));
        }
        params.insert("content".to_string(), json!(scrubbed_content));
        if let Some(ref hash) = op.expected_content_hash {
            params.insert("expected_content_hash".to_string(), json!(hash));
        }
        if let Some(rev) = op.expected_revision_id {
            params.insert("expected_revision_id".to_string(), json!(rev));
        }
        params.insert("actor_role".to_string(), json!(op.actor_role));

        self.call_op(WireRequest {
            op: Some("patch".to_string()),
            params: Some(params),
            ..WireRequest::default()
        })
        .await
    }

    /// Create an offered continuity handoff ticket (`"handoff_begin"`).
    ///
    /// # Errors
    /// Propagates transport/wire errors.
    pub async fn handoff_begin(
        &self,
        payload: &CrossToolHandoffPayload,
    ) -> HarnessResult<CrossToolHandoffPayload> {
        let scrubbed_milestone = self.scrub_untrusted_text(&payload.milestone).await;
        let mut params = Map::new();
        params.insert("scope".to_string(), json!(payload.scope));
        params.insert("milestone".to_string(), json!(scrubbed_milestone));
        params.insert(
            "unblocked_next_steps".to_string(),
            json!(payload.unblocked_next_steps),
        );
        params.insert("modified_files".to_string(), json!(payload.modified_files));
        params.insert("session_id".to_string(), json!(payload.source_session_id));

        let resp = self
            .call_op(WireRequest {
                op: Some("handoff_begin".to_string()),
                params: Some(params),
                ..WireRequest::default()
            })
            .await?;
        let parsed = resp
            .rows
            .first()
            .and_then(|row| parse_handoff_row(row, &payload.workspace_path, &payload.source_agent))
            .unwrap_or_else(|| payload.clone());
        Ok(parsed)
    }

    /// List offered or claimed continuity handoff tickets (`"handoff_list"`).
    ///
    /// # Errors
    /// Propagates transport/wire errors.
    pub async fn handoff_list(
        &self,
        scope: &str,
        status: &str,
        workspace_hint: &Path,
    ) -> HarnessResult<Vec<CrossToolHandoffPayload>> {
        let mut params = Map::new();
        params.insert("scope".to_string(), json!(scope));
        params.insert("status".to_string(), json!(status));
        let resp = self
            .call_op(WireRequest {
                op: Some("handoff_list".to_string()),
                params: Some(params),
                ..WireRequest::default()
            })
            .await?;
        Ok(resp
            .rows
            .iter()
            .filter_map(|row| parse_handoff_row(row, workspace_hint, "external"))
            .collect())
    }

    /// Atomically claim an offered handoff ticket (`"handoff_accept"`).
    ///
    /// # Errors
    /// Propagates transport/wire errors.
    pub async fn handoff_accept(
        &self,
        ticket_id: &str,
        session_id: &str,
        workspace_hint: &Path,
    ) -> HarnessResult<CrossToolHandoffPayload> {
        let mut params = Map::new();
        params.insert("ticket_id".to_string(), json!(ticket_id));
        params.insert("session_id".to_string(), json!(session_id));
        let resp = self
            .call_op(WireRequest {
                op: Some("handoff_accept".to_string()),
                params: Some(params),
                ..WireRequest::default()
            })
            .await?;
        resp.rows
            .first()
            .and_then(|row| parse_handoff_row(row, workspace_hint, "external"))
            .ok_or_else(|| HarnessError::Wire {
                reason: "handoff_accept succeeded without returning ticket row".to_string(),
            })
    }

    /// Send an idempotent cross-project message (`"message_send"`).
    ///
    /// # Errors
    /// Propagates transport/wire errors.
    pub async fn message_send(&self, msg: &CrossProjectMessageWire) -> HarnessResult<WireResponse> {
        let scrubbed_body = self.scrub_untrusted_text(&msg.body).await;
        let evidence_strings: Vec<String> = msg
            .evidence
            .iter()
            .filter_map(|ev| serde_json::to_string(ev).ok())
            .collect();
        let mut params = Map::new();
        params.insert("to_scope".to_string(), json!(msg.to_scope));
        params.insert("body".to_string(), json!(scrubbed_body));
        params.insert("message_id".to_string(), json!(msg.message_id));
        params.insert("target_harness".to_string(), json!(msg.target_harness));
        if !evidence_strings.is_empty() {
            params.insert("evidence".to_string(), json!(evidence_strings));
        }

        self.call_op(WireRequest {
            op: Some("message_send".to_string()),
            params: Some(params),
            ..WireRequest::default()
        })
        .await
    }

    /// List cross-project messages (`"message_list"`).
    ///
    /// # Errors
    /// Propagates transport/wire errors.
    pub async fn message_list(
        &self,
        status: &str,
        target_harness: &str,
        limit: usize,
    ) -> HarnessResult<Vec<CrossProjectMessageWire>> {
        let mut params = Map::new();
        params.insert("status".to_string(), json!(status));
        params.insert("target_harness".to_string(), json!(target_harness));
        params.insert("limit".to_string(), json!(limit.clamp(1, 1000)));
        let resp = self
            .call_op(WireRequest {
                op: Some("message_list".to_string()),
                params: Some(params),
                ..WireRequest::default()
            })
            .await?;
        Ok(resp
            .rows
            .iter()
            .filter_map(|row| parse_message_row(row))
            .collect())
    }

    /// Atomically pop one pending cross-project message (`"message_pop"`).
    ///
    /// # Errors
    /// Propagates transport/wire errors.
    pub async fn message_pop(
        &self,
        target_harness: &str,
    ) -> HarnessResult<Option<CrossProjectMessageWire>> {
        let mut params = Map::new();
        params.insert("target_harness".to_string(), json!(target_harness));
        let resp = self
            .call_op(WireRequest {
                op: Some("message_pop".to_string()),
                params: Some(params),
                ..WireRequest::default()
            })
            .await?;
        Ok(resp.rows.first().and_then(|row| parse_message_row(row)))
    }

    /// Control `sulur-server`'s 7-phase Dream Engine (`"dream_control"`).
    ///
    /// # Errors
    /// Propagates transport/wire errors.
    pub async fn dream_control(&self, action: &str) -> HarnessResult<WireResponse> {
        self.call_op(WireRequest {
            op: Some("dream_control".to_string()),
            action: Some(action.to_string()),
            ..WireRequest::default()
        })
        .await
    }

    /// Invoke `"wiki_sync"` wire op (`"export"` or `"import"`) without holding external `akar.lock`.
    ///
    /// # Errors
    /// Propagates transport/wire errors.
    pub async fn wiki_sync(&self, action: &str, wiki_dir: &Path) -> HarnessResult<WireResponse> {
        self.call_op(WireRequest {
            op: Some("wiki_sync".to_string()),
            action: Some(action.to_string()),
            path: Some(wiki_dir.to_string_lossy().into_owned()),
            ..WireRequest::default()
        })
        .await
    }

    /// Append a sanitized [`LifecycleSpoolRecord`] atomically to `<normalized_db>.spool.jsonl`.
    ///
    /// Enforces `MAX_SPOOL_LINES` (`4096`) and `config.spool.max_spool_bytes` (`64 MiB`).
    ///
    /// # Errors
    /// Returns [`HarnessError::Wire`] if spool capacity limits are exceeded or [`HarnessError::Io`] on disk failure.
    pub async fn append_spool(&self, mut record: LifecycleSpoolRecord) -> HarnessResult<()> {
        let scrubbed_payload = self.scrub_json_value(&record.payload).await;
        record.payload = scrubbed_payload;
        let path = self.spool_path();
        let max_bytes = self.config.spool.max_spool_bytes;
        let line = serde_json::to_string(&record).map_err(|err| HarnessError::Wire {
            reason: format!("failed serializing LifecycleSpoolRecord: {err}"),
        })?;

        tokio::task::spawn_blocking(move || append_spool_line_sync(&path, &line, max_bytes))
            .await
            .map_err(|err| HarnessError::Wire {
                reason: format!("spool append task panicked/cancelled: {err}"),
            })?
    }

    /// Persist a turn note over wire `remember`, transparently falling back to `.spool.jsonl`
    /// when `sulur-server` is busy/unreachable (`FR-010`, `SC-004`).
    ///
    /// # Errors
    /// Only returns error if BOTH wire write and `.spool.jsonl` fallback fail.
    pub async fn remember_or_spool(
        &self,
        content: &str,
        scope: &str,
        label: &str,
        session_id: &str,
        profile: Option<&str>,
    ) -> HarnessResult<bool> {
        let scrubbed = self.scrub_untrusted_text(content).await;
        match self
            .remember(&scrubbed, scope, label, Some(session_id), profile, 0.85)
            .await
        {
            Ok(_) => Ok(true),
            Err(err) => {
                let seq = self
                    .turn_counter
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                ::zeroclaw_log::record!(
                    WARN,
                    ::zeroclaw_log::Event::new("harness.sulur.spool", ::zeroclaw_log::Action::Note)
                        .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                        .with_attrs(json!({
                            "session_id": session_id,
                            "scope": scope,
                            "reason": err.to_string(),
                        })),
                    "sulur-server unavailable/busy; spooling lifecycle event losslessly"
                );
                let rec = LifecycleSpoolRecord::new(
                    session_id,
                    scope,
                    "PostTurnSummary",
                    seq,
                    now_epoch_ms(),
                    json!({
                        "label": label,
                        "profile": profile,
                        "content": scrubbed,
                    }),
                );
                self.append_spool(rec).await?;
                Ok(false)
            }
        }
    }

    /// Count queued lines currently awaiting drain in `<normalized_db>.spool.jsonl`.
    pub async fn pending_spool_count(&self) -> usize {
        let path = self.spool_path();
        tokio::task::spawn_blocking(move || match fs::read_to_string(&path) {
            Ok(txt) => txt.lines().filter(|l| !l.trim().is_empty()).count(),
            Err(_) => 0,
        })
        .await
        .unwrap_or(0)
    }

    async fn scrub_json_value(&self, value: &Value) -> Value {
        match value {
            Value::String(s) => Value::String(self.scrub_untrusted_text(s).await),
            Value::Array(arr) => {
                let mut out = Vec::with_capacity(arr.len());
                for item in arr {
                    out.push(Box::pin(self.scrub_json_value(item)).await);
                }
                Value::Array(out)
            }
            Value::Object(map) => {
                let mut out = Map::with_capacity(map.len());
                for (k, v) in map {
                    out.insert(k.clone(), Box::pin(self.scrub_json_value(v)).await);
                }
                Value::Object(out)
            }
            other => other.clone(),
        }
    }
}

fn append_spool_line_sync(path: &Path, json_line: &str, max_bytes: u64) -> HarnessResult<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|source| HarnessError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }

    if path.exists() {
        let meta = fs::metadata(path).map_err(|source| HarnessError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let projected_bytes = meta.len().saturating_add(json_line.len() as u64 + 1);
        if projected_bytes > max_bytes {
            return Err(HarnessError::Wire {
                reason: format!(
                    "spool file `{}` exceeded max_spool_bytes ({max_bytes})",
                    path.display()
                ),
            });
        }
        let existing = fs::read_to_string(path).map_err(|source| HarnessError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let line_count = existing.lines().filter(|l| !l.trim().is_empty()).count();
        if line_count >= MAX_SPOOL_LINES {
            return Err(HarnessError::Wire {
                reason: format!(
                    "spool file `{}` reached {MAX_SPOOL_LINES}-line safety cap",
                    path.display()
                ),
            });
        }
    }

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|source| HarnessError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    writeln!(file, "{json_line}").map_err(|source| HarnessError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    file.flush().map_err(|source| HarnessError::Io {
        path: path.to_path_buf(),
        source,
    })
}

async fn read_sidecar_descriptor(path: PathBuf) -> HarnessResult<Option<SidecarDescriptor>> {
    tokio::task::spawn_blocking(move || {
        if !path.exists() {
            return Ok(None);
        }
        let raw = fs::read_to_string(&path).map_err(|source| HarnessError::Io {
            path: path.clone(),
            source,
        })?;
        match serde_json::from_str::<SidecarDescriptor>(&raw) {
            Ok(desc) => Ok(Some(desc)),
            Err(_) => Ok(None),
        }
    })
    .await
    .map_err(|err| HarnessError::DaemonUnavailable {
        reason: format!("sidecar read task cancelled: {err}"),
    })?
}

async fn spawn_detached_sulur_server(bin: PathBuf, normalized_db: String) -> HarnessResult<()> {
    tokio::task::spawn_blocking(move || {
        let mut cmd = Command::new(&bin);
        cmd.args(["start", "--db", &normalized_db])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const DETACHED_PROCESS: u32 = 0x0000_0008;
            const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
            cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
        }

        cmd.spawn()
            .map(|_| ())
            .map_err(|err| HarnessError::DaemonUnavailable {
                reason: format!(
                    "failed spawning `{}` start --db {}: {err}",
                    bin.display(),
                    normalized_db
                ),
            })
    })
    .await
    .map_err(|err| HarnessError::DaemonUnavailable {
        reason: format!("sidecar spawn task panicked: {err}"),
    })?
}

fn parse_handoff_row(
    row: &[Option<Value>],
    workspace_hint: &Path,
    default_agent: &str,
) -> Option<CrossToolHandoffPayload> {
    let ticket_id = row.first()?.as_ref()?.as_str()?.to_string();
    let scope = row.get(1)?.as_ref()?.as_str()?.to_string();
    let milestone = row.get(2)?.as_ref()?.as_str()?.to_string();
    let steps_str = row
        .get(3)
        .and_then(|v| v.as_ref())
        .and_then(Value::as_str)
        .unwrap_or("[]");
    let files_str = row
        .get(4)
        .and_then(|v| v.as_ref())
        .and_then(Value::as_str)
        .unwrap_or("[]");
    let status = row
        .get(5)
        .and_then(|v| v.as_ref())
        .and_then(Value::as_str)
        .unwrap_or("offered")
        .to_string();
    let offered_by = row
        .get(6)
        .and_then(|v| v.as_ref())
        .and_then(Value::as_str)
        .unwrap_or("session")
        .to_string();
    let created_at = row
        .get(8)
        .and_then(|v| v.as_ref())
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let claimed_at = row.get(9).and_then(|v| v.as_ref()).and_then(Value::as_i64);

    let unblocked_next_steps: Vec<String> = serde_json::from_str(steps_str).unwrap_or_default();
    let modified_files: Vec<String> = serde_json::from_str(files_str).unwrap_or_default();

    Some(CrossToolHandoffPayload {
        ticket_id: Some(ticket_id),
        scope,
        source_session_id: offered_by,
        source_agent: default_agent.to_string(),
        target_harness: None,
        workspace_path: workspace_hint.to_path_buf(),
        git_branch: None,
        milestone,
        unblocked_next_steps,
        modified_files,
        status,
        created_at,
        claimed_at,
    })
}

fn parse_message_row(row: &[Option<Value>]) -> Option<CrossProjectMessageWire> {
    let message_id = row.first()?.as_ref()?.as_str()?.to_string();
    let from_scope = row.get(1)?.as_ref()?.as_str()?.to_string();
    let to_scope = row.get(2)?.as_ref()?.as_str()?.to_string();
    let target_harness = row
        .get(3)
        .and_then(|v| v.as_ref())
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let body = row.get(4)?.as_ref()?.as_str()?.to_string();
    let ev_str = row
        .get(5)
        .and_then(|v| v.as_ref())
        .and_then(Value::as_str)
        .unwrap_or("[]");
    let evidence: Vec<MessageEvidenceRef> = serde_json::from_str(ev_str).unwrap_or_default();
    let status = row
        .get(6)
        .and_then(|v| v.as_ref())
        .and_then(Value::as_str)
        .unwrap_or("pending")
        .to_string();
    let created_at = row
        .get(7)
        .and_then(|v| v.as_ref())
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let claimed_at = row.get(8).and_then(|v| v.as_ref()).and_then(Value::as_i64);

    Some(CrossProjectMessageWire {
        message_id,
        from_scope,
        to_scope,
        target_harness,
        body,
        evidence,
        status,
        created_at,
        claimed_at,
    })
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

/// Format recalled JSON rows or `results` array into concise summary strings (`content`, `score`, `channel`).
#[must_use]
pub fn extract_recall_lines(resp: &WireResponse) -> Vec<BTreeMap<String, String>> {
    let mut out = Vec::new();
    if let Some(ref items) = resp.results {
        for item in items {
            let mut m = BTreeMap::new();
            let id = item
                .get("memory_id")
                .or_else(|| item.get("id"))
                .and_then(Value::as_i64)
                .map(|v| v.to_string())
                .unwrap_or_default();
            let content = item
                .get("body")
                .or_else(|| item.get("content"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let label = item
                .get("label")
                .and_then(Value::as_str)
                .unwrap_or("memory")
                .to_string();
            let channel = item
                .get("channel")
                .and_then(Value::as_str)
                .unwrap_or("recall")
                .to_string();
            let score = item
                .get("score")
                .and_then(Value::as_f64)
                .map(|s| format!("{s:.2}"))
                .unwrap_or_default();
            m.insert("id".to_string(), id);
            m.insert("label".to_string(), label);
            m.insert("content".to_string(), content);
            m.insert("channel".to_string(), channel);
            m.insert("score".to_string(), score);
            out.push(m);
        }
        return out;
    }

    for row in &resp.rows {
        let id = row
            .first()
            .and_then(|v| v.as_ref())
            .and_then(Value::as_i64)
            .map(|v| v.to_string())
            .unwrap_or_default();
        let label = row
            .get(1)
            .and_then(|v| v.as_ref())
            .and_then(Value::as_str)
            .unwrap_or("memory")
            .to_string();
        let content = row
            .get(2)
            .and_then(|v| v.as_ref())
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let score = row
            .get(3)
            .and_then(|v| v.as_ref())
            .and_then(Value::as_f64)
            .map(|s| format!("{s:.2}"))
            .unwrap_or_default();
        let channel = row
            .get(5)
            .and_then(|v| v.as_ref())
            .and_then(Value::as_str)
            .unwrap_or("recall")
            .to_string();
        if !content.is_empty() {
            let mut m = BTreeMap::new();
            m.insert("id".to_string(), id);
            m.insert("label".to_string(), label);
            m.insert("content".to_string(), content);
            m.insert("channel".to_string(), channel);
            m.insert("score".to_string(), score);
            out.push(m);
        }
    }
    out
}
