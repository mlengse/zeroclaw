//! Capabilities built from config by today's `create_*` factories.
//!
//! These sources reproduce the construction the entry points performed inline
//! before they took capabilities, so an adapter that routes through them
//! builds the same provider, memory and observer it did before. They are
//! public through [`super::defaults`] so the application layer composes the
//! same recipe instead of copying it.

use std::sync::Arc;

use async_trait::async_trait;
use zeroclaw_api::channel::Channel;
use zeroclaw_api::memory_traits::Memory;
use zeroclaw_api::model_provider::ModelProvider;
use zeroclaw_api::tool::Tool;
use zeroclaw_config::schema::Config;

use super::{
    ChannelSource, MemoryRequest, MemorySource, NativeRegistryRecipe, ProviderRequest,
    ProviderSource, RuntimeCapabilities, ToolRequest, ToolSource,
};

pub(super) fn capabilities_with_observer(
    observer: Arc<dyn zeroclaw_api::observability_traits::Observer>,
) -> RuntimeCapabilities {
    RuntimeCapabilities {
        providers: Arc::new(ConfigProviders),
        memory: Arc::new(ConfigMemory),
        tools: Arc::new(NoSuppliedTools),
        channels: Arc::new(NoOutboundChannels),
        observer,
    }
}

pub(super) fn capabilities(config: &Config) -> RuntimeCapabilities {
    capabilities_with_observer(Arc::from(crate::observability::create_observer(
        &config.observability,
    )))
}

pub(super) fn unobserved_capabilities() -> RuntimeCapabilities {
    capabilities_with_observer(Arc::new(crate::observability::NoopObserver))
}

/// Builds the routed, resilient provider the turn loop and the agent built,
/// and the agent's config-snapshot provider on a model switch.
pub struct ConfigProviders;

impl ProviderSource for ConfigProviders {
    fn model_provider(
        &self,
        request: &ProviderRequest<'_>,
    ) -> anyhow::Result<Arc<dyn ModelProvider>> {
        let config = request.config;
        let agent_entry = config.resolved_model_provider_for_agent(request.agent_alias);
        let provider_ref = match request.provider_ref {
            Some(provider_ref) => provider_ref.to_string(),
            None => agent_entry
                .map(|(family, alias, _)| format!("{family}.{alias}"))
                .ok_or_else(|| {
                    anyhow::Error::msg(format!(
                        "agents.{}.model_provider does not resolve to a configured \
                         [providers.models.<type>.<alias>] entry",
                        request.agent_alias
                    ))
                })?,
        };
        let target_entry = provider_ref
            .split_once('.')
            .and_then(|(family, alias)| config.providers.models.find(family, alias));
        let model = request
            .model
            .map(str::to_string)
            .or_else(|| {
                target_entry
                    .and_then(|entry| entry.model.as_deref())
                    .map(str::trim)
                    .filter(|model| !model.is_empty())
                    .map(str::to_string)
            })
            .ok_or_else(|| {
                anyhow::Error::msg(format!(
                    "model_provider `{provider_ref}` has no `model` configured and no model \
                     was requested"
                ))
            })?;

        // A configured target entry is the canonical source of credentials and
        // endpoint. The agent's own entry is the fallback only when the
        // reference names no configured entry, as a bare-family override does.
        let credential_entry = target_entry.or(agent_entry.map(|(_, _, entry)| entry));
        let api_key = credential_entry.and_then(|entry| entry.api_key.as_deref());
        let uri = credential_entry.and_then(|entry| entry.uri.as_deref());

        let agent_options = match agent_entry {
            Some((family, alias, _)) => {
                zeroclaw_providers::provider_runtime_options_for_alias(config, family, alias)
            }
            None => {
                zeroclaw_providers::provider_runtime_options_for_agent(config, request.agent_alias)
            }
        };
        let options =
            zeroclaw_providers::options_for_provider_ref(config, &provider_ref, &agent_options);

        let provider = zeroclaw_providers::create_routed_model_provider_with_options(
            config,
            &provider_ref,
            api_key,
            uri,
            &config.reliability,
            &config.model_routes,
            &model,
            &options,
        )?;
        Ok(Arc::from(provider))
    }

    /// The agent's config-snapshot switch recipe, so a capability-built agent
    /// on these sources switches exactly as an adapter-built agent does. It
    /// differs from a session start in two places: a matching `model_routes`
    /// credential is preferred, and a bare-family target takes only the
    /// root multimodal policy rather than the agent's other options.
    fn switched_model_provider(
        &self,
        request: &ProviderRequest<'_>,
    ) -> anyhow::Result<Arc<dyn ModelProvider>> {
        let (Some(provider_ref), Some(model)) = (request.provider_ref, request.model) else {
            return self.model_provider(request);
        };
        let (provider, _resolver) = crate::agent::agent::config_switch_provider(
            request.config,
            request.agent_alias,
            provider_ref,
            model,
        )?;
        Ok(Arc::from(provider))
    }

    /// The vision route is built through the alias-aware factory the turn's
    /// vision routing has always used, so its per-alias `vision` override,
    /// endpoint and credentials are honored exactly as before.
    fn vision_model_provider(
        &self,
        request: &ProviderRequest<'_>,
    ) -> anyhow::Result<Arc<dyn ModelProvider>> {
        let Some(provider_ref) = request.provider_ref else {
            return self.model_provider(request);
        };
        let resolved = zeroclaw_providers::create_model_provider_from_ref_with_model(
            request.config,
            provider_ref,
        )?;
        Ok(Arc::from(resolved.provider))
    }
}

#[cfg(feature = "herdr-sulur-harness")]
type SharedSulurEntry = (
    zeroclaw_config::harness::SulurHarnessConfig,
    Arc<zeroclaw_harness::SulurLifecycleManager>,
);

#[cfg(feature = "herdr-sulur-harness")]
static SHARED_SULUR_MANAGERS: std::sync::OnceLock<
    parking_lot::Mutex<std::collections::HashMap<String, SharedSulurEntry>>,
> = std::sync::OnceLock::new();

/// Return the shared [`zeroclaw_harness::SulurLifecycleManager`] for the configured Sulur DB path,
/// initializing or refreshing it when `[harness.sulur]` settings change.
#[cfg(feature = "herdr-sulur-harness")]
pub(crate) fn shared_sulur_lifecycle_manager(
    cfg: &zeroclaw_config::harness::SulurHarnessConfig,
) -> Arc<zeroclaw_harness::SulurLifecycleManager> {
    let key = zeroclaw_harness::sulur_bridge::normalize_db_path(&cfg.db_path.to_string_lossy());
    let map = SHARED_SULUR_MANAGERS
        .get_or_init(|| parking_lot::Mutex::new(std::collections::HashMap::new()));
    let mut guard = map.lock();
    if let Some((existing_cfg, existing_mgr)) = guard.get(&key)
        && existing_cfg == cfg
    {
        return Arc::clone(existing_mgr);
    }
    let bridge = Arc::new(zeroclaw_harness::SulurBridge::new(cfg.clone()));
    let mgr = Arc::new(zeroclaw_harness::SulurLifecycleManager::new(bridge));
    guard.insert(key, (cfg.clone(), Arc::clone(&mgr)));
    mgr
}

/// Opens the agent's memory with the agent provider's credential, which
/// embedding resolution inherits when `[memory]` names none of its own.
/// When `[harness.sulur].enabled` is true and the sidecar is reachable,
/// returns [`zeroclaw_harness::SulurWireMemory`] backed by the shared manager,
/// falling back gracefully to `zeroclaw_memory::create_memory_for_agent` if offline.
pub struct ConfigMemory;

#[async_trait]
impl MemorySource for ConfigMemory {
    async fn memory(&self, request: &MemoryRequest<'_>) -> anyhow::Result<Arc<dyn Memory>> {
        let api_key = request
            .config
            .resolved_model_provider_for_agent(request.agent_alias)
            .and_then(|(_, _, entry)| entry.api_key.as_deref());
        #[cfg(feature = "herdr-sulur-harness")]
        if request.config.harness.sulur.enabled {
            let sulur_cfg = &request.config.harness.sulur;
            let scope = if sulur_cfg.default_scope.trim().is_empty() {
                request.agent_alias.to_string()
            } else {
                sulur_cfg.default_scope.clone()
            };
            let manager = shared_sulur_lifecycle_manager(sulur_cfg);
            match zeroclaw_harness::HarnessLifecycleHooks::on_session_start(
                manager.as_ref(),
                &scope,
                "session",
            )
            .await
            {
                Ok(()) => {
                    return Ok(Arc::new(zeroclaw_harness::SulurWireMemory::new(
                        Arc::clone(manager.bridge()),
                        scope,
                    )));
                }
                Err(err) => {
                    ::zeroclaw_log::record!(
                        WARN,
                        ::zeroclaw_log::Event::new(
                            "harness.lifecycle.session_start",
                            ::zeroclaw_log::Action::Fail,
                        )
                        .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                        .with_attrs(::serde_json::json!({ "err": err.to_string() })),
                        "herdr-sulur sidecar unavailable; falling back to local memory backend"
                    );
                }
            }
        }
        zeroclaw_memory::create_memory_for_agent(request.config, request.agent_alias, api_key).await
    }
}

/// Every tool is still built by the runtime's own registry, so the
/// config-backed set supplies none of its own.
pub struct NoSuppliedTools;

impl ToolSource for NoSuppliedTools {
    fn native_recipe<'s>(
        &'s self,
        _request: &ToolRequest<'_>,
    ) -> anyhow::Result<Option<&'s NativeRegistryRecipe>> {
        Ok(Some(&native_compat_registry))
    }
    fn tools(&self, _request: &ToolRequest<'_>) -> anyhow::Result<Vec<Box<dyn Tool>>> {
        Ok(Vec::new())
    }
}

/// The runtime's native recipe: builds the native registry from the request's
/// config with the caller's own handles. It reads configuration facts only;
/// the policy, runtime and memory come from the request unchanged.
pub fn native_compat_registry(
    inputs: super::NativeRecipeInputs<'_>,
) -> anyhow::Result<crate::tools::AllToolsResult> {
    let super::NativeRecipeInputs {
        request,
        workspace_dir,
        canvas_store,
        is_subagent_caller,
        forwarded_environment: tui_env,
        sop_engine,
        sop_audit,
        live_config,
        execution_capability,
        acp_sessions,
    } = inputs;
    let config = request.config.as_ref();
    let risk_profile = config
        .risk_profile_for_agent(request.agent_alias)
        .ok_or_else(|| anyhow::Error::msg("native registry risk profile is not configured"))?;
    let composio_key = config
        .composio
        .enabled
        .then_some(config.composio.api_key.as_deref())
        .flatten();
    let composio_entity = config
        .composio
        .enabled
        .then_some(config.composio.entity_id.as_str());
    let fallback_key = config
        .resolved_model_provider_for_agent(request.agent_alias)
        .and_then(|(_, _, provider)| provider.api_key.as_deref());
    crate::tools::all_tools_with_runtime_context(
        Arc::clone(request.config),
        request.security,
        risk_profile,
        request.agent_alias,
        Arc::clone(request.runtime),
        Arc::clone(request.memory),
        composio_key,
        composio_entity,
        &config.browser,
        &config.http_request,
        &config.web_fetch,
        workspace_dir,
        &config.agents,
        fallback_key,
        config,
        canvas_store,
        is_subagent_caller,
        tui_env,
        sop_engine,
        sop_audit,
        live_config,
        execution_capability,
        acp_sessions,
    )
}

/// The config-backed channel source. Despite its name it serves one channel:
/// the `cli` alias, from the CLI channel factory the application registered.
/// Every other alias is `None`; outbound channels are not routed through it.
pub struct NoOutboundChannels;

impl ChannelSource for NoOutboundChannels {
    fn channel(&self, alias: &str) -> Option<Arc<dyn Channel>> {
        (alias == "cli")
            .then(|| crate::agent::loop_::CLI_CHANNEL_FN.get())
            .flatten()
            .map(|factory| Arc::from(factory()))
    }
}

#[cfg(all(test, feature = "herdr-sulur-harness"))]
mod harness_tests {
    use super::*;
    use zeroclaw_config::harness::SidecarMode;

    #[test]
    fn shared_sulur_lifecycle_manager_reuses_same_arc_per_db_path() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let mut cfg = zeroclaw_config::harness::SulurHarnessConfig::default();
        cfg.db_path = tmp.path().to_path_buf();
        cfg.enabled = true;

        let m1 = shared_sulur_lifecycle_manager(&cfg);
        let m2 = shared_sulur_lifecycle_manager(&cfg);
        assert!(Arc::ptr_eq(&m1, &m2));
    }

    #[tokio::test]
    async fn config_memory_falls_back_gracefully_when_sulur_sidecar_offline() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let mut config = Config::default();
        config.data_dir = tmp.path().join("data");
        config.memory.backend = "none".to_string();
        let mut agent_cfg = zeroclaw_config::schema::AliasedAgentConfig::default();
        agent_cfg.memory.backend = zeroclaw_config::multi_agent::MemoryBackendKind::None;
        config.agents.insert("default".to_string(), agent_cfg);
        config.harness.sulur.enabled = true;
        config.harness.sulur.sidecar_mode = SidecarMode::ExternalOnly;
        config.harness.sulur.db_path = tmp.path().join("missing-sulur-db");

        let mem = ConfigMemory
            .memory(&MemoryRequest {
                config: &config,
                agent_alias: "default",
            })
            .await
            .expect("offline sidecar must fall back gracefully");
        assert_ne!(mem.name(), "sulur-wire");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn config_memory_returns_sulur_wire_when_sidecar_responds() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let db_path = tmp.path().join("sulur.db");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let _ = listener.set_nonblocking(false);
        let port = listener.local_addr().expect("addr").port();
        let norm = zeroclaw_harness::sulur_bridge::normalize_db_path(&db_path.to_string_lossy());
        let sidecar = format!("{norm}.daemon.json");
        std::fs::write(
            &sidecar,
            serde_json::json!({
                "host": "127.0.0.1",
                "port": port,
                "token": "test-tok",
                "db_path": norm,
                "protocol": "akar-json-v1",
                "pid": 1,
                "started_at": 1.0
            })
            .to_string(),
        )
        .expect("write sidecar");

        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_flag = std::sync::Arc::clone(&stop);
        let server_thread = std::thread::spawn(move || {
            for stream in listener.incoming() {
                if stop_flag.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
                let Ok(mut stream) = stream else {
                    break;
                };
                if stop_flag.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
                std::thread::spawn(move || {
                    let mut len_buf = [0_u8; 4];
                    if stream.read_exact(&mut len_buf).is_err() {
                        return;
                    }
                    let len = u32::from_le_bytes(len_buf) as usize;
                    let mut buf = vec![0_u8; len];
                    if stream.read_exact(&mut buf).is_err() {
                        return;
                    }
                    let req: serde_json::Value = serde_json::from_slice(&buf).unwrap_or_default();
                    let resp = match req.get("op").and_then(serde_json::Value::as_str) {
                        Some("ping") => serde_json::json!({ "success": true, "message": "pong" }),
                        _ => serde_json::json!({ "success": true, "rows": [] }),
                    };
                    let body = serde_json::to_vec(&resp).expect("serialize");
                    let out_len = (body.len() as u32).to_le_bytes();
                    let _ = stream.write_all(&out_len);
                    let _ = stream.write_all(&body);
                    let _ = stream.flush();
                });
            }
        });

        let mut config = Config::default();
        config.data_dir = tmp.path().join("data");
        config.memory.backend = "none".to_string();
        let mut agent_cfg = zeroclaw_config::schema::AliasedAgentConfig::default();
        agent_cfg.memory.backend = zeroclaw_config::multi_agent::MemoryBackendKind::None;
        config.agents.insert("default".to_string(), agent_cfg);
        config.harness.sulur.enabled = true;
        config.harness.sulur.sidecar_mode = SidecarMode::ExternalOnly;
        config.harness.sulur.db_path = db_path;

        let mem = ConfigMemory
            .memory(&MemoryRequest {
                config: &config,
                agent_alias: "default",
            })
            .await
            .expect("online sidecar returns SulurWireMemory");
        assert_eq!(mem.name(), "sulur-wire");

        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = std::net::TcpStream::connect(("127.0.0.1", port));
        let _ = server_thread.join();
    }
}
