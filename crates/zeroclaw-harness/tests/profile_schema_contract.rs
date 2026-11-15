//! TDD contract & schema tests for declarative Herdr-compatible agent profiles (`T009`).

use std::path::PathBuf;
use zeroclaw_harness::detector::{
    AgentDetectionConfig, CompiledProfileRegistry, RawDetectedState, RegionSpec,
};
use zeroclaw_harness::HarnessError;

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR = <workspace>/zeroclaw/crates/zeroclaw-harness
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("zeroclaw root")
        .to_path_buf()
}

#[test]
fn vendored_profiles_match_schema_contract() {
    let detection_dir = workspace_root().join("distribution/agent-detection");
    let registry = CompiledProfileRegistry::load_from_dir(&detection_dir)
        .expect("load distribution/agent-detection/*.toml");

    // 1. OpenCode v2 profile
    let opencode = registry
        .resolve("opencode")
        .expect("opencode profile registered");
    assert_eq!(opencode.profile.id, "opencode");
    assert_eq!(opencode.profile.version, "2026.06.10.1");
    assert_eq!(opencode.profile.min_engine_version, 1);
    assert_eq!(opencode.profile.startup_grace_ms, 3_000);
    assert_eq!(opencode.profile.idle_debounce.recheck_ms, 100);
    assert_eq!(opencode.profile.idle_debounce.confirmations, 3);
    assert_eq!(opencode.profile.idle_debounce.cap_ms, 700);
    assert_eq!(opencode.profile.approval_inputs.approve_sequence, "y\r");
    assert_eq!(opencode.profile.approval_inputs.reject_sequence, "n\r");
    let ipc = opencode
        .profile
        .ipc_plugin
        .as_ref()
        .expect("opencode requires ipc_plugin metadata");
    assert_eq!(ipc.env_flag, "HERDR_ENV");
    assert_eq!(ipc.socket_env_var, "HERDR_SOCKET_PATH");
    assert_eq!(ipc.pane_id_env_var, "HERDR_PANE_ID");
    assert_eq!(opencode.rules.len(), 3);
    assert_eq!(opencode.rules[0].rule.id, "permission_required");
    assert_eq!(opencode.rules[0].rule.state, RawDetectedState::Blocked);
    assert_eq!(opencode.rules[0].rule.priority, 300);

    // Aliases for opencode
    for alias in ["open-code", "herdr:opencode", "opencode-v2"] {
        assert_eq!(
            registry.resolve(alias).map(|p| p.profile.id.as_str()),
            Some("opencode"),
            "alias `{alias}` should resolve to opencode"
        );
    }

    // 2. Antigravity CLI (`agy`) profile
    let agy = registry.resolve("agy").expect("agy profile registered");
    assert_eq!(agy.profile.id, "agy");
    assert_eq!(agy.profile.version, "2026.10.05.1");
    assert!(agy.profile.ipc_plugin.is_none());
    assert_eq!(agy.profile.approval_inputs.approve_sequence, "\r");
    assert_eq!(agy.profile.approval_inputs.reject_sequence, "\u{001b}");
    assert_eq!(agy.rules.len(), 6);
    assert_eq!(
        agy.rules[0].region,
        RegionSpec::BottomNonEmptyLines(2)
    );
    assert_eq!(agy.rules[2].region, RegionSpec::BottomNonEmptyLines(8));
    assert_eq!(agy.rules[3].region, RegionSpec::WholeRecent);
    assert_eq!(agy.rules[5].region, RegionSpec::BottomNonEmptyLines(12));

    for alias in ["antigravity", "antigravity-cli"] {
        assert_eq!(
            registry.resolve(alias).map(|p| p.profile.id.as_str()),
            Some("agy"),
            "alias `{alias}` should resolve to agy"
        );
    }
}

#[test]
fn parses_contract_schema_toml_directly() {
    let contract_path = workspace_root()
        .parent()
        .expect("memory workspace")
        .join("specs/040-herdr-sulur-harness/contracts/agent-detection-schema.toml");
    let raw = std::fs::read_to_string(&contract_path).expect("read contract file");
    let parsed = AgentDetectionConfig::from_toml_str(&raw).expect("parse contract TOML");
    assert_eq!(parsed.schema_version, 1);
    assert_eq!(parsed.profiles.len(), 2);

    let registry = CompiledProfileRegistry::from_configs([parsed]).expect("compile contract");
    assert!(registry.resolve("opencode").is_some());
    assert!(registry.resolve("agy").is_some());
}

#[test]
fn parses_bare_single_profile_herdr_format() {
    let bare = r#"
id = "custom-cli"
version = "2026.11.01.1"
aliases = ["custom"]

[[rules]]
id = "busy_spinner"
state = "working"
priority = 100
region = "bottom_non_empty_lines(4)"
regex = ['Working\.\.\.']
"#;
    let parsed = AgentDetectionConfig::from_toml_str(bare).expect("parse bare single profile");
    assert_eq!(parsed.schema_version, 1);
    assert_eq!(parsed.profiles.len(), 1);
    assert_eq!(parsed.profiles[0].id, "custom-cli");
    assert_eq!(parsed.profiles[0].startup_grace_ms, 3_000);
    assert_eq!(parsed.profiles[0].idle_debounce.confirmations, 3);
}

#[test]
fn rejects_unsupported_schema_version() {
    let bad = r#"
schema_version = 99

[[profiles]]
id = "future"
version = "2099.01.01.1"
"#;
    let err = AgentDetectionConfig::from_toml_str(bad)
        .and_then(CompiledProfileRegistry::compile_config)
        .expect_err("schema_version = 99 must fail");
    assert!(matches!(err, HarnessError::InvalidProfile { .. }));
}

#[test]
fn rejects_invalid_regex_rule() {
    let bad = r#"
schema_version = 1

[[profiles]]
id = "broken-regex"
version = "2026.01.01.1"

[[profiles.rules]]
id = "bad_rule"
state = "working"
priority = 100
region = "whole_recent"
regex = ['[unclosed(']
"#;
    let err = AgentDetectionConfig::from_toml_str(bad)
        .and_then(CompiledProfileRegistry::compile_config)
        .expect_err("broken regex must fail");
    assert!(matches!(err, HarnessError::InvalidRuleRegex { .. }));
}

#[test]
fn rejects_out_of_bounds_region_spec() {
    for invalid in ["bottom_non_empty_lines(0)", "bottom_non_empty_lines(65)", "top_lines(3)"] {
        let parsed = RegionSpec::parse(invalid);
        assert!(
            matches!(parsed, Err(HarnessError::InvalidRegionSpec(_))),
            "expected InvalidRegionSpec for `{invalid}`, got {parsed:?}"
        );
    }
}
