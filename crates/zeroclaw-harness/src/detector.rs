//! Declarative agent state detection via Herdr-compatible TOML rules and out-of-band IPC.
//!
//! Strictly pure-Rust streaming ANSI/OSC stripping into a bounded ring buffer
//! (maximum 64 lines and 256 KiB per active session) with zero graphical terminal dependencies.

use crate::{HarnessError, HarnessResult};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Maximum number of stripped lines retained in an active session's detection ring buffer.
pub const MAX_RING_LINES: usize = 64;

/// Maximum UTF-8 byte footprint retained across all lines in [`AnsiStripRingBuffer`].
pub const MAX_RING_BYTES: usize = 256 * 1024;

/// Maximum excerpt length forwarded in approval prompts (aligned with `ApprovalPromptPayload`).
pub const MAX_EXCERPT_CHARS: usize = 1_200;

/// Supported `schema_version` for [`AgentDetectionConfig`].
pub const SUPPORTED_SCHEMA_VERSION: u32 = 1;

/// Top-level Herdr-compatible agent detection registry parsed from `.toml` manifests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentDetectionConfig {
    /// Contract schema version (`1`).
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    /// Loaded declarative CLI agent profiles (`opencode`, `agy`, and user extensions).
    #[serde(default)]
    pub profiles: Vec<AgentProfileToml>,
}

const fn default_schema_version() -> u32 {
    SUPPORTED_SCHEMA_VERSION
}

impl AgentDetectionConfig {
    /// Parse either the contracted multi-profile manifest (`schema_version` + `[[profiles]]`)
    /// or a bare single-profile Herdr `.toml` file (`id = ...`, `[[rules]]`).
    ///
    /// # Errors
    /// Returns [`HarnessError::InvalidProfile`] when TOML parsing fails or required fields are missing.
    pub fn from_toml_str(input: &str) -> HarnessResult<Self> {
        let value: toml::Value =
            toml::from_str(input).map_err(|err| HarnessError::InvalidProfile {
                profile: "<toml>".to_string(),
                reason: err.to_string(),
            })?;

        let Some(table) = value.as_table() else {
            return Err(HarnessError::InvalidProfile {
                profile: "<toml>".to_string(),
                reason: "root TOML value must be a table".to_string(),
            });
        };

        if table.contains_key("schema_version") || table.contains_key("profiles") {
            toml::from_str::<Self>(input).map_err(|err| HarnessError::InvalidProfile {
                profile: "<manifest>".to_string(),
                reason: err.to_string(),
            })
        } else if table.contains_key("id") {
            let single = toml::from_str::<AgentProfileToml>(input).map_err(|err| {
                HarnessError::InvalidProfile {
                    profile: table
                        .get("id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("<single>")
                        .to_string(),
                    reason: err.to_string(),
                }
            })?;
            Ok(Self {
                schema_version: SUPPORTED_SCHEMA_VERSION,
                profiles: vec![single],
            })
        } else {
            Err(HarnessError::InvalidProfile {
                profile: "<toml>".to_string(),
                reason:
                    "expected either `schema_version`/`[[profiles]]` or a top-level profile `id`"
                        .to_string(),
            })
        }
    }
}

/// Single declarative agent profile deserialized from `distribution/agent-detection/*.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentProfileToml {
    /// Canonical agent identifier (e.g. `"opencode"`, `"agy"`).
    pub id: String,
    /// Calendar/schema version string (e.g. `"2026.06.10.1"`).
    pub version: String,
    /// Minimum detector engine compatibility version (`>= 1`).
    #[serde(default = "default_min_engine_version")]
    pub min_engine_version: u32,
    /// ISO-8601 UTC timestamp of profile definition update.
    #[serde(default)]
    pub updated_at: Option<String>,
    /// Alternative CLI or slash command names mapping to this profile.
    #[serde(default)]
    pub aliases: Vec<String>,
    /// Candidate executable filenames searched on PATH (platform-specific allowed).
    #[serde(default)]
    pub binary_names: Vec<String>,
    /// Default CLI arguments passed when spawning interactively under PTY.
    #[serde(default)]
    pub default_args: Vec<String>,
    /// Static environment overrides injected into the spawned child process.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Grace window in milliseconds after process spawn before reporting plain idle (`default: 3000`).
    #[serde(default = "default_startup_grace_ms")]
    pub startup_grace_ms: u64,
    /// Debounce policy for Working -> Idle transitions without an explicit idle pattern.
    #[serde(default)]
    pub idle_debounce: IdleDebounceConfig,
    /// Optional out-of-band plugin IPC configuration (used by OpenCode v2 `HerdrAgentStatePlugin`).
    #[serde(default)]
    pub ipc_plugin: Option<IpcPluginConfig>,
    /// Keystroke/input sequences written to PTY stdin on Discord operator decisions.
    #[serde(default)]
    pub approval_inputs: ApprovalInputMap,
    /// Ordered detection rules evaluated against ANSI-stripped PTY output regions.
    #[serde(default)]
    pub rules: Vec<DetectionRuleToml>,
}

const fn default_min_engine_version() -> u32 {
    1
}

const fn default_startup_grace_ms() -> u64 {
    3_000
}

/// Idle confirmation debounce parameters matching Herdr `PendingIdleConfirmation`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdleDebounceConfig {
    /// Re-evaluation interval in milliseconds (`default: 100`).
    #[serde(default = "default_recheck_ms")]
    pub recheck_ms: u64,
    /// Consecutive non-matching ticks required to confirm Idle (`default: 3`).
    #[serde(default = "default_confirmations")]
    pub confirmations: u8,
    /// Maximum hold duration in milliseconds before forcing Idle (`default: 700`).
    #[serde(default = "default_cap_ms")]
    pub cap_ms: u64,
}

impl Default for IdleDebounceConfig {
    fn default() -> Self {
        Self {
            recheck_ms: default_recheck_ms(),
            confirmations: default_confirmations(),
            cap_ms: default_cap_ms(),
        }
    }
}

const fn default_recheck_ms() -> u64 {
    100
}

const fn default_confirmations() -> u8 {
    3
}

const fn default_cap_ms() -> u64 {
    700
}

/// Out-of-band IPC listener configuration injected into compatible sub-agents (OpenCode v2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpcPluginConfig {
    /// Environment toggle exported to child process (e.g. `"HERDR_ENV"` = `"1"`).
    #[serde(default = "default_env_flag")]
    pub env_flag: String,
    /// Environment variable carrying the Named Pipe or Unix socket path (`"HERDR_SOCKET_PATH"`).
    #[serde(default = "default_socket_env_var")]
    pub socket_env_var: String,
    /// Environment variable carrying the pane/session ID (`"HERDR_PANE_ID"`).
    #[serde(default = "default_pane_id_env_var")]
    pub pane_id_env_var: String,
}

impl Default for IpcPluginConfig {
    fn default() -> Self {
        Self {
            env_flag: default_env_flag(),
            socket_env_var: default_socket_env_var(),
            pane_id_env_var: default_pane_id_env_var(),
        }
    }
}

fn default_env_flag() -> String {
    "HERDR_ENV".to_string()
}

fn default_socket_env_var() -> String {
    "HERDR_SOCKET_PATH".to_string()
}

fn default_pane_id_env_var() -> String {
    "HERDR_PANE_ID".to_string()
}

/// PTY stdin sequences injected when Discord operators click Approve, Reject, or send follow-up text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalInputMap {
    /// Raw UTF-8 bytes/escape sequence written on approval (`default: "y\r"`).
    #[serde(default = "default_approve_seq")]
    pub approve_sequence: String,
    /// Raw UTF-8 bytes/escape sequence written on rejection or timeout (`default: "n\r"`).
    #[serde(default = "default_reject_seq")]
    pub reject_sequence: String,
    /// Interrupt sequence sent on cancellation or agent switch (`default: "\u{001b}"`).
    #[serde(default = "default_interrupt_seq")]
    pub interrupt_sequence: String,
    /// Whether custom free-form replies may follow an approval/question prompt.
    #[serde(default = "default_true")]
    pub supports_custom_reply: bool,
}

impl Default for ApprovalInputMap {
    fn default() -> Self {
        Self {
            approve_sequence: default_approve_seq(),
            reject_sequence: default_reject_seq(),
            interrupt_sequence: default_interrupt_seq(),
            supports_custom_reply: true,
        }
    }
}

fn default_approve_seq() -> String {
    "y\r".to_string()
}

fn default_reject_seq() -> String {
    "n\r".to_string()
}

fn default_interrupt_seq() -> String {
    "\u{001b}".to_string()
}

const fn default_true() -> bool {
    true
}

/// Target state emitted by a declarative Herdr rule before harness mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawDetectedState {
    #[serde(alias = "waiting_for_input", alias = "awaiting_approval")]
    Blocked,
    #[serde(alias = "running")]
    Working,
    Idle,
}

/// Stripped terminal region inspected by a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum RegionSpec {
    /// Entire bounded 64-line recent ring buffer.
    WholeRecent,
    /// Only the bottom `n` non-empty stripped lines (`n` in `1..=64`).
    BottomNonEmptyLines(usize),
}

impl RegionSpec {
    /// Parse a Herdr region spec string (`"whole_recent"` or `"bottom_non_empty_lines(N)"`).
    ///
    /// # Errors
    /// Returns [`HarnessError::InvalidRegionSpec`] when syntax or line count `1..=64` is invalid.
    pub fn parse(raw: &str) -> HarnessResult<Self> {
        let trimmed = raw.trim();
        if trimmed == "whole_recent" {
            return Ok(Self::WholeRecent);
        }
        if let Some(inner) = trimmed
            .strip_prefix("bottom_non_empty_lines(")
            .and_then(|s| s.strip_suffix(')'))
        {
            let n: usize = inner
                .trim()
                .parse()
                .map_err(|_| HarnessError::InvalidRegionSpec(raw.to_string()))?;
            if (1..=MAX_RING_LINES).contains(&n) {
                return Ok(Self::BottomNonEmptyLines(n));
            }
        }
        Err(HarnessError::InvalidRegionSpec(raw.to_string()))
    }
}

impl TryFrom<String> for RegionSpec {
    type Error = HarnessError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<RegionSpec> for String {
    fn from(spec: RegionSpec) -> Self {
        match spec {
            RegionSpec::WholeRecent => "whole_recent".to_string(),
            RegionSpec::BottomNonEmptyLines(n) => format!("bottom_non_empty_lines({n})"),
        }
    }
}

/// Recursive boolean/string matcher predicate compatible with Herdr `.toml` rules.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct MatcherPredicate {
    /// Case-insensitive substring matches: all entries in this vec must match (AND).
    #[serde(default)]
    pub contains: Vec<String>,
    /// Multi-line regex patterns evaluated against the region text (AND within clause).
    #[serde(default)]
    pub regex: Vec<String>,
    /// Single-line regex patterns matched against at least one individual line in the region.
    #[serde(default)]
    pub line_regex: Vec<String>,
    /// Disjunctive sub-predicates (any child matching satisfies this group).
    #[serde(default)]
    pub any: Vec<MatcherPredicate>,
    /// Conjunctive sub-predicates (all children must match).
    #[serde(default)]
    pub all: Vec<MatcherPredicate>,
    /// Negated sub-predicates (none may match).
    #[serde(default)]
    pub none: Vec<MatcherPredicate>,
}

/// Single rule inside `[[rules]]` of an [`AgentProfileToml`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectionRuleToml {
    pub id: String,
    pub state: RawDetectedState,
    pub priority: u16,
    pub region: RegionSpec,
    #[serde(default)]
    pub visible_blocker: bool,
    #[serde(default)]
    pub visible_working: bool,
    #[serde(default)]
    pub visible_idle: bool,
    /// Optional fine-grained phase hint (`"thinking"` or `"streaming"`).
    #[serde(default)]
    pub subphase: Option<String>,
    #[serde(flatten)]
    pub predicate: MatcherPredicate,
}

/// Pre-compiled predicate ready for repeated zero-allocation matching against stripped lines.
#[derive(Debug, Clone)]
pub struct CompiledPredicate {
    contains_lower: Vec<String>,
    regexes: Vec<Regex>,
    line_regexes: Vec<Regex>,
    any: Vec<CompiledPredicate>,
    all: Vec<CompiledPredicate>,
    none: Vec<CompiledPredicate>,
}

impl CompiledPredicate {
    fn compile(profile: &str, rule: &str, pred: &MatcherPredicate) -> HarnessResult<Self> {
        let mut regexes = Vec::with_capacity(pred.regex.len());
        for pat in &pred.regex {
            let compiled = Regex::new(pat).map_err(|source| HarnessError::InvalidRuleRegex {
                profile: profile.to_string(),
                rule: rule.to_string(),
                source,
            })?;
            regexes.push(compiled);
        }

        let mut line_regexes = Vec::with_capacity(pred.line_regex.len());
        for pat in &pred.line_regex {
            let compiled = Regex::new(pat).map_err(|source| HarnessError::InvalidRuleRegex {
                profile: profile.to_string(),
                rule: rule.to_string(),
                source,
            })?;
            line_regexes.push(compiled);
        }

        let mut any = Vec::with_capacity(pred.any.len());
        for child in &pred.any {
            any.push(Self::compile(profile, rule, child)?);
        }

        let mut all = Vec::with_capacity(pred.all.len());
        for child in &pred.all {
            all.push(Self::compile(profile, rule, child)?);
        }

        let mut none = Vec::with_capacity(pred.none.len());
        for child in &pred.none {
            none.push(Self::compile(profile, rule, child)?);
        }

        Ok(Self {
            contains_lower: pred.contains.iter().map(|s| s.to_lowercase()).collect(),
            regexes,
            line_regexes,
            any,
            all,
            none,
        })
    }

    fn is_empty(&self) -> bool {
        self.contains_lower.is_empty()
            && self.regexes.is_empty()
            && self.line_regexes.is_empty()
            && self.any.is_empty()
            && self.all.is_empty()
            && self.none.is_empty()
    }

    /// Evaluate compiled predicate against `region_text` (joined lines) and its lowercase form + lines.
    #[must_use]
    pub fn matches(&self, region_text: &str, region_lower: &str, region_lines: &[&str]) -> bool {
        if self.is_empty() {
            return false;
        }
        for needle in &self.contains_lower {
            if !region_lower.contains(needle.as_str()) {
                return false;
            }
        }
        for re in &self.regexes {
            if !re.is_match(region_text) {
                return false;
            }
        }
        for re in &self.line_regexes {
            if !region_lines.iter().any(|line| re.is_match(line)) {
                return false;
            }
        }
        if !self.any.is_empty()
            && !self
                .any
                .iter()
                .any(|child| child.matches(region_text, region_lower, region_lines))
        {
            return false;
        }
        if !self
            .all
            .iter()
            .all(|child| child.matches(region_text, region_lower, region_lines))
        {
            return false;
        }
        if self
            .none
            .iter()
            .any(|child| child.matches(region_text, region_lower, region_lines))
        {
            return false;
        }
        true
    }
}

/// Validated & pre-compiled rule ordered by descending priority.
#[derive(Debug, Clone)]
pub struct CompiledDetectionRule {
    pub rule: DetectionRuleToml,
    pub region: RegionSpec,
    pub predicate: CompiledPredicate,
}

/// Compiled agent profile ready for live PTY rule evaluation.
#[derive(Debug, Clone)]
pub struct CompiledAgentProfile {
    pub profile: AgentProfileToml,
    /// Rules sorted descending by `priority` (highest priority first).
    pub rules: Vec<CompiledDetectionRule>,
}

/// Outcome of a matching declarative rule against stripped PTY buffer content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleMatchResult {
    pub rule_id: String,
    pub state: RawDetectedState,
    pub subphase: Option<String>,
    pub priority: u16,
    pub matched_excerpt: String,
}

impl CompiledAgentProfile {
    /// Compile and validate a parsed [`AgentProfileToml`].
    ///
    /// # Errors
    /// Returns [`HarnessError::InvalidProfile`] on empty `id` or unsupported `min_engine_version`,
    /// or [`HarnessError::InvalidRuleRegex`] if any pattern fails regex compilation.
    pub fn compile(profile: AgentProfileToml) -> HarnessResult<Self> {
        if profile.id.trim().is_empty() {
            return Err(HarnessError::InvalidProfile {
                profile: "<unnamed>".to_string(),
                reason: "profile `id` cannot be empty".to_string(),
            });
        }
        if profile.min_engine_version > SUPPORTED_SCHEMA_VERSION {
            return Err(HarnessError::InvalidProfile {
                profile: profile.id.clone(),
                reason: format!(
                    "min_engine_version {} exceeds supported version {}",
                    profile.min_engine_version, SUPPORTED_SCHEMA_VERSION
                ),
            });
        }

        let mut rules = Vec::with_capacity(profile.rules.len());
        for rule in &profile.rules {
            let predicate = CompiledPredicate::compile(&profile.id, &rule.id, &rule.predicate)?;
            rules.push(CompiledDetectionRule {
                region: rule.region,
                rule: rule.clone(),
                predicate,
            });
        }

        // Stable sort descending by priority so tie order matches TOML file order.
        rules.sort_by_key(|b| std::cmp::Reverse(b.rule.priority));

        Ok(Self { profile, rules })
    }

    /// Evaluate compiled rules against an [`AnsiStripRingBuffer`] in descending priority order.
    ///
    /// Inspects only lines emitted at or after the buffer's current detection floor so previously
    /// resolved blocker prompts cannot re-trigger on subsequent output chunks.
    #[must_use]
    pub fn evaluate_buffer(&self, ring: &AnsiStripRingBuffer) -> Option<RuleMatchResult> {
        let all_lines = ring.evaluation_lines();
        if all_lines.is_empty() {
            return None;
        }

        // Cache extracted region strings when multiple rules share `RegionSpec`.
        let mut whole_cache: Option<(String, String)> = None;

        for compiled in &self.rules {
            let matched = match compiled.region {
                RegionSpec::WholeRecent => {
                    let (text, lower) = whole_cache.get_or_insert_with(|| {
                        let joined = all_lines.join("\n");
                        let lower = joined.to_lowercase();
                        (joined, lower)
                    });
                    compiled.predicate.matches(text, lower, &all_lines)
                }
                RegionSpec::BottomNonEmptyLines(n) => {
                    let subset = tail_non_empty_lines(&all_lines, n);
                    if subset.is_empty() {
                        false
                    } else {
                        let joined = subset.join("\n");
                        let lower = joined.to_lowercase();
                        compiled.predicate.matches(&joined, &lower, &subset)
                    }
                }
            };

            if matched {
                let raw_excerpt = match compiled.region {
                    RegionSpec::WholeRecent => whole_cache
                        .as_ref()
                        .map(|(t, _)| t.clone())
                        .unwrap_or_else(|| all_lines.join("\n")),
                    RegionSpec::BottomNonEmptyLines(n) => {
                        tail_non_empty_lines(&all_lines, n).join("\n")
                    }
                };
                return Some(RuleMatchResult {
                    rule_id: compiled.rule.id.clone(),
                    state: compiled.rule.state,
                    subphase: compiled.rule.subphase.clone(),
                    priority: compiled.rule.priority,
                    matched_excerpt: truncate_chars_tail(&raw_excerpt, MAX_EXCERPT_CHARS),
                });
            }
        }

        None
    }
}

/// Registry holding all compiled declarative CLI profiles loaded from disk or config.
#[derive(Debug, Clone, Default)]
pub struct CompiledProfileRegistry {
    profiles: Vec<CompiledAgentProfile>,
}

impl CompiledProfileRegistry {
    /// Load and compile every `*.toml` profile file inside `dir` (sorted deterministically by filename).
    ///
    /// # Errors
    /// Returns [`HarnessError::Io`] if reading `dir` fails, or profile/regex validation errors.
    pub fn load_from_dir(dir: &Path) -> HarnessResult<Self> {
        let entries = std::fs::read_dir(dir).map_err(|source| HarnessError::Io {
            path: dir.to_path_buf(),
            source,
        })?;

        let mut paths: Vec<PathBuf> = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|source| HarnessError::Io {
                path: dir.to_path_buf(),
                source,
            })?;
            let path = entry.path();
            if path.is_file() && path.extension().and_then(|e| e.to_str()) == Some("toml") {
                paths.push(path);
            }
        }
        paths.sort();

        let mut configs = Vec::with_capacity(paths.len());
        for path in paths {
            let raw = std::fs::read_to_string(&path).map_err(|source| HarnessError::Io {
                path: path.clone(),
                source,
            })?;
            let cfg = AgentDetectionConfig::from_toml_str(&raw)?;
            configs.push(cfg);
        }
        Self::from_configs(configs)
    }

    /// Compile and validate a single [`AgentDetectionConfig`].
    ///
    /// # Errors
    /// Rejects unsupported `schema_version != 1` or invalid rule regexes/profiles.
    pub fn compile_config(config: AgentDetectionConfig) -> HarnessResult<Self> {
        Self::from_configs([config])
    }

    /// Aggregate and compile an iterator of [`AgentDetectionConfig`] manifests.
    ///
    /// # Errors
    /// Returns [`HarnessError::InvalidProfile`] on unsupported `schema_version` or duplicate IDs.
    pub fn from_configs<I>(configs: I) -> HarnessResult<Self>
    where
        I: IntoIterator<Item = AgentDetectionConfig>,
    {
        let mut profiles: Vec<CompiledAgentProfile> = Vec::new();
        let mut seen_ids = std::collections::BTreeSet::new();

        for cfg in configs {
            if cfg.schema_version != SUPPORTED_SCHEMA_VERSION {
                return Err(HarnessError::InvalidProfile {
                    profile: "<manifest>".to_string(),
                    reason: format!(
                        "unsupported schema_version {}; expected {}",
                        cfg.schema_version, SUPPORTED_SCHEMA_VERSION
                    ),
                });
            }
            for profile in cfg.profiles {
                if !seen_ids.insert(profile.id.to_lowercase()) {
                    return Err(HarnessError::InvalidProfile {
                        profile: profile.id,
                        reason: "duplicate profile id across detection manifests".to_string(),
                    });
                }
                profiles.push(CompiledAgentProfile::compile(profile)?);
            }
        }

        Ok(Self { profiles })
    }

    /// Look up a profile by canonical `id`, case-insensitive match, or declared `aliases`.
    #[must_use]
    pub fn resolve(&self, name_or_alias: &str) -> Option<&CompiledAgentProfile> {
        let needle = name_or_alias.trim().to_lowercase();
        self.profiles.iter().find(|entry| {
            entry.profile.id.to_lowercase() == needle
                || entry
                    .profile
                    .aliases
                    .iter()
                    .any(|alias| alias.to_lowercase() == needle)
        })
    }

    /// Return all registered compiled profiles in deterministic load order.
    #[must_use]
    pub fn list(&self) -> &[CompiledAgentProfile] {
        &self.profiles
    }
}

/// Streaming ANSI/OSC parser state machine inside [`AnsiStripRingBuffer`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum AnsiParseState {
    #[default]
    Ground,
    Escape,
    Csi,
    Osc,
    OscEscape,
    StringControl,
    StringEscape,
    CharsetDesignate,
}

/// Bounded pure-Rust ANSI/control stripper holding at most 64 stripped lines and 256 KiB.
#[derive(Debug, Clone, Default)]
pub struct AnsiStripRingBuffer {
    lines: VecDeque<String>,
    current_line: String,
    stored_bytes: usize,
    total_lines_evicted: usize,
    detection_floor_line: usize,
    floor_line_byte_offset: usize,
    pending_utf8: Vec<u8>,
    state: AnsiParseState,
    pending_cr: bool,
    csi_buf: String,
    pending_responses: Vec<Vec<u8>>,
}

impl AnsiStripRingBuffer {
    /// Create a new empty bounded strip buffer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Total number of completed lines plus an active non-empty partial line.
    #[must_use]
    pub fn line_count(&self) -> usize {
        self.lines.len() + usize::from(!self.current_line.is_empty())
    }

    /// Current UTF-8 byte length stored across all retained lines and active partial line.
    #[must_use]
    pub fn total_bytes(&self) -> usize {
        self.stored_bytes + self.current_line.len()
    }

    /// Snapshot slice of all active lines in chronological order.
    #[must_use]
    pub fn lines_snapshot(&self) -> Vec<&str> {
        let mut out: Vec<&str> = self.lines.iter().map(String::as_str).collect();
        if !self.current_line.is_empty() {
            out.push(self.current_line.as_str());
        }
        out
    }

    /// Advance the rule-evaluation watermark to the end of text currently buffered.
    ///
    /// Keeps [`Self::lines_snapshot`] intact for `tail_excerpt` while preventing already-resolved
    /// blocker prompts still retained in the 64-line window from re-triggering on trailing output.
    pub fn advance_detection_floor(&mut self) {
        self.detection_floor_line = self.total_lines_evicted + self.lines.len();
        self.floor_line_byte_offset = self.current_line.len();
    }

    /// Snapshot of stripped lines produced strictly at or after the current detection floor.
    #[must_use]
    pub fn evaluation_lines(&self) -> Vec<&str> {
        let skip = self
            .detection_floor_line
            .saturating_sub(self.total_lines_evicted);
        if skip > self.lines.len() {
            return Vec::new();
        }
        let mut out: Vec<&str> = Vec::with_capacity(self.lines.len().saturating_sub(skip) + 1);
        for (idx, line) in self.lines.iter().enumerate().skip(skip) {
            let offset =
                if idx == skip && self.total_lines_evicted + idx == self.detection_floor_line {
                    clamp_char_boundary(line, self.floor_line_byte_offset)
                } else {
                    0
                };
            let slice = &line[offset..];
            if offset == 0 || !slice.is_empty() {
                out.push(slice);
            }
        }
        if !self.current_line.is_empty() {
            let offset = if self.total_lines_evicted + self.lines.len() == self.detection_floor_line
            {
                clamp_char_boundary(&self.current_line, self.floor_line_byte_offset)
            } else {
                0
            };
            let slice = &self.current_line[offset..];
            if offset == 0 || !slice.is_empty() {
                out.push(slice);
            }
        }
        out
    }

    /// Drain any VT Device Status / Device Attribute replies (e.g. `\x1b[1;1R` for `\x1b[6n`
    /// emitted by Windows ConPTY when `PSEUDOCONSOLE_INHERIT_CURSOR` is active).
    pub fn take_terminal_responses(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.pending_responses)
    }

    /// Feed raw PTY output bytes, incrementally stripping ANSI CSI/OSC/DCS/ESC sequences
    /// and enforcing hard bounds (`<= 64` lines, `<= 256 KiB`).
    pub fn push_bytes(&mut self, chunk: &[u8]) {
        let _ = self.push_bytes_delta(chunk);
    }

    /// Feed raw PTY output bytes and return the newly stripped printable text delta
    /// produced by this chunk (maintaining continuous ANSI parser state across calls).
    pub fn push_bytes_delta(&mut self, chunk: &[u8]) -> String {
        if chunk.is_empty() {
            return String::new();
        }
        self.pending_utf8.extend_from_slice(chunk);

        let decoded = decode_valid_utf8_prefix(&mut self.pending_utf8);
        if decoded.is_empty() {
            return String::new();
        }

        let mut delta = String::with_capacity(decoded.len());
        for ch in decoded.chars() {
            if let Some(emitted) = self.process_char(ch) {
                delta.push(emitted);
            }
        }
        self.evict_to_budget();
        delta
    }

    fn process_char(&mut self, ch: char) -> Option<char> {
        if self.pending_cr && ch != '\n' {
            // Standalone `\r` resets only the in-progress terminal line (spinners/progress redraws).
            self.pending_cr = false;
            if self.state == AnsiParseState::Ground {
                self.current_line.clear();
                if self.total_lines_evicted + self.lines.len() == self.detection_floor_line {
                    self.floor_line_byte_offset = 0;
                }
            }
        }

        match self.state {
            AnsiParseState::Ground => match ch {
                '\x1b' => {
                    self.pending_cr = false;
                    self.state = AnsiParseState::Escape;
                    None
                }
                '\r' => {
                    self.pending_cr = true;
                    None
                }
                '\n' => {
                    self.pending_cr = false;
                    self.commit_current_line();
                    Some('\n')
                }
                '\t' => {
                    self.push_visible_char('\t');
                    Some('\t')
                }
                c if (c as u32) < 0x20 || c == '\x7f' => {
                    // Drop other C0/DEL control bytes (BELL, BS, etc.).
                    None
                }
                c => {
                    self.push_visible_char(c);
                    Some(c)
                }
            },
            AnsiParseState::Escape => {
                self.state = match ch {
                    '[' => {
                        self.csi_buf.clear();
                        AnsiParseState::Csi
                    }
                    ']' => AnsiParseState::Osc,
                    'P' | 'X' | '^' | '_' => AnsiParseState::StringControl,
                    '(' | ')' | '*' | '+' | '-' | '.' | '/' => AnsiParseState::CharsetDesignate,
                    _ => AnsiParseState::Ground,
                };
                None
            }
            AnsiParseState::CharsetDesignate => {
                self.state = AnsiParseState::Ground;
                None
            }
            AnsiParseState::Csi => {
                if self.csi_buf.len() < 32 {
                    self.csi_buf.push(ch);
                }
                // Parameter/intermediate bytes are in 0x20..=0x3F; final byte in 0x40..=0x7E.
                if ('@'..='~').contains(&ch) || ch == '\x1b' {
                    match self.csi_buf.as_str() {
                        "6n" | "?6n" => self.pending_responses.push(b"\x1b[1;1R".to_vec()),
                        "5n" => self.pending_responses.push(b"\x1b[0n".to_vec()),
                        "c" | "0c" => self.pending_responses.push(b"\x1b[?1;0c".to_vec()),
                        _ => {}
                    }
                    self.csi_buf.clear();
                    self.state = AnsiParseState::Ground;
                }
                None
            }
            AnsiParseState::Osc => {
                if ch == '\x07' {
                    self.state = AnsiParseState::Ground;
                } else if ch == '\x1b' {
                    self.state = AnsiParseState::OscEscape;
                }
                None
            }
            AnsiParseState::OscEscape => {
                self.state = if ch == '\\' || ch == '\x07' {
                    AnsiParseState::Ground
                } else {
                    AnsiParseState::Osc
                };
                None
            }
            AnsiParseState::StringControl => {
                if ch == '\x1b' {
                    self.state = AnsiParseState::StringEscape;
                }
                None
            }
            AnsiParseState::StringEscape => {
                self.state = if ch == '\\' {
                    AnsiParseState::Ground
                } else {
                    AnsiParseState::StringControl
                };
                None
            }
        }
    }

    fn push_visible_char(&mut self, ch: char) {
        self.current_line.push(ch);
        if self.current_line.len() > MAX_RING_BYTES {
            let trim_target = self.current_line.len() - MAX_RING_BYTES;
            let cut = next_char_boundary(&self.current_line, trim_target);
            self.current_line.drain(..cut);
            if self.total_lines_evicted + self.lines.len() == self.detection_floor_line {
                self.floor_line_byte_offset = self.floor_line_byte_offset.saturating_sub(cut);
            }
        }
    }

    fn commit_current_line(&mut self) {
        let line = std::mem::take(&mut self.current_line);
        self.stored_bytes += line.len();
        self.lines.push_back(line);
        self.evict_to_budget();
    }

    fn evict_to_budget(&mut self) {
        while self.line_count() > MAX_RING_LINES || self.total_bytes() > MAX_RING_BYTES {
            if let Some(oldest) = self.lines.pop_front() {
                self.stored_bytes = self.stored_bytes.saturating_sub(oldest.len());
                self.total_lines_evicted = self.total_lines_evicted.saturating_add(1);
                if self.detection_floor_line < self.total_lines_evicted {
                    self.detection_floor_line = self.total_lines_evicted;
                    self.floor_line_byte_offset = 0;
                }
            } else {
                // Only `current_line` remains and exceeds `MAX_RING_BYTES`.
                if self.current_line.len() > MAX_RING_BYTES {
                    let excess = self.current_line.len() - MAX_RING_BYTES;
                    let cut = next_char_boundary(&self.current_line, excess);
                    self.current_line.drain(..cut);
                    if self.total_lines_evicted + self.lines.len() == self.detection_floor_line {
                        self.floor_line_byte_offset =
                            self.floor_line_byte_offset.saturating_sub(cut);
                    }
                }
                break;
            }
        }
    }
}

fn clamp_char_boundary(s: &str, idx: usize) -> usize {
    let clamped = idx.min(s.len());
    if s.is_char_boundary(clamped) {
        clamped
    } else {
        next_char_boundary(s, clamped)
    }
}

fn tail_non_empty_lines<'a>(lines: &'a [&'a str], n: usize) -> Vec<&'a str> {
    if n == 0 {
        return Vec::new();
    }
    let mut rev: Vec<&'a str> = lines
        .iter()
        .rev()
        .copied()
        .filter(|line| !line.trim().is_empty())
        .take(n)
        .collect();
    rev.reverse();
    rev
}

/// Keep the tail up to `max_chars` Unicode scalar values on valid UTF-8 boundaries.
#[must_use]
pub fn truncate_chars_tail(text: &str, max_chars: usize) -> String {
    let char_count = text.chars().count();
    if char_count <= max_chars {
        return text.to_string();
    }
    let skip = char_count - max_chars;
    let start_byte = text.char_indices().nth(skip).map_or(0, |(idx, _)| idx);
    text[start_byte..].to_string()
}

fn next_char_boundary(s: &str, mut idx: usize) -> usize {
    if idx >= s.len() {
        return s.len();
    }
    while !s.is_char_boundary(idx) && idx < s.len() {
        idx += 1;
    }
    idx
}

fn decode_valid_utf8_prefix(buf: &mut Vec<u8>) -> String {
    let mut out = String::new();
    loop {
        match std::str::from_utf8(buf) {
            Ok(valid) => {
                out.push_str(valid);
                buf.clear();
                break;
            }
            Err(err) => {
                let valid_up_to = err.valid_up_to();
                if valid_up_to > 0 {
                    // Valid UTF-8 prefix guaranteed by Utf8Error invariant.
                    out.push_str(&String::from_utf8_lossy(&buf[..valid_up_to]));
                    buf.drain(..valid_up_to);
                }
                if let Some(error_len) = err.error_len() {
                    out.push(char::REPLACEMENT_CHARACTER);
                    buf.drain(..error_len);
                } else {
                    // Incomplete multi-byte sequence at tail; wait for next chunk (unless stuck > 4 bytes).
                    if buf.len() > 4 {
                        out.push(char::REPLACEMENT_CHARACTER);
                        buf.drain(..1);
                    } else {
                        break;
                    }
                }
            }
        }
    }
    out
}

/// Structured IPC state push payload emitted by OpenCode v2 `HerdrAgentStatePlugin`
/// or ZeroClaw's internal flat IPC state messages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IpcStateMessage {
    pub pane_id: String,
    pub state: RawDetectedState,
    pub event: String,
    #[serde(default)]
    pub ts: Option<u64>,
    #[serde(default)]
    pub detail: Option<String>,
    #[serde(default)]
    pub agent_session_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum DualFormatIpcFrame {
    HerdrJsonRpc(HerdrJsonRpcFrame),
    Flat(FlatIpcStateFrame),
}

#[derive(Debug, Clone, Deserialize)]
struct HerdrJsonRpcFrame {
    method: String,
    params: HerdrJsonRpcParams,
}

#[derive(Debug, Clone, Deserialize)]
struct HerdrJsonRpcParams {
    pane_id: String,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    agent_session_id: Option<String>,
    #[serde(default)]
    seq: Option<u64>,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    detail: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct FlatIpcStateFrame {
    pane_id: String,
    state: RawDetectedState,
    event: String,
    #[serde(default)]
    ts: Option<u64>,
    #[serde(default)]
    detail: Option<String>,
    #[serde(default)]
    agent_session_id: Option<String>,
}

impl<'de> Deserialize<'de> for IpcStateMessage {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let frame = DualFormatIpcFrame::deserialize(deserializer)?;
        match frame {
            DualFormatIpcFrame::HerdrJsonRpc(rpc) => {
                Self::from_json_rpc(rpc).map_err(serde::de::Error::custom)
            }
            DualFormatIpcFrame::Flat(flat) => Ok(Self {
                pane_id: flat.pane_id,
                state: flat.state,
                event: flat.event,
                ts: flat.ts,
                detail: flat.detail,
                agent_session_id: flat.agent_session_id,
            }),
        }
    }
}

impl IpcStateMessage {
    fn from_json_rpc(rpc: HerdrJsonRpcFrame) -> Result<Self, String> {
        let params = rpc.params;
        match rpc.method.as_str() {
            "pane.report_agent" => {
                let (state, event) = match params.state.as_deref() {
                    Some(raw) => (
                        parse_herdr_state_str(raw)?,
                        "pane.report_agent".to_string(),
                    ),
                    None if params.agent_session_id.is_some() => (
                        RawDetectedState::Idle,
                        "pane.report_agent_session".to_string(),
                    ),
                    None => {
                        return Err(
                            "pane.report_agent requires `params.state` or `params.agent_session_id`"
                                .to_string(),
                        );
                    }
                };
                Ok(Self {
                    pane_id: params.pane_id,
                    state,
                    event,
                    ts: params.seq,
                    detail: params.detail.or(params.source),
                    agent_session_id: params.agent_session_id,
                })
            }
            "pane.report_agent_session" => Ok(Self {
                pane_id: params.pane_id,
                state: RawDetectedState::Idle,
                event: "pane.report_agent_session".to_string(),
                ts: params.seq,
                detail: params.detail.or(params.source),
                agent_session_id: params.agent_session_id,
            }),
            other => Err(format!("unsupported Herdr JSON-RPC method `{other}`")),
        }
    }

    /// Parse a single newline-delimited JSON status frame from `HerdrAgentStatePlugin`
    /// or ZeroClaw internal flat state payloads.
    ///
    /// # Errors
    /// Returns [`HarnessError::InvalidProfile`] when JSON syntax or required fields are malformed.
    pub fn parse_ndjson_line(line: &str) -> HarnessResult<Self> {
        serde_json::from_str::<Self>(line.trim()).map_err(|err| HarnessError::InvalidProfile {
            profile: "ipc:herdr_plugin".to_string(),
            reason: format!("invalid IPC state payload: {err}"),
        })
    }
}

fn parse_herdr_state_str(raw: &str) -> Result<RawDetectedState, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "working" | "running" => Ok(RawDetectedState::Working),
        "blocked" | "waiting_for_input" | "awaiting_approval" => Ok(RawDetectedState::Blocked),
        "idle" => Ok(RawDetectedState::Idle),
        other => Err(format!("unknown Herdr IPC state `{other}`")),
    }
}

/// Normalize a Windows Named Pipe path so repeated `\\.\pipe\` prefixes are collapsed to a single
/// `\\.\pipe\` prefix for direct pipe opening.
#[must_use]
pub fn normalize_windows_pipe_path(raw: &str) -> String {
    let mut trimmed = raw.trim();
    loop {
        if let Some(rest) = trimmed.strip_prefix(r"\\.\pipe\") {
            trimmed = rest;
        } else if let Some(rest) = trimmed.strip_prefix(r"\\.\PIPE\") {
            trimmed = rest;
        } else {
            break;
        }
    }
    let bare = trimmed.trim_start_matches('\\');
    if bare.is_empty() {
        String::new()
    } else {
        format!(r"\\.\pipe\{bare}")
    }
}

/// Format `HERDR_SOCKET_PATH` exported to child processes so Windows Herdr JS plugins that prepend
/// `\\.\pipe\` never duplicate the prefix, while direct-path readers remain compatible.
#[must_use]
pub fn normalize_herdr_socket_env(endpoint_path: &str) -> String {
    #[cfg(windows)]
    {
        let normalized = normalize_windows_pipe_path(endpoint_path);
        normalized
            .strip_prefix(r"\\.\pipe\")
            .unwrap_or(&normalized)
            .to_string()
    }
    #[cfg(not(windows))]
    {
        endpoint_path.trim().to_string()
    }
}

/// Cross-platform out-of-band IPC listener (`Named Pipe` on Windows, `UnixSocket` on Unix).
pub struct HerdrIpcListener {
    endpoint_path: String,
    rx: mpsc::Receiver<IpcStateMessage>,
    cancel: CancellationToken,
    #[cfg(unix)]
    socket_path_for_cleanup: PathBuf,
}

impl HerdrIpcListener {
    /// Bind a fresh OS-appropriate IPC listener endpoint and spawn its background accept loop.
    ///
    /// # Errors
    /// Returns [`HarnessError::Io`] if binding the socket/pipe fails immediately.
    pub fn bind(session_id: &str, cancel: CancellationToken) -> HarnessResult<Self> {
        let (tx, rx) = mpsc::channel(64);
        let safe_id: String = session_id
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();

        #[cfg(unix)]
        {
            let dir = std::env::temp_dir();
            let sock_path = dir.join(format!("zc-herdr-{safe_id}-{}.sock", uuid::Uuid::new_v4()));
            if sock_path.exists() {
                let _ = std::fs::remove_file(&sock_path);
            }
            let listener =
                tokio::net::UnixListener::bind(&sock_path).map_err(|source| HarnessError::Io {
                    path: sock_path.clone(),
                    source,
                })?;
            let endpoint_path = sock_path.to_string_lossy().into_owned();
            let loop_cancel = cancel.clone();
            ::zeroclaw_spawn::spawn!(async move {
                loop {
                    tokio::select! {
                        () = loop_cancel.cancelled() => break,
                        accepted = listener.accept() => {
                            match accepted {
                                Ok((stream, _)) => {
                                    let tx_conn = tx.clone();
                                    let conn_cancel = loop_cancel.clone();
                                    ::zeroclaw_spawn::spawn!(async move {
                                        read_ndjson_stream(stream, tx_conn, conn_cancel).await;
                                    });
                                }
                                Err(err) => {
                                    ::zeroclaw_log::record!(
                                        DEBUG,
                                        ::zeroclaw_log::Event::new(
                                            "harness.ipc.accept",
                                            ::zeroclaw_log::Action::Fail,
                                        )
                                        .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                                        .with_attrs(::serde_json::json!({ "err": err.to_string() })),
                                        "herdr unix ipc accept error"
                                    );
                                    break;
                                }
                            }
                        }
                    }
                }
            });

            Ok(Self {
                endpoint_path,
                rx,
                cancel,
                socket_path_for_cleanup: sock_path,
            })
        }

        #[cfg(windows)]
        {
            use tokio::net::windows::named_pipe::ServerOptions;
            let pipe_name = format!(
                r"\\.\pipe\zeroclaw-herdr-{safe_id}-{}",
                uuid::Uuid::new_v4()
            );
            let mut server = ServerOptions::new()
                .first_pipe_instance(true)
                .create(&pipe_name)
                .map_err(|source| HarnessError::Io {
                    path: PathBuf::from(&pipe_name),
                    source,
                })?;

            let endpoint_path = pipe_name.clone();
            let loop_cancel = cancel.clone();
            ::zeroclaw_spawn::spawn!(async move {
                loop {
                    tokio::select! {
                        () = loop_cancel.cancelled() => break,
                        res = server.connect() => {
                            if let Err(err) = res {
                                ::zeroclaw_log::record!(
                                    DEBUG,
                                    ::zeroclaw_log::Event::new(
                                        "harness.ipc.connect",
                                        ::zeroclaw_log::Action::Fail,
                                    )
                                    .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                                    .with_attrs(::serde_json::json!({ "err": err.to_string() })),
                                    "herdr named-pipe connect error"
                                );
                                break;
                            }
                            let connected = server;
                            match ServerOptions::new().create(&pipe_name) {
                                Ok(next) => server = next,
                                Err(err) => {
                                    ::zeroclaw_log::record!(
                                        DEBUG,
                                        ::zeroclaw_log::Event::new(
                                            "harness.ipc.pipe_next",
                                            ::zeroclaw_log::Action::Fail,
                                        )
                                        .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                                        .with_attrs(::serde_json::json!({ "err": err.to_string() })),
                                        "herdr named-pipe next instance error"
                                    );
                                    let conn_cancel = loop_cancel.clone();
                                    read_ndjson_stream(connected, tx.clone(), conn_cancel).await;
                                    break;
                                }
                            }
                            let tx_conn = tx.clone();
                            let conn_cancel = loop_cancel.clone();
                            ::zeroclaw_spawn::spawn!(async move {
                                read_ndjson_stream(connected, tx_conn, conn_cancel).await;
                            });
                        }
                    }
                }
            });

            Ok(Self {
                endpoint_path,
                rx,
                cancel,
            })
        }
    }

    /// Environment socket/pipe address passed to child processes via `HERDR_SOCKET_PATH`.
    #[must_use]
    pub fn endpoint_path(&self) -> &str {
        &self.endpoint_path
    }

    /// Split out the inbound [`mpsc::Receiver<IpcStateMessage>`] without triggering Drop cancellation prematurely.
    pub fn receiver_mut(&mut self) -> &mut mpsc::Receiver<IpcStateMessage> {
        &mut self.rx
    }
}

impl Drop for HerdrIpcListener {
    fn drop(&mut self) {
        self.cancel.cancel();
        #[cfg(unix)]
        if self.socket_path_for_cleanup.exists() {
            let _ = std::fs::remove_file(&self.socket_path_for_cleanup);
        }
    }
}

async fn write_ndjson_ack<W: tokio::io::AsyncWrite + Unpin>(
    write_half: &mut W,
    ack: serde_json::Value,
) {
    use tokio::io::AsyncWriteExt as _;
    let mut ack_line = serde_json::to_vec(&ack).unwrap_or_default();
    ack_line.push(b'\n');
    let _ = write_half.write_all(&ack_line).await;
    let _ = write_half.flush().await;
}

async fn read_ndjson_stream<S>(
    stream: S,
    tx: mpsc::Sender<IpcStateMessage>,
    cancel: CancellationToken,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half).lines();
    loop {
        tokio::select! {
            () = cancel.cancelled() => break,
            line = reader.next_line() => match line {
                Ok(Some(raw)) if !raw.trim().is_empty() => {
                    let ack_id = serde_json::from_str::<serde_json::Value>(raw.trim())
                        .ok()
                        .and_then(|v| v.get("id").cloned());
                    match IpcStateMessage::parse_ndjson_line(&raw) {
                        Ok(msg) => {
                            if tx.send(msg).await.is_err() {
                                break;
                            }
                            let ack = match ack_id {
                                Some(id) => serde_json::json!({ "id": id, "ok": true }),
                                None => serde_json::json!({ "ok": true }),
                            };
                            write_ndjson_ack(&mut write_half, ack).await;
                        }
                        Err(err) => {
                            ::zeroclaw_log::record!(
                                WARN,
                                ::zeroclaw_log::Event::new(
                                    "harness.ipc.parse",
                                    ::zeroclaw_log::Action::Fail,
                                )
                                .with_outcome(::zeroclaw_log::EventOutcome::Failure)
                                .with_attrs(::serde_json::json!({ "err": err.to_string() })),
                                "ignoring malformed IPC frame from child agent"
                            );
                            if let Some(id) = ack_id {
                                write_ndjson_ack(
                                    &mut write_half,
                                    serde_json::json!({ "id": id, "ok": false }),
                                )
                                .await;
                            }
                        }
                    }
                }
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => break,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_csi_osc_and_charset_sequences_across_split_chunks() {
        let mut buf = AnsiStripRingBuffer::new();
        // Split CSI color code & OSC window title across chunks
        buf.push_bytes(b"\x1b]0;opencode title");
        buf.push_bytes(b"\x07\x1b[38;5;196mHello\x1b[0m ");
        buf.push_bytes(b"\x1b(Bworld\r\nNext line");
        assert_eq!(buf.lines_snapshot(), vec!["Hello world", "Next line"]);
    }

    #[test]
    fn enforces_64_line_and_256kib_cap_on_heavy_ansi_burst() {
        let mut buf = AnsiStripRingBuffer::new();
        for i in 0..2_000 {
            let line = format!("\x1b[32mline-{i:04}: {}\x1b[0m\r\n", "x".repeat(256));
            buf.push_bytes(line.as_bytes());
        }
        assert!(buf.line_count() <= MAX_RING_LINES);
        assert!(buf.total_bytes() <= MAX_RING_BYTES);
        assert!(
            buf.lines_snapshot()
                .last()
                .is_some_and(|l| l.starts_with("line-1999:")),
            "newest lines must survive eviction"
        );
    }

    #[test]
    fn enforces_256kib_cap_even_without_newlines() {
        let mut buf = AnsiStripRingBuffer::new();
        let big = vec![b'A'; 400 * 1024];
        buf.push_bytes(&big);
        assert!(buf.total_bytes() <= MAX_RING_BYTES);
        assert_eq!(buf.line_count(), 1);
    }

    #[test]
    fn evaluates_opencode_priority_blocked_over_working() {
        let toml_raw = include_str!("../../../distribution/agent-detection/opencode.toml");
        let cfg = AgentDetectionConfig::from_toml_str(toml_raw).expect("parse opencode.toml");
        let registry = CompiledProfileRegistry::compile_config(cfg).expect("compile");
        let profile = registry.resolve("opencode").expect("opencode present");

        let mut buf = AnsiStripRingBuffer::new();
        buf.push_bytes(b"\x1b[36mThinking... esc to interrupt\x1b[0m\r\n");
        let m1 = profile.evaluate_buffer(&buf).expect("working rule matches");
        assert_eq!(m1.state, RawDetectedState::Working);
        assert_eq!(m1.subphase.as_deref(), Some("thinking"));

        // Simultaneous blocked prompt + working hint -> blocked (priority 300) wins!
        buf.push_bytes(b"\x1b[33m\xE2\x96\xB3 Permission required: run rm?\x1b[0m\r\n");
        let m2 = profile.evaluate_buffer(&buf).expect("blocked rule matches");
        assert_eq!(m2.state, RawDetectedState::Blocked);
        assert_eq!(m2.rule_id, "permission_required");
        assert_eq!(m2.priority, 300);
    }

    #[test]
    fn evaluates_agy_bottom_non_empty_lines_and_spinner() {
        let toml_raw = include_str!("../../../distribution/agent-detection/antigravity.toml");
        let cfg = AgentDetectionConfig::from_toml_str(toml_raw).expect("parse antigravity.toml");
        let registry = CompiledProfileRegistry::compile_config(cfg).expect("compile");
        let profile = registry.resolve("agy").expect("agy present");

        let mut buf = AnsiStripRingBuffer::new();
        buf.push_bytes(b"\xE2\xA0\x8B Inspecting codebase\r\n");
        buf.push_bytes(b"\r\n\r\n");
        let m1 = profile.evaluate_buffer(&buf).expect("spinner matches");
        assert_eq!(m1.state, RawDetectedState::Working);
        assert_eq!(m1.rule_id, "spinner_working");

        // Blocker in bottom 2 non-empty lines beats spinner above!
        buf.push_bytes(b"\xE2\x86\x91/\xE2\x86\x93 Navigate \xc2\xb7 tab Amend \xc2\xb7 ctrl+g edit\r\nesc to cancel\r\n");
        let m2 = profile
            .evaluate_buffer(&buf)
            .expect("permission_prompt matches");
        assert_eq!(m2.state, RawDetectedState::Blocked);
        assert_eq!(m2.rule_id, "permission_prompt");
    }

    #[test]
    fn parses_herdr_ipc_ndjson_payload() {
        let raw =
            r#"{"pane_id":"pane-1","state":"blocked","event":"permission.asked","ts":1760000000}"#;
        let msg = IpcStateMessage::parse_ndjson_line(raw).expect("valid ndjson");
        assert_eq!(msg.pane_id, "pane-1");
        assert_eq!(msg.state, RawDetectedState::Blocked);
        assert_eq!(msg.event, "permission.asked");
        assert_eq!(msg.ts, Some(1_760_000_000));
    }

    #[test]
    fn responds_to_dsr_cursor_position_query() {
        let mut buf = AnsiStripRingBuffer::new();
        let delta = buf.push_bytes_delta(b"\x1b[6n\x1b[32mok\x1b[0m\r\n");
        assert_eq!(delta, "ok\n");
        assert_eq!(buf.take_terminal_responses(), vec![b"\x1b[1;1R".to_vec()]);
        assert!(buf.take_terminal_responses().is_empty());
    }
}
