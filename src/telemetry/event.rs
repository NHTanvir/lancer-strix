use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A single OpenTelemetry span event as emitted by Strix v0.8.3 in JSONL format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEvent {
    /// Span/event name (e.g. "agent.step", "tool.call", "finding.reported")
    pub name: String,

    /// Trace ID (hex string)
    #[serde(default)]
    pub trace_id: String,

    /// Span ID
    #[serde(default)]
    pub span_id: String,

    /// Parent span ID (empty if root)
    #[serde(default)]
    pub parent_span_id: String,

    /// Start time (Unix ns)
    #[serde(default)]
    pub start_time_unix_nano: u64,

    /// End time (Unix ns)
    #[serde(default)]
    pub end_time_unix_nano: u64,

    /// Arbitrary key-value attributes
    #[serde(default)]
    pub attributes: HashMap<String, serde_json::Value>,

    /// Resource attributes (service.name, etc.)
    #[serde(default)]
    pub resource: HashMap<String, serde_json::Value>,
}

impl TraceEvent {
    /// Returns the agent step index, if this is an agent.step event.
    pub fn step_index(&self) -> Option<u64> {
        self.attributes
            .get("agent.step")
            .and_then(|v| v.as_u64())
    }

    /// Returns the tool name for tool.call events.
    pub fn tool_name(&self) -> Option<&str> {
        self.attributes
            .get("tool.name")
            .and_then(|v| v.as_str())
    }

    /// Returns the CVE/vuln ID for finding.reported events.
    pub fn finding_id(&self) -> Option<&str> {
        self.attributes
            .get("finding.id")
            .and_then(|v| v.as_str())
    }

    /// Returns token cost for agent.step events.
    pub fn token_cost(&self) -> Option<f64> {
        self.attributes
            .get("llm.cost_usd")
            .and_then(|v| v.as_f64())
    }

    pub fn duration_ms(&self) -> f64 {
        if self.end_time_unix_nano == 0 || self.start_time_unix_nano == 0 {
            return 0.0;
        }
        (self.end_time_unix_nano - self.start_time_unix_nano) as f64 / 1_000_000.0
    }
}
