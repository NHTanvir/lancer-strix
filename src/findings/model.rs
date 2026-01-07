use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A single vulnerability finding, compatible with Strix's findings.json format
/// and Lancer's internal vulnerability schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Unique finding ID (Lancer-assigned)
    pub id: String,

    /// The Strix run that produced this finding
    pub run_id: String,

    /// Vulnerability class (e.g. "SQL Injection", "SSRF", "XSS")
    pub vuln_class: String,

    /// Title / one-liner
    pub title: String,

    /// Full description with reproduction steps
    pub description: String,

    /// Affected URL/endpoint
    pub url: String,

    /// HTTP method
    pub method: String,

    /// CVSS 3.1 score
    pub cvss_score: f32,

    /// Severity derived from CVSS
    pub severity: Severity,

    /// CWE ID (e.g. "CWE-89")
    pub cwe: Option<String>,

    /// CVE ID if known
    pub cve: Option<String>,

    /// Proof-of-concept request/response (raw HTTP)
    pub poc_request: Option<String>,
    pub poc_response: Option<String>,

    /// Strix's suggested fix
    pub fix_suggestion: Option<String>,

    /// Code location (file:line) from SAST findings
    pub code_location: Option<String>,

    /// Validation state
    pub validation: ValidationStatus,

    /// Timestamp when Strix reported this finding
    pub reported_at: DateTime<Utc>,

    /// Timestamp when Lancer re-validated the PoC
    pub validated_at: Option<DateTime<Utc>>,

    /// Whether an existing Lancer scanner finding was merged here
    pub merged_from_scanner: bool,

    /// Tags (e.g. ["[strix]", "[authenticated]"])
    pub tags: Vec<String>,
}

impl Finding {
    pub fn new(run_id: impl Into<String>) -> Self {
        Finding {
            id: Uuid::new_v4().to_string(),
            run_id: run_id.into(),
            vuln_class: String::new(),
            title: String::new(),
            description: String::new(),
            url: String::new(),
            method: "GET".to_string(),
            cvss_score: 0.0,
            severity: Severity::Informational,
            cwe: None,
            cve: None,
            poc_request: None,
            poc_response: None,
            fix_suggestion: None,
            code_location: None,
            validation: ValidationStatus::Pending,
            reported_at: Utc::now(),
            validated_at: None,
            merged_from_scanner: false,
            tags: vec!["[strix]".to_string()],
        }
    }

    /// True if this finding should be included in a bug-bounty report.
    /// Filters for validated HIGH/CRITICAL only.
    pub fn is_reportable(&self) -> bool {
        matches!(self.validation, ValidationStatus::Confirmed)
            && self.cvss_score >= 7.0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

impl Severity {
    pub fn from_cvss(score: f32) -> Self {
        match score as u8 {
            9..=10 => Severity::Critical,
            7..=8 => Severity::High,
            4..=6 => Severity::Medium,
            1..=3 => Severity::Low,
            _ => Severity::Informational,
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
            Severity::Informational => write!(f, "INFO"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ValidationStatus {
    /// Not yet re-validated by Lancer
    Pending,
    /// Lancer re-ran the PoC and confirmed the vulnerability
    Confirmed,
    /// Lancer re-ran the PoC and could not reproduce — possible false positive
    NotReproduced,
    /// Skipped (e.g. requires manual verification)
    Skipped,
}

impl std::fmt::Display for ValidationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationStatus::Pending => write!(f, "pending"),
            ValidationStatus::Confirmed => write!(f, "confirmed"),
            ValidationStatus::NotReproduced => write!(f, "not_reproduced"),
            ValidationStatus::Skipped => write!(f, "skipped"),
        }
    }
}
