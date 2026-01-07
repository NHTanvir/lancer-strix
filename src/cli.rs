use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser, Debug)]
#[command(
    name = "lancer-strix",
    version,
    about = "Lancer orchestration layer for the Strix autonomous AI pentest agent"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Run an autonomous Strix pentest scan
    Run(RunArgs),

    /// Generate a bounty report from stored findings
    Report(ReportArgs),

    /// Manage Docker target-policy templates
    Template(TemplateArgs),

    /// Install / list Lancer Strix skills into the Strix container
    Skills(SkillsArgs),

    /// Show stored findings for a run
    Findings(FindingsArgs),

    /// Re-validate HIGH/CRITICAL findings by replaying their PoC requests
    Validate(ValidateArgs),
}

// ---------------------------------------------------------------------------
// Run subcommand
// ---------------------------------------------------------------------------

#[derive(clap::Args, Debug)]
pub struct RunArgs {
    /// Target: URL, GitHub repo, local path, or IP/CIDR
    #[arg(short, long)]
    pub target: String,

    /// Natural-language instruction for Strix (e.g. "Focus on IDOR in /api/v2")
    #[arg(short, long)]
    pub instruction: Option<String>,

    /// Path to a markdown instruction file (--instruction-file)
    #[arg(long)]
    pub instruction_file: Option<String>,

    /// Scan depth
    #[arg(long, default_value = "standard")]
    pub scan_mode: ScanMode,

    /// LLM to use (e.g. anthropic/claude-sonnet-4-6)
    #[arg(long, default_value = "anthropic/claude-sonnet-4-6")]
    pub model: String,

    /// LLM reasoning effort (extended thinking)
    #[arg(long, default_value = "medium")]
    pub reasoning_effort: ReasoningEffort,

    /// Max tokens budget per scan (0 = unlimited)
    #[arg(long, default_value_t = 0)]
    pub token_budget: u64,

    /// Lancer proxy address (host:port) — Strix traffic routes through this
    #[arg(long, default_value = "127.0.0.1:8080")]
    pub proxy_addr: String,

    /// Lancer OAST collaborator domain for blind SSRF/XSS detection
    #[arg(long)]
    pub oast_domain: Option<String>,

    /// Lancer API base URL to POST findings into
    #[arg(long, default_value = "http://127.0.0.1:9090")]
    pub lancer_api: String,

    /// Docker image for the Strix sandbox
    #[arg(long, default_value = "usestrix/strix:latest")]
    pub docker_image: String,

    /// Apply a named Docker policy template
    #[arg(long)]
    pub template: Option<String>,

    /// Restrict egress to target IP only (Linux only — uses nftables)
    #[arg(long)]
    pub strict_egress: bool,

    /// Run headless (no TUI)
    #[arg(short = 'n', long)]
    pub headless: bool,

    /// Enable interactive / human-in-the-loop mode (Strix v0.8.3+)
    #[arg(long)]
    pub interactive: bool,
}

#[derive(ValueEnum, Debug, Clone)]
pub enum ScanMode {
    Quick,
    Standard,
    Deep,
}

impl std::fmt::Display for ScanMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanMode::Quick => write!(f, "quick"),
            ScanMode::Standard => write!(f, "standard"),
            ScanMode::Deep => write!(f, "deep"),
        }
    }
}

#[derive(ValueEnum, Debug, Clone)]
pub enum ReasoningEffort {
    Low,
    Medium,
    High,
}

impl std::fmt::Display for ReasoningEffort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReasoningEffort::Low => write!(f, "low"),
            ReasoningEffort::Medium => write!(f, "medium"),
            ReasoningEffort::High => write!(f, "high"),
        }
    }
}

// ---------------------------------------------------------------------------
// Report subcommand
// ---------------------------------------------------------------------------

#[derive(clap::Args, Debug)]
pub struct ReportArgs {
    /// Run ID to generate report for (defaults to most recent)
    #[arg(long)]
    pub run_id: Option<String>,

    /// Output file path (defaults to stdout)
    #[arg(short, long)]
    pub output: Option<String>,

    /// Report platform format
    #[arg(long, default_value = "hackerone")]
    pub platform: ReportPlatform,

    /// Only include findings at or above this CVSS score
    #[arg(long, default_value_t = 4.0)]
    pub min_cvss: f32,

    /// Only include validated findings (re-validation PoC passed)
    #[arg(long)]
    pub validated_only: bool,
}

#[derive(ValueEnum, Debug, Clone)]
pub enum ReportPlatform {
    HackerOne,
    Bugcrowd,
    Markdown,
}

// ---------------------------------------------------------------------------
// Template subcommand
// ---------------------------------------------------------------------------

#[derive(clap::Args, Debug)]
pub struct TemplateArgs {
    #[command(subcommand)]
    pub action: TemplateAction,
}

#[derive(Subcommand, Debug)]
pub enum TemplateAction {
    /// List available templates
    List,
    /// Show template configuration
    Show {
        /// Template name
        name: String,
    },
}

// ---------------------------------------------------------------------------
// Skills subcommand
// ---------------------------------------------------------------------------

#[derive(clap::Args, Debug)]
pub struct SkillsArgs {
    #[command(subcommand)]
    pub action: SkillsAction,
}

#[derive(Subcommand, Debug)]
pub enum SkillsAction {
    /// List bundled Lancer skills
    List,
    /// Copy skills into a running or named Strix container
    Install {
        /// Container ID or name (defaults to the most recent lancer-strix container)
        #[arg(long)]
        container: Option<String>,
    },
}

// ---------------------------------------------------------------------------
// Validate subcommand
// ---------------------------------------------------------------------------

#[derive(clap::Args, Debug)]
pub struct ValidateArgs {
    /// Run ID to validate (defaults to most recent)
    #[arg(long)]
    pub run_id: Option<String>,

    /// Only re-validate findings at or above this CVSS score
    #[arg(long, default_value_t = 7.0)]
    pub min_cvss: f32,
}

// ---------------------------------------------------------------------------
// Findings subcommand
// ---------------------------------------------------------------------------

#[derive(clap::Args, Debug)]
pub struct FindingsArgs {
    /// Run ID (defaults to most recent)
    #[arg(long)]
    pub run_id: Option<String>,

    /// Only show findings at or above this CVSS score
    #[arg(long)]
    pub min_cvss: Option<f32>,

    /// Only show validated findings
    #[arg(long)]
    pub validated_only: bool,
}
