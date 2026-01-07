mod cli;
mod findings;
mod orchestrator;
mod proxy;
mod reports;
mod skills;
mod telemetry;
mod validator;

use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;
use tracing::{error, info, warn};

use cli::{Cli, Command, TemplateAction, SkillsAction};
use findings::FindingsStore;
use validator::Validator;
use orchestrator::container::{ContainerHandle, OrchestratorConfig};
use orchestrator::network::{apply_egress_firewall, target_to_cidr};
use proxy::ProxyConfig;
use reports::templates;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("lancer_strix=info".parse().unwrap()),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Run(args) => cmd_run(args).await,
        Command::Report(args) => cmd_report(args),
        Command::Template(args) => cmd_template(args),
        Command::Skills(args) => cmd_skills(args),
        Command::Findings(args) => cmd_findings(args),
        Command::Validate(args) => cmd_validate(args).await,
    }
}

// ---------------------------------------------------------------------------
// run
// ---------------------------------------------------------------------------

async fn cmd_run(args: cli::RunArgs) -> Result<()> {
    let run_id = ContainerHandle::new_run_id();
    info!("Starting Strix run: {run_id}");
    info!("Target: {}", args.target);
    info!("Model:  {} | Scan: {}", args.model, args.scan_mode);

    // -- Proxy reachability check
    let proxy = ProxyConfig::new(&args.proxy_addr);
    if !proxy.check_reachable().await {
        warn!(
            "Lancer proxy not reachable at {} — Strix traffic won't be captured",
            args.proxy_addr
        );
    }

    // -- Resolve template overrides
    let (scan_mode, instruction) = if let Some(tmpl_name) = &args.template {
        match templates::find_template(tmpl_name) {
            Some(t) => {
                info!("Applying template: {}", t.name);
                (
                    t.scan_mode.to_string(),
                    args.instruction.as_deref().unwrap_or(t.instruction).to_string(),
                )
            }
            None => {
                warn!("Template '{}' not found — using CLI args", tmpl_name);
                (args.scan_mode.to_string(), args.instruction.clone().unwrap_or_default())
            }
        }
    } else {
        (
            args.scan_mode.to_string(),
            args.instruction.clone().unwrap_or_default(),
        )
    };

    // -- Open findings DB
    let db_path = lancer_data_dir().join("findings.db");
    let store = FindingsStore::open(&db_path)?;
    store.insert_run(&run_id, &args.target, &args.model, &scan_mode)?;

    // -- Prepare runs dir
    let runs_dir = lancer_data_dir().join("runs");
    std::fs::create_dir_all(&runs_dir)?;

    // -- Build skills dir (write bundled skills to a temp location)
    let skills_dir = lancer_data_dir().join("skills");
    skills::install_skills(&skills_dir)?;

    // -- Resolve LLM API key
    let llm_api_key = std::env::var("LLM_API_KEY")
        .or_else(|_| std::env::var("ANTHROPIC_API_KEY"))
        .unwrap_or_else(|_| {
            warn!("LLM_API_KEY not set — Strix will fail to call the LLM");
            String::new()
        });

    // -- Build orchestrator config
    let config = OrchestratorConfig {
        image: args.docker_image.clone(),
        target: args.target.clone(),
        instruction: if instruction.is_empty() { None } else { Some(instruction) },
        instruction_file: args.instruction_file.clone(),
        scan_mode,
        model: args.model.clone(),
        reasoning_effort: args.reasoning_effort.to_string(),
        llm_api_key,
        proxy_addr: args.proxy_addr.clone(),
        oast_domain: args.oast_domain.clone(),
        lancer_api: args.lancer_api.clone(),
        token_budget: args.token_budget,
        headless: args.headless,
        interactive: args.interactive,
        runs_dir: runs_dir.to_string_lossy().to_string(),
        run_id: run_id.clone(),
        skills_dir: Some(skills_dir.to_string_lossy().to_string()),
    };

    // -- Spawn Strix container
    let handle = match ContainerHandle::spawn(&config).await {
        Ok(h) => h,
        Err(e) => {
            error!("Failed to spawn Strix container: {e}");
            return Err(e);
        }
    };

    // -- Apply egress firewall if requested (Linux only)
    if args.strict_egress {
        let mut cidrs = vec![];
        if let Some(cidr) = target_to_cidr(&args.target) {
            cidrs.push(cidr);
        }
        // Always allow the LLM API (simplified: allow all — operator adds specific CIDRs)
        if let Err(e) = apply_egress_firewall(&handle.container_id, &cidrs).await {
            warn!("Egress firewall failed (non-fatal): {e}");
        }
    }

    // -- Set up JSONL trace consumer
    let trace_path = runs_dir
        .join(&run_id)
        .join("traces.jsonl");

    let (consumer, mut trace_rx) = telemetry::TraceConsumer::new(&trace_path);

    // Spawn the trace consumer in background
    tokio::spawn(async move {
        if let Err(e) = consumer.run().await {
            warn!("Trace consumer error: {e}");
        }
    });

    // Spawn log streaming in background
    // (we need a second handle to the container for logs — use container_id)
    let container_id_for_logs = handle.container_id.clone();
    let docker_for_logs = bollard::Docker::connect_with_local_defaults().ok();
    if let Some(docker) = docker_for_logs {
        let cid = container_id_for_logs.clone();
        tokio::spawn(async move {
            use bollard::container::LogsOptions;
            use futures_util::stream::StreamExt;
            let opts = LogsOptions::<String> {
                follow: true,
                stdout: true,
                stderr: true,
                ..Default::default()
            };
            let mut stream = docker.logs(&cid, Some(opts));
            while let Some(msg) = stream.next().await {
                if let Ok(output) = msg {
                    let text = output.to_string();
                    let text = text.trim();
                    if !text.is_empty() {
                        info!("[strix] {text}");
                    }
                }
            }
        });
    }

    // Consume trace events and surface key ones
    tokio::spawn(async move {
        while let Ok(event) = trace_rx.recv().await {
            if event.name == "finding.reported" {
                info!(
                    "[finding] {} — run the `findings` subcommand to see details",
                    event.attributes.get("finding.title")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown")
                );
            }
        }
    });

    // -- Wait for container to finish
    info!("Waiting for Strix to complete...");
    let exit_code = handle.wait().await?;
    info!("Strix exited with code: {exit_code}");

    store.finish_run(&run_id, exit_code)?;

    // -- Ingest findings from Strix's findings.json into Lancer DB
    let findings_json = runs_dir.join(&run_id).join("findings.json");
    if findings_json.exists() {
        match ingest_findings_json(&findings_json, &run_id, &store) {
            Ok(count) => info!("Ingested {count} findings from Strix into Lancer DB"),
            Err(e) => warn!("Could not ingest findings.json: {e}"),
        }
    }

    // -- Correlate with Lancer's existing scanner findings (Week 7)
    if let Err(e) = correlate_with_lancer(&store, &run_id, &args.lancer_api).await {
        warn!("Findings correlation skipped: {e}");
    }

    println!("\nRun complete: {run_id}");
    println!("Findings DB: {}", db_path.display());
    println!("Run with: lancer-strix findings --run-id {run_id}");

    Ok(())
}

/// Week 7: For each ingested finding, query Lancer's API for an existing scanner
/// finding at the same URL + vuln_class. If the existing scanner already flagged
/// the same issue, mark `merged_from_scanner = true` to boost confidence.
async fn correlate_with_lancer(
    store: &FindingsStore,
    run_id: &str,
    lancer_api: &str,
) -> Result<()> {
    let findings = store.get_findings(run_id, None, false)?;
    if findings.is_empty() {
        return Ok(());
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;

    let search_url = format!("{lancer_api}/api/findings/search");
    let mut merged = 0usize;

    for finding in &findings {
        if finding.url.is_empty() {
            continue;
        }

        let resp = client
            .get(&search_url)
            .query(&[
                ("url", finding.url.as_str()),
                ("vuln_class", finding.vuln_class.as_str()),
            ])
            .send()
            .await;

        let Ok(r) = resp else { continue };
        if !r.status().is_success() {
            continue;
        }

        let body: serde_json::Value = r.json().await.unwrap_or_default();
        let count = body.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
        if count > 0 {
            let mut updated = finding.clone();
            updated.merged_from_scanner = true;
            store.insert_finding(&updated)?;
            merged += 1;
        }
    }

    if merged > 0 {
        info!(
            "Correlated {merged} Strix findings with existing Lancer scanner results"
        );
    }
    Ok(())
}

fn ingest_findings_json(
    path: &PathBuf,
    run_id: &str,
    store: &FindingsStore,
) -> Result<usize> {
    let content = std::fs::read_to_string(path)?;
    let raw: Vec<serde_json::Value> = serde_json::from_str(&content)?;
    let mut count = 0;

    for item in &raw {
        let mut f = findings::Finding::new(run_id);
        f.vuln_class = item["vuln_class"].as_str().unwrap_or("Unknown").to_string();
        f.title = item["title"].as_str().unwrap_or("Untitled").to_string();
        f.description = item["description"].as_str().unwrap_or("").to_string();
        f.url = item["url"].as_str().unwrap_or("").to_string();
        f.method = item["method"].as_str().unwrap_or("GET").to_string();
        f.cvss_score = item["cvss_score"].as_f64().unwrap_or(0.0) as f32;
        f.severity = findings::Severity::from_cvss(f.cvss_score);
        f.cwe = item["cwe"].as_str().map(String::from);
        f.poc_request = item["poc_request"].as_str().map(String::from);
        f.poc_response = item["poc_response"].as_str().map(String::from);
        f.fix_suggestion = item["fix_suggestion"].as_str().map(String::from);

        store.insert_finding(&f)?;
        count += 1;
    }

    Ok(count)
}

// ---------------------------------------------------------------------------
// report
// ---------------------------------------------------------------------------

fn cmd_report(args: cli::ReportArgs) -> Result<()> {
    let db_path = lancer_data_dir().join("findings.db");
    let store = FindingsStore::open(&db_path)?;

    let run_id = resolve_run_id(args.run_id.as_deref(), &store)?;
    info!("Generating report for run: {run_id}");

    let findings = store.get_findings(&run_id, Some(args.min_cvss), args.validated_only)?;
    info!("Found {} findings", findings.len());

    // Determine target from first finding URL or use run_id
    let target = findings
        .first()
        .map(|f| extract_host(&f.url))
        .unwrap_or_else(|| run_id.clone());

    let report = reports::generate_report(&findings, &target, &run_id, &args.platform)?;

    match args.output {
        Some(path) => {
            std::fs::write(&path, &report)
                .with_context(|| format!("Failed to write report to {path}"))?;
            println!("Report written to: {path}");
        }
        None => print!("{report}"),
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// template
// ---------------------------------------------------------------------------

fn cmd_template(args: cli::TemplateArgs) -> Result<()> {
    match args.action {
        TemplateAction::List => print!("{}", templates::list_templates()),
        TemplateAction::Show { name } => println!("{}", templates::show_template(&name)),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// skills
// ---------------------------------------------------------------------------

fn cmd_skills(args: cli::SkillsArgs) -> Result<()> {
    match args.action {
        SkillsAction::List => skills::list_skills(),
        SkillsAction::Install { container: _ } => {
            let skills_dir = lancer_data_dir().join("skills");
            skills::install_skills(&skills_dir)?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// findings
// ---------------------------------------------------------------------------

fn cmd_findings(args: cli::FindingsArgs) -> Result<()> {
    let db_path = lancer_data_dir().join("findings.db");
    let store = FindingsStore::open(&db_path)?;

    let run_id = resolve_run_id(args.run_id.as_deref(), &store)?;
    let findings = store.get_findings(&run_id, args.min_cvss, args.validated_only)?;

    if findings.is_empty() {
        println!("No findings for run {run_id}");
        return Ok(());
    }

    println!("Findings for run: {run_id}\n");
    println!("{:<5} {:<12} {:<6} {:<14} {}", "#", "Severity", "CVSS", "Status", "Title");
    println!("{}", "-".repeat(80));

    for (i, f) in findings.iter().enumerate() {
        println!(
            "{:<5} {:<12} {:<6.1} {:<14} {}",
            i + 1,
            f.severity.to_string(),
            f.cvss_score,
            f.validation.to_string(),
            f.title,
        );
    }

    println!("\nTotal: {} findings", findings.len());
    Ok(())
}

// ---------------------------------------------------------------------------
// validate
// ---------------------------------------------------------------------------

async fn cmd_validate(args: cli::ValidateArgs) -> Result<()> {
    let db_path = lancer_data_dir().join("findings.db");
    let store = FindingsStore::open(&db_path)?;
    let run_id = resolve_run_id(args.run_id.as_deref(), &store)?;

    info!("Re-validating findings for run: {run_id}");

    let validator = Validator::new()?;
    let (confirmed, not_reproduced) = validator
        .validate_run(&store, &run_id, args.min_cvss)
        .await?;

    println!("\nValidation complete:");
    println!("  Confirmed:      {confirmed}");
    println!("  Not reproduced: {not_reproduced}");
    if confirmed > 0 {
        println!(
            "\nRun `lancer-strix findings --run-id {run_id} --validated-only` to review."
        );
        println!("Run `lancer-strix report --run-id {run_id} --validated-only` to export.");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn lancer_data_dir() -> PathBuf {
    dirs_base()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".lancer")
        .join("strix")
}

fn dirs_base() -> Option<PathBuf> {
    // Windows: %APPDATA%\..\..  → user home
    // Linux/macOS: $HOME
    std::env::var("HOME")
        .ok()
        .map(PathBuf::from)
        .or_else(|| std::env::var("USERPROFILE").ok().map(PathBuf::from))
}

fn resolve_run_id(arg: Option<&str>, store: &FindingsStore) -> Result<String> {
    match arg {
        Some(id) => Ok(id.to_string()),
        None => store
            .latest_run_id()?
            .ok_or_else(|| anyhow::anyhow!("No runs found. Run `lancer-strix run --target <url>` first.")),
    }
}

fn extract_host(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(String::from))
        .unwrap_or_else(|| url.to_string())
}
