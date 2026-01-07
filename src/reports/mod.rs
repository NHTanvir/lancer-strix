pub mod templates;

use anyhow::Result;
use chrono::Utc;

use crate::cli::ReportPlatform;
use crate::findings::model::{Finding, ValidationStatus};

/// Generate a bug-bounty report from a list of findings.
pub fn generate_report(
    findings: &[Finding],
    target: &str,
    run_id: &str,
    platform: &ReportPlatform,
) -> Result<String> {
    let validated: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.validation == ValidationStatus::Confirmed)
        .collect();

    match platform {
        ReportPlatform::HackerOne => generate_hackerone(&validated, target, run_id),
        ReportPlatform::Bugcrowd => generate_bugcrowd(&validated, target, run_id),
        ReportPlatform::Markdown => generate_markdown(findings, target, run_id),
    }
}

fn generate_hackerone(findings: &[&Finding], target: &str, run_id: &str) -> Result<String> {
    let mut out = String::new();
    let now = Utc::now().format("%Y-%m-%d");

    out.push_str(&format!(
        "# Vulnerability Report — {target}\n\n\
         **Run ID:** `{run_id}`  \n\
         **Date:** {now}  \n\
         **Tool:** lancer-strix (Strix autonomous AI pentest agent)  \n\n\
         ---\n\n"
    ));

    if findings.is_empty() {
        out.push_str("No confirmed HIGH/CRITICAL findings to report.\n");
        return Ok(out);
    }

    for (i, f) in findings.iter().enumerate() {
        out.push_str(&format!(
            "## Finding #{}: {}\n\n\
             **Severity:** {} (CVSS {:.1})  \n\
             **Weakness:** {}  \n\
             **URL:** {}  \n\
             **Method:** {}  \n\n",
            i + 1,
            f.title,
            f.severity,
            f.cvss_score,
            f.cwe.as_deref().unwrap_or("N/A"),
            f.url,
            f.method,
        ));

        out.push_str("### Description\n\n");
        out.push_str(&f.description);
        out.push_str("\n\n");

        if let Some(poc_req) = &f.poc_request {
            out.push_str("### Proof of Concept\n\n```http\n");
            out.push_str(poc_req);
            out.push_str("\n```\n\n");
        }

        if let Some(poc_resp) = &f.poc_response {
            out.push_str("**Response:**\n\n```http\n");
            out.push_str(poc_resp);
            out.push_str("\n```\n\n");
        }

        if let Some(fix) = &f.fix_suggestion {
            out.push_str("### Suggested Fix\n\n");
            out.push_str(fix);
            out.push_str("\n\n");
        }

        if let Some(loc) = &f.code_location {
            out.push_str(&format!("**Code Location:** `{loc}`\n\n"));
        }

        out.push_str("---\n\n");
    }

    Ok(out)
}

fn generate_bugcrowd(findings: &[&Finding], target: &str, run_id: &str) -> Result<String> {
    // Bugcrowd format is very similar to HackerOne — same markdown, different header
    let mut report = generate_hackerone(findings, target, run_id)?;
    report = report.replacen(
        "Vulnerability Report",
        "Bugcrowd Submission",
        1,
    );
    Ok(report)
}

fn generate_markdown(findings: &[Finding], target: &str, run_id: &str) -> Result<String> {
    let mut out = String::new();
    let now = Utc::now().format("%Y-%m-%d %H:%M UTC");

    out.push_str(&format!(
        "# Strix Findings — {target}\n\n\
         Run: `{run_id}` | Generated: {now}\n\n\
         | # | Title | Severity | CVSS | Status | URL |\n\
         |---|-------|----------|------|--------|-----|\n"
    ));

    for (i, f) in findings.iter().enumerate() {
        out.push_str(&format!(
            "| {} | {} | {} | {:.1} | {} | {} |\n",
            i + 1,
            f.title,
            f.severity,
            f.cvss_score,
            f.validation,
            f.url,
        ));
    }

    out.push('\n');

    for (i, f) in findings.iter().enumerate() {
        out.push_str(&format!(
            "## {} — {}\n\n{}\n\n",
            i + 1,
            f.title,
            f.description
        ));

        if let Some(poc) = &f.poc_request {
            out.push_str("```http\n");
            out.push_str(poc);
            out.push_str("\n```\n\n");
        }

        if let Some(fix) = &f.fix_suggestion {
            out.push_str("**Fix:** ");
            out.push_str(fix);
            out.push_str("\n\n");
        }
    }

    Ok(out)
}
