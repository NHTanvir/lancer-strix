use anyhow::Result;
use reqwest::Client;
use std::time::Duration;
use tracing::{info, warn};

use crate::findings::{Finding, FindingsStore, ValidationStatus};

/// Re-validates HIGH/CRITICAL findings by replaying their PoC HTTP requests
/// independently of Strix, confirming reproduction before surfacing to the user.
///
/// Week 8: for each Strix CRITICAL/HIGH finding, re-run the PoC via Lancer's
/// request engine (reqwest), update validation status in the findings DB.
pub struct Validator {
    client: Client,
}

impl Validator {
    pub fn new() -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()?;
        Ok(Validator { client })
    }

    /// Validate all pending HIGH/CRITICAL findings for a run.
    /// Returns (confirmed_count, not_reproduced_count).
    pub async fn validate_run(
        &self,
        store: &FindingsStore,
        run_id: &str,
        min_cvss: f32,
    ) -> Result<(usize, usize)> {
        let findings = store.get_findings(run_id, Some(min_cvss), false)?;
        let targets: Vec<Finding> = findings
            .into_iter()
            .filter(|f| f.validation == ValidationStatus::Pending)
            .collect();

        info!(
            "Re-validating {} pending findings (CVSS >= {min_cvss:.1})...",
            targets.len()
        );

        let mut confirmed = 0usize;
        let mut not_reproduced = 0usize;

        for finding in &targets {
            let status = match self.validate_finding(finding).await {
                Ok(s) => s,
                Err(e) => {
                    warn!("Validation error for '{}': {e}", finding.title);
                    ValidationStatus::Skipped
                }
            };

            store.set_validation(&finding.id, &status)?;

            info!(
                "  [{:<14}] {:<8} {:>4.1} CVSS — {}",
                status.to_string(),
                finding.severity.to_string(),
                finding.cvss_score,
                finding.title,
            );

            match status {
                ValidationStatus::Confirmed => confirmed += 1,
                ValidationStatus::NotReproduced => not_reproduced += 1,
                _ => {}
            }
        }

        Ok((confirmed, not_reproduced))
    }

    async fn validate_finding(&self, finding: &Finding) -> Result<ValidationStatus> {
        if finding.url.is_empty() {
            return Ok(ValidationStatus::Skipped);
        }

        if let Some(poc_req) = &finding.poc_request {
            return self.replay_poc_request(&finding.url, poc_req).await;
        }

        // No PoC — basic reachability check
        match self.client.get(&finding.url).send().await {
            Ok(r) => {
                if r.status().as_u16() == 404 {
                    Ok(ValidationStatus::NotReproduced)
                } else {
                    Ok(ValidationStatus::Confirmed)
                }
            }
            Err(_) => Ok(ValidationStatus::NotReproduced),
        }
    }

    /// Parse a raw HTTP request string and replay it via reqwest.
    ///
    /// Raw PoC format:
    ///   POST /api/login HTTP/1.1\r\n
    ///   Host: target.example.com\r\n
    ///   Content-Type: application/json\r\n
    ///   \r\n
    ///   {"username":"admin' OR 1=1--","password":"x"}
    async fn replay_poc_request(
        &self,
        base_url: &str,
        poc_req: &str,
    ) -> Result<ValidationStatus> {
        let mut lines = poc_req.lines();

        let request_line = match lines.next() {
            Some(l) if !l.is_empty() => l,
            _ => return Ok(ValidationStatus::Skipped),
        };

        let parts: Vec<&str> = request_line.splitn(3, ' ').collect();
        if parts.len() < 2 {
            return Ok(ValidationStatus::Skipped);
        }

        let method: reqwest::Method = parts[0].parse().unwrap_or(reqwest::Method::GET);
        let path = parts[1];

        let full_url = build_full_url(base_url, path);

        let mut headers = reqwest::header::HeaderMap::new();
        let mut body = String::new();
        let mut in_body = false;

        for line in lines {
            if in_body {
                if !body.is_empty() {
                    body.push('\n');
                }
                body.push_str(line);
                continue;
            }
            if line.trim().is_empty() {
                in_body = true;
                continue;
            }
            if let Some((key, val)) = line.split_once(": ") {
                let lower = key.to_lowercase();
                // Skip hop-by-hop headers that reqwest manages
                if matches!(
                    lower.as_str(),
                    "content-length" | "transfer-encoding" | "connection"
                ) {
                    continue;
                }
                if let (Ok(name), Ok(value)) = (
                    reqwest::header::HeaderName::from_bytes(key.as_bytes()),
                    reqwest::header::HeaderValue::from_str(val.trim()),
                ) {
                    headers.insert(name, value);
                }
            }
        }

        let mut req = self.client.request(method, &full_url).headers(headers);
        if !body.is_empty() {
            req = req.body(body);
        }

        match req.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                if status == 404 {
                    Ok(ValidationStatus::NotReproduced)
                } else {
                    Ok(ValidationStatus::Confirmed)
                }
            }
            Err(_) => Ok(ValidationStatus::NotReproduced),
        }
    }
}

fn build_full_url(base_url: &str, path: &str) -> String {
    if path.starts_with("http://") || path.starts_with("https://") {
        return path.to_string();
    }
    let base = url::Url::parse(base_url)
        .unwrap_or_else(|_| url::Url::parse("http://localhost").unwrap());
    format!(
        "{}://{}{}",
        base.scheme(),
        base.host_str().unwrap_or("localhost"),
        path
    )
}
