use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use std::path::Path;
use tracing::info;

use super::model::{Finding, Severity, ValidationStatus};

/// SQLite-backed persistent store for vulnerability findings.
/// Each lancer-strix install uses a single DB at `~/.lancer/strix/findings.db`.
pub struct FindingsStore {
    conn: Connection,
}

impl FindingsStore {
    /// Open (or create) the findings database at `path`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent)?;
        }

        let conn = Connection::open(path.as_ref())
            .context("Failed to open findings database")?;

        let store = FindingsStore { conn };
        store.migrate()?;

        info!("Findings DB ready at {:?}", path.as_ref());
        Ok(store)
    }

    /// Run schema migrations (idempotent).
    fn migrate(&self) -> Result<()> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS findings (
                id                  TEXT PRIMARY KEY,
                run_id              TEXT NOT NULL,
                vuln_class          TEXT NOT NULL,
                title               TEXT NOT NULL,
                description         TEXT NOT NULL,
                url                 TEXT NOT NULL,
                method              TEXT NOT NULL,
                cvss_score          REAL NOT NULL,
                severity            TEXT NOT NULL,
                cwe                 TEXT,
                cve                 TEXT,
                poc_request         TEXT,
                poc_response        TEXT,
                fix_suggestion      TEXT,
                code_location       TEXT,
                validation          TEXT NOT NULL DEFAULT 'pending',
                reported_at         TEXT NOT NULL,
                validated_at        TEXT,
                merged_from_scanner INTEGER NOT NULL DEFAULT 0,
                tags                TEXT NOT NULL DEFAULT '[]'
            );

            CREATE TABLE IF NOT EXISTS runs (
                run_id      TEXT PRIMARY KEY,
                target      TEXT NOT NULL,
                model       TEXT NOT NULL,
                scan_mode   TEXT NOT NULL,
                started_at  TEXT NOT NULL,
                finished_at TEXT,
                exit_code   INTEGER
            );

            CREATE INDEX IF NOT EXISTS idx_findings_run_id ON findings(run_id);
            CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
            CREATE INDEX IF NOT EXISTS idx_findings_validation ON findings(validation);",
        )?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Runs
    // ------------------------------------------------------------------

    pub fn insert_run(&self, run_id: &str, target: &str, model: &str, scan_mode: &str) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO runs (run_id, target, model, scan_mode, started_at)
             VALUES (?1, ?2, ?3, ?4, datetime('now'))",
            params![run_id, target, model, scan_mode],
        )?;
        Ok(())
    }

    pub fn finish_run(&self, run_id: &str, exit_code: i64) -> Result<()> {
        self.conn.execute(
            "UPDATE runs SET finished_at = datetime('now'), exit_code = ?1 WHERE run_id = ?2",
            params![exit_code, run_id],
        )?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Findings
    // ------------------------------------------------------------------

    pub fn insert_finding(&self, f: &Finding) -> Result<()> {
        let tags = serde_json::to_string(&f.tags)?;
        self.conn.execute(
            "INSERT OR REPLACE INTO findings (
                id, run_id, vuln_class, title, description, url, method,
                cvss_score, severity, cwe, cve, poc_request, poc_response,
                fix_suggestion, code_location, validation, reported_at,
                validated_at, merged_from_scanner, tags
             ) VALUES (
                ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20
             )",
            params![
                f.id,
                f.run_id,
                f.vuln_class,
                f.title,
                f.description,
                f.url,
                f.method,
                f.cvss_score,
                f.severity.to_string(),
                f.cwe,
                f.cve,
                f.poc_request,
                f.poc_response,
                f.fix_suggestion,
                f.code_location,
                f.validation.to_string(),
                f.reported_at.to_rfc3339(),
                f.validated_at.map(|t| t.to_rfc3339()),
                f.merged_from_scanner as i32,
                tags,
            ],
        )?;
        Ok(())
    }

    pub fn set_validation(&self, finding_id: &str, status: &ValidationStatus) -> Result<()> {
        self.conn.execute(
            "UPDATE findings SET validation = ?1, validated_at = datetime('now') WHERE id = ?2",
            params![status.to_string(), finding_id],
        )?;
        Ok(())
    }

    /// Load findings for a run, optionally filtered by min CVSS and validation status.
    pub fn get_findings(
        &self,
        run_id: &str,
        min_cvss: Option<f32>,
        validated_only: bool,
    ) -> Result<Vec<Finding>> {
        let min_cvss = min_cvss.unwrap_or(0.0);

        let mut stmt = self.conn.prepare(
            "SELECT id, run_id, vuln_class, title, description, url, method,
                    cvss_score, severity, cwe, cve, poc_request, poc_response,
                    fix_suggestion, code_location, validation, reported_at,
                    validated_at, merged_from_scanner, tags
             FROM findings
             WHERE run_id = ?1
               AND cvss_score >= ?2
             ORDER BY cvss_score DESC",
        )?;

        let findings: Vec<Finding> = stmt
            .query_map(params![run_id, min_cvss], |row| {
                let severity_str: String = row.get(8)?;
                let validation_str: String = row.get(15)?;
                let tags_str: String = row.get(19)?;

                Ok(Finding {
                    id: row.get(0)?,
                    run_id: row.get(1)?,
                    vuln_class: row.get(2)?,
                    title: row.get(3)?,
                    description: row.get(4)?,
                    url: row.get(5)?,
                    method: row.get(6)?,
                    cvss_score: row.get(7)?,
                    severity: parse_severity(&severity_str),
                    cwe: row.get(9)?,
                    cve: row.get(10)?,
                    poc_request: row.get(11)?,
                    poc_response: row.get(12)?,
                    fix_suggestion: row.get(13)?,
                    code_location: row.get(14)?,
                    validation: parse_validation(&validation_str),
                    reported_at: chrono::DateTime::parse_from_rfc3339(
                        &row.get::<_, String>(16)?,
                    )
                    .unwrap_or_default()
                    .with_timezone(&chrono::Utc),
                    validated_at: row
                        .get::<_, Option<String>>(17)?
                        .and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
                        .map(|dt| dt.with_timezone(&chrono::Utc)),
                    merged_from_scanner: row.get::<_, i32>(18)? != 0,
                    tags: serde_json::from_str(&tags_str).unwrap_or_default(),
                })
            })?
            .filter_map(|r| r.ok())
            .filter(|f| {
                if validated_only {
                    f.validation == ValidationStatus::Confirmed
                } else {
                    true
                }
            })
            .collect();

        Ok(findings)
    }

    /// Load the most recent run ID from the DB.
    pub fn latest_run_id(&self) -> Result<Option<String>> {
        let result = self.conn.query_row(
            "SELECT run_id FROM runs ORDER BY started_at DESC LIMIT 1",
            [],
            |row| row.get(0),
        );
        match result {
            Ok(id) => Ok(Some(id)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}

fn parse_severity(s: &str) -> Severity {
    match s {
        "CRITICAL" => Severity::Critical,
        "HIGH" => Severity::High,
        "MEDIUM" => Severity::Medium,
        "LOW" => Severity::Low,
        _ => Severity::Informational,
    }
}

fn parse_validation(s: &str) -> ValidationStatus {
    match s {
        "confirmed" => ValidationStatus::Confirmed,
        "not_reproduced" => ValidationStatus::NotReproduced,
        "skipped" => ValidationStatus::Skipped,
        _ => ValidationStatus::Pending,
    }
}
