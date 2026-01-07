# CLAUDE.md

Guidance for Claude Code (and humans) working in this repository.

## What this is

`lancer-strix` — A Rust orchestration layer around **Strix**, the open-source autonomous AI pentest agent, forming part of the Lancer 2026 bug-bounty toolkit. It wraps the Strix Docker container with Lancer-specific infrastructure: egress firewall, proxy chain, OAST collaborator, findings DB, re-validation, and bug-bounty report export. The tool drives a Think-Plan-Act-Observe loop via Claude/GPT-5/Gemini inside a Docker sandbox equipped with Playwright, Caido proxy, sqlmap, nuclei, and semgrep.

## Architecture

- `src/main.rs` — Binary entry point; bootstraps the async runtime and dispatches CLI subcommands.
- `src/cli.rs` — CLI surface built with `clap` derive; defines all subcommands (`run`, `validate`, `report`, `findings`, `template`, `skills`) and their flags.
- `src/orchestrator/` — Docker container lifecycle management; pulls the `usestrix/strix:latest` image, injects Lancer proxy/OAST env vars, streams OpenTelemetry JSONL traces in real time.
  - `orchestrator/container.rs` — Container spawn, env injection, log streaming.
  - `orchestrator/mod.rs` — Module root; re-exports orchestrator surface.
  - `orchestrator/network.rs` — Egress firewall / nftables integration for `--strict-egress`.
- `src/findings/` — SQLite-backed findings store powered by `rusqlite`.
  - `findings/model.rs` — Finding domain model (`Finding`, severity, status).
  - `findings/store.rs` — CRUD + query operations against the SQLite DB.
  - `findings/mod.rs` — Module root.
- `src/telemetry/` — OpenTelemetry JSONL trace consumer (file-watch via `notify`).
  - `telemetry/event.rs` — Trace event deserialization.
  - `telemetry/mod.rs` — Module root; wires watcher to findings ingestion.
- `src/reports/` — Report exporters (HackerOne, Bugcrowd, Markdown).
  - `reports/mod.rs` — Module root.
  - `reports/templates.rs` — Template rendering for each report format.
- `src/proxy.rs` — Lancer proxy integration; routes all Strix HTTP traffic through Lancer history.
- `src/skills.rs` — Bundled Lancer skill management; list/install skills into running containers.
- `src/validator.rs` — PoC HTTP request re-replay for HIGH/CRITICAL finding validation.
- `skills/` — Bundled Lancer skill markdown files (e.g., `lancer-oast-collaborator.md`, `lancer-vuln-report.md`).

## Conventions

- Error propagation uses `anyhow::Result`; no `unwrap`/`expect` on fallible I/O.
- All async code uses `tokio` with the `#[tokio::main]` runtime; prefer `tokio::spawn` for concurrent container log streaming.
- Library code lives in per-module files under `src/`; binary entry point in `src/main.rs`.
- Serialization uses `serde` + `serde_json`; all domain models derive `Serialize`/`Deserialize`.
- LLM model strings follow the LiteLLM convention (`anthropic/claude-sonnet-4-6`); never hardcode provider-specific API paths.
- Findings are keyed by UUID v4 and timestamped with `chrono`; severity levels mirror HackerOne's taxonomy (informational / low / medium / high / critical).

## Build / test / run

```
build.bat                   # Windows → build\lancer-strix.exe
./build-linux.sh            # Linux/macOS
cargo build --release       # standard release build
cargo test                  # unit + integration tests
```

## Repo notes

- `plan.md` is local-only and must NOT be committed. It is gitignored; if ever tracked, run `git rm --cached plan.md`.
- `.claude/` and `target/`/`build/`/`dist/` are local-only and gitignored.
