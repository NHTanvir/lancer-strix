# lancer-strix

Rust orchestration layer around **Strix** — the open-source autonomous AI pentest agent. Part of the Lancer bug bounty toolkit.

Strix (Python, 25.6k stars) is an autonomous AI pentester that finds and exploits web vulnerabilities using a Think-Plan-Act-Observe loop with Claude/GPT-5/Gemini, inside a Docker sandbox with Playwright, Caido proxy, sqlmap, nuclei, and semgrep. This crate wraps it with Lancer-specific infrastructure: egress firewall, proxy chain, OAST collaborator, findings DB, re-validation, and bug-bounty report export.

## Architecture

```
lancer-strix run --target https://acme.com
      │
      ├─ Pulls usestrix/strix:latest Docker image
      ├─ Injects Lancer proxy (HTTP_PROXY) → all Strix HTTP traffic visible in Lancer history
      ├─ Injects LANCER_OAST_DOMAIN → blind SSRF/XSS detection via Lancer collaborator
      ├─ Injects custom skills (lancer-oast-collaborator.md, lancer-vuln-report.md)
      ├─ Streams OpenTelemetry JSONL traces in real time
      └─ Ingests findings.json → Lancer SQLite DB after scan completes

lancer-strix validate          # re-replay PoC requests to confirm findings
lancer-strix report            # export HackerOne / Bugcrowd markdown report
lancer-strix findings          # list findings table
lancer-strix template list     # show Docker policy presets
lancer-strix skills list       # show bundled Lancer skills
```

## Quick start

```bash
# 1. Set LLM API key
export LLM_API_KEY="sk-ant-..."          # Anthropic (recommended)
# or: OPENAI_API_KEY, GEMINI_API_KEY — Strix routes through LiteLLM

# 2. Run a scan
lancer-strix run \
  --target https://target-in-scope.com \
  --instruction "Focus on IDOR in /api/v2/users and JWT issues" \
  --scan-mode deep \
  --model anthropic/claude-opus-4-7

# 3. Re-validate HIGH/CRITICAL findings
lancer-strix validate

# 4. Generate a HackerOne report (validated findings only)
lancer-strix report --validated-only --output report.md

# 5. Browse findings
lancer-strix findings
```

## Subcommands

| Subcommand | Description |
|---|---|
| `run` | Spawn a Strix Docker container and run an autonomous pentest |
| `validate` | Re-replay PoC HTTP requests to confirm HIGH/CRITICAL findings |
| `report` | Export findings as a HackerOne, Bugcrowd, or Markdown report |
| `findings` | Display a findings table for a run |
| `template` | List / show Docker policy presets (WordPress, GraphQL, JWT, SPA) |
| `skills` | List / install bundled Lancer skills into the Strix container |

## Key flags

```
run:
  --target            URL, GitHub repo, local path, or IP/CIDR
  --instruction       Natural-language focus instruction for Strix
  --instruction-file  Markdown instruction file (bind-mounted into container)
  --scan-mode         quick | standard | deep  (default: standard)
  --model             LiteLLM model string (default: anthropic/claude-sonnet-4-6)
  --reasoning-effort  low | medium | high  (default: medium)
  --proxy-addr        Lancer proxy host:port (default: 127.0.0.1:8080)
  --oast-domain       Lancer OAST collaborator domain for blind vuln detection
  --lancer-api        Lancer API base URL (default: http://127.0.0.1:9090)
  --template          Apply a named Docker policy template
  --strict-egress     Restrict container egress to target IP (Linux/nftables only)
  --interactive       Enable Strix human-in-the-loop mode (v0.8.3+)
  --headless          No TUI, plain log output (good for CI)

validate:
  --run-id            Run to validate (defaults to most recent)
  --min-cvss          Only validate findings >= this score (default: 7.0)

report:
  --run-id            Run to report (defaults to most recent)
  --platform          hackerone | bugcrowd | markdown  (default: hackerone)
  --min-cvss          Filter by CVSS (default: 4.0)
  --validated-only    Only include Confirmed findings
  --output            File path (defaults to stdout)
```

## Bundled Lancer skills

These Strix v0.7+ markdown skills are injected into the container at scan start:

- **lancer-oast-collaborator.md** — teaches Strix to use Lancer's OAST domain for blind SSRF/XSS
- **lancer-vuln-report.md** — replaces Strix's default reporting with Lancer API POST

## Docker templates

Pre-configured instruction + scan-mode bundles for common stacks:

```bash
lancer-strix template list
lancer-strix template show wordpress
lancer-strix run --target https://wp-site.com --template wordpress
```

Available: `wordpress`, `graphql`, `jwt-rest`, `spa-rest`

## Findings storage

All findings are persisted to `~/.lancer/strix/findings.db` (SQLite). Run traces land in `~/.lancer/strix/runs/<run-id>/`.

## Build

### Windows
```
build.bat
```
Output: `build\lancer-strix.exe`

Packaged dist:
```
build-windows.bat
```
Output: `dist\lancer-strix-windows-x86_64\bin\lancer-strix.exe`

### Linux / macOS
```bash
./build-linux.sh
```
Output: `build/lancer-strix`

### Requirements
- [Rust / Cargo](https://rustup.rs)
- Docker (for `run` subcommand)
- (Windows) Visual C++ Build Tools 2019/2022
