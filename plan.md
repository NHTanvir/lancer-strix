# RESEARCH DOSSIER: Strix

> Part of the Lancer ecosystem. A Rust wrapper + orchestration layer around Strix — the open-source autonomous AI pentest agent (XBOW alternative). Build with Claude Code.
> Upstream: github.com/usestrix/strix (Python, 25.6k stars, v0.8.3 March 2026). 96% solve rate on XBEN benchmark.

## Feature Parity Mandate

**`lancer-strix` MUST ship with 100% feature parity to the upstream `strix` tool — every flag, every subcommand, every output format, every probe / detector / module / payload / mode — plus a native Rust GUI on top.** This is not a "subset clone" — this is a full reimplementation in Rust with a GUI wrapper.

### Parity contract

- **Every CLI flag** documented in upstream `strix --help` (and the long-form man page / docs) must work in `lancer-strix --cli`.
- **Every output format** the upstream tool emits (text, JSON, XML, CSV, SARIF, custom formats) must round-trip through `lancer-strix` byte-equivalent where the format allows.
- **Every probe / detector / module / category / payload class / built-in script** must be ported. None silently dropped.
- **Every supported target type / input format / protocol / file format / language** must work.
- **Every configuration option** (config files, env vars, registry / settings entries) must be honoured.
- **Companion binaries / sub-tools** in the upstream suite (if any) must each get their own binary in this workspace.

### GUI on top

Every feature reachable via CLI is also reachable from the GUI (see `## GUI (Lancer-standard pattern)` below). The GUI is not a subset — it is an alternate frontend over the same `core` library that the CLI uses. The `core` crate is GUI-agnostic.

### Verification

- The `## Granular feature catalog` section below enumerates everything that must be supported.
- Reference: `tests/upstream_parity/` will pin upstream flag combinations + canned outputs as parity tests. CI fails if any flag is unsupported or output diverges.
- A `lancer-strix --self-test` flag runs the full parity matrix against a bundled reference target and prints pass/fail per upstream feature group.

### What is allowed to diverge

- **Performance** — Rust-native, async-first; we are allowed to be faster.
- **Memory footprint** — we are allowed to be smaller.
- **GUI** — entirely new (no upstream GUI to copy except where the upstream ships its own GUI like Zenmap / Wireshark UI / Ghidra GUI / jadx-gui — in which case our GUI must cover every panel the upstream GUI has, plus the Lancer-standard layout from `## GUI` below).
- **AI augmentation** — net-new (see `## AI augmentation ideas`).

### What is NOT allowed to diverge

- Any flag silently dropped, renamed, or behavior-changed compared to upstream.
- Any output format / record schema diverging in field names, types, or semantics.
- Any built-in script / detector / module not ported (mark explicitly with `[N/A — see note]` if genuinely impossible in Rust, e.g. NSE Lua scripts requiring features not in `mlua`).

## What it actually does

Strix is an **open-source autonomous AI pentest agent** — point it at a URL or codebase, it finds and exploits vulnerabilities in isolated Docker containers, validates with proof-of-concept exploits, and produces vulnerability reports with CVSS scores and code-location-anchored fix suggestions.

It's the open-source answer to **XBOW** (the closed-source autonomous pentester that hit #1 on HackerOne US in 2025 with ~1,060 reported vulns). XBOW raised $117M in 2025-2026; Strix is the community-driven equivalent that "top 1% bug bounty hunters on HackerOne" reportedly use.

**One-line architecture:** A LiteLLM-routed LLM (Claude Sonnet 4.6, GPT-5.4, Gemini 3 Pro, or local) running in a "Think-Plan-Act-Observe" loop inside a Docker container with full pentest toolkit (Caido proxy, Playwright browser, tmux terminal, IPython runtime, semgrep, sqlmap, nuclei), capable of spawning a graph of sub-agents that each own a specific attack surface.

Strix passed **Ostorlab's 2026 evaluation of 8 open-source AI pentest tools** as one of only two successful frameworks (alongside CAI), finding blind SQL injection (CVSS 10.0), connection-pool exhaustion, API backend leakage, and mapping 40+ endpoints against `vulnbank.org`. On the XBEN benchmark (104 CTF web challenges), **Strix v0.4.0 solved 100/104 = 96% success rate.**

## Rust port viability — HONEST verdict

**Don't port. Keep Python. Build Rust tooling Strix can shell into.**

Reasoning:
- Strix's core value is the agent loop + prompt engineering + tool ecosystem (Playwright, semgrep, sqlmap, nuclei, Caido — all mature and most have Python bindings).
- Rust LLM-agent frameworks **exist** (Rig, AutoAgents, OpenFANG, langchain-ai-rust, swiftide) and are getting better, but:
  - The agent-loop pattern is I/O-bound (~6s per LLM call); Rust's perf advantage barely matters here.
  - You'd lose LiteLLM's instant access to 100+ providers — `litellm-rust` exists but covers ~4 providers.
  - You'd lose Playwright/IPython ergonomics.
  - You'd lose semgrep/sqlmap/nuclei wrapper code already written in Python.
- The Rust ecosystem **is** better for the **infrastructure** around Strix: container orchestration, OAST collaborator, HTTP proxy, signal-processing of agent telemetry. Those are exactly Lancer's strengths.

**Recommendation for Lancer:** Keep Strix in Python. Build Lancer's "Autonomous LLM Pentester" as an opinionated **launcher + integration layer** in Rust that:

1. **Spawns Strix in a Lancer-controlled Docker container** with Lancer's proxy as the upstream (so all Strix HTTP traffic flows through Lancer for capture/inspection).
2. **Provides custom Strix skills** (the v0.7 markdown-format skills) for Lancer-specific things: "use Lancer OAST collaborator for SSRF detection", "report findings into Lancer's vulnerability DB via this API", "consult Lancer's site-map before recon".
3. **Replaces Strix's reporting tool** with one that writes into Lancer's vulnerability schema natively.
4. **Adds a Lancer "Autonomous Agent" tab** that drives Strix via subprocess + OpenTelemetry JSONL traces (Strix v0.8.3 emits these).

If you absolutely must build a Rust autonomous agent for your own learning, **wait 6 months** — the Rust agent ecosystem is hitting a maturity inflection in late 2026 (Rig 24.3% CPU vs Python's ~80%, sub-5ms cold starts vs 60-140ms). For shipping a Burp-clone with autonomous LLM-pentest features **today**, wrap Strix.

## Internal architecture (with code refs)

**Top-level repo layout** (Python 3.11+, uv-managed):

```
strix/
├── strix/                          # the Python package
│   ├── agents/
│   │   ├── base_agent.py           # abstract agent class — perceive/think/act loop
│   │   ├── state.py                # agent state object
│   │   └── StrixAgent/
│   │       ├── strix_agent.py      # concrete agent — main loop implementation
│   │       └── system_prompt.jinja # THE prompt
│   ├── llm/
│   │   ├── llm.py                  # LiteLLM wrapper, retry, streaming, thinking blocks
│   │   └── memory_compressor.py    # summarizes old turns when context fills
│   ├── runtime/
│   │   └── docker_runtime.py       # spawns Docker container with Tool Server API
│   ├── tools/
│   │   ├── argument_parser.py
│   │   ├── context.py
│   │   ├── executor.py             # central tool dispatcher
│   │   ├── registry.py             # tool registration
│   │   ├── agents_graph/           # spawn/coordinate sub-agents
│   │   ├── browser/                # Playwright-driven Chrome
│   │   ├── proxy/                  # Caido HTTP proxy interface
│   │   ├── terminal/               # libtmux interactive shell
│   │   ├── python/                 # IPython exploit runtime
│   │   ├── file_edit/              # file mutations
│   │   ├── notes/                  # agent scratchpad
│   │   ├── thinking/               # reasoning tool (force CoT)
│   │   ├── todo/                   # task tracking (v0.5+)
│   │   ├── reporting/              # create_vulnerability_report
│   │   ├── web_search/             # Perplexity-backed search
│   │   ├── load_skill/             # dynamic skill loading (v0.7+)
│   │   └── finish/                 # task termination
│   ├── skills/                     # markdown skill files (v0.7+, was Jinja pre-v0.7)
│   ├── interface/
│   │   ├── cli.py                  # standard CLI
│   │   └── tui.py                  # Textual-based TUI
│   ├── telemetry/
│   │   ├── tracer.py
│   │   └── utils.py                # OpenTelemetry JSONL export (v0.8.3)
│   ├── config/
│   └── utils/
├── containers/                     # Dockerfiles for sandbox
├── benchmarks/                     # XBEN harness, vulnbank harness
└── pyproject.toml
```

### Agent loop (Think-Plan-Act-Observe)

`strix/agents/StrixAgent/strix_agent.py`:

```
loop:
  messages = state.compress(memory_compressor)        # if approaching context limit
  resp = llm.generate(system_prompt, messages, tools)  # streaming
  if resp.has_thinking_blocks:
    preserve & chain across steps (v0.6 thinking-block reuse)
  tool_calls = parse_tool_invocations(resp)
  for call in tool_calls:
    result = tool_executor.dispatch(call)
    state.append(call, result)
  if 'finish' or scan_mode budget exhausted: break
```

`LLM.generate()` uses `litellm.acompletion(..., stream=True)` with `stream_options: {"include_usage": True}`. Parses tool invocations after stream completes by regex-matching `</function>` and `</invoke>` closers. Implements exponential backoff `wait = min(90, 2 * (2**attempt))`.

**State management** tracks `messages: list[Message]`, `tool_results: list`, `todo: list[Task]`, `findings: list[Vulnerability]`, `cost: float`, `tokens_in/out: int`, `step_count: int`.

**Memory management**: when message history approaches model context limit (default 80% of context window), `MemoryCompressor.compress()` summarizes the oldest 50% into a concise "memory note" via a cheap model (`gpt-4o-mini` / `claude-haiku-4.5`), preserving recent turns verbatim. Anthropic prompt caching is enabled for system prompt + compressed history.

### Tool layer

The 13 tool categories:

| Tool dir | Backend | Purpose |
|---|---|---|
| `browser/` | Playwright (Chromium) | Multi-tab browser; XSS/CSRF/auth flows. v0.6.2: single shared browser instance across agents |
| `proxy/` | Caido | Full request/response intercept + replay; v0.8.2 exposes proxy port to human |
| `terminal/` | libtmux | Persistent interactive shells; run nmap, sqlmap, nuclei, semgrep |
| `python/` | IPython | Exploit dev — pwntools-style PoC writing, request crafting |
| `file_edit/` | local FS | Patch source code, write exploits to disk |
| `notes/` | local FS | Agent scratchpad |
| `thinking/` | n/a | Forces explicit chain-of-thought without consuming completion tokens |
| `todo/` | local FS | Task tracking (v0.5+) |
| `reporting/` | local FS + Tracer | `create_vulnerability_report(...)` — THE only way to count a finding |
| `web_search/` | Perplexity API | Look up CVEs, framework defaults |
| `load_skill/` | local FS | Dynamic load of markdown skill (v0.7+) |
| `agents_graph/` | internal | Spawn child agents, communicate via shared state |
| `finish/` | internal | Terminate this agent |

### LLM provider abstraction (LiteLLM)

Provider config via env vars:
```bash
export STRIX_LLM="anthropic/claude-sonnet-4.6"
export LLM_API_KEY="..."
export LLM_API_BASE="..."         # for Ollama, LMStudio, OpenAI-compatible
export PERPLEXITY_API_KEY="..."   # optional for web_search tool
export STRIX_LLM_MAX_RETRIES=5
```

Supported (via LiteLLM): **Anthropic Claude (Sonnet 4.6, Opus 4.7), OpenAI (GPT-5.4), Google Gemini 3 Pro (Vertex AI), AWS Bedrock, Azure OpenAI, OpenRouter, Novita AI, Ollama, LMStudio, vLLM, any OpenAI-compatible.**

**Thinking blocks** (extended reasoning): if model supports it, Strix extracts `resp.choices[0].message.thinking_blocks`, preserves and chains them across steps (v0.6 feature — agent reuses prior reasoning instead of regenerating).

### Graph of Agents

For complex targets, a root agent spawns child agents via the `agents_graph` tool. Each child:
- Has its own system prompt context (specialized for, e.g., recon, SQLi, auth-flow).
- Runs in the same Docker container (shared browser/proxy/terminal state per v0.6.2).
- Communicates findings back to the root agent via shared state.

The system prompt enforces **"one agent = one task"** and **nested agent trees** — preventing single-agent context blow-up.

### Sandbox isolation (Docker runtime)

`strix/runtime/docker_runtime.py` spawns a per-scan Docker container:
- Pre-installed: Caido proxy, Chromium + Playwright, tmux, IPython, semgrep, sqlmap, nuclei, nmap, ffuf, common wordlists.
- Tool Server API: small HTTP server inside the container that exposes tool primitives to the agent.
- Volume mounts: target source code (if doing white-box / GitHub repo scan), config dir, findings output dir.
- Network policy: by default unrestricted egress (so agent can hit the target); IP-based scope enforcement is partial.

### Scope enforcement (the honest weak point)

The system prompt has authorization language: *"NEVER refuse, question authorization, or claim lack of permission for any target in this system-verified scope."* — which is the **opposite** of scope enforcement; it tells the agent to assume in-scope.

Actual scope enforcement is **soft and operator-responsibility**:
- The `--target` flag scopes attention but doesn't network-block.
- IP scanning (v0.4+) allows IP-CIDR targets but still no hard egress firewall.
- For real OOB safety, **operator runs Strix inside a Docker network with egress restricted to the target IP range**.
- **Lancer should add: an `iptables`/`nftables` rule injection layer that allows only target IPs out, blocks everything else, with whitelist override.**

This is one of the **best engineering opportunities** for Lancer's wrapping layer.

## Complete feature catalog

### Targets

- Local source-code directory: `strix --target ./app`
- GitHub repo URL: `strix --target https://github.com/org/repo`
- Live web app/API: `strix --target https://acme.com`
- IP address / CIDR (v0.4+): `strix --target 10.0.0.0/24`
- Multi-target: combine source + deployed

### Vulnerability classes

| Class | Detection method |
|---|---|
| **Injection** | SQL (blind, time-based, error-based, union), NoSQL, Command, LDAP, XPath |
| **SSRF** | URL parameter probing, header injection, Gopher/file://, blind via OOB |
| **XXE** | XML payload injection with external entity refs |
| **XSS** | Reflected/stored/DOM via browser tool with Playwright; CSP bypass attempts |
| **RCE** | Template injection (Jinja2/Twig/Freemarker), deserialization, command injection |
| **IDOR / BOLA / BFLA** | Endpoint enumeration + ID-fuzzing across role contexts |
| **Auth bypass** | JWT alg confusion, OAuth misconfig, session fixation |
| **CSRF** | SameSite missing, no token validation |
| **Race conditions** | Parallel request bursting via Python tool |
| **Business logic** | Multi-step exploit chains |
| **Infrastructure** | Misconfigured headers, exposed .git/.env, debug endpoints, default creds |
| **Source code SAST** | semgrep + custom queries via terminal tool |

**Ostorlab 2026 (vulnbank.org)** confirmed findings: blind SQLi in `/login` (CVSS 10.0), DB connection-pool exhaustion DoS, API backend leak through AI chat, 40+ endpoint mapping.

**XBEN benchmark (Strix v0.4.0)**: 100/104 solved (96%).

### Modes

- **Autonomous mode**: `strix --target ... `
- **Guided / instruction mode**: `strix --target ... --instruction "Focus on..."`
- **File-based instructions (v0.4+)**: `--instruction-file my_pentest_plan.md`
- **Headless mode (CI)**: `strix -n --target ... --scan-mode quick`
- **Interactive mode (v0.8.3)**: hooks into agent loop for human-in-loop steering
- **Caido proxy port exposed (v0.8.2)**: human can intercept/tamper while agent runs

### Scan modes (v0.5+)

- `quick` — fast surface sweep, low cost, fewer steps
- `standard` — default, balanced
- `deep` — exhaustive, "2000+ steps minimum"

### Output formats

- TUI: live findings panel, agent stats (tokens, cost, steps), syntax-highlighted markdown (v0.7)
- CLI: streaming markdown
- JSON findings file: `~/.strix/runs/<run-id>/findings.json` (real-time persistence v0.4+)
- Vulnerability reports (v0.8): nested XML code-location format with CVSS scoring; PR-suggestion-ready
- Autofix: agent generates fix suggestions
- OpenTelemetry JSONL traces (v0.8.3) at `~/.strix/runs/<run-id>/traces.jsonl`

### vs XBOW (the comparison everyone makes)

| Dimension | Strix (open) | XBOW (closed) |
|---|---|---|
| Source | Open MIT | Closed SaaS |
| Funding | Community + small commercial | $117M raised 2025-2026 |
| HackerOne rank | "top 1% hunters use it" (anecdotal) | **#1 on HackerOne US, ~1,060 vulns** |
| Validation | Ostorlab 2026: pass; XBEN: 96% | Public leaderboard performance |
| Tool stack | Caido + Playwright + tmux + IPython + semgrep/sqlmap/nuclei | Proprietary |
| LLM | Any via LiteLLM | Proprietary mix |
| Hosted | Self-host Docker | SaaS-only |

**Bottom line**: XBOW wins on raw bug-hunting performance today; Strix wins on transparency, customization, on-prem, cost. For a bug-bounty hunter, Strix is the right tool to compose into a personal workflow you control.

## Engineering hard parts

1. **Planner-executor split (avoiding context explosion).** Strix's answer: spawn sub-agents via `agents_graph` tool. Each sub-agent has its own fresh context, narrow task, reports a structured result. Root agent never sees raw tool output from sub-agents — only summaries. This is **the** architectural trick that lets it scale beyond a single LLM context window.
2. **Tool result parsing back into agent state.** Long tool outputs get **truncated and summarized** via `MemoryCompressor` before being appended to messages. Critical: preserve **exact** values that look like flags, tokens, IDs (LLM can lose them in compression). Strix uses heuristic extractors for high-entropy strings.
3. **Scope enforcement / safety.** Soft enforcement via prompt only. Hard enforcement is operator-responsibility (Docker network policies). Lancer should add this layer.
4. **Validation (real findings vs hallucinations).** The **"evidence-before-claim" pattern**: system prompt mandates that *"A vulnerability is ONLY considered reported when a reporting agent uses `create_vulnerability_report`"* AND the vuln has a working PoC. The reporting agent is a separate sub-agent that **independently re-runs the PoC** before filing. This drops false-positive rate dramatically (why Ostorlab 2026 lists Strix as one of only two passing tools).
5. **Thinking-block preservation (v0.6).** When the model supports extended reasoning, Strix preserves thinking blocks and chains them across loop iterations.
6. **Vulnerability dedup (v0.6).** LLM-based dedup across all findings before report time.
7. **Cost control.** Live stats panel shows tokens/cost per agent; agents have token budgets. `scan-mode quick` caps step count.
8. **Browser instance sharing (v0.6.2).** Single Playwright Chromium across all sub-agents.
9. **Caido proxy + human-in-loop (v0.8.2).** Exposed port lets human intercept while agent runs.
10. **System prompt engineering.** The Jinja system prompt is the secret sauce: mandates "EVERY message during work MUST contain exactly one tool call", enumerates the 10 vuln categories, prefers established tools over custom scripts, requires PoC-before-report.

## Library mapping (for keep-Python-add-Rust-tooling approach)

**Python deps to keep using:**
- LiteLLM — 100+ providers, you'd lose this in Rust
- Playwright — battle-tested browser automation
- IPython — exploit dev ergonomics
- libtmux — terminal multiplexer
- Textual — TUI framework
- Caido — HTTP proxy

**Where Rust adds value (Lancer's additions to Strix workflow):**

| Need | Rust crate | Why Rust |
|---|---|---|
| Lancer's HTTP proxy chain | `hudsucker`, `rustls`, `hyper` | Performance — Strix can fire 1000s of requests during fuzzing |
| OAST collaborator server | `axum`, `dns-server` crates | Always-on listener, low resource |
| Docker container orchestration with strict egress firewall | `bollard` (Docker SDK), `nftables-rust` | Reliability, parallelism |
| OpenTelemetry trace consumer (Strix v0.8.3 emits JSONL) | `opentelemetry`, `tokio` | Stream parsing into Lancer DB |
| Vulnerability DB | `rusqlite` / `sqlx` | Lancer's existing storage |
| TUI bridging into Lancer's GUI | egui or native Tauri | Lancer's existing UI |
| If you write your own agent later | `rig`, `langchain-ai-rust`, `swiftide` | When Python's overhead hurts |

**Rust agent ecosystem state (May 2026):**
- **Rig** (`rig.rs`) — most mature; 24.3% CPU util vs Python's ~80%. Modular LLM abstractions. Active dev.
- **AutoAgents** — Ractor actor-model multi-agent orchestration; benchmarks well.
- **OpenFANG** — 137k LoC "Agent OS", full-featured.
- **langchain-ai-rust** — LangChain port; type-safe chains/agents/RAG/LangGraph; covers OpenAI/Claude/Gemini/Mistral/Bedrock/Ollama.
- **swiftide** — indexing/RAG focused.
- **litellm-rust** (avivsinai) — port of LiteLLM; OpenAI/Anthropic/Gemini/xAI; under active dev.
- **litellm-rs** (majiayu000) — high-perf AI Gateway, 10k+ req/s, 100+ providers.

**Performance numbers from 2026 benchmarks**: Rust frameworks <1.1GB peak memory vs Python's >4.7GB — 5x memory advantage. Cold start: 4ms Rust vs 60-140ms Python. Latency dominated by LLM round-trip (5,700-7,000ms), so Rust's perf win is on infra cost, not user-perceived speed.

## 2024-2026 state — version-by-version evolution

| Version | Date | Headline |
|---|---|---|
| v0.4.0 | 2025 Nov | Live agent stats, real-time findings persistence, file-based instructions, IP scanning. XBEN: 96%. |
| v0.5.0 | 2025 Dec | `todo` tool, scan modes (quick/standard/deep), syntax highlighting, **PyInstaller standalone binary**, **Vertex AI support**. |
| v0.6.0 | 2026 Jan 12 | "Stronger Reasoning, Cleaner Findings, Better UX" — **thinking-block preservation across steps**, LLM-based vulnerability dedup, live vulns panel in TUI, persistent config. |
| v0.6.2 | 2026 Jan 19 | Parallel tool execution fix, **single shared browser instance across agents**. |
| v0.7.0 | 2026 Jan 23 | **Skills migrated from Jinja to Markdown** (huge UX win for skill authors), TUI streaming perf. |
| v0.8.0 | 2026 Feb 19 | **Redesigned vuln reporting** with nested XML code locations + CVSS scoring. |
| v0.8.1 | 2026 Feb 20 | LLM API base/model config fixes. |
| v0.8.2 | 2026 Feb 24 | **Exposed Caido proxy port for human-in-the-loop**. |
| v0.8.3 | 2026 Mar 23 | **OpenTelemetry observability (local JSONL traces)**, **interactive mode for agent loop**, skills for specific tools. |
| v1.0.0 | 2026 May 26 | **Major release** — native tool calling, **save & resume**, formal multi-agent orchestration, source-aware testing, Poetry→uv migration, per-subagent LLM stats, NoSQL injection + Kubernetes security skills, MiniMax tool-call normalization, **Novita AI provider**, system-prompt token budgeting in memory compression, Docker sandbox host mappings, "wake on state change" (replaces 500ms polling). |
| v1.0.1 | 2026 May 27 | PyInstaller bundle fix — agent-SDK data + GraphQL imports. |
| v1.0.2 | 2026 May 28 | Reasoning-model patch — `tool_choice=required` no longer rejected. |

**Trend**: 0.4 → 1.0.2 trajectory is from "basic autonomous scanner" to "interactive, observable, reasoning-aware, human-in-loop-capable, resumable, source-aware agent platform". The v0.6 thinking-block work + v0.7 markdown skills + v0.8 reporting redesign + v1.0 save/resume + formal multi-agent orchestration are the five most consequential releases for production use.

### Deep-research note (2026-05-30)

Cross-referenced upstream `github.com/usestrix/strix`, `docs.strix.ai`, release tags through v1.0.2, deepwiki architecture page, and Help Net Security 2025-11 coverage. **New upstream capabilities since the original dossier was written:**

1. **v1.0.0 save & resume** — agents serialize full state (messages, tool results, todo, findings, cost, tokens) to disk and resume after interruption. Critical for long bug-bounty runs and CI re-attempts. Lancer must wrap this as **"Pause / Resume / Fork" in the Autonomous Agent tab** with on-disk run snapshots tied to Lancer's project DB.
2. **Source-aware testing methodology (v1.0.0)** — agents correlate dynamic findings back to source-code locations during white-box runs. Sharpens autofix PR generation.
3. **`--scope-mode diff` + `--diff-base`** — only test code/endpoints changed since a git base. Built for PR-gating in CI. Lancer should expose this as **"Diff scan"** in the GUI with branch picker.
4. **`-t` multi-target / repeated `--target`** — single run against several targets.
5. **NoSQL injection skill, Kubernetes security skill, NestJS security skill** — three new specialized skills shipped between v0.8.3 and v1.0.0.
6. **Novita AI provider, MiniMax tool-call normalization** — broader provider matrix beyond what was captured in the original dossier.
7. **`TelemetrySanitizer`** — automatic redaction of API keys, tokens, passwords from telemetry before export/log. Lancer's OTEL consumer must respect this and add its own scrubber pass on ingress to the Lancer event bus.
8. **Traceloop integration (v0.8.3)** — alternative to local JSONL OTEL export; cloud observability path. Lancer should detect and offer to switch endpoints.
9. **System-prompt token budgeting in memory compression (v1.0.0)** — compressor now accounts for the system-prompt size when deciding what to compress; reduces silent context-overflow failures.
10. **GitHub Actions block-on-finding + autofix PR (productionized in v1.0.x)** — Strix now posts a **ready-to-merge PR with the fix**, not just a suggestion. Lancer should mirror this with a "Generate Fix PR" button that reuses Strix's autofix tool but routes through Lancer's git integration so the PR comes from the user's identity, not the Strix bot.
11. **`wake on state change`** — replaces 500ms polling in the agent loop, cuts idle CPU and lets sub-agent fan-out scale further.
12. **Help Net Security (2025-11-17)** and HN Show HN (Aug 2025) confirm initial public release was Aug 2025, growing to ~25.6k stars by May 2026 — repo is alive, weekly commits, not abandoned.

## Bug-bounty workflow

```bash
# 1. Install
pip install uv && uv tool install strix-agent

# 2. Configure LLM (Claude Opus 4.7 strongly recommended for hard targets)
export STRIX_LLM="anthropic/claude-opus-4-7"
export LLM_API_KEY="sk-ant-..."

# 3. Run against a bug-bounty target (in-scope only)
strix \
  --target https://target-bbp.com \
  --instruction "Authenticated testing as user1@test.com / Hunter2! Focus on IDOR in /api/v2/users, billing endpoints, and JWT issues. Bug bounty in-scope only." \
  --scan-mode deep

# 4. Watch TUI for findings, traces persist to ~/.strix/runs/<id>/
# 5. Review findings.json, manually verify, write report
```

**Verification-before-report pattern (CRITICAL for bug bounty):**
1. Read Strix's `findings.json`.
2. For each finding, **reproduce the PoC manually** in Lancer Repeater / Burp Repeater — don't trust the report blindly.
3. Filter for CRITICAL/HIGH only (bounty programs hate "informational" reports).
4. Format into program's required template.
5. Submit.

**Critical Thinking Podcast Ep 134, 152, 162, 165** discuss exactly this workflow — autonomous agents are force multipliers, not report-generators. The hunter still owns the final write-up and validation.

## AI augmentation (using Claude inside Strix)

**Claude Sonnet 4.6 as agent brain (recommended for cost):**
```bash
export STRIX_LLM="anthropic/claude-sonnet-4-6"
strix --target https://acme.com
```

**Claude Opus 4.7 as agent brain (recommended for hard targets):**
```bash
export STRIX_LLM="anthropic/claude-opus-4-7"
```

**Configure thinking effort** (extended reasoning):
```bash
export STRIX_REASONING_EFFORT="high"   # also: "medium", "low"
```

Strix v0.6+ preserves thinking blocks across the agent loop — agent reuses prior reasoning instead of re-deriving. Cuts cost ~40-50% on long runs.

**Prompt caching** is automatically enabled by Strix for Anthropic models (system prompt + compressed memory get cached). Anthropic caches have 5-minute TTL — Strix's agent loop fires steps fast enough to stay in cache for most of a scan.

**Hybrid model strategy (advanced)**:
- Use Opus 4.7 for the root agent (planning, hard reasoning).
- Use Sonnet 4.6 for sub-agents (recon, fuzzing, validation).
- LiteLLM model routing makes this configurable via per-tool model override.

## Validation corpus (for clone correctness)

1. **XBEN** — 104 web security CTF challenges (used by Strix v0.4 benchmark, 96% solve rate). Clone target.
2. **Ostorlab vulnbank.org** — 40+ endpoint bank-app target, known vulns include SQLi in `/login` (CVSS 10.0), conn-pool DoS, API leak.
3. **DVWA** — Damn Vulnerable Web Application.
4. **OWASP Juice Shop** — modern SPA-style vulnerable app.
5. **PortSwigger Web Security Academy** — ~300 labs. Agent should solve 80%+ of "Apprentice" labs.
6. **HackTheBox Starting Point + retired easy boxes** — Lame, Legacy, Blue, Devel, Beep, Optimum, Sense.
7. **VulnHub VMs** — Mr-Robot, Kioptrix, Stapler.

**Pass criteria for a Strix-equivalent clone**: ≥80% of PortSwigger Apprentice labs, ≥50% of Practitioner labs, pwn 5/5 of the easy HTB boxes listed above, ≥90% on XBEN.

## Implementation phases — HONEST 12-week plan (for the "wrap Strix" approach)

| Week | Deliverable |
|---|---|
| 1 | `lancer-strix-orch` Rust crate. `bollard`-driven Docker container spawn with Strix image. Egress firewall via `nftables` allowing only target IP/CIDR + LLM API + OAST domain. |
| 2 | Lancer HTTP proxy as Strix's upstream (Strix Caido → Lancer proxy → target). Full req/resp visible in Lancer HTTP history with `[strix]` tag. |
| 3 | OpenTelemetry JSONL trace consumer (`opentelemetry` crate) — stream Strix traces into Lancer's event bus, surface in real-time UI. |
| 4 | Custom Strix skill (markdown, since v0.7): `lancer-oast-collaborator.md` — teaches agent to use Lancer's OAST domain for SSRF/blind-XSS detection, correlates hits back to attacks. |
| 5 | Custom Strix skill: `lancer-vuln-report.md` — replaces Strix's built-in reporting tool with one that POSTs findings into Lancer's `/api/vulnerabilities`. |
| 6 | Lancer UI tab: "Autonomous Agent" — config wizard (target, instruction, model, budget), live findings stream, cost meter, stop button. |
| 7 | Findings correlation — when Strix reports SQLi at `/login` and Lancer's existing active scanner also flagged it, merge into single high-confidence finding. |
| 8 | Re-validation tool — for each Strix CRITICAL/HIGH finding, re-run the PoC via Lancer's request engine (independent of Strix), confirm reproduction before surfacing to user. |
| 9 | Bounty report exporter — Markdown report formatted for HackerOne/Bugcrowd from validated findings. Include req/resp from Lancer history (not Strix's). |
| 10 | Per-target Docker policy templates — preset configs for "WordPress site", "GraphQL API", "JWT-auth REST API", "SPA + REST". |
| 11 | Validation: run wrapper against DVWA, Juice Shop, PortSwigger Apprentice labs subset; tune. |
| 12 | Docs, blog post: "Burp + Strix = Lancer Autonomous Mode". |

**Total honest LoC estimate: ~5-7k Rust + ~1k Python (custom skills) + minor PR upstream to Strix for clean OTEL trace formatting.** Full Rust port of Strix would be 40-80k LoC and 6-12 months — don't.

## Final answer to the meta-question

**"Should I clone Strix in Rust?"** No. **"Should I integrate Strix into Lancer?"** Yes — aggressively. The bug-bounty thesis for 2026 is: humans + autonomous agents + LLM-aware tooling. Whoever ships the cleanest unified UI on top of Strix + Promptfoo + Burp-style proxy in 2026 has a real product. Rust is the right choice for **Lancer's core** (proxy, scanner, UI shell, OAST, container orch, telemetry) — it's the wrong choice for **replicating Strix's tool ecosystem**, because it moves too fast and has strong ergonomic advantages in Python.

---

## GUI (Lancer-standard pattern)

`lancer-strix` ships as a **native GUI application** by default. The CLI surface listed in `## Granular feature catalog` is still available behind a `--cli` flag (or via the `lancer-strix-cli` companion binary), but the **plain `lancer-strix` invocation opens a native desktop window**, matching every other tool in the Lancer ecosystem. No terminal-only mode.

### Framework

Pure-Rust GUI stack — no JavaScript, no Node, single static binary:

| Crate | Role |
|-------|------|
| `eframe` | Cross-platform window + event loop wrapper around `egui` |
| `egui` | Immediate-mode UI widgets (panels, tables, forms, menus, drag-and-drop) |
| `egui_extras` | Sortable tables, image loaders, syntax highlighting, date pickers |
| `egui_plot` | Charts, graphs, timelines (histograms, activity meters, progress) |
| `rfd` | Native file/folder pickers (open file, save dialog) |
| `directories` | Per-OS config dir (`~/.config/lancer-strix/`, `%APPDATA%\lancer-strix\`, etc.) |
| `image` | Screenshot / preview rendering inside egui |
| `arboard` | Clipboard read/write for "copy result" actions |
| `muda` | Native menu bar (Linux / macOS / Windows) |
| `egui-notify` | Toast notifications |

Optional dark/light theme persisted to `lancer-strix-config.json` via `serde_json`.

### Window layout

Three-pane layout matching the Lancer mothership GUI:

```
┌─────────────────────────────────────────────────────────────────────┐
│  File   Tools   Settings   Help                              [≡]    │
├──────────┬────────────────────────────────────────┬─────────────────┤
│          │                                        │                 │
│  Inputs  │           Main view                    │  Detail pane    │
│  / jobs  │  (table of results / source tree /     │  (full record / │
│  / scope │   findings list / packet list / etc.)  │   bytes / src / │
│          │                                        │   remediation)  │
│          │                                        │                 │
├──────────┴────────────────────────────────────────┴─────────────────┤
│  Status: idle           Items: 0          [Open]  [Run]  [Export]   │
└─────────────────────────────────────────────────────────────────────┘
```

- **Left sidebar (200-300px)** — inputs / queued jobs / scope / target list. Drag-and-drop accepted.
- **Center pane (flexible)** — primary result view appropriate to the tool (table for findings, tree for hierarchical data, code editor for source).
- **Right pane (300-400px, collapsible)** — full detail of the currently-selected item.
- **Top menu bar** — File (Open / Save / Export / Recent / Quit), Tools (per-tool actions), Settings (theme, fonts, integrations), Help (About / Docs).
- **Bottom status bar** — current activity, item counts, primary action buttons.

### Cross-tool integration with Lancer + the other 29 clones

Every Lancer-clone GUI exposes a small local HTTP server on a port auto-allocated at launch (`127.0.0.1:<port>`, written to `%TEMP%/lancer-strix.port`):

- The main Lancer GUI discovers running tools by scanning `%TEMP%/lancer-*.port` and lists them in its sidebar.
- Right-clicking any item in any tool can "Send to <other Lancer tool>" — the receiving tool fetches the payload via its own HTTP endpoint.
- A future "Lancer Hub" tray shell can launch / focus any of the 30 GUIs from one menu.
- HTTP endpoints exposed:
  - `GET  /v1/state` — current jobs / progress
  - `POST /v1/import` — accept a target / file / record from another Lancer tool
  - `GET  /v1/export?format=json|csv|sarif|markdown` — pull the current result set in a portable format

### Async work + responsiveness

- Long-running scans run on a Tokio task pool; the GUI thread only renders.
- Progress propagates via `crossbeam::channel` from worker → UI.
- A `Stop` button cancels in-flight work via a `CancellationToken`.
- All file I/O / network I/O / subprocess work goes through async channels — the egui thread never blocks.

### Build output

The existing `build.bat` / `build-windows.bat` / `build-linux.sh` already produce a single binary. With `eframe` linked, the same binary is the GUI app.

- Windows: `build\lancer-strix.exe` (double-click opens the GUI window).
- Linux: `build/lancer-strix` (also installable as a `.desktop` entry via `build-linux.sh --install`).
- macOS: `build/lancer-strix` (bundled into `lancer-strix.app` via `cargo-bundle` in the `build-mac.sh` companion).

For CI / headless / scripting, pass `--cli` to fall through to the CLI surface from `## Granular feature catalog`.

## Build Setup (Lancer-standard pattern)

This clone follows the same build pattern as the main Lancer project — single `.exe` output via `build.bat` on Windows, `.so/elf` via `build-linux.sh` on Linux.

### Project layout

```
lancer-strix/
├── Cargo.toml              # single-crate Rust project
├── Cargo.lock              # committed (binary, not library)
├── src/
│   └── main.rs             # entry point (scaffold)
├── build.bat               # Windows build → build/lancer-strix.exe
├── build-windows.bat       # Windows packaged dist build → dist/lancer-strix-windows-x86_64/
├── build-linux.sh          # Linux build → build/lancer-strix
├── .gitignore              # plan.md (local-only) + target/ + build/ + dist/
├── README.md               # public-facing (pushed to GitHub)
└── plan.md                 # this file (gitignored — local blueprint, never pushed)
```

### Build commands

**Windows (double-click `build.bat`):**
```
build.bat
```
Produces `build\lancer-strix.exe`. Pauses at end so the window stays open.

**Windows (packaged dist):**
```
build-windows.bat
```
Produces `dist\lancer-strix-windows-x86_64\bin\lancer-strix.exe` plus LICENSE/README — ready to zip.

**Linux / macOS:**
```bash
./build-linux.sh
```
Produces `build/lancer-strix`.

### Requirements
- Rust toolchain (https://rustup.rs)
- Windows: Visual C++ Build Tools 2019/2022 (needed by some crates)

### CI

The build pattern is intentionally identical across Lancer and all 19 clones, so a single Jenkins/GitHub Actions matrix can build everything by calling `build-windows.bat` or `build-linux.sh` per repo.
