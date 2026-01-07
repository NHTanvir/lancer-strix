# Lancer Vulnerability Report

Use this skill instead of Strix's default `create_vulnerability_report` tool
when running inside a Lancer-orchestrated scan. It writes findings directly
into Lancer's vulnerability database via the Lancer API, enabling:

- Real-time correlation with Lancer's existing scanner findings
- Unified CVSS scoring and dedup
- Export to HackerOne/Bugcrowd report format

## When to use this skill

Load this skill at the start of every Lancer-managed scan. The system prompt
will instruct you when to call `create_vulnerability_report`. Use this skill
to understand how to properly format and POST that report to Lancer.

## Environment variables

```
LANCER_API    — Lancer API base URL (e.g. http://127.0.0.1:9090)
STRIX_RUN_ID  — Set by Lancer; uniquely identifies this scan run
```

## How to report a finding to Lancer

After you have confirmed a vulnerability with a working PoC, use the Python
tool to POST it to Lancer:

```python
import requests, os, json

lancer_api = os.environ.get("LANCER_API", "http://127.0.0.1:9090")
run_id = os.environ.get("STRIX_RUN_ID", "unknown")

finding = {
    "run_id": run_id,
    "vuln_class": "SQL Injection",          # e.g. SQL Injection, SSRF, XSS, RCE
    "title": "Blind SQLi in /api/login",
    "description": "The 'username' parameter is vulnerable to time-based blind SQL injection...",
    "url": "https://target.example.com/api/login",
    "method": "POST",
    "cvss_score": 9.8,
    "cwe": "CWE-89",
    "poc_request": "POST /api/login HTTP/1.1\r\nHost: target.example.com\r\n\r\nusername=admin'%20AND%20SLEEP(5)--&password=x",
    "poc_response": "HTTP/1.1 200 OK\r\n[response after 5s delay]",
    "fix_suggestion": "Use parameterized queries. Replace string concatenation with prepared statements.",
    "tags": ["[strix]", "[authenticated]"]
}

r = requests.post(f"{lancer_api}/api/findings", json=finding)
r.raise_for_status()
finding_id = r.json()["id"]
print(f"Finding submitted to Lancer: {finding_id}")
```

## CVSS guidance

| Vuln Class | Typical CVSS | Notes |
|---|---|---|
| SQLi (auth bypass / data exfil) | 9.0–9.8 | Network, no auth, high impact |
| RCE | 9.8–10.0 | Critical by default |
| SSRF (internal reach) | 8.6–9.3 | High if reaches metadata service |
| Stored XSS | 6.1–8.8 | Higher if admin-facing |
| IDOR (sensitive data) | 6.5–8.1 | Medium-High |
| JWT alg confusion | 9.0 | Full auth bypass |
| CSRF (state-changing) | 5.4–6.8 | Medium |
| Reflected XSS | 4.7–6.1 | Low-Medium |

## Rules for reporting (CRITICAL — follow exactly)

1. **Never report without a working PoC.** The PoC must have been run in this
   session and returned the expected indicator (error, delay, data, OAST hit).
2. **Re-run the PoC exactly once more** after identifying the vulnerability,
   before submitting, to rule out transient errors.
3. **CVSS score must be manually set** — do not leave at 0.0.
4. **Include full raw HTTP request and response** in poc_request / poc_response.
5. For blind vulnerabilities, include the OAST hit JSON as poc_response.
6. Include `"[strix]"` in tags — this allows Lancer to filter AI-generated findings.

## Checking your submitted finding

```python
r = requests.get(f"{lancer_api}/api/findings/{finding_id}")
print(r.json())
```

## Do NOT use this skill if

- You are running outside Lancer (e.g. standalone `strix` CLI without
  LANCER_API set). In that case, use the default `create_vulnerability_report`
  tool as documented in Strix's built-in help.
