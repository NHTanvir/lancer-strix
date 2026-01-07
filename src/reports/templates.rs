/// Per-target Docker policy templates (Week 10).
/// Each template provides opinionated Strix configuration for a common app stack.

#[derive(Debug, Clone)]
pub struct Template {
    pub name: &'static str,
    pub description: &'static str,
    pub scan_mode: &'static str,
    pub instruction: &'static str,
    pub extra_env: &'static [(&'static str, &'static str)],
}

pub const TEMPLATES: &[Template] = &[
    Template {
        name: "wordpress",
        description: "WordPress site (plugin/theme/core CVEs, SQLi, RCE via upload)",
        scan_mode: "deep",
        instruction: "Focus on: WordPress plugin CVEs, SQLi in custom plugins, \
                      CSRF in admin actions, arbitrary file upload to /wp-content/uploads, \
                      XML-RPC brute force, REST API user enumeration. \
                      Check wp-config.php exposure. \
                      Tools: semgrep for PHP, nuclei for WordPress templates.",
        extra_env: &[("STRIX_SKILL", "wordpress-pentest")],
    },
    Template {
        name: "graphql",
        description: "GraphQL API (introspection, batching DoS, IDOR, injection)",
        scan_mode: "standard",
        instruction: "Focus on: GraphQL introspection abuse, batch query DoS, \
                      IDOR via object ID fields, SQL/NoSQL injection in resolvers, \
                      missing field-level authorization (BFLA), subscription abuse. \
                      Check for __schema queries allowed in production. \
                      Use the Python tool to craft GraphQL mutation floods.",
        extra_env: &[],
    },
    Template {
        name: "jwt-rest",
        description: "JWT-authenticated REST API (alg confusion, scope bypass, IDOR)",
        scan_mode: "standard",
        instruction: "Focus on: JWT algorithm confusion (RS256→HS256, none alg), \
                      token replay, scope/role bypass, IDOR across user-scoped endpoints, \
                      mass assignment, BOLA in /api/v*/users/<id> pattern. \
                      Try expired token reuse. Check refresh token rotation.",
        extra_env: &[("STRIX_SKILL", "jwt-auth-pentest")],
    },
    Template {
        name: "spa-rest",
        description: "Single-Page App + REST backend (XSS, CSRF, CORS, auth flow)",
        scan_mode: "deep",
        instruction: "Focus on: DOM XSS in SPA routing, stored XSS via API fields, \
                      CORS misconfiguration (null origin, wildcard with credentials), \
                      CSRF in state-changing requests, insecure postMessage handlers, \
                      prototype pollution in JS deps. \
                      Use Playwright browser tool for full JS rendering.",
        extra_env: &[],
    },
];

/// Look up a template by name (case-insensitive).
pub fn find_template(name: &str) -> Option<&'static Template> {
    TEMPLATES.iter().find(|t| t.name.eq_ignore_ascii_case(name))
}

pub fn list_templates() -> String {
    let mut out = String::from("Available target templates:\n\n");
    for t in TEMPLATES {
        out.push_str(&format!("  {:15} — {}\n", t.name, t.description));
    }
    out
}

pub fn show_template(name: &str) -> String {
    match find_template(name) {
        Some(t) => format!(
            "Template: {}\n\
             Description: {}\n\
             Scan mode:   {}\n\n\
             Instruction:\n{}\n\n\
             Extra env:\n{}",
            t.name,
            t.description,
            t.scan_mode,
            textwrap(t.instruction, 72),
            if t.extra_env.is_empty() {
                "  (none)".to_string()
            } else {
                t.extra_env
                    .iter()
                    .map(|(k, v)| format!("  {k}={v}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            }
        ),
        None => format!(
            "Template '{}' not found. Run `lancer-strix template list` to see available templates.",
            name
        ),
    }
}

fn textwrap(s: &str, width: usize) -> String {
    let mut out = String::new();
    let mut col = 0usize;
    for word in s.split_whitespace() {
        if col + word.len() + 1 > width && col > 0 {
            out.push('\n');
            col = 0;
        } else if col > 0 {
            out.push(' ');
            col += 1;
        }
        out.push_str(word);
        col += word.len();
    }
    out
}
