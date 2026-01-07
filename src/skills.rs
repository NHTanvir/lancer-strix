use anyhow::Result;
use std::path::Path;
use tracing::info;

/// Bundled Lancer skills shipped with this binary.
/// These are the Strix v0.7+ markdown skill files that teach the agent
/// to use Lancer-specific infrastructure.
pub const BUNDLED_SKILLS: &[(&str, &str)] = &[
    (
        "lancer-oast-collaborator.md",
        include_str!("../skills/lancer-oast-collaborator.md"),
    ),
    (
        "lancer-vuln-report.md",
        include_str!("../skills/lancer-vuln-report.md"),
    ),
];

/// List skill names to stdout.
pub fn list_skills() {
    println!("Bundled Lancer Strix skills:\n");
    for (name, content) in BUNDLED_SKILLS {
        let first_line = content.lines().next().unwrap_or("").trim_start_matches('#').trim();
        println!("  {name:<40} — {first_line}");
    }
}

/// Write all bundled skills to `dest_dir`.
/// The skills are installed into the Strix container's skills directory
/// so they are available via the `load_skill` tool.
pub fn install_skills(dest_dir: impl AsRef<Path>) -> Result<()> {
    let dest = dest_dir.as_ref();
    std::fs::create_dir_all(dest)?;

    for (name, content) in BUNDLED_SKILLS {
        let path = dest.join(name);
        std::fs::write(&path, content)?;
        info!("Installed skill: {}", path.display());
    }

    println!("Installed {} skills to {}", BUNDLED_SKILLS.len(), dest.display());
    Ok(())
}
