use anyhow::Result;
use tracing::{info, warn};

/// Apply an egress firewall to the given Docker network / container,
/// restricting outbound traffic to the provided target CIDRs plus
/// LLM API endpoints.
///
/// On Linux this uses nftables. On Windows this is a no-op (Docker Desktop
/// on Windows uses a virtual network; use Docker network policies instead).
pub async fn apply_egress_firewall(
    container_id: &str,
    allowed_cidrs: &[String],
) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        apply_nftables(container_id, allowed_cidrs).await
    }

    #[cfg(not(target_os = "linux"))]
    {
        warn!(
            "Egress firewall requested but not supported on this platform. \
             Use Docker Desktop network policies or run lancer-strix on Linux for hard egress restriction."
        );
        let _ = (container_id, allowed_cidrs);
        Ok(())
    }
}

#[cfg(target_os = "linux")]
async fn apply_nftables(container_id: &str, allowed_cidrs: &[String]) -> Result<()> {
    use std::process::Command;

    // Retrieve the container's PID from Docker inspect so we can enter its
    // network namespace and apply nftables rules scoped to that container.
    let pid = get_container_pid(container_id).await?;
    let netns = format!("/proc/{pid}/ns/net");

    info!("Applying nftables egress rules to container {container_id} (pid={pid})");

    // Build the nftables ruleset
    let mut ruleset = String::from(
        "table inet lancer_egress {\n\
         \tchain output {\n\
         \t\ttype filter hook output priority 0; policy drop;\n\
         \t\t# Allow loopback\n\
         \t\tip daddr 127.0.0.0/8 accept\n\
         \t\t# Allow established/related\n\
         \t\tct state established,related accept\n",
    );

    // Allow explicitly whitelisted CIDRs (target + LLM API)
    for cidr in allowed_cidrs {
        ruleset.push_str(&format!("\t\tip daddr {cidr} accept\n"));
    }

    ruleset.push_str("\t}\n}\n");

    // Write ruleset to a temp file and apply with nsenter
    let tmp_path = format!("/tmp/lancer-nft-{container_id}.conf");
    std::fs::write(&tmp_path, &ruleset)?;

    let status = Command::new("nsenter")
        .args(["--net", &netns, "--", "nft", "-f", &tmp_path])
        .status()?;

    if !status.success() {
        anyhow::bail!("nftables apply failed for container {container_id}");
    }

    std::fs::remove_file(&tmp_path).ok();

    info!("Egress firewall applied: allowed CIDRs: {allowed_cidrs:?}");
    Ok(())
}

#[cfg(target_os = "linux")]
async fn get_container_pid(container_id: &str) -> Result<u32> {
    use std::process::Command;
    let output = Command::new("docker")
        .args(["inspect", "--format", "{{.State.Pid}}", container_id])
        .output()?;

    let pid_str = String::from_utf8(output.stdout)?;
    pid_str
        .trim()
        .parse::<u32>()
        .map_err(|e| anyhow::anyhow!("Could not parse container PID: {e}"))
}

/// Parse a target string into an IP CIDR suitable for firewall rules.
/// Returns None if the target is a URL (DNS resolution is needed at runtime).
pub fn target_to_cidr(target: &str) -> Option<String> {
    // Already an IP or CIDR
    if target.contains('/') {
        // Looks like a CIDR
        return Some(target.to_string());
    }

    // Check if it's a bare IP address (IPv4)
    let parts: Vec<&str> = target.split('.').collect();
    if parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok()) {
        return Some(format!("{target}/32"));
    }

    None
}
