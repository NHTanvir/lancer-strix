use anyhow::{Context, Result};
use bollard::container::{
    Config, CreateContainerOptions, RemoveContainerOptions, StartContainerOptions,
    StopContainerOptions,
};
use bollard::image::CreateImageOptions;
use bollard::models::{HostConfig, PortBinding};
use bollard::Docker;
use futures_util::stream::StreamExt;
use std::collections::HashMap;
use tracing::{info, warn};
use uuid::Uuid;

/// Configuration for a single Strix container run.
#[derive(Debug, Clone)]
pub struct OrchestratorConfig {
    /// Docker image to use for Strix sandbox
    pub image: String,
    /// Target to pentest (URL, path, IP/CIDR)
    pub target: String,
    /// Natural-language instruction for Strix
    pub instruction: Option<String>,
    /// Path to instruction file (inside host — will be bind-mounted)
    pub instruction_file: Option<String>,
    /// Scan depth mode
    pub scan_mode: String,
    /// LLM model string (e.g. "anthropic/claude-sonnet-4-6")
    pub model: String,
    /// Extended reasoning effort
    pub reasoning_effort: String,
    /// API key for the LLM provider
    pub llm_api_key: String,
    /// Lancer upstream proxy address (host:port)
    pub proxy_addr: String,
    /// Lancer OAST collaborator domain
    pub oast_domain: Option<String>,
    /// Lancer API base URL for findings ingest
    pub lancer_api: String,
    /// Max step budget (0 = unlimited)
    pub token_budget: u64,
    /// Run headless (no Strix TUI)
    pub headless: bool,
    /// Enable Strix interactive mode
    pub interactive: bool,
    /// Directory to mount for findings output
    pub runs_dir: String,
    /// Run ID (generated before container creation)
    pub run_id: String,
    /// Skills directory path on host (bind-mounted into container)
    pub skills_dir: Option<String>,
}

/// A live handle to a running Strix container.
pub struct ContainerHandle {
    docker: Docker,
    pub container_id: String,
    pub run_id: String,
}

impl ContainerHandle {
    /// Spawn a Strix container according to `config`.
    /// Pulls the image if not present, creates and starts the container.
    pub async fn spawn(config: &OrchestratorConfig) -> Result<Self> {
        let docker = Docker::connect_with_local_defaults()
            .context("Failed to connect to Docker — is Docker running?")?;

        info!("Pulling Strix image: {}", config.image);
        pull_image_if_needed(&docker, &config.image).await?;

        let name = format!("lancer-strix-{}", &config.run_id[..8]);
        info!("Creating container: {}", name);

        let env = build_env(config);
        let cmd = build_cmd(config);
        let binds = build_binds(config);
        let port_bindings = build_port_bindings();

        let host_config = HostConfig {
            binds: Some(binds),
            port_bindings: Some(port_bindings),
            // Network mode — default bridge; egress restriction applied separately
            network_mode: Some("bridge".to_string()),
            ..Default::default()
        };

        let container_config = Config {
            image: Some(config.image.clone()),
            cmd: Some(cmd),
            env: Some(env),
            host_config: Some(host_config),
            ..Default::default()
        };

        let create_opts = CreateContainerOptions {
            name: name.clone(),
            platform: None,
        };

        let response = docker
            .create_container(Some(create_opts), container_config)
            .await
            .context("Failed to create Strix container")?;

        let container_id = response.id;

        docker
            .start_container(&container_id, None::<StartContainerOptions<String>>)
            .await
            .context("Failed to start Strix container")?;

        info!("Container started: {} (id={})", name, &container_id[..12]);

        Ok(ContainerHandle {
            docker,
            container_id,
            run_id: config.run_id.clone(),
        })
    }

    /// Wait for the container to exit and return the exit code.
    pub async fn wait(&self) -> Result<i64> {
        use bollard::container::WaitContainerOptions;
        let mut stream = self
            .docker
            .wait_container(&self.container_id, None::<WaitContainerOptions<String>>);

        let mut exit_code = 0i64;
        while let Some(result) = stream.next().await {
            match result {
                Ok(response) => exit_code = response.status_code,
                Err(e) => warn!("Wait stream error: {e}"),
            }
        }
        Ok(exit_code)
    }

    /// Stream container logs to tracing.
    pub async fn stream_logs(&self) {
        use bollard::container::LogsOptions;
        let opts = LogsOptions::<String> {
            follow: true,
            stdout: true,
            stderr: true,
            ..Default::default()
        };
        let mut stream = self.docker.logs(&self.container_id, Some(opts));
        while let Some(msg) = stream.next().await {
            match msg {
                Ok(output) => {
                    let text = output.to_string();
                    let text = text.trim();
                    if !text.is_empty() {
                        info!("[strix] {text}");
                    }
                }
                Err(e) => warn!("Log stream error: {e}"),
            }
        }
    }

    /// Stop and remove the container.
    pub async fn cleanup(self) -> Result<()> {
        info!("Stopping container {}", &self.container_id[..12]);
        let _ = self
            .docker
            .stop_container(
                &self.container_id,
                Some(StopContainerOptions { t: 10 }),
            )
            .await;

        self.docker
            .remove_container(
                &self.container_id,
                Some(RemoveContainerOptions {
                    force: true,
                    ..Default::default()
                }),
            )
            .await
            .context("Failed to remove container")?;

        Ok(())
    }

    /// Generate a fresh run ID.
    pub fn new_run_id() -> String {
        Uuid::new_v4().to_string()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn pull_image_if_needed(docker: &Docker, image: &str) -> Result<()> {
    // Check if image already exists locally
    if docker.inspect_image(image).await.is_ok() {
        info!("Image already present: {image}");
        return Ok(());
    }

    info!("Image not found locally, pulling: {image}");
    let opts = CreateImageOptions {
        from_image: image,
        ..Default::default()
    };
    let mut stream = docker.create_image(Some(opts), None, None);
    while let Some(item) = stream.next().await {
        match item {
            Ok(info) => {
                if let Some(status) = info.status {
                    tracing::debug!("[pull] {status}");
                }
            }
            Err(e) => return Err(anyhow::anyhow!("Image pull failed: {e}")),
        }
    }
    Ok(())
}

fn build_env(config: &OrchestratorConfig) -> Vec<String> {
    let mut env = vec![
        format!("STRIX_LLM={}", config.model),
        format!("LLM_API_KEY={}", config.llm_api_key),
        format!("STRIX_REASONING_EFFORT={}", config.reasoning_effort),
        format!("LANCER_API={}", config.lancer_api),
        format!("STRIX_RUN_ID={}", config.run_id),
        format!("HTTPS_PROXY=http://{}", config.proxy_addr),
        format!("HTTP_PROXY=http://{}", config.proxy_addr),
    ];

    if let Some(oast) = &config.oast_domain {
        env.push(format!("LANCER_OAST_DOMAIN={oast}"));
    }

    if config.token_budget > 0 {
        env.push(format!("STRIX_TOKEN_BUDGET={}", config.token_budget));
    }

    env
}

fn build_cmd(config: &OrchestratorConfig) -> Vec<String> {
    let mut cmd = vec![
        "strix".to_string(),
        "--target".to_string(),
        config.target.clone(),
        "--scan-mode".to_string(),
        config.scan_mode.clone(),
    ];

    if let Some(instr) = &config.instruction {
        cmd.push("--instruction".to_string());
        cmd.push(instr.clone());
    }

    if config.instruction_file.is_some() {
        // File is bind-mounted into /instructions/plan.md
        cmd.push("--instruction-file".to_string());
        cmd.push("/instructions/plan.md".to_string());
    }

    if config.headless {
        cmd.push("-n".to_string());
    }

    if config.interactive {
        cmd.push("--interactive".to_string());
    }

    cmd
}

fn build_binds(config: &OrchestratorConfig) -> Vec<String> {
    let mut binds = vec![
        // Findings output
        format!("{}/{}:/root/.strix/runs/{}", config.runs_dir, config.run_id, config.run_id),
    ];

    if let Some(instr_file) = &config.instruction_file {
        binds.push(format!("{instr_file}:/instructions/plan.md:ro"));
    }

    if let Some(skills_dir) = &config.skills_dir {
        binds.push(format!("{skills_dir}:/root/.strix/skills:ro"));
    }

    binds
}

fn build_port_bindings() -> HashMap<String, Option<Vec<PortBinding>>> {
    // Expose Caido proxy port (v0.8.2) so human can intercept while agent runs
    let mut map = HashMap::new();
    map.insert(
        "8282/tcp".to_string(),
        Some(vec![PortBinding {
            host_ip: Some("127.0.0.1".to_string()),
            host_port: Some("8282".to_string()),
        }]),
    );
    map
}
