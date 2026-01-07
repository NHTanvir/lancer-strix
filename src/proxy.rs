/// Proxy configuration passed to Strix via environment variables.
/// Week 2: Strix traffic routes through Lancer's HTTP proxy for full
/// request/response capture and tagging in Lancer HTTP history.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Lancer proxy listening address (host:port)
    pub addr: String,
}

impl ProxyConfig {
    pub fn new(addr: impl Into<String>) -> Self {
        ProxyConfig { addr: addr.into() }
    }

    /// Returns the HTTP proxy URL for Strix env vars (HTTP_PROXY / HTTPS_PROXY).
    pub fn proxy_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Validate that the proxy is reachable before spawning Strix.
    /// Non-fatal — Strix will still run; it just won't have proxy capture.
    pub async fn check_reachable(&self) -> bool {
        let addr = self.addr.clone();
        tokio::net::TcpStream::connect(&addr).await.is_ok()
    }
}
