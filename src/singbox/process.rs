use crate::config::SingboxConfig;
use crate::singbox::config::generate_minimal_config;
use std::collections::HashSet;
use std::process::Stdio;
use tokio::process::{Child, Command};

pub struct SingboxManager {
    config: SingboxConfig,
    process: Option<Child>,
    client: reqwest::Client,
    api_base: String,
    port_pool: PortPool,
}

struct PortPool {
    base_port: u16,
    max_ports: u16,
    used: HashSet<u16>,
}

impl PortPool {
    fn new(base_port: u16, max_ports: u16) -> Self {
        PortPool {
            base_port,
            max_ports,
            used: HashSet::new(),
        }
    }

    fn allocate(&mut self) -> Option<u16> {
        for offset in 1..=self.max_ports {
            let port = self.base_port + offset;
            if !self.used.contains(&port) {
                self.used.insert(port);
                return Some(port);
            }
        }
        None
    }

    fn free(&mut self, port: u16) {
        self.used.remove(&port);
    }

    fn used_count(&self) -> usize {
        self.used.len()
    }
}

impl SingboxManager {
    pub fn new(config: SingboxConfig, extra_ports: u16) -> Self {
        let api_base = format!("http://127.0.0.1:{}", config.api_port);
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("Failed to build HTTP client");

        let max_ports = config.max_proxies as u16 + extra_ports;
        let base_port = config.base_port;

        SingboxManager {
            config,
            process: None,
            client,
            api_base,
            port_pool: PortPool::new(base_port, max_ports),
        }
    }

    /// Start sing-box with minimal config, then poll the API until ready.
    pub async fn start(&mut self) -> Result<(), String> {
        // Generate minimal config
        let api_addr = format!("127.0.0.1:{}", self.config.api_port);
        let api_secret = self.config.api_secret.as_deref().unwrap_or("");
        let config_json = generate_minimal_config(&api_addr, api_secret);
        let config_str = serde_json::to_string_pretty(&config_json)
            .map_err(|e| format!("Failed to serialize config: {e}"))?;

        // Ensure directory exists
        if let Some(parent) = self.config.config_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }

        // Write config file
        std::fs::write(&self.config.config_path, &config_str)
            .map_err(|e| format!("Failed to write config: {e}"))?;

        tracing::info!(
            "Generated minimal sing-box config at {}",
            self.config.config_path.display()
        );

        // Resolve binary
        let binary = which_singbox(&self.config.binary_path);

        let config_path = self
            .config
            .config_path
            .canonicalize()
            .unwrap_or_else(|_| self.config.config_path.clone());

        tracing::info!(
            "Starting sing-box: {} run -c {}",
            binary.display(),
            config_path.display()
        );

        let child = Command::new(&binary)
            .args(["run", "-c", &config_path.to_string_lossy()])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| format!("Failed to start sing-box: {e}"))?;

        tracing::info!("sing-box started with PID: {:?}", child.id());
        self.process = Some(child);

        // Poll the Clash API until it's ready
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut ready = false;
        while tokio::time::Instant::now() < deadline {
            if self.client.get(&self.api_base).send().await.is_ok() {
                ready = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
        if ready {
            tracing::info!("sing-box API ready at {}", self.api_base);
        } else {
            tracing::warn!("sing-box API readiness probe timed out, proceeding anyway");
        }

        Ok(())
    }

    pub async fn stop(&mut self) {
        if let Some(mut child) = self.process.take() {
            tracing::info!("Stopping sing-box process...");
            let _ = child.kill().await;
            let _ = child.wait().await;
            tracing::info!("sing-box process stopped");
        }
    }

    /// Create a binding: allocate a port and POST to the bindings API.
    /// Returns the allocated local port on success.
    pub async fn create_binding(
        &mut self,
        proxy_id: &str,
        outbound_json: &serde_json::Value,
    ) -> Result<u16, String> {
        let port = self
            .port_pool
            .allocate()
            .ok_or_else(|| "No available ports in pool".to_string())?;

        let url = format!("{}/bindings", self.api_base);
        let secret = self.config.api_secret.clone().unwrap_or_default();

        let payload = serde_json::json!({
            "tag": proxy_id,
            "listen_port": port,
            "outbound": outbound_json,
        });

        let result = self
            .client
            .post(&url)
            .bearer_auth(&secret)
            .json(&payload)
            .send()
            .await;

        match result {
            Ok(resp) if resp.status().is_success() => {
                tracing::debug!("Created binding {proxy_id} on port {port}");
                Ok(port)
            }
            Ok(resp) => {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                self.port_pool.free(port);
                Err(format!(
                    "Bindings API returned {status} for {proxy_id}: {body}"
                ))
            }
            Err(e) => {
                self.port_pool.free(port);
                Err(format!("Bindings API request failed for {proxy_id}: {e}"))
            }
        }
    }

    /// Remove a binding: DELETE from the API and free the port.
    pub async fn remove_binding(&mut self, proxy_id: &str, port: u16) -> Result<(), String> {
        let url = format!("{}/bindings/{}", self.api_base, proxy_id);
        let secret = self.config.api_secret.clone().unwrap_or_default();

        let result = self
            .client
            .delete(&url)
            .bearer_auth(&secret)
            .send()
            .await;

        match result {
            Ok(resp) if resp.status().is_success() => {
                self.port_pool.free(port);
                tracing::debug!("Removed binding {proxy_id} (port {port})");
                Ok(())
            }
            Ok(resp) => {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                // Free port anyway — the binding may already be gone
                self.port_pool.free(port);
                Err(format!(
                    "Bindings API DELETE returned {status} for {proxy_id}: {body}"
                ))
            }
            Err(e) => {
                self.port_pool.free(port);
                Err(format!(
                    "Bindings API DELETE request failed for {proxy_id}: {e}"
                ))
            }
        }
    }

    /// Sync bindings: compute diff between desired and current, then remove/add as needed.
    /// `desired` is a list of (proxy_id, outbound_json, current_local_port).
    /// Returns a list of (proxy_id, assigned_port) for successfully created bindings.
    pub async fn sync_bindings(
        &mut self,
        desired: &[(String, serde_json::Value)],
        current_ports: &[(String, u16)],
    ) -> Vec<(String, u16)> {
        let desired_ids: HashSet<&str> = desired.iter().map(|(id, _)| id.as_str()).collect();
        let current_map: std::collections::HashMap<&str, u16> = current_ports
            .iter()
            .map(|(id, port)| (id.as_str(), *port))
            .collect();

        // To remove: have a port but not in desired set
        let to_remove: Vec<(String, u16)> = current_ports
            .iter()
            .filter(|(id, _)| !desired_ids.contains(id.as_str()))
            .cloned()
            .collect();

        // To add: in desired but don't have a port
        let to_add: Vec<(String, serde_json::Value)> = desired
            .iter()
            .filter(|(id, _)| !current_map.contains_key(id.as_str()))
            .cloned()
            .collect();

        // Remove first to free ports
        for (id, port) in &to_remove {
            if let Err(e) = self.remove_binding(id, *port).await {
                tracing::warn!("Failed to remove binding {id}: {e}");
            }
        }

        // Add new bindings
        let mut assignments = Vec::new();

        // Keep existing bindings that are still desired
        for (id, port) in current_ports {
            if desired_ids.contains(id.as_str()) {
                assignments.push((id.clone(), *port));
            }
        }

        for (id, outbound) in &to_add {
            match self.create_binding(id, outbound).await {
                Ok(port) => {
                    assignments.push((id.clone(), port));
                }
                Err(e) => {
                    tracing::warn!("Failed to create binding {id}: {e}");
                }
            }
        }

        assignments
    }

    pub fn is_running(&mut self) -> bool {
        if let Some(ref mut child) = self.process {
            match child.try_wait() {
                Ok(Some(_)) => {
                    self.process = None;
                    false
                }
                Ok(None) => true,
                Err(_) => false,
            }
        } else {
            false
        }
    }

    pub fn used_ports(&self) -> usize {
        self.port_pool.used_count()
    }
}

/// Try to find sing-box: same directory as our executable first, then config path, then system PATH.
fn which_singbox(config_path: &std::path::Path) -> std::path::PathBuf {
    // 1. Check same directory as our own executable
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            let name = if cfg!(windows) { "sing-box.exe" } else { "sing-box" };
            let local = exe_dir.join(name);
            if local.exists() {
                tracing::info!("Found sing-box next to executable: {}", local.display());
                return local;
            }
        }
    }

    // 2. Check config path
    if config_path.exists() {
        tracing::info!("Using sing-box from config: {}", config_path.display());
        return config_path.to_path_buf();
    }

    // 3. Fall back to system PATH
    for name in &["sing-box", "sing-box.exe"] {
        if let Ok(output) =
            std::process::Command::new(if cfg!(windows) { "where" } else { "which" })
                .arg(name)
                .output()
        {
            if output.status.success() {
                let path = String::from_utf8_lossy(&output.stdout)
                    .lines()
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_string();
                if !path.is_empty() {
                    tracing::info!("Found sing-box in PATH: {path}");
                    return std::path::PathBuf::from(path);
                }
            }
        }
    }

    tracing::warn!(
        "sing-box not found locally or in PATH, will attempt config path: {}",
        config_path.display()
    );
    config_path.to_path_buf()
}
