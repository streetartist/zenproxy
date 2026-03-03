mod api;
mod config;
mod db;
mod error;
mod parser;
mod pool;
mod quality;
mod singbox;

use crate::config::AppConfig;
use crate::db::{Database, User};
use crate::pool::manager::ProxyPool;
use crate::singbox::process::SingboxManager;
use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct AppState {
    pub config: AppConfig,
    pub db: Database,
    pub pool: ProxyPool,
    pub singbox: Arc<Mutex<SingboxManager>>,
    /// Cached reqwest::Client per proxy local_port — avoids rebuilding per request.
    pub relay_clients: DashMap<u16, reqwest::Client>,
    /// Auth cache: (api_key | session_id) → (User, expires_at_instant).
    pub auth_cache: DashMap<String, (User, tokio::time::Instant)>,
    /// Ensures only one validate_all / check_all runs at a time.
    pub validation_lock: Mutex<()>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "zenproxy=info,tower_http=info".into()),
        )
        .init();

    let config = AppConfig::load().expect("Failed to load config");
    tracing::info!("ZenProxy starting on {}:{}", config.server.host, config.server.port);

    // Ensure data directory exists
    std::fs::create_dir_all("data").ok();

    // Initialize database
    let db = Database::new(&config.database.path).expect("Failed to initialize database");

    // Initialize proxy pool from database
    let pool = ProxyPool::new();
    pool.load_from_db(&db);

    // Clear stale local_port values — sing-box starts fresh, old ports have no bindings
    pool.clear_all_local_ports();
    db.clear_all_proxy_local_ports().ok();

    // Initialize SingboxManager and start with minimal config
    let mut manager = SingboxManager::new(config.singbox.clone(), config.validation.batch_size as u16);
    if let Err(e) = manager.start().await {
        tracing::warn!("Failed to start sing-box: {e}");
    }

    // Create initial bindings for valid proxies
    {
        let mut proxies = pool.get_valid_proxies();
        proxies.truncate(config.singbox.max_proxies);
        if !proxies.is_empty() {
            let desired: Vec<(String, serde_json::Value)> = proxies
                .iter()
                .map(|p| (p.id.clone(), p.singbox_outbound.clone()))
                .collect();
            // No existing bindings at startup
            let assignments = manager.sync_bindings(&desired, &[]).await;
            for (id, port) in &assignments {
                pool.set_local_port(id, *port);
                db.update_proxy_local_port(id, *port as i32).ok();
            }
            tracing::info!(
                "Created {} initial bindings for valid proxies",
                assignments.len()
            );
        } else {
            tracing::info!("No valid proxies, sing-box running with minimal config");
        }
    }

    let singbox = Arc::new(Mutex::new(manager));

    let state = Arc::new(AppState {
        config: config.clone(),
        db,
        pool,
        singbox,
        relay_clients: DashMap::new(),
        auth_cache: DashMap::new(),
        validation_lock: Mutex::new(()),
    });

    // Start background tasks
    start_background_tasks(state.clone()).await;

    // Build router
    let app = api::router(state.clone());

    let addr = format!("{}:{}", config.server.host, config.server.port);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    tracing::info!("ZenProxy listening on http://{addr}");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();

    // Cleanup: stop sing-box
    tracing::info!("Shutting down sing-box...");
    let mut mgr = state.singbox.lock().await;
    mgr.stop().await;
    tracing::info!("ZenProxy stopped");
}

async fn start_background_tasks(state: Arc<AppState>) {
    let state_clone = state.clone();
    // Periodic validation
    tokio::spawn(async move {
        let interval = std::time::Duration::from_secs(state_clone.config.validation.interval_mins * 60);
        loop {
            tokio::time::sleep(interval).await;
            tracing::info!("Running periodic proxy validation...");
            if let Err(e) = pool::validator::validate_all(state_clone.clone()).await {
                tracing::error!("Validation error: {e}");
            }
        }
    });

    let state_clone = state.clone();
    // Quality check — only checks proxies without quality data or with stale data
    tokio::spawn(async move {
        // Wait a bit on startup for proxies to be validated first
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        loop {
            let checked = match quality::checker::check_all(state_clone.clone()).await {
                Ok(n) => n,
                Err(e) => {
                    tracing::error!("Quality check error: {e}");
                    0
                }
            };
            // If nothing needed checking, wait longer before next round
            let pause = if checked == 0 { 300 } else { 30 };
            tokio::time::sleep(std::time::Duration::from_secs(pause)).await;
        }
    });

    let state_clone = state.clone();
    // Periodic session cleanup (every 6 hours)
    tokio::spawn(async move {
        let interval = std::time::Duration::from_secs(6 * 60 * 60);
        loop {
            tokio::time::sleep(interval).await;
            tracing::info!("Cleaning up expired sessions...");
            match state_clone.db.cleanup_expired_sessions() {
                Ok(count) => {
                    if count > 0 {
                        tracing::info!("Cleaned up {count} expired sessions");
                    }
                }
                Err(e) => tracing::error!("Session cleanup error: {e}"),
            }
        }
    });

    let state_clone = state.clone();
    // Periodic auth cache cleanup (every 5 minutes)
    tokio::spawn(async move {
        let interval = std::time::Duration::from_secs(5 * 60);
        loop {
            tokio::time::sleep(interval).await;
            let now = tokio::time::Instant::now();
            state_clone.auth_cache.retain(|_, (_, expires)| now < *expires);
        }
    });

    // Periodic subscription auto-refresh
    if state.config.subscription.auto_refresh_interval_mins > 0 {
        let state_clone = state.clone();
        tokio::spawn(async move {
            let interval = std::time::Duration::from_secs(
                state_clone.config.subscription.auto_refresh_interval_mins * 60,
            );
            loop {
                tokio::time::sleep(interval).await;
                refresh_all_subscriptions(&state_clone).await;
            }
        });
    }
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install Ctrl+C handler");
    tracing::info!("Received shutdown signal");
}

async fn refresh_all_subscriptions(state: &Arc<AppState>) {
    let subs = match state.db.get_subscriptions() {
        Ok(subs) => subs,
        Err(e) => {
            tracing::error!("Auto-refresh: failed to get subscriptions: {e}");
            return;
        }
    };

    let refreshable: Vec<_> = subs.into_iter().filter(|s| s.url.is_some()).collect();
    if refreshable.is_empty() {
        return;
    }

    tracing::info!("Auto-refreshing {} subscriptions...", refreshable.len());

    let mut success = 0;
    let mut failed = 0;
    for sub in &refreshable {
        match api::subscription::refresh_subscription_core(state, sub).await {
            Ok(count) => {
                tracing::info!(
                    "Auto-refresh '{}': updated with {} proxies",
                    sub.name,
                    count
                );
                success += 1;
            }
            Err(e) => {
                tracing::error!("Auto-refresh '{}' failed: {e}", sub.name);
                failed += 1;
            }
        }
    }

    tracing::info!(
        "Auto-refresh complete: {success} succeeded, {failed} failed"
    );

    // Run validation once after all subscriptions are refreshed
    if success > 0 {
        let state2 = state.clone();
        tokio::spawn(async move {
            if let Err(e) = pool::validator::validate_all(state2).await {
                tracing::error!("Validation after auto-refresh failed: {e}");
            }
        });
    }
}
