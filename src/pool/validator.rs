use crate::api::subscription::SyncMode;
use crate::pool::manager::ProxyStatus;
use crate::AppState;
use std::sync::Arc;
use tokio::sync::Semaphore;

pub async fn validate_all(state: Arc<AppState>) -> Result<(), String> {
    // Serialize validations — wait if another is running, then check for remaining work
    let _lock = state.validation_lock.lock().await;

    let total = state.pool.count();
    if total == 0 {
        tracing::info!("No proxies to validate");
        return Ok(());
    }

    // Reset Valid proxies with error_count > 0 back to Untested so they get re-validated.
    // This catches proxies that users reported as failing via relay.
    let recheck: Vec<String> = state
        .pool
        .get_all()
        .iter()
        .filter(|p| p.status == ProxyStatus::Valid && p.error_count > 0)
        .map(|p| p.id.clone())
        .collect();
    if !recheck.is_empty() {
        tracing::info!("Re-validating {} proxies with relay errors", recheck.len());
        for id in &recheck {
            state.pool.set_status(id, ProxyStatus::Untested);
        }
    }

    let concurrency = state.config.validation.concurrency;
    let timeout_duration = std::time::Duration::from_secs(state.config.validation.timeout_secs);
    let validation_url = state.config.validation.url.clone();
    let max_proxies = state.config.singbox.max_proxies;

    let mut round = 0u32;
    let mut total_validated = 0usize;

    loop {
        round += 1;

        // Use validation-mode sorting: Untested get port priority over Valid
        crate::api::subscription::sync_proxy_bindings(&state, SyncMode::Validation).await;

        // Collect proxies that have ports and need validation
        let to_validate: Vec<_> = state
            .pool
            .get_all()
            .into_iter()
            .filter(|p| p.local_port.is_some() && p.status == ProxyStatus::Untested)
            .collect();

        if to_validate.is_empty() {
            // No Untested proxies got ports — mark any remaining Untested as Invalid
            // (they were prioritized by sync but binding creation failed, likely bad config)
            let stuck: Vec<_> = state
                .pool
                .get_all()
                .into_iter()
                .filter(|p| p.status == ProxyStatus::Untested)
                .collect();
            for p in &stuck {
                tracing::warn!("Proxy {} failed to get binding, marking invalid", p.name);
                state.pool.set_status(&p.id, ProxyStatus::Invalid);
                state.db.update_proxy_validation(&p.id, false, Some("binding creation failed")).ok();
            }
            break;
        }

        tracing::info!(
            "Validation round {round}: checking {} proxies (max_proxies={max_proxies})",
            to_validate.len()
        );

        // Validate this batch
        let round_count = validate_batch(
            &to_validate,
            &validation_url,
            timeout_duration,
            concurrency,
            &state,
        )
        .await;

        total_validated += round_count;

        let valid = state.pool.count_valid();
        let total = state.pool.count();
        let untested_remaining = total
            - state
                .pool
                .get_all()
                .iter()
                .filter(|p| p.status != ProxyStatus::Untested)
                .count();

        tracing::info!(
            "Round {round}: {round_count} checked, {valid}/{total} valid, {untested_remaining} untested remaining"
        );

        if untested_remaining == 0 {
            break;
        }
    }

    // Cleanup high-error proxies (once, after all rounds)
    let threshold = state.config.validation.error_threshold;
    match state.db.cleanup_high_error_proxies(threshold) {
        Ok(count) if count > 0 => {
            tracing::info!("Cleaned up {count} proxies exceeding error threshold");
            let all = state.pool.get_all();
            for p in &all {
                if p.error_count >= threshold {
                    state.pool.remove(&p.id);
                }
            }
        }
        _ => {}
    }

    // Final assignment: normal mode (Valid gets priority for serving traffic)
    crate::api::subscription::sync_proxy_bindings(&state, SyncMode::Normal).await;

    let valid = state.pool.count_valid();
    let total = state.pool.count();
    tracing::info!(
        "Validation complete: {total_validated} checked in {round} rounds, {valid}/{total} valid"
    );

    Ok(())
}

/// Validate a batch of proxies concurrently, reusing one reqwest::Client per proxy port.
async fn validate_batch(
    proxies: &[crate::pool::manager::PoolProxy],
    validation_url: &str,
    timeout: std::time::Duration,
    concurrency: usize,
    state: &Arc<AppState>,
) -> usize {
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let mut handles = Vec::with_capacity(proxies.len());

    for proxy in proxies {
        let local_port = match proxy.local_port {
            Some(p) => p,
            None => continue,
        };

        let sem = semaphore.clone();
        let state = state.clone();
        let url = validation_url.to_string();
        let proxy_id = proxy.id.clone();
        let proxy_name = proxy.name.clone();

        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();

            let proxy_addr = format!("http://127.0.0.1:{local_port}");
            let result = validate_single(&proxy_addr, &url, timeout).await;

            match result {
                Ok(()) => {
                    state.pool.set_status(&proxy_id, ProxyStatus::Valid);
                    state
                        .db
                        .update_proxy_validation(&proxy_id, true, None)
                        .ok();
                }
                Err(e) => {
                    tracing::debug!("Proxy {proxy_name} failed validation: {e}");
                    state.pool.set_status(&proxy_id, ProxyStatus::Invalid);
                    state
                        .db
                        .update_proxy_validation(&proxy_id, false, Some(&e))
                        .ok();
                }
            }
        });
        handles.push(handle);
    }

    let mut count = 0;
    for handle in handles {
        if handle.await.is_ok() {
            count += 1;
        }
    }
    count
}

async fn validate_single(
    proxy_addr: &str,
    target_url: &str,
    timeout: std::time::Duration,
) -> Result<(), String> {
    let proxy = reqwest::Proxy::all(proxy_addr).map_err(|e| format!("Proxy config error: {e}"))?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .proxy(proxy)
        .timeout(timeout)
        .danger_accept_invalid_certs(true)
        .pool_max_idle_per_host(0) // don't keep idle connections
        .build()
        .map_err(|e| format!("Client build error: {e}"))?;

    let resp = client
        .get(target_url)
        .send()
        .await
        .map_err(|e| format!("Request failed: {e}"))?;

    if resp.status().is_success() || resp.status().is_redirection() {
        Ok(())
    } else {
        Err(format!("HTTP {}", resp.status()))
    }
}
