use crate::db::{ProxyRow, Subscription};
use crate::error::AppError;
use crate::parser;
use crate::pool::manager::{PoolProxy, ProxyStatus};
use crate::AppState;
use axum::extract::{Path, State};
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct AddSubscriptionRequest {
    pub name: String,
    #[serde(rename = "type", default = "default_sub_type")]
    pub sub_type: String,
    pub url: Option<String>,
    pub content: Option<String>,
}

fn default_sub_type() -> String {
    "auto".to_string()
}

#[derive(Debug, Clone, Copy)]
pub enum SyncMode {
    Normal,
    Validation,
    QualityCheck,
}

pub async fn list_subscriptions(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let subs = state.db.get_subscriptions()?;
    Ok(Json(json!({ "subscriptions": subs })))
}

pub async fn add_subscription(
    State(state): State<Arc<AppState>>,
    body: axum::body::Body,
) -> Result<Json<serde_json::Value>, AppError> {
    // Try to parse as JSON first
    let bytes = axum::body::to_bytes(body, 10 * 1024 * 1024)
        .await
        .map_err(|e| AppError::BadRequest(format!("Failed to read body: {e}")))?;

    let req: AddSubscriptionRequest = serde_json::from_slice(&bytes)
        .map_err(|e| AppError::BadRequest(format!("Invalid JSON: {e}")))?;

    // Fetch content from URL or use provided content
    let content = if let Some(ref url) = req.url {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let resp = client
            .get(url)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to fetch subscription: {e}")))?;
        resp.text()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to read response: {e}")))?
    } else if let Some(ref content) = req.content {
        content.clone()
    } else {
        return Err(AppError::BadRequest(
            "Either 'url' or 'content' must be provided".into(),
        ));
    };

    // Parse the content
    let parsed = parser::parse_subscription(&content, &req.sub_type);
    if parsed.is_empty() {
        return Err(AppError::BadRequest(
            "No proxies found in subscription content".into(),
        ));
    }

    let now = chrono::Utc::now().to_rfc3339();
    let sub_id = uuid::Uuid::new_v4().to_string();

    let subscription = Subscription {
        id: sub_id.clone(),
        name: req.name.clone(),
        sub_type: req.sub_type.clone(),
        url: req.url.clone(),
        content: Some(content),
        proxy_count: parsed.len() as i32,
        created_at: now.clone(),
        updated_at: now.clone(),
    };

    state.db.insert_subscription(&subscription)?;

    // Insert proxies
    let mut added = 0;
    for pc in &parsed {
        let proxy_id = uuid::Uuid::new_v4().to_string();
        let proxy_row = ProxyRow {
            id: proxy_id.clone(),
            subscription_id: sub_id.clone(),
            name: pc.name.clone(),
            proxy_type: pc.proxy_type.to_string(),
            server: pc.server.clone(),
            port: pc.port as i32,
            config_json: serde_json::to_string(&pc.singbox_outbound).unwrap_or_default(),
            is_valid: false,
            local_port: None,
            error_count: 0,
            last_error: None,
            last_validated: None,
            created_at: now.clone(),
            updated_at: now.clone(),
        };
        state.db.insert_proxy(&proxy_row)?;

        let pool_proxy = PoolProxy {
            id: proxy_id,
            subscription_id: sub_id.clone(),
            name: pc.name.clone(),
            proxy_type: pc.proxy_type.to_string(),
            server: pc.server.clone(),
            port: pc.port,
            singbox_outbound: pc.singbox_outbound.clone(),
            status: ProxyStatus::Untested,
            local_port: None,
            error_count: 0,
            quality: None,
        };
        state.pool.add(pool_proxy);
        added += 1;
    }

    tracing::info!("Added subscription '{}' with {added} proxies", req.name);

    // Assign ports then validate in background (must be sequential, not two separate spawns)
    let state2 = state.clone();
    tokio::spawn(async move {
        tracing::info!("Running initial validation for new proxies...");
        if let Err(e) = crate::pool::validator::validate_all(state2).await {
            tracing::error!("Initial validation failed: {e}");
        }
    });

    Ok(Json(json!({
        "subscription": subscription,
        "proxies_added": added,
    })))
}

pub async fn delete_subscription(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    state.pool.remove_by_subscription(&id);
    state.db.delete_subscription(&id)?;

    // Sync bindings in background
    let state2 = state.clone();
    tokio::spawn(async move {
        sync_proxy_bindings(&state2, SyncMode::Normal).await;
    });

    Ok(Json(json!({ "message": "Subscription deleted" })))
}

/// Core logic for refreshing a subscription: fetch content, parse, replace proxies.
/// Returns the number of new proxies added, or an error message.
/// Does NOT spawn validation — the caller decides when/how to validate.
///
/// This uses a **smooth replacement** strategy:
/// 1. Fetch & parse first — if it fails, old proxies are untouched.
/// 2. If parse returns 0 proxies, abort (don't wipe the subscription).
/// 3. For proxies whose (server, port, proxy_type) match an existing one,
///    preserve their validation status, error_count, local_port and quality data.
/// 4. Only then remove old proxies that no longer appear in the new list.
pub async fn refresh_subscription_core(state: &Arc<AppState>, sub: &Subscription) -> Result<usize, String> {
    let content = if let Some(ref url) = sub.url {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|e| format!("Failed to build HTTP client: {e}"))?;
        let resp = client
            .get(url)
            .send()
            .await
            .map_err(|e| format!("Failed to fetch: {e}"))?;
        resp.text()
            .await
            .map_err(|e| format!("Failed to read: {e}"))?
    } else if let Some(ref content) = sub.content {
        content.clone()
    } else {
        return Err("No URL or content to refresh".into());
    };

    let parsed = parser::parse_subscription(&content, &sub.sub_type);
    if parsed.is_empty() {
        return Err("Parsed 0 proxies, keeping existing data".into());
    }

    // Collect old proxies for this subscription, keyed by (server, port, proxy_type)
    let old_proxies: Vec<PoolProxy> = state
        .pool
        .get_all()
        .into_iter()
        .filter(|p| p.subscription_id == sub.id)
        .collect();
    let mut old_map: std::collections::HashMap<(String, u16, String), PoolProxy> = old_proxies
        .iter()
        .map(|p| ((p.server.clone(), p.port, p.proxy_type.clone()), p.clone()))
        .collect();

    let now = chrono::Utc::now().to_rfc3339();
    let mut added = 0;
    let mut kept_ids: std::collections::HashSet<String> = std::collections::HashSet::new();

    for pc in &parsed {
        let key = (pc.server.clone(), pc.port, pc.proxy_type.to_string());

        if let Some(old) = old_map.remove(&key) {
            // Same proxy still exists — update config but preserve status
            kept_ids.insert(old.id.clone());

            // Update the outbound config in DB (it may have changed)
            let new_config = serde_json::to_string(&pc.singbox_outbound).unwrap_or_default();
            state.db.update_proxy_config(&old.id, &pc.name, &new_config)
                .map_err(|e| format!("Failed to update proxy config: {e}"))?;

            // Update pool entry's name and outbound (keep status, local_port, etc.)
            state.pool.update_proxy_config(&old.id, &pc.name, pc.singbox_outbound.clone());

            added += 1;
        } else {
            // New proxy — insert fresh
            let proxy_id = uuid::Uuid::new_v4().to_string();
            let proxy_row = ProxyRow {
                id: proxy_id.clone(),
                subscription_id: sub.id.clone(),
                name: pc.name.clone(),
                proxy_type: pc.proxy_type.to_string(),
                server: pc.server.clone(),
                port: pc.port as i32,
                config_json: serde_json::to_string(&pc.singbox_outbound).unwrap_or_default(),
                is_valid: false,
                local_port: None,
                error_count: 0,
                last_error: None,
                last_validated: None,
                created_at: now.clone(),
                updated_at: now.clone(),
            };
            state.db.insert_proxy(&proxy_row)
                .map_err(|e| format!("Failed to insert proxy: {e}"))?;

            let pool_proxy = PoolProxy {
                id: proxy_id,
                subscription_id: sub.id.clone(),
                name: pc.name.clone(),
                proxy_type: pc.proxy_type.to_string(),
                server: pc.server.clone(),
                port: pc.port,
                singbox_outbound: pc.singbox_outbound.clone(),
                status: ProxyStatus::Untested,
                local_port: None,
                error_count: 0,
                quality: None,
            };
            state.pool.add(pool_proxy);
            added += 1;
        }
    }

    // Remove old proxies that no longer appear in the new list
    let removed: Vec<String> = old_map.values().map(|p| p.id.clone()).collect();
    for id in &removed {
        state.pool.remove(id);
        state.db.delete_proxy(id).ok();
    }

    state
        .db
        .update_subscription_proxy_count(&sub.id, added as i32)
        .map_err(|e| format!("Failed to update proxy count: {e}"))?;

    if !removed.is_empty() {
        tracing::info!(
            "Refresh '{}': kept {}, new {}, removed {}",
            sub.name, kept_ids.len(),
            added - kept_ids.len(), removed.len()
        );
    }

    Ok(added)
}

pub async fn refresh_subscription(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let sub = state
        .db
        .get_subscription(&id)?
        .ok_or_else(|| AppError::NotFound("Subscription not found".into()))?;

    let added = refresh_subscription_core(&state, &sub)
        .await
        .map_err(|e| AppError::Internal(e))?;

    // Validate in background
    let state2 = state.clone();
    tokio::spawn(async move {
        if let Err(e) = crate::pool::validator::validate_all(state2).await {
            tracing::error!("Validation after refresh failed: {e}");
        }
    });

    Ok(Json(json!({
        "message": "Subscription refreshed",
        "proxies_added": added,
    })))
}

/// Sync proxy bindings dynamically without restarting sing-box.
///
/// Port pool total = max_proxies + batch_size.
/// - Normal: top max_proxies Valid proxies get ports.
/// - Validation: keep ALL Valid bindings untouched; Untested use extra batch_size ports.
/// - QualityCheck: keep ALL Valid bindings; needs-quality use extra batch_size ports.
/// Zero disruption to user traffic during validation/quality-check.
pub async fn sync_proxy_bindings(state: &Arc<AppState>, mode: SyncMode) {
    let all_proxies = state.pool.get_all();
    if all_proxies.is_empty() {
        return;
    }

    let max = state.config.singbox.max_proxies;
    let batch = state.config.validation.batch_size;

    // Snapshot ALL current ports before changes (for sync_bindings diff)
    let all_current_ports: Vec<(String, u16)> = all_proxies
        .iter()
        .filter_map(|p| p.local_port.map(|port| (p.id.clone(), port)))
        .collect();

    // Classify proxies
    let mut valid_with_port: Vec<PoolProxy> = Vec::new();
    let mut valid_no_port: Vec<PoolProxy> = Vec::new();
    let mut untested: Vec<PoolProxy> = Vec::new();
    let mut invalid: Vec<PoolProxy> = Vec::new();
    let mut needs_quality: Vec<PoolProxy> = Vec::new();

    let now = chrono::Utc::now();
    for p in all_proxies {
        match p.status {
            ProxyStatus::Valid => {
                if matches!(mode, SyncMode::QualityCheck) && needs_quality_check(&p, &now) {
                    needs_quality.push(p);
                } else if p.local_port.is_some() {
                    valid_with_port.push(p);
                } else {
                    valid_no_port.push(p);
                }
            }
            ProxyStatus::Untested => untested.push(p),
            ProxyStatus::Invalid => invalid.push(p),
        }
    }

    valid_with_port.sort_by_key(|p| p.error_count);
    valid_no_port.sort_by_key(|p| p.error_count);
    untested.sort_by_key(|p| p.error_count);
    needs_quality.sort_by_key(|p| p.error_count);

    let mut selected: Vec<PoolProxy> = Vec::new();

    match mode {
        SyncMode::Normal => {
            // Valid first, fill up to max_proxies only (no extra ports)
            let mut ordered = Vec::new();
            ordered.extend(valid_with_port);
            ordered.extend(valid_no_port);
            ordered.extend(untested);
            ordered.extend(invalid);
            let cap = max.min(ordered.len());
            selected = ordered.drain(..cap).collect();
            for p in &ordered {
                if p.local_port.is_some() {
                    state.pool.clear_local_port(&p.id);
                    state.db.update_proxy_local_port_null(&p.id).ok();
                }
            }
        }
        SyncMode::Validation => {
            // Keep ALL Valid-with-port (up to max). Fill remaining normal slots with valid_no_port.
            // Then use EXTRA batch_size ports (beyond max_proxies) for Untested.
            let keep = valid_with_port.len().min(max);
            selected.extend(valid_with_port.drain(..keep));
            let normal_remaining = max.saturating_sub(selected.len());
            let fill = normal_remaining.min(valid_no_port.len());
            selected.extend(valid_no_port.drain(..fill));
            // Extra ports for Untested — these use ports max_proxies+1 .. max_proxies+batch_size
            let test_count = untested.len().min(batch);
            selected.extend(untested.drain(..test_count));
            // Clear ports for everything not selected
            for p in valid_with_port.iter().chain(valid_no_port.iter())
                .chain(untested.iter()).chain(invalid.iter())
            {
                if p.local_port.is_some() {
                    state.pool.clear_local_port(&p.id);
                    state.db.update_proxy_local_port_null(&p.id).ok();
                }
            }
        }
        SyncMode::QualityCheck => {
            // Keep ALL Valid-with-port. Use EXTRA batch_size ports for quality checks.
            let keep = valid_with_port.len().min(max);
            selected.extend(valid_with_port.drain(..keep));
            let normal_remaining = max.saturating_sub(selected.len());
            let fill = normal_remaining.min(valid_no_port.len());
            selected.extend(valid_no_port.drain(..fill));
            // Extra ports for quality checks
            let check_count = needs_quality.len().min(batch);
            selected.extend(needs_quality.drain(..check_count));
            for p in valid_with_port.iter().chain(valid_no_port.iter())
                .chain(needs_quality.iter()).chain(untested.iter()).chain(invalid.iter())
            {
                if p.local_port.is_some() {
                    state.pool.clear_local_port(&p.id);
                    state.db.update_proxy_local_port_null(&p.id).ok();
                }
            }
        }
    }

    let desired: Vec<(String, serde_json::Value)> = selected
        .iter()
        .map(|p| (p.id.clone(), p.singbox_outbound.clone()))
        .collect();

    let mode_str = match mode {
        SyncMode::Normal => "normal",
        SyncMode::Validation => "validation",
        SyncMode::QualityCheck => "quality-check",
    };
    tracing::info!(
        "Syncing bindings: {} selected (mode={}, max={}, batch={})",
        selected.len(), mode_str, max, batch,
    );

    let mut mgr = state.singbox.lock().await;
    let assignments = mgr.sync_bindings(&desired, &all_current_ports).await;
    drop(mgr);

    // Update pool and DB
    for p in &selected {
        state.pool.clear_local_port(&p.id);
    }
    for (id, port) in &assignments {
        state.pool.set_local_port(id, *port);
        state.db.update_proxy_local_port(id, *port as i32).ok();
    }
    let assigned_ids: std::collections::HashSet<&str> =
        assignments.iter().map(|(id, _)| id.as_str()).collect();
    for p in &selected {
        if !assigned_ids.contains(p.id.as_str()) && p.local_port.is_some() {
            state.db.update_proxy_local_port_null(&p.id).ok();
        }
    }

    let active_ports: Vec<u16> = assignments.iter().map(|(_, port)| *port).collect();
    crate::api::relay::invalidate_relay_clients(state, &active_ports);
}

/// Check if a proxy needs quality check (same logic as checker.rs)
fn needs_quality_check(proxy: &PoolProxy, now: &chrono::DateTime<chrono::Utc>) -> bool {
    match &proxy.quality {
        None => true,
        Some(q) => {
            if q.country.is_none() || q.ip_type.is_none() || q.ip_address.is_none() || q.risk_level == "Unknown" {
                return true;
            }
            if let Some(ref checked_str) = q.checked_at {
                if let Ok(checked) = chrono::DateTime::parse_from_rfc3339(checked_str) {
                    let age = *now - checked.with_timezone(&chrono::Utc);
                    age.num_hours() >= 24
                } else {
                    true
                }
            } else {
                true
            }
        }
    }
}
