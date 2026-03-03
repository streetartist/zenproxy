use crate::api::auth;
use crate::error::AppError;
use crate::pool::manager::{PoolProxy, ProxyFilter};
use crate::AppState;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use std::sync::Arc;

/// Headers that should NOT be forwarded from the user request to the target.
/// Only hop-by-hop headers and `host` are skipped.
const SKIP_HEADERS: &[&str] = &[
    "host",
    "connection",
    "transfer-encoding",
];

#[derive(Debug, Deserialize)]
pub struct RelayParams {
    pub url: Option<String>,
    pub method: Option<String>,
    pub proxy_id: Option<String>,
    pub api_key: Option<String>,
    // Quality filters
    #[serde(default)]
    pub chatgpt: bool,
    #[serde(default)]
    pub google: bool,
    #[serde(default)]
    pub residential: bool,
    pub risk_max: Option<f64>,
    pub country: Option<String>,
    #[serde(rename = "type")]
    pub proxy_type: Option<String>,
}

pub async fn relay_request(
    State(state): State<Arc<AppState>>,
    Query(params): Query<RelayParams>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response, AppError> {
    // Authenticate: relay requires api_key query parameter only,
    // so Authorization/Cookie headers are free for the target.
    let api_key = params.api_key.as_deref()
        .ok_or_else(|| AppError::BadRequest("Relay requires 'api_key' query parameter".into()))?;
    auth::authenticate_request(&state, &headers, Some(api_key)).await?;

    let target_url = params
        .url
        .as_deref()
        .ok_or_else(|| AppError::BadRequest("Missing 'url' parameter".into()))?;

    let method = params.method.as_deref().unwrap_or("GET");

    let filter = ProxyFilter {
        chatgpt: params.chatgpt,
        google: params.google,
        residential: params.residential,
        risk_max: params.risk_max,
        country: params.country,
        proxy_type: params.proxy_type,
        proxy_id: params.proxy_id,
        count: None,
    };

    // Try to find a working proxy
    let max_retries = 5;

    // If specific proxy requested
    if let Some(ref id) = filter.proxy_id {
        if let Some(proxy) = state.pool.get(id) {
            let local_port = if let Some(port) = proxy.local_port {
                port
            } else {
                // On-demand binding: proxy exists but has no port assigned
                // Lock and re-check to avoid duplicate bindings from concurrent requests
                let mut mgr = state.singbox.lock().await;
                if let Some(port) = state.pool.get(id).and_then(|p| p.local_port) {
                    // Another request already created the binding
                    drop(mgr);
                    port
                } else {
                    let port = mgr
                        .create_binding(&proxy.id, &proxy.singbox_outbound)
                        .await
                        .map_err(|e| AppError::Internal(format!("Failed to create binding: {e}")))?;
                    drop(mgr);
                    state.pool.set_local_port(&proxy.id, port);
                    state.db.update_proxy_local_port(&proxy.id, port as i32).ok();
                    port
                }
            };

            let client = get_or_create_client(&state, local_port)?;
            match do_relay(&client, target_url, method, &headers, &body).await {
                Ok(resp) => {
                    return Ok(build_streaming_response(resp, &proxy, None));
                }
                Err(e) => {
                    return Err(AppError::Internal(format!("Relay failed: {e}")));
                }
            }
        }
        return Err(AppError::NotFound("Specified proxy not found".into()));
    }

    // Try random proxies
    for attempt in 0..max_retries {
        let candidates = state.pool.pick_random(&filter, 1);
        let proxy = match candidates.first() {
            Some(p) => p,
            None => {
                return Err(AppError::NotFound(
                    "No proxies match the given filters".into(),
                ));
            }
        };

        let local_port = match proxy.local_port {
            Some(p) => p,
            None => continue,
        };

        let client = get_or_create_client(&state, local_port)?;
        match do_relay(&client, target_url, method, &headers, &body).await {
            Ok(resp) => {
                return Ok(build_streaming_response(resp, proxy, Some(attempt + 1)));
            }
            Err(e) => {
                tracing::debug!("Relay attempt {} failed with proxy {}: {e}", attempt + 1, proxy.name);
                // Mark proxy as having a failure so periodic validation will re-check it
                state.pool.increment_error(&proxy.id);
                state.db.increment_proxy_error_count(&proxy.id).ok();
                continue;
            }
        }
    }

    Err(AppError::Internal(format!(
        "All {max_retries} relay attempts failed"
    )))
}

/// Get a cached reqwest::Client for the given proxy port, or create one.
fn get_or_create_client(state: &AppState, local_port: u16) -> Result<reqwest::Client, AppError> {
    if let Some(client) = state.relay_clients.get(&local_port) {
        return Ok(client.clone());
    }

    let proxy_addr = format!("http://127.0.0.1:{local_port}");
    let proxy = reqwest::Proxy::all(&proxy_addr)
        .map_err(|e| AppError::Internal(format!("Proxy config error: {e}")))?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .proxy(proxy)
        .timeout(std::time::Duration::from_secs(30))
        .danger_accept_invalid_certs(true)
        .pool_max_idle_per_host(10)
        .build()
        .map_err(|e| AppError::Internal(format!("Client build error: {e}")))?;

    state.relay_clients.insert(local_port, client.clone());
    Ok(client)
}

/// Invalidate cached clients for ports that are no longer in use.
pub fn invalidate_relay_clients(state: &AppState, active_ports: &[u16]) {
    let stale: Vec<u16> = state
        .relay_clients
        .iter()
        .map(|e| *e.key())
        .filter(|port| !active_ports.contains(port))
        .collect();
    for port in stale {
        state.relay_clients.remove(&port);
    }
}

/// Headers that should NOT be forwarded from the target response back to the user.
const SKIP_RESPONSE_HEADERS: &[&str] = &[
    "connection",
    "transfer-encoding",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "upgrade",
];

/// Build a streaming axum Response from a reqwest::Response, attaching X-Proxy-* headers.
fn build_streaming_response(resp: reqwest::Response, proxy: &PoolProxy, attempt: Option<u32>) -> Response {
    let status = resp.status();

    // Collect response headers before consuming the body
    let resp_headers = resp.headers().clone();

    let encoded_name = percent_encoding::utf8_percent_encode(
        &proxy.name,
        percent_encoding::NON_ALPHANUMERIC,
    ).to_string();

    // Stream the response body without buffering
    let body = axum::body::Body::from_stream(resp.bytes_stream());

    let mut response = (status, body).into_response();

    let h = response.headers_mut();

    // Forward all response headers from target (except hop-by-hop)
    for (name, value) in resp_headers.iter() {
        let key = name.as_str().to_lowercase();
        if SKIP_RESPONSE_HEADERS.contains(&key.as_str()) {
            continue;
        }
        h.insert(name.clone(), value.clone());
    }

    // Add proxy metadata headers
    h.insert("X-Proxy-Id", proxy.id.parse().unwrap());
    h.insert("X-Proxy-Name", encoded_name.parse().unwrap());
    h.insert("X-Proxy-Server", format!("{}:{}", proxy.server, proxy.port).parse().unwrap());
    if let Some(q) = &proxy.quality {
        if let Some(ref ip) = q.ip_address {
            if let Ok(v) = ip.parse() { h.insert("X-Proxy-IP", v); }
        }
        if let Some(ref country) = q.country {
            if let Ok(v) = country.parse() { h.insert("X-Proxy-Country", v); }
        }
    }
    if let Some(a) = attempt {
        h.insert("X-Proxy-Attempt", a.to_string().parse().unwrap());
    }
    response
}

/// Send the relay request through the proxy, forwarding user headers and body.
/// Returns the raw reqwest::Response for streaming.
async fn do_relay(
    client: &reqwest::Client,
    target_url: &str,
    method: &str,
    user_headers: &HeaderMap,
    body: &[u8],
) -> Result<reqwest::Response, String> {
    let mut req = match method.to_uppercase().as_str() {
        "POST" => client.post(target_url),
        "PUT" => client.put(target_url),
        "DELETE" => client.delete(target_url),
        "PATCH" => client.patch(target_url),
        "HEAD" => client.head(target_url),
        _ => client.get(target_url),
    };

    // Forward user headers (excluding hop-by-hop and sensitive ones)
    for (name, value) in user_headers.iter() {
        let key = name.as_str().to_lowercase();
        if SKIP_HEADERS.contains(&key.as_str()) {
            continue;
        }
        req = req.header(name.clone(), value.clone());
    }

    // Forward request body for any method that has one
    if !body.is_empty() {
        req = req.body(body.to_vec());
    }

    req.send().await.map_err(|e| e.to_string())
}
