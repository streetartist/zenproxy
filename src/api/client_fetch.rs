use crate::api::auth;
use crate::api::fetch::FetchQuery;
use crate::error::AppError;
use crate::pool::manager::ProxyFilter;
use crate::AppState;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::Json;
use serde_json::json;
use std::sync::Arc;

/// Client fetch endpoint - returns proxies with their outbound configurations.
/// Used by local sing-box clients to get proxy configs for direct use.
pub async fn client_fetch_proxies(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<FetchQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth::authenticate_request(&state, &headers, query.api_key.as_deref()).await?;

    let filter = ProxyFilter {
        chatgpt: query.chatgpt,
        google: query.google,
        residential: query.residential,
        risk_max: query.risk_max,
        country: query.country,
        proxy_type: query.proxy_type,
        count: query.count,
        proxy_id: query.proxy_id,
    };
    let count = filter.count.unwrap_or(10);

    if let Some(ref id) = filter.proxy_id {
        if let Some(proxy) = state.pool.get(id) {
            return Ok(Json(json!({
                "proxies": [client_proxy_to_json(&proxy)],
                "count": 1
            })));
        } else {
            return Err(AppError::NotFound(format!("Proxy {id} not found")));
        }
    }

    let proxies = state.pool.pick_random(&filter, count);
    if proxies.is_empty() {
        return Ok(Json(json!({
            "proxies": [],
            "count": 0,
            "message": "No proxies match the given filters"
        })));
    }

    let proxy_list: Vec<serde_json::Value> = proxies.iter().map(client_proxy_to_json).collect();
    let len = proxy_list.len();

    Ok(Json(json!({
        "proxies": proxy_list,
        "count": len,
    })))
}

fn client_proxy_to_json(p: &crate::pool::manager::PoolProxy) -> serde_json::Value {
    json!({
        "id": p.id,
        "name": p.name,
        "type": p.proxy_type,
        "server": p.server,
        "port": p.port,
        "outbound": p.singbox_outbound,
        "quality": p.quality.as_ref().map(|q| json!({
            "country": q.country,
            "chatgpt": q.chatgpt_accessible,
            "google": q.google_accessible,
            "is_residential": q.is_residential,
            "risk_score": q.risk_score,
            "risk_level": q.risk_level,
        })),
    })
}
