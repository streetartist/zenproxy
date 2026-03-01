pub mod admin;
pub mod auth;
pub mod client_fetch;
pub mod fetch;
pub mod relay;
pub mod subscription;

use crate::AppState;
use axum::{
    extract::State,
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::{delete, get, post},
    Router,
};
use axum::extract::DefaultBodyLimit;
use std::sync::Arc;
use tower_http::cors::CorsLayer;

pub fn router(state: Arc<AppState>) -> Router {
    // Auth routes — no auth required
    let auth_routes = Router::new()
        .route("/api/auth/login", get(auth::login))
        .route("/api/auth/callback", get(auth::callback))
        .route("/api/auth/me", get(auth::me))
        .route("/api/auth/logout", post(auth::logout))
        .route("/api/auth/regenerate-key", post(auth::regenerate_key));

    // Admin routes — protected by admin password
    let admin_routes = Router::new()
        .route("/api/admin/proxies", get(admin::list_proxies))
        .route("/api/admin/proxies/:id", delete(admin::delete_proxy))
        .route("/api/admin/proxies/cleanup", post(admin::cleanup_proxies))
        .route("/api/admin/validate", post(admin::trigger_validation))
        .route("/api/admin/quality-check", post(admin::trigger_quality_check))
        .route("/api/admin/stats", get(admin::get_stats))
        .route("/api/admin/users", get(admin::list_users))
        .route("/api/admin/users/:id", delete(admin::delete_user))
        .route("/api/admin/users/:id/ban", post(admin::ban_user))
        .route("/api/admin/users/:id/unban", post(admin::unban_user))
        .route(
            "/api/subscriptions",
            get(subscription::list_subscriptions).post(subscription::add_subscription),
        )
        .route(
            "/api/subscriptions/:id",
            delete(subscription::delete_subscription),
        )
        .route(
            "/api/subscriptions/:id/refresh",
            post(subscription::refresh_subscription),
        )
        .route_layer(middleware::from_fn_with_state(state.clone(), admin_auth));

    // Fetch/Relay/Proxies routes — handler-level auth (API key or session)
    let fetch_relay_routes = Router::new()
        .route("/api/fetch", get(fetch::fetch_proxies))
        .route("/api/client/fetch", get(client_fetch::client_fetch_proxies))
        .route("/api/proxies", get(fetch::list_all_proxies))
        .route(
            "/api/relay",
            get(relay::relay_request)
                .post(relay::relay_request),
        )
        .layer(DefaultBodyLimit::max(10 * 1024 * 1024)); // 10 MB

    // Page routes — no auth
    let page_routes = Router::new()
        .route("/", get(user_page))
        .route("/admin", get(admin_page))
        .route("/docs", get(docs_page));

    Router::new()
        .merge(auth_routes)
        .merge(admin_routes)
        .merge(fetch_relay_routes)
        .merge(page_routes)
        .layer(CorsLayer::permissive())
        .with_state(state)
}

async fn admin_auth(
    State(state): State<Arc<AppState>>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let expected = &state.config.server.admin_password;

    let authorized = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|token| token == expected)
        .unwrap_or(false);

    if authorized {
        Ok(next.run(request).await)
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

async fn user_page() -> axum::response::Html<&'static str> {
    axum::response::Html(include_str!("../web/user.html"))
}

async fn admin_page() -> axum::response::Html<&'static str> {
    axum::response::Html(include_str!("../web/admin.html"))
}

async fn docs_page() -> axum::response::Html<String> {
    use pulldown_cmark::{Parser, Options, html};
    let readme = include_str!("../../README.md");
    let mut options = Options::empty();
    options.insert(Options::ENABLE_TABLES);
    options.insert(Options::ENABLE_STRIKETHROUGH);
    let parser = Parser::new_ext(readme, options);
    let mut rendered = String::new();
    html::push_html(&mut rendered, parser);
    let template = include_str!("../web/docs.html");
    let page = template.replace("{{CONTENT}}", &rendered);
    axum::response::Html(page)
}
