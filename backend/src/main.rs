use std::sync::Arc;

use tower_http::cors::CorsLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use watchbeat::auth::{self, AppState, JwtValidator};
use watchbeat::config::Config;
use watchbeat::db::Database;
use watchbeat::embed::serve_embedded;
use watchbeat::netcheck;
use watchbeat::routes;
use watchbeat::scheduler::SchedulerManager;

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    // âââââ rustls CryptoProvider âââââ
    // `reqwest` pulls in `aws-lc-rs` while we depend on `ring`; without an explicit
    // process-level default, `rustls::ClientConfig::builder()` panics. Install `ring`.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let config = Config::load();

    // âââââ DNS resolver âââââ
    // Must run before the first check: the resolver is built once, lazily.
    watchbeat::dns::init(config.dns_upstreams.clone());

    // âââââ Tracing âââââ
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.log_level));

    if config.log_format == "json" {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer().json())
            .init();
    } else {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(
                tracing_subscriber::fmt::layer()
                    .pretty()
                    .with_target(true)
                    .with_file(true)
                    .with_line_number(true),
            )
            .init();
    }

    tracing::info!("ð WatchBeat starting...");

    // âââââ Connectivity verification âââââ
    tracing::info!("ð Checking connectivity...");
    let check_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();
    match check_client.get("https://1.1.1.1").send().await {
        Ok(_) => tracing::info!("â Internet connectivity OK"),
        Err(e) => tracing::warn!("â ï¸  Internet connectivity check failed: {} (non-fatal)", e),
    }
    match check_client
        .get(format!(
            "{}/.well-known/openid-configuration",
            config.oidc_issuer_url.trim_end_matches('/')
        ))
        .send()
        .await
    {
        Ok(_) => tracing::info!("â OIDC provider reachable"),
        Err(e) => tracing::warn!("â ï¸  OIDC provider not reachable: {} (will retry)", e),
    }

    // âââââ Data directory âââââ
    if let Err(e) = tokio::fs::create_dir_all(&config.data_dir).await {
        tracing::warn!("Could not create data dir: {}", e);
    }

    // âââââ Database âââââ
    let db = match Database::open(&config.database_url).await {
        Ok(db) => {
            tracing::info!("ð¦ Database opened: {}", config.database_url.display());
            db
        }
        Err(e) => {
            tracing::error!("â Failed to open database: {}", e);
            std::process::exit(1);
        }
    };

    // âââââ OIDC (mandatory) âââââ
    let oidc_metadata = match auth::discover_oidc(&config).await {
        Ok(m) => {
            tracing::info!("â OIDC discovery: {}", m.issuer);
            m
        }
        Err(e) => {
            tracing::error!("â OIDC discovery failed: {}", e);
            std::process::exit(1);
        }
    };

    // âââââ JWKS (como populates) âââââ
    // Validate against the issuer exactly as published in the discovery
    // document: Authentik's issuer ends with a slash, and the `iss` claim of
    // its ID tokens matches that value.
    let jwt_validator = JwtValidator::new(&oidc_metadata.issuer, &config.oidc_client_id);
    if let Err(e) = jwt_validator.fetch_jwks(&config.oidc_issuer_url).await {
        tracing::error!("â JWKS fetch failed: {}. OIDC will not work.", e);
        std::process::exit(1);
    }
    let jwt_validator = Arc::new(jwt_validator);

    // âââââ App State âââââ
    let (event_tx, _) = tokio::sync::broadcast::channel(auth::SSE_CHANNEL_CAPACITY);

    // âââââ Network health canary âââââ
    // Publishes the health of our own egress; the scheduler reads it (never
    // awaits) to attribute every failure to the target or to our connectivity.
    // The period comes from the `canary_interval_secs` setting (default 30s).
    let canary_secs = db
        .get_setting(netcheck::SETTING_CANARY_INTERVAL_SECS)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(
                error = %e,
                "netcheck: no se pudo leer canary_interval_secs; usando default"
            );
            None
        });
    let netcheck_handle = netcheck::spawn(netcheck::interval_from_setting(canary_secs.as_deref()));

    // Start the scheduler (per-monitor timers, no more polling)
    let scheduler_mgr =
        SchedulerManager::spawn(db.clone(), event_tx.clone(), netcheck_handle.clone()).await;

    let app_state = Arc::new(AppState {
        config: config.clone(),
        db: db.clone(),
        oidc_metadata: Some(oidc_metadata),
        jwt_validator: jwt_validator.clone(),
        oidc_states: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        scheduler_mgr,
        event_tx: event_tx.clone(),
        netcheck: netcheck_handle,
    });

    // âââââ Daily Cleanup Loop âââââ
    let db_for_cleanup = db.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(86400));
        // First run after 1h to let scheduler populate data
        tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
        loop {
            interval.tick().await;
            tracing::info!(
                "Running daily cleanup of old checks (retention={}d)",
                config.retention_days
            );
            if let Err(e) = db_for_cleanup
                .cleanup_old_checks(config.retention_days)
                .await
            {
                tracing::warn!("Cleanup: failed: {}", e);
            }
        }
    });

    // âââââ Router (como populates) âââââ
    let state_for_middleware = app_state.clone();
    let app = routes::api_routes()
        .layer(CorsLayer::permissive())
        .layer(axum::middleware::from_fn(
            move |mut req: axum::extract::Request, next: axum::middleware::Next| {
                let state = state_for_middleware.clone();
                async move {
                    req.extensions_mut().insert(state);
                    watchbeat::auth::require_auth(req, next).await
                }
            },
        ))
        .fallback(|req: axum::extract::Request| async move {
            let path = req.uri().path().to_string();
            serve_embedded(&path).await
        })
        .with_state(app_state);

    let addr = if config.host == "0.0.0.0" {
        format!("[::]:{}", config.port)
    } else {
        format!("{}:{}", config.host, config.port)
    };

    tracing::info!("ð WatchBeat en http://{}", addr);

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("Failed to bind address");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("Server error");
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.expect("ctrl_c handler");
    };
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("signal handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => { tracing::info!("ð SIGINT received, shutting down..."); }
        _ = terminate => { tracing::info!("ð SIGTERM received, shutting down..."); }
    }
}
