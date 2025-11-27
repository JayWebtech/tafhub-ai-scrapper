use axum::{
    extract::Request,
    http::StatusCode,
    response::{IntoResponse, Response},
    middleware::Next,
};
use governor::{clock::DefaultClock, state::keyed::DefaultKeyedStateStore, Quota, RateLimiter};
use std::num::NonZeroU32;
use std::sync::Arc;

/// Rate limiter middleware using governor crate
/// Tracks requests per IP address
#[derive(Clone)]
pub struct RateLimitLayer {
    limiter: Arc<RateLimiter<String, DefaultKeyedStateStore<String>, DefaultClock>>,
}

impl RateLimitLayer {
    /// Create a new rate limiter with the specified quota
    /// quota: maximum number of requests per duration
    /// Example: RateLimitLayer::new(5, std::time::Duration::from_secs(60)) = 5 requests per minute
    pub fn new(quota: u32, duration: std::time::Duration) -> Self {
        let quota = Quota::with_period(duration)
            .unwrap()
            .allow_burst(NonZeroU32::new(quota).unwrap());
        let limiter = Arc::new(RateLimiter::keyed(quota));
        Self { limiter }
    }

    /// Get a reference to the underlying rate limiter
    pub fn limiter(&self) -> &Arc<RateLimiter<String, DefaultKeyedStateStore<String>, DefaultClock>> {
        &self.limiter
    }

    /// Axum middleware function for rate limiting
    pub async fn rate_limit_middleware(
        limiter: Arc<RateLimiter<String, DefaultKeyedStateStore<String>, DefaultClock>>,
        req: Request,
        next: Next,
    ) -> Response {
        // Extract IP address from request
        let ip = req
            .headers()
            .get("x-forwarded-for")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.split(',').next())
            .map(|s| s.trim().to_string())
            .or_else(|| {
                req.headers()
                    .get("x-real-ip")
                    .and_then(|h| h.to_str().ok())
                    .map(|s| s.to_string())
            })
            .or_else(|| {
                req.extensions()
                    .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
                    .map(|addr| addr.ip().to_string())
            })
            .unwrap_or_else(|| "unknown".to_string());

        // Check rate limit
        if limiter.check_key(&ip).is_err() {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                axum::Json(serde_json::json!({
                    "error": "Rate limit exceeded. Please try again later.",
                    "status": 429
                })),
            )
                .into_response();
        }

        next.run(req).await
    }
}
