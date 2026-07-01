//! Request-ID propagation middleware.
//!
//! If the incoming request carries an `X-Request-Id` header that value is reused;
//! otherwise a fresh UUID v4 is generated.  The ID is inserted into request extensions
//! (so downstream handlers can read it) and echoed back in the response as `X-Request-Id`.

use axum::{
    extract::Request,
    http::{HeaderName, HeaderValue},
    middleware::Next,
    response::Response,
};
use uuid::Uuid;

pub async fn propagate_request_id(mut request: Request, next: Next) -> Response {
    // Extract existing request-id or generate a new one.
    let request_id = request
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    // Make the ID available to handlers via extensions.
    request.extensions_mut().insert(request_id.clone());

    let mut response = next.run(request).await;

    // Echo the ID back to the caller.
    if let Ok(value) = HeaderValue::from_str(&request_id) {
        response
            .headers_mut()
            .insert(HeaderName::from_static("x-request-id"), value);
    }

    response
}
