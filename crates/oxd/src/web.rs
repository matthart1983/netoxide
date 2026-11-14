//! The web UI: three static files compiled into the daemon.
//!
//! The page itself is public, like a login page. It holds no data. Every
//! call it makes to the API carries the access token the user types in.

use axum::{
    Router,
    http::header,
    response::{IntoResponse, Response},
    routing::get,
};

use crate::{Shared, api::security_headers};

fn file(content_type: &'static str, body: &'static str) -> Response {
    let mut response = ([(header::CONTENT_TYPE, content_type)], body).into_response();
    response.headers_mut().extend(security_headers());
    // The files change only when the daemon is upgraded.
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        "no-cache".parse().expect("static header"),
    );
    response
}

pub fn routes() -> Router<Shared> {
    Router::new()
        .route(
            "/",
            get(|| async {
                file(
                    "text/html; charset=utf-8",
                    include_str!("../web/index.html"),
                )
            }),
        )
        .route(
            "/app.js",
            get(|| async {
                file(
                    "text/javascript; charset=utf-8",
                    include_str!("../web/app.js"),
                )
            }),
        )
        .route(
            "/app.css",
            get(|| async { file("text/css; charset=utf-8", include_str!("../web/app.css")) }),
        )
}
