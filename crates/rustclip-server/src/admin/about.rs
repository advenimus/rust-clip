use askama::Template;
use axum::response::{Html, IntoResponse, Response};

use crate::{error::AppResult, middleware::AdminUser};

const REPO_URL: &str = "https://github.com/advenimus/rust-clip";
const AUTHOR_NAME: &str = "Chris Vautour";
const AUTHOR_HANDLE: &str = "advenimus";

#[derive(Template)]
#[template(path = "about.html")]
struct AboutTemplate<'a> {
    admin_display_name: &'a str,
    version: &'static str,
    repo_url: &'static str,
    author_name: &'static str,
    author_handle: &'static str,
}

pub async fn show(admin: AdminUser) -> AppResult<Response> {
    let tmpl = AboutTemplate {
        admin_display_name: &admin.display_name,
        version: env!("CARGO_PKG_VERSION"),
        repo_url: REPO_URL,
        author_name: AUTHOR_NAME,
        author_handle: AUTHOR_HANDLE,
    };
    Ok(Html(tmpl.render()?).into_response())
}
