use askama::Template;
use axum::{
    extract::State,
    response::{Html, IntoResponse, Response},
};

use crate::{error::AppResult, middleware::AdminUser, state::AppState, update_check};

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
    update_check_enabled: bool,
    update_available: Option<AboutUpdate>,
}

pub struct AboutUpdate {
    pub latest_version: String,
    pub release_url: String,
    pub published_at: String,
    pub body: String,
}

pub async fn show(State(state): State<AppState>, admin: AdminUser) -> AppResult<Response> {
    let settings = state.settings.snapshot().await;
    let update_available = if settings.update_check_enabled {
        match state.update_state.snapshot().await {
            Some(latest) if update_check::is_newer(env!("CARGO_PKG_VERSION"), &latest.tag_name) => {
                Some(AboutUpdate {
                    latest_version: latest.tag_name,
                    release_url: latest.html_url,
                    published_at: latest.published_at,
                    body: latest.body,
                })
            }
            _ => None,
        }
    } else {
        None
    };
    let tmpl = AboutTemplate {
        admin_display_name: &admin.display_name,
        version: env!("CARGO_PKG_VERSION"),
        repo_url: REPO_URL,
        author_name: AUTHOR_NAME,
        author_handle: AUTHOR_HANDLE,
        update_check_enabled: settings.update_check_enabled,
        update_available,
    };
    Ok(Html(tmpl.render()?).into_response())
}
