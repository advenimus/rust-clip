use std::sync::Arc;

use crate::{config::Config, db::DbPool};

#[derive(Clone)]
pub struct AppState {
    pub db: DbPool,
    pub config: Arc<Config>,
}
