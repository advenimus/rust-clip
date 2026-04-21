use std::sync::Arc;

use crate::{config::Config, db::DbPool, ws::hub::Hub};

#[derive(Clone)]
pub struct AppState {
    pub db: DbPool,
    pub config: Arc<Config>,
    pub hub: Arc<Hub>,
}
