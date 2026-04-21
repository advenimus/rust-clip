use std::sync::Arc;

use crate::{
    config::Config, db::DbPool, rate_limit::RateLimiter, settings::SettingsStore, ws::hub::Hub,
};

#[derive(Clone)]
pub struct AppState {
    pub db: DbPool,
    pub config: Arc<Config>,
    pub settings: SettingsStore,
    pub hub: Arc<Hub>,
    pub auth_limiter: RateLimiter,
}
