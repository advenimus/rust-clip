//! Broadcast-per-user routing for live clip events.
//!
//! Devices that connect subscribe to their user's channel. When any device
//! publishes a clip event the hub fans it out to all subscribers; the session
//! task filters out its own device id before writing to the socket.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use rustclip_shared::protocol::ClipEventMessage;
use tokio::sync::broadcast;
use uuid::Uuid;

const CHANNEL_BUFFER: usize = 256;

#[derive(Clone)]
pub struct ClipBroadcast {
    pub source_device_id: Uuid,
    pub event: ClipEventMessage,
}

pub struct Hub {
    senders: Mutex<HashMap<Uuid, broadcast::Sender<Arc<ClipBroadcast>>>>,
}

impl Hub {
    pub fn new() -> Self {
        Self {
            senders: Mutex::new(HashMap::new()),
        }
    }

    pub fn subscribe(&self, user_id: Uuid) -> broadcast::Receiver<Arc<ClipBroadcast>> {
        let mut senders = self.senders.lock().expect("hub mutex poisoned");
        senders
            .entry(user_id)
            .or_insert_with(|| broadcast::channel(CHANNEL_BUFFER).0)
            .subscribe()
    }

    pub fn publish(&self, user_id: Uuid, bcast: ClipBroadcast) {
        let sender = {
            let senders = self.senders.lock().expect("hub mutex poisoned");
            senders.get(&user_id).cloned()
        };
        if let Some(s) = sender {
            // .send fails only when there are no active receivers; that's fine.
            let _ = s.send(Arc::new(bcast));
        }
    }
}

impl Default for Hub {
    fn default() -> Self {
        Self::new()
    }
}
