use crate::Snapshot;
use hickory_server::{
    net::NetError,
    proto::{rr::Record, serialize::binary::BinEncoder},
    server::{Request, ResponseHandler, ResponseInfo},
    zone_handler::MessageResponse,
};
use std::sync::{Arc, Mutex};

/// Resolver management runs behind the same admission limits as native DNS.
#[async_trait::async_trait]
pub trait Processor: Send + Sync {
    async fn process(
        &self,
        snapshot: Arc<Snapshot>,
        request: &Request,
        profile: Option<&str>,
    ) -> anyhow::Result<Vec<u8>>;
    async fn profile_exists(&self, profile: &str) -> bool;
}

#[derive(Clone, Default)]
pub struct CapturedResponse(Arc<Mutex<Option<Vec<u8>>>>);

impl CapturedResponse {
    pub fn take(&self) -> Option<Vec<u8>> {
        self.0.lock().ok().and_then(|mut wire| wire.take())
    }
}

#[async_trait::async_trait]
impl ResponseHandler for CapturedResponse {
    async fn send_response<'a>(
        &mut self,
        response: MessageResponse<
            '_,
            'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
        >,
    ) -> std::result::Result<ResponseInfo, NetError> {
        let mut wire = Vec::new();
        let mut encoder = BinEncoder::new(&mut wire);
        encoder.set_max_size(u16::MAX);
        let info = response.destructive_emit(&mut encoder)?;
        *self
            .0
            .lock()
            .map_err(|_| std::io::Error::other("DNS response lock poisoned"))? = Some(wire);
        Ok(info)
    }
}
