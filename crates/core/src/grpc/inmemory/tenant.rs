/// In-memory tenant token storage.
use crate::ids::{TenantId, TenantToken};
use crate::storage::{StorageError, TenantTokenError, TenantTokenStore};
use async_trait::async_trait;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Clone, Default)]
pub struct InMemoryTenantTokens {
    tokens: Arc<Mutex<HashMap<TenantToken, TenantId>>>,
}

impl InMemoryTenantTokens {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, token: impl Into<TenantToken>, tenant: TenantId) {
        let mut map = self.tokens.lock();
        map.insert(token.into(), tenant);
    }
}

#[async_trait]
impl TenantTokenStore for InMemoryTenantTokens {
    async fn resolve_tenant(&self, token: &TenantToken) -> Result<TenantId, TenantTokenError> {
        let map = self.tokens.lock();
        map.get(token).copied().ok_or(TenantTokenError::Unknown)
    }

    async fn insert(&self, token: &TenantToken, tenant: TenantId) -> Result<(), StorageError> {
        let mut map = self.tokens.lock();
        map.insert(token.clone(), tenant);
        Ok(())
    }
}
