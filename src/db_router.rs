use crate::types::TenantDbConfig;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Default, Clone)]
pub struct DbRouter {
    by_tenant: Arc<HashMap<String, TenantDbConfig>>,
}

impl DbRouter {
    pub fn new(configs: Vec<TenantDbConfig>) -> Self {
        let map = configs
            .into_iter()
            .map(|c| (c.tenant_id.clone(), c))
            .collect();
        Self {
            by_tenant: Arc::new(map),
        }
    }

    pub fn for_tenant(&self, tid: &str) -> anyhow::Result<&TenantDbConfig> {
        self.by_tenant
            .get(tid)
            .ok_or_else(|| anyhow::anyhow!("unknown tenant: {tid}"))
    }
}
