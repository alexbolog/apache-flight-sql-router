use async_trait::async_trait;
use arrow_array::RecordBatch;
use arrow_schema::SchemaRef;
use std::pin::Pin;
use futures::Stream;

pub type BatchStream =
    Pin<Box<dyn Stream<Item = anyhow::Result<RecordBatch>> + Send + 'static>>;

#[async_trait]
pub trait SqlBackend: Send + Sync {
    fn name(&self) -> &'static str;

    /// Discover the Arrow schema for a SQL statement.
    async fn schema(&self, sql: &str, ctx: &crate::auth::AuthContext) -> anyhow::Result<SchemaRef>;

    /// Execute and stream Arrow record batches.
    async fn query(&self, sql: &str, ctx: &crate::auth::AuthContext) -> anyhow::Result<BatchStream>;
}
