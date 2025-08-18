use crate::AuthContext;
use arrow_array::*;
use arrow_schema::{DataType, Field, Schema, TimeUnit};
use deadpool_postgres::{Client, Pool};
use tokio_postgres::types::Type;

pub struct PostgresBackend {
    pool: Pool,
}

impl PostgresBackend {
    pub fn new(pool: Pool) -> Self {
        Self { pool }
    }

    // check if this mapping is actually needed or will be provided by flight-sql
    fn map_pg_type(ty: &Type) -> anyhow::Result<DataType> {
        Ok(match *ty {
            Type::BOOL => DataType::Boolean,
            Type::INT2 => DataType::Int16,
            Type::INT4 => DataType::Int32,
            Type::INT8 => DataType::Int64,
            Type::FLOAT4 => DataType::Float32,
            Type::FLOAT8 => DataType::Float64,
            Type::TEXT | Type::VARCHAR | Type::BPCHAR => DataType::Utf8,
            Type::TIMESTAMPTZ => DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
            Type::TIMESTAMP => DataType::Timestamp(TimeUnit::Microsecond, None),
            Type::BYTEA => DataType::Binary,
            Type::NUMERIC => DataType::Decimal128(38, 9), // pick sane default or inspect typmod
            _ => anyhow::bail!("unsupported pg type: {ty:?}"),
        })
    }

    async fn client_for(&self, ctx: &AuthContext) -> anyhow::Result<Client> {
        let client = self.pool.get().await?;
        // Enforce tenancy here (choose one strategy):
        // 1) RLS guard variable:
        // client.batch_execute(&format!("SET LOCAL app.tenant_id = '{}'", ctx.tenant_id.replace('\'', "''"))).await?;
        // 2) Schema-per-tenant:
        // client.batch_execute(&format!("SET LOCAL search_path = {}", quote_ident(&ctx.tenant_id))).await?;
        Ok(client)
    }
}
