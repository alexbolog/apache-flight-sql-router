use crate::{AuthContext, BatchStream, SqlBackend};
use arrow_array::*;
use arrow_schema::{DataType, Field, Schema, SchemaRef, TimeUnit};
use deadpool_postgres::{Client, Pool};
use std::sync::Arc;
use tokio_postgres::types::Type;

pub struct PostgresBackend {
    pool: Pool,
}

impl PostgresBackend {
    pub fn new(pool: Pool) -> Self {
        Self { pool }
    }

    pub fn new_from_conn_string(conn_str: &str) -> Self {
        let mgr = deadpool_postgres::Manager::new(conn_str.parse().unwrap(), tokio_postgres::NoTls);
        let pool = deadpool_postgres::Pool::builder(mgr)
            .max_size(4)
            .build()
            .unwrap();

        Self::new(pool)
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

#[async_trait::async_trait]
impl SqlBackend for PostgresBackend {
    fn name(&self) -> &'static str {
        "postgres"
    }

    async fn schema(&self, sql: &str, ctx: &AuthContext) -> anyhow::Result<SchemaRef> {
        let client = self.client_for(ctx).await?;
        let stmt = client.prepare(sql).await?;
        let fields = stmt
            .columns()
            .iter()
            .map(|c| -> anyhow::Result<Field> {
                let dt = Self::map_pg_type(c.type_())?;
                Ok(Field::new(c.name(), dt, true))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        Ok(Arc::new(Schema::new(fields)))
    }

    async fn query(&self, sql: &str, ctx: &AuthContext) -> anyhow::Result<BatchStream> {
        let client = self.client_for(ctx).await?;
        // For production: use portals + fetch N rows per batch; here we fetch all for brevity
        let stmt = client.prepare(sql).await?;
        let rows = client.query(&stmt, &[]).await?;
        let schema = self.schema(sql, ctx).await?;

        // Build arrays per column according to schema types
        let mut arrays: Vec<ArrayRef> = Vec::with_capacity(schema.fields().len());
        for (i, f) in schema.fields().iter().enumerate() {
            let arr: ArrayRef = match f.data_type() {
                DataType::Int64 => Arc::new(Int64Array::from(
                    rows.iter()
                        .map(|r| r.try_get::<usize, Option<i64>>(i).ok().flatten())
                        .collect::<Vec<_>>(),
                )),
                DataType::Int32 => Arc::new(Int32Array::from(
                    rows.iter()
                        .map(|r| r.try_get::<usize, Option<i32>>(i).ok().flatten())
                        .collect::<Vec<_>>(),
                )),
                DataType::Utf8 => Arc::new(StringArray::from(
                    rows.iter()
                        .map(|r| r.try_get::<usize, Option<String>>(i).ok().flatten())
                        .collect::<Vec<_>>(),
                )),
                DataType::Boolean => Arc::new(BooleanArray::from(
                    rows.iter()
                        .map(|r| r.try_get::<usize, Option<bool>>(i).ok().flatten())
                        .collect::<Vec<_>>(),
                )),
                DataType::Float64 => Arc::new(Float64Array::from(
                    rows.iter()
                        .map(|r| r.try_get::<usize, Option<f64>>(i).ok().flatten())
                        .collect::<Vec<_>>(),
                )),
                DataType::Float32 => Arc::new(Float32Array::from(
                    rows.iter()
                        .map(|r| r.try_get::<usize, Option<f32>>(i).ok().flatten())
                        .collect::<Vec<_>>(),
                )),
                DataType::Binary => Arc::new(BinaryArray::from_iter(
                    rows.iter()
                        .map(|r| r.try_get::<usize, Option<Vec<u8>>>(i).ok().flatten()),
                )),
                DataType::Timestamp(TimeUnit::Microsecond, _) => {
                    let vals: Vec<Option<i64>> = rows
                        .iter()
                        .map(|r| {
                            // Adjust if using timestamptz vs timestamp; you can use with-chrono features to parse
                            let v: Option<chrono::NaiveDateTime> = r.try_get(i).ok().flatten();
                            v.map(|t| t.and_utc().timestamp_micros())
                        })
                        .collect();
                    Arc::new(TimestampMicrosecondArray::from(vals))
                }
                DataType::Decimal128(p, s) => {
                    // Convert NUMERIC → i128 with scale; adapt to your bigint/decimal crate
                    let vals: Vec<Option<i128>> = rows
                        .iter()
                        .map(|r| {
                            let v: Option<String> = r.try_get(i).ok().flatten(); // or a decimal type if feature enabled
                            v.and_then(|sval| decimal_string_to_i128_scaled(&sval, *s as i32).ok())
                        })
                        .collect();
                    Arc::new(Decimal128Array::from(vals).with_precision_and_scale(*p, *s)?)
                }
                other => anyhow::bail!("demo skipped Arrow type: {other:?}"),
            };
            arrays.push(arr);
        }

        let batch = RecordBatch::try_new(schema, arrays)?;
        let stream = futures::stream::iter(vec![Ok(batch)]);
        Ok(Box::pin(stream))
    }
}

fn decimal_string_to_i128_scaled(s: &str, scale: i32) -> anyhow::Result<i128> {
    // naive; use a real decimal type in production
    let bd = rust_decimal::Decimal::from_str_exact(s)?;
    let scale = rust_decimal::Decimal::new(1, scale as u32).normalize();
    let scaled = bd * scale;
    Ok(scaled.mantissa())
}

#[cfg(test)]
mod tests {
    use crate::db_backends::pg_backend::PostgresBackend;
    use crate::{AuthContext, SqlBackend};
    use arrow_array::StringArray;
    use futures::StreamExt;
    use testcontainers_modules::{postgres, testcontainers::runners::SyncRunner};

    #[test]
    fn test_postgres_backend() {
        let container = postgres::Postgres::default().start().unwrap();
        let host_port = container.get_host_port_ipv4(5432).unwrap();
        let conn_str = &format!("postgres://postgres:postgres@127.0.0.1:{host_port}/postgres",);
        let backend = PostgresBackend::new_from_conn_string(conn_str);

        // Run async logic inside a tokio runtime manually
        tokio_test::block_on(async {
            let (client, connection) = tokio_postgres::connect(&conn_str, tokio_postgres::NoTls)
                .await
                .expect("Failed to connect");

            tokio::spawn(async move {
                if let Err(e) = connection.await {
                    eprintln!("Connection error: {}", e);
                }
            });

            client
                .execute(
                    "CREATE TABLE users (id SERIAL PRIMARY KEY, name TEXT NOT NULL)",
                    &[],
                )
                .await
                .unwrap();

            client
                .execute("INSERT INTO users (name) VALUES ($1)", &[&"alice"])
                .await
                .unwrap();

            let mut stream = backend
                .query(
                    "SELECT name FROM users WHERE name = \'alice\'",
                    &AuthContext::default(),
                )
                .await
                .expect("Failed to execute query");

            // Take the first batch from the stream
            let batch = stream.next().await.unwrap().unwrap();

            // Access the "name" column (assuming it's the first column, index 0)
            let col = batch
                .column(0)
                .as_any()
                .downcast_ref::<StringArray>()
                .expect("Column 0 should be StringArray");

            // Row 0 should be "alice"
            let name = col.value(0);
            assert_eq!(name, "alice");
        });
    }
}
