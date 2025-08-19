# Apache Flight SQL Router

A modular Apache Arrow Flight SQL server implementation in Rust with JWT authentication, role-based access control, and multi-tenant database routing.

## Project Structure

The project follows a clean, modular architecture with clear separation of concerns:

```
src/
├── auth.rs              # Authentication & authorization system
├── db_backends/         # Database backend implementations
│   ├── mod.rs          # Backend module exports
│   └── pg_backend.rs   # PostgreSQL backend implementation
├── db_router.rs         # Multi-tenant database routing
├── interceptor.rs       # gRPC authentication middleware
├── sql_service.rs       # Main Flight SQL service implementation
├── types.rs             # Common types, traits, and interfaces
├── utils.rs             # Arrow Flight data conversion utilities
├── lib.rs               # Library entry point and module exports
└── main.rs              # Binary entry point
```

### Module Responsibilities

#### `auth.rs` - Authentication & Authorization
- **Account management**: User accounts with Argon2-hashed passwords, roles, and tenant IDs
- **JWT handling**: Token creation, validation, and claims management using HS256
- **Password verification**: Secure password checking using Argon2 with configurable salts
- **Token revocation**: In-memory token blacklisting for security
- **Multi-tenant support**: Tenant isolation through user-tenant mapping

#### `db_backends/` - Database Backend Implementations
- **PostgreSQL backend**: Full implementation with connection pooling via deadpool
- **Type mapping**: Automatic PostgreSQL to Arrow data type conversion
- **Connection management**: Tenant-aware database connections with RLS support
- **Extensible design**: Easy to add new database backends (MySQL, SQL Server, etc.)

#### `db_router.rs` - Multi-Tenant Database Routing
- **Tenant isolation**: Routes requests to appropriate database backends based on tenant ID
- **Configuration management**: Tenant-specific database configurations
- **Dynamic routing**: Runtime tenant-to-backend mapping

#### `interceptor.rs` - gRPC Authentication Middleware
- **JWT validation**: Automatic token validation for incoming requests
- **Context injection**: Extracts user context and injects into request extensions
- **Token revocation checking**: Validates tokens against revocation list
- **Security middleware**: Ensures all requests are properly authenticated

#### `sql_service.rs` - Flight SQL Service Implementation
- **Flight SQL protocol**: Full implementation of the Arrow Flight SQL standard
- **Handshake authentication**: Username/password authentication with JWT token issuance
- **Query execution**: SQL statement execution with tenant-aware routing
- **Schema discovery**: Automatic schema inference from SQL statements
- **Data streaming**: Efficient Arrow record batch streaming
- **Action handling**: Token revocation and administrative operations

#### `types.rs` - Common Types & Interfaces
- **SqlBackend trait**: Abstract interface for different database backends
- **TenantDbConfig**: Configuration structure for tenant-specific database settings
- **BatchStream**: Arrow record batch streaming definitions
- **Common structures**: Shared types used across modules

#### `utils.rs` - Arrow Flight Utilities
- **Data conversion**: Arrow schema and record batch to Flight IPC conversion
- **Streaming support**: Efficient batch-to-flight-data conversion
- **Dictionary handling**: Proper dictionary encoding for complex data types

## Features

- **JWT Authentication**: Secure token-based authentication with HS256
- **Role-Based Access Control**: User roles and permissions system
- **Multi-Tenant Support**: Complete tenant isolation with separate database backends
- **Password Security**: Argon2 password hashing with configurable salts
- **Token Revocation**: In-memory token blacklisting for security
- **Arrow Flight SQL Protocol**: Full implementation of the Flight SQL standard
- **gRPC Server**: High-performance gRPC-based communication
- **PostgreSQL Support**: Production-ready PostgreSQL backend with connection pooling
- **Type Safety**: Full Rust type safety with async/await support

## Usage

### Starting the Server

```rust
use apache_flight_sql_router::{run, db_router::DbRouter};
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let router = build_router().await?;
    let addr: SocketAddr = "0.0.0.0:50051".parse()?;
    let issuer = "flight-demo-auth".to_string();
    let audience = "flight-clients".to_string();

    run(addr, issuer, audience, router).await
}
```

### Building a Multi-Tenant Router

```rust
use apache_flight_sql_router::{
    db_router::DbRouter,
    db_backends::PostgresBackend,
    types::TenantDbConfig,
};
use std::sync::Arc;

async fn build_router() -> Result<DbRouter, Box<dyn std::error::Error>> {
    let tenants = vec![
        TenantDbConfig {
            tenant_id: "tenant_acme".to_string(),
            backend: Arc::new(PostgresBackend::new_from_conn_string(
                "postgres://user:pass@localhost:5432/acme_db"
            )),
            default_schema: None,
        },
        TenantDbConfig {
            tenant_id: "tenant_beta".to_string(),
            backend: Arc::new(PostgresBackend::new_from_conn_string(
                "postgres://user:pass@localhost:5432/beta_db"
            )),
            default_schema: None,
        },
    ];

    Ok(DbRouter::new(tenants))
}
```

### Authentication Flow

1. **Handshake**: Client sends username/password via Flight handshake
2. **Credential Verification**: Server validates against Argon2-hashed passwords
3. **JWT Issuance**: HS256 JWT token with user claims is returned
4. **Request Authentication**: All subsequent requests include the JWT token
5. **Tenant Routing**: Server routes requests to appropriate database based on tenant ID

### Example Client Usage

```rust
use arrow_flight::flight_service_client::FlightServiceClient;
use arrow_flight::sql::client::FlightSqlServiceClient;

// Connect to server
let mut client = FlightServiceClient::connect("http://localhost:50051").await?;

// Authenticate via handshake
let creds = HandshakeCreds {
    username: "alice".to_string(),
    password: "secret1".to_string(),
};

let payload = bytes::Bytes::from(serde_json::to_vec(&creds).unwrap());
let req_stream = tokio_stream::iter(vec![HandshakeRequest {
    protocol_version: 0,
    payload,
}]);

let mut hs = client.handshake(Request::new(req_stream)).await?.into_inner();
let token = String::from_utf8(hs.message().await.unwrap().unwrap().payload.to_vec()).unwrap();

// Use token for SQL operations
let mut sql = FlightSqlServiceClient::new(channel);
sql.set_header("authorization", format!("Bearer {token}"));

// Execute SQL query
let info = sql.execute("SELECT name FROM users".to_string(), None).await?;
let ticket = info.endpoint[0].ticket.as_ref().unwrap().clone();
let flight_data_stream = sql.do_get(Request::new(ticket)).await?.into_inner();

// Process results
let mut rb_stream = FlightRecordBatchStream::new(flight_data_stream);
while let Some(batch) = rb_stream.try_next().await? {
    // Process Arrow record batch
}
```

## Development

### Running Tests

```bash
cargo test
```

The test suite includes comprehensive end-to-end testing with:
- Multi-tenant database isolation testing
- JWT authentication flow testing
- Token revocation testing
- PostgreSQL backend testing with testcontainers

### Code Organization Principles

- **Single Responsibility**: Each module has one clear purpose
- **Dependency Inversion**: High-level modules don't depend on low-level details
- **Interface Segregation**: Clean, focused trait definitions
- **Open/Closed**: Easy to extend without modifying existing code
- **Async-First**: Built with async/await for high performance

### Adding New Features

1. **New authentication methods**: Extend the `auth` module
2. **Additional interceptors**: Add to the `interceptor` module
3. **New service endpoints**: Extend the `sql_service` module
4. **Database backends**: Implement the `SqlBackend` trait in `types`
5. **New data types**: Extend type mapping in backend implementations

## Security Considerations

- **Production Use**: Replace hardcoded JWT secrets with secure key management
- **Password Storage**: Argon2 is used for password hashing (production-ready)
- **Token Expiration**: JWT tokens have configurable expiration
- **Revocation**: Implement persistent token revocation for production
- **HTTPS**: Always use TLS in production environments
- **Tenant Isolation**: Complete database-level tenant separation
- **Connection Pooling**: Efficient database connection management

## Dependencies

- **tonic**: gRPC framework for Rust
- **arrow-flight**: Apache Arrow Flight protocol implementation
- **jsonwebtoken**: JWT token handling
- **argon2**: Password hashing
- **tokio**: Async runtime
- **serde**: Serialization/deserialization
- **deadpool-postgres**: PostgreSQL connection pooling
- **tokio-postgres**: PostgreSQL driver
- **testcontainers**: Testing infrastructure
- **anyhow**: Error handling
- **futures**: Async stream utilities

## Architecture Highlights

- **Multi-tenant by design**: Built from the ground up for tenant isolation
- **Database agnostic**: Easy to add new database backends
- **High performance**: Async/await with efficient streaming
- **Production ready**: Connection pooling, proper error handling, comprehensive testing
- **Extensible**: Clean trait-based design for easy extension
