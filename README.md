# Apache Flight SQL Router

A modular Apache Arrow Flight SQL server implementation in Rust with JWT authentication and role-based access control.

## Project Structure

The project has been refactored into a clean, modular architecture following separation of concerns:

```
src/
├── auth/           # Authentication & authorization
├── interceptor/    # gRPC middleware & interceptors
├── service/        # Main Flight service implementation
├── types/          # Common types, traits, and interfaces
├── tests/          # Test utilities and test cases
├── lib.rs          # Library entry point and module exports
└── main.rs         # Binary entry point
```

### Module Responsibilities

#### `auth/` - Authentication & Authorization
- **Account management**: User accounts, passwords (Argon2 hashed), roles, and tenant IDs
- **JWT handling**: Token creation, validation, and claims management
- **Password verification**: Secure password checking using Argon2
- **Token revocation**: In-memory token blacklisting for security

#### `interceptor/` - gRPC Middleware
- **Authentication interceptor**: JWT token validation for incoming requests
- **Request processing**: Extracts and validates authentication context
- **Security middleware**: Ensures all requests are properly authenticated

#### `service/` - Flight Service Implementation
- **gRPC service**: Implements the Arrow Flight protocol
- **Handshake**: User authentication and JWT token issuance
- **Flight operations**: Query execution, schema discovery, and data streaming
- **Action handling**: Token revocation and other administrative actions

#### `types/` - Common Types & Interfaces
- **SQL backend trait**: Abstract interface for different database backends
- **Stream types**: Arrow record batch streaming definitions
- **Common structures**: Shared types used across modules

#### `tests/` - Testing Infrastructure
- **Test utilities**: Server setup and teardown helpers
- **Integration tests**: End-to-end service testing
- **Unit tests**: Individual component testing

## Features

- **JWT Authentication**: Secure token-based authentication
- **Role-Based Access Control**: User roles and permissions
- **Multi-Tenant Support**: Tenant isolation for different organizations
- **Password Security**: Argon2 password hashing
- **Token Revocation**: Ability to revoke compromised tokens
- **Arrow Flight Protocol**: Full implementation of the Flight SQL standard
- **gRPC Server**: High-performance gRPC-based communication

## Usage

### Starting the Server

```rust
use apache_flight_sql_router::{MyFlightService, run};

fn main() {
    run();
}
```

### Authentication Flow

1. **Handshake**: Client sends username/password
2. **Verification**: Server validates credentials using Argon2
3. **Token Issuance**: JWT token with user claims is returned
4. **Request Authentication**: All subsequent requests include the JWT token
5. **Context Extraction**: Server extracts user context for authorization

### Example Client Usage

```rust
use arrow_flight::flight_service_client::FlightServiceClient;

// Connect to server
let mut client = FlightServiceClient::connect("http://localhost:8080").await?;

// Authenticate
let creds = HandshakeCreds {
    username: "alice".to_string(),
    password: "secret1".to_string(),
};

// Perform handshake to get JWT token
let token = client.handshake(/* ... */).await?;

// Use token for subsequent requests
let mut request = tonic::Request::new(/* ... */);
request.metadata_mut().insert("authorization", format!("Bearer {}", token));
```

## Development

### Running Tests

```bash
cargo test
```

### Code Organization Principles

- **Single Responsibility**: Each module has one clear purpose
- **Dependency Inversion**: High-level modules don't depend on low-level details
- **Interface Segregation**: Clean, focused trait definitions
- **Open/Closed**: Easy to extend without modifying existing code

### Adding New Features

1. **New authentication methods**: Extend the `auth` module
2. **Additional interceptors**: Add to the `interceptor` module
3. **New service endpoints**: Extend the `service` module
4. **Database backends**: Implement the `SqlBackend` trait in `types`

## Security Considerations

- **Production Use**: Replace hardcoded JWT secrets with secure key management
- **Password Storage**: Argon2 is used for password hashing (production-ready)
- **Token Expiration**: JWT tokens expire after 10 minutes
- **Revocation**: Implement persistent token revocation for production
- **HTTPS**: Always use TLS in production environments

## Dependencies

- **tonic**: gRPC framework for Rust
- **arrow-flight**: Apache Arrow Flight protocol implementation
- **jsonwebtoken**: JWT token handling
- **argon2**: Password hashing
- **tokio**: Async runtime
- **serde**: Serialization/deserialization
- **tracing**: Structured logging
