# Auth Service gRPC (Go)

A high-performance gRPC microservice for authentication built in Go. Provides secure user authentication, profile management, and JWT token issuance for distributed applications.

---

## Features

- **gRPC-first design** — High-performance communication with strong typing and generated clients
- **JWT-based authentication** — Stateless tokens with access/refresh token rotation
- **Token revocation** — Access token blacklist via Redis for immediate session invalidation
- **User management** — Registration, login, profile updates, password changes
- **Token validation** — Dedicated endpoint for downstream services to verify tokens
- **Brute-force protection** — Login rate limiting via Redis with configurable attempt window and block duration
- **Security best practices** — bcrypt password hashing, HMAC-signed refresh tokens, TLS-ready
- **Clean architecture** — Domain-driven design with clear separation of concerns

---

## Services

| Service | Methods                                                                           | Description |
|---------|-----------------------------------------------------------------------------------|-------------|
| `Auth` | `Login`, `Register`, `Refresh`, `Logout`                                          | User authentication and session management |
| `User` | `GetUser`, `GetUsers`, `UpdateUser`, `ChangePassword`, `AssignRole`, `RevokeRole` | Profile management and password operations |
| `Token` | `ValidateToken`                                                                   | Token validation for service-to-service authentication |

## Tech Stack

| Component | Technology                                              |
|-----------|---------------------------------------------------------|
| **Protocol** | Protocol Buffers (proto3) + gRPC                        |
| **Language** | Go 1.24+                                                |
| **Tokens** | JWT (HS256) + Refresh tokens (HMAC-SHA256)              |
| **Password Hashing** | bcrypt (cost=10)                                        |
| **Database** | MySQL 8.0                                               |
| **Cache/Blacklist** | Redis 7 (for access token revocation and rate limiting) |
| **Logging** | slog (structured JSON logging)                          |
| **Migrations** | golang-migrate                                          |

## Quick Start

### Prerequisites

- Go 1.24+
- Docker + Docker Compose
- Task (optional, for convenience)

### Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `CONFIG_PATH` | Path to config file | `config/local.yaml` |
| `JWT_SECRET_BASE64` | Base64-encoded JWT secret (32 bytes) | Required |
| `HMAC_SECRET_BASE64` | Base64-encoded HMAC secret for refresh tokens | Required |
| `MYSQL_ROOT_PASSWORD` | MySQL root password | Required |
| `REDIS_PASSWORD` | Redis password | Required |

## Rate Limiting

Login attempts are protected against brute-force attacks via a Redis-backed rate limiter.

**Behavior:**
- Each failed login attempt increments a per-login counter in Redis
- Once the counter exceeds `max_attempts`, the login is blocked and returns `8 ResourceExhausted`
- On successful login the counter is reset immediately

**Configuration** (`config/*.yaml`):

| Field | Description |
|-------|-------------|
| `rate_limiter.max_attempts` | Maximum allowed failed attempts before blocking |
| `rate_limiter.window` | Time window after which the counter resets |
| `rate_limiter.block_duration` | Block extension applied on each attempt past the limit |

**Fail-open:** if Redis is unavailable, rate limiting is skipped with a warning — login remains operational.

---

## Security Considerations

- **Passwords** — Never stored in plain text, hashed with bcrypt
- **Refresh Tokens** — Stored as HMAC-SHA256 hashes in database (not raw values)
- **Access Tokens** — Short-lived (15 min), can be revoked via Redis blacklist
- **Logout** — Invalidates both refresh token (DB) and access token (Redis)
- **Brute-force** — Login rate limiting per account, independent of IP address
- **Transport** — TLS recommended for production deployments