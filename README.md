# Auth Service gRPC (Go)

A high-performance gRPC microservice for authentication built in Go. Provides secure user authentication, profile management, and JWT token issuance for distributed applications.

---

## Features

- **gRPC-first design** — High-performance communication with strong typing and generated clients
- **JWT-based authentication** — Stateless tokens with access/refresh token rotation
- **Token revocation** — Access token blacklist via Redis for immediate session invalidation
- **User management** — Registration, login, profile updates, password changes
- **Token validation** — Dedicated endpoint for downstream services to verify tokens
- **Security best practices** — bcrypt password hashing, HMAC-signed refresh tokens, TLS-ready
- **Clean architecture** — Domain-driven design with clear separation of concerns

---

## Services

| Service | Methods | Description |
|---------|---------|-------------|
| `Auth` | `Login`, `Register`, `Refresh`, `Logout` | User authentication and session management |
| `User` | `GetUser`, `UpdateUser`, `ChangePassword` | Profile management and password operations |
| `Token` | `ValidateToken` | Token validation for service-to-service authentication |

## Tech Stack

| Component | Technology |
|-----------|------------|
| **Protocol** | Protocol Buffers (proto3) + gRPC |
| **Language** | Go 1.24+ |
| **Tokens** | JWT (HS256) + Refresh tokens (HMAC-SHA256) |
| **Password Hashing** | bcrypt (cost=10) |
| **Database** | MySQL 8.0 |
| **Cache/Blacklist** | Redis 7 (for access token revocation) |
| **Logging** | slog (structured JSON logging) |
| **Migrations** | golang-migrate |

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

## Security Considerations

- **Passwords** — Never stored in plain text, hashed with bcrypt
- **Refresh Tokens** — Stored as HMAC-SHA256 hashes in database (not raw values)
- **Access Tokens** — Short-lived (15 min), can be revoked via Redis blacklist
- **Logout** — Invalidates both refresh token (DB) and access token (Redis)
- **Transport** — TLS recommended for production deployments