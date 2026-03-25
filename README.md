# 🔐 Auth Service gRPC (Go)

A high-performance gRPC microservice for authentication built in Go. Provides secure user authentication, profile management, and JWT token issuance for your applications.

**Features:**

🚀 **gRPC-first design** — High-performance communication with strong typing  
🔒 **JWT-based authentication** — Stateless tokens with access/refresh rotation  
👤 **User management** — Registration, login, profile updates, password changes  
🔑 **Token validation** — Fast endpoint for downstream services to verify tokens  
🛡️ **Security best practices** — bcrypt password hashing, token rotation, TLS-ready  
📦 **Easy integration** — Clean proto contracts, ready to use in any Go project

---

**Services:**

- `Auth` — Login, Register, Refresh, Logout
- `User` — GetUser, UpdateUser, ChangePassword
- `Token` — ValidateToken for service-to-service auth

---

**Tech Stack:**

- Protocol Buffers (proto3)
- Go + gRPC
- JWT (RS256/HS256)
- bcrypt for password hashing