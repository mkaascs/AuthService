FROM golang:1.24-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o /auth-service ./cmd/auth-service/main.go

FROM alpine:3.21

WORKDIR /app

# ca-certificates нужен для TLS соединений
RUN apk --no-cache add ca-certificates tzdata

COPY --from=builder /auth-service .
COPY config/ ./config/
COPY migrations/ ./migrations/

EXPOSE 5505

CMD ["/app/auth-service"]