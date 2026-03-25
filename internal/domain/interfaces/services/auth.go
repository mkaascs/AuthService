package services

import (
	"auth-service/internal/domain/dto/auth/commands"
	"auth-service/internal/domain/dto/auth/results"
	"context"
)

type Auth interface {
	Register(ctx context.Context, command commands.Register) (*results.Register, error)
	Login(ctx context.Context, command commands.Login) (*results.Login, error)
	Refresh(ctx context.Context, command commands.Refresh) (*results.Refresh, error)
}
