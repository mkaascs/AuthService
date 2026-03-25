package services

import (
	"auth-service/internal/domain/dto/tokens/commands"
	"auth-service/internal/domain/dto/tokens/results"
	"context"
)

type Token interface {
	ValidateToken(ctx context.Context, command commands.Validate) (*results.Validate, error)
}
