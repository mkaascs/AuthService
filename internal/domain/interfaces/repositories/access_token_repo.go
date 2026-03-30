package repositories

import (
	"auth-service/internal/domain/dto/tokens/commands"
	"context"
)

type AccessTokenRepo interface {
	Revoke(ctx context.Context, command commands.Revoke) error
	IsRevoked(ctx context.Context, jti string) (bool, error)
}
