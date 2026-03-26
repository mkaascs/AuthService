package auth

import (
	"auth-service/internal/domain/dto/auth/commands"
	"context"
)

func (s *service) Logout(ctx context.Context, command commands.Logout) error {
	return nil
}
