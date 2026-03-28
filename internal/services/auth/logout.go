package auth

import (
	"auth-service/internal/domain/dto/auth/commands"
	tokenCommands "auth-service/internal/domain/dto/tokens/commands"
	authErrors "auth-service/internal/domain/entities/errors"
	sloglib "auth-service/internal/lib/log/slog"
	"auth-service/internal/lib/refreshToken"
	"context"
	"errors"
	"fmt"
	"log/slog"
)

func (s *service) Logout(ctx context.Context, command commands.Logout) error {
	const fn = "services.auth.service.Logout"
	log := s.log.With(slog.String("fn", fn))

	tx, err := s.tokenRepo.BeginTx(ctx)
	if err != nil {
		log.Error("failed to begin tx", sloglib.Error(err))
		return fmt.Errorf("%s: failed to begin tx: %w", fn, err)
	}

	defer func() {
		if err := tx.Rollback(); err != nil {
			log.Error("failed to rollback tx", sloglib.Error(err))
		}
	}()

	refreshTokenHash := refreshToken.Hash(command.RefreshToken, s.hmacSecret)
	result, err := s.tokenRepo.DeleteByTokenTx(ctx, tx, tokenCommands.DeleteByToken{
		RefreshTokenHash: refreshTokenHash,
	})

	if err != nil {
		const msg = "failed to delete refresh token"
		if errors.Is(err, authErrors.ErrInvalidRefreshToken) {
			log.Info(msg, sloglib.Error(err))
			return authErrors.ErrInvalidRefreshToken
		}

		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			log.Info(msg, sloglib.Error(err))
			return ctx.Err()
		}

		log.Error(msg, sloglib.Error(err))
		return fmt.Errorf("%s: %s: %w", fn, msg, err)
	}

	if err := tx.Commit(); err != nil {
		log.Error("failed to commit tx", sloglib.Error(err))
		return fmt.Errorf("%s: failed to commit tx: %w", fn, err)
	}

	log.Info("user logged out successfully", slog.Int64("user_id", result.UserID))

	return nil
}
