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
	"time"
)

func (s *service) Logout(ctx context.Context, command commands.Logout) error {
	const fn = "services.auth.service.Logout"
	log := s.log.With(slog.String("fn", fn))

	claims, err := s.accessTokenSvc.Parse(tokenCommands.Parse{
		Token: command.AccessToken,
	})

	if err != nil {
		log.Info("failed to parse access token", sloglib.Error(err))
		if !errors.Is(err, authErrors.ErrAccessTokenExpired) {
			return fmt.Errorf("%s: failed to parse access token: %w", fn, err)
		}
	}

	tx, err := s.tokenRepo.BeginTx(ctx)
	if err != nil {
		log.Error("failed to begin tx", sloglib.Error(err))
		return fmt.Errorf("%s: failed to begin tx: %w", fn, err)
	}

	committed := false
	defer func() {
		if !committed {
			if err := tx.Rollback(); err != nil {
				log.Error("failed to rollback tx", sloglib.Error(err))
			}
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

	committed = true

	if claims != nil {
		if remainingTTL := time.Until(claims.ExpiresAt); remainingTTL > 0 {
			revoke := tokenCommands.Revoke{
				JTI: claims.JTI,
				TTL: remainingTTL,
			}

			if err := s.accessTokenRepo.Revoke(ctx, revoke); err != nil {
				log.Warn("failed to revoke access token", sloglib.Error(err))
			}
		}
	}

	log.Info("user logged out successfully", slog.Int64("user_id", result.UserID))

	return nil
}
