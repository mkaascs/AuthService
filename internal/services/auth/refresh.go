package auth

import (
	"auth-service/internal/domain/dto/auth/commands"
	"auth-service/internal/domain/dto/auth/results"
	tokenCommands "auth-service/internal/domain/dto/tokens/commands"
	"auth-service/internal/domain/entities"
	authErrors "auth-service/internal/domain/entities/errors"
	sloglib "auth-service/internal/lib/log/slog"
	"auth-service/internal/lib/refreshToken"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

func (s *service) Refresh(ctx context.Context, command commands.Refresh) (*results.Refresh, error) {
	const fn = "services.auth.service.Refresh"
	log := s.log.With(slog.String("fn", fn))

	tx, err := s.tokenRepo.BeginTx(ctx)
	if err != nil {
		log.Error("failed to begin tx", sloglib.Error(err))
		return nil, fmt.Errorf("%s: failed to begin tx: %w", fn, err)
	}

	committed := false
	defer func() {
		if !committed {
			if err := tx.Rollback(); err != nil {
				log.Error("failed to rollback tx", sloglib.Error(err))
			}
		}
	}()

	newRefreshToken := refreshToken.Generate()

	result, err := s.tokenRepo.UpdateByTokenTx(ctx, tx, tokenCommands.UpdateByToken{
		RefreshTokenHash:    refreshToken.Hash(command.RefreshToken, s.hmacSecret),
		NewRefreshTokenHash: refreshToken.Hash(newRefreshToken, s.hmacSecret),
		ExpiresAt:           time.Now().Add(s.config.RefreshTokenTTL),
	})

	if err != nil {
		const msg = "failed to update refresh token"
		if errors.Is(err, authErrors.ErrInvalidRefreshToken) {
			log.Info(msg, sloglib.Error(err))
			return nil, authErrors.ErrInvalidRefreshToken
		}

		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			log.Info(msg, sloglib.Error(err))
			return nil, ctx.Err()
		}

		log.Error(msg, sloglib.Error(err))
		return nil, fmt.Errorf("%s: %s: %w", fn, msg, err)
	}

	user, err := s.userRepo.GetByIDTx(ctx, tx, result.UserID)
	if err != nil {
		const msg = "failed to get user"
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			log.Info(msg, sloglib.Error(err))
			return nil, ctx.Err()
		}

		log.Error(msg, sloglib.Error(err))
		return nil, fmt.Errorf("%s: %s: %w", fn, msg, err)
	}

	accessToken, err := s.accessTokenSvc.Generate(tokenCommands.Generate{
		UserID: user.User.ID,
		Roles:  user.User.Roles,
	})

	if err != nil {
		log.Error("failed to generate access token", sloglib.Error(err))
		return nil, fmt.Errorf("%s: failed to generate access token: %w", fn, err)
	}

	if err = tx.Commit(); err != nil {
		log.Error("failed to commit tx", sloglib.Error(err))
		return nil, fmt.Errorf("%s: failed to commit tx: %w", fn, err)
	}

	committed = true

	log.Info("user refreshed token successfully", slog.Int64("user_id", user.User.ID))

	return &results.Refresh{
		Tokens: entities.TokenPair{
			AccessToken:  accessToken.Token,
			RefreshToken: newRefreshToken,
		},
		ExpiresIn: s.config.AccessTokenTTL,
	}, nil
}
