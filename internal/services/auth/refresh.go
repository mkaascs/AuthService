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
)

func (s *service) Refresh(ctx context.Context, command commands.Refresh) (*results.Refresh, error) {
	const fn = "services.auth.service.Refresh"
	log := s.log.With(slog.String("fn", fn))

	tx, err := s.tokenRepo.BeginTx(ctx)
	if err != nil {
		log.Error("failed to begin tx", sloglib.Error(err))
		return nil, fmt.Errorf("%s: failed to begin tx: %w", fn, err)
	}

	defer func() {
		if err := tx.Rollback(); err != nil {
			log.Error("failed to rollback tx", sloglib.Error(err))
		}
	}()

	newRefreshToken := refreshToken.Generate()

	result, err := s.tokenRepo.UpdateByTokenTx(ctx, tx, tokenCommands.UpdateByToken{
		RefreshTokenHash:    refreshToken.Hash(command.RefreshToken, s.hmacSecret),
		NewRefreshTokenHash: refreshToken.Hash(newRefreshToken, s.hmacSecret),
	})

	if err != nil {
		if errors.Is(err, authErrors.ErrInvalidRefreshToken) {
			log.Info("failed to update refresh token", sloglib.Error(err))
			return nil, authErrors.ErrInvalidRefreshToken
		}

		log.Error("failed to update refresh token", sloglib.Error(err))
		return nil, fmt.Errorf("%s: failed to update refresh token: %w", fn, err)
	}

	user, err := s.userRepo.GetByIDTx(ctx, tx, result.UserID)
	if err != nil {
		log.Error("failed to get user", sloglib.Error(err))
		return nil, fmt.Errorf("%s: failed to get user: %w", fn, err)
	}

	accessToken, err := s.accessTokens.Generate(tokenCommands.Generate{
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

	log.Info("user refreshed token successfully", slog.Int64("user_id", user.User.ID))

	return &results.Refresh{
		Tokens: entities.TokenPair{
			AccessToken:  accessToken.Token,
			RefreshToken: newRefreshToken,
		},
		ExpiresIn: s.config.AccessTokenTTL,
	}, nil
}
