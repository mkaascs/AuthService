package token

import (
	"auth-service/internal/domain/dto/tokens/commands"
	"auth-service/internal/domain/dto/tokens/results"
	authErrors "auth-service/internal/domain/entities/errors"
	sloglib "auth-service/internal/lib/log/slog"
	"context"
	"errors"
	"fmt"
	"log/slog"
)

func (s *service) ValidateToken(ctx context.Context, command commands.Validate) (*results.Validate, error) {
	const fn = "services.token.service.ValidateToken"
	log := s.log.With(slog.String("fn", fn))

	result, err := s.accessTokenSvc.Parse(commands.Parse{
		Token: command.AccessToken,
	})

	if err != nil {
		const msg = "failed to parse access token"
		if errors.Is(err, authErrors.ErrInvalidAccessToken) || errors.Is(err, authErrors.ErrAccessTokenExpired) {
			log.Info(msg, sloglib.Error(err))
			return nil, err
		}

		log.Error(msg, sloglib.Error(err))
		return nil, fmt.Errorf("%s: %s: %w", fn, msg, err)
	}

	isRevoked, err := s.accessTokenRepo.IsRevoked(ctx, result.JTI)
	if err != nil {
		log.Warn("failed to check if token is revoked", sloglib.Error(err))
	}

	if isRevoked {
		log.Info("access token is revoked", slog.Int64("user_id", result.UserID))
		return nil, authErrors.ErrAccessTokenRevoked
	}

	log.Info("access token validated successfully", slog.Int64("user_id", result.UserID))

	return &results.Validate{
		UserID:    result.UserID,
		Roles:     result.Roles,
		ExpiresAt: result.ExpiresAt,
	}, nil
}
