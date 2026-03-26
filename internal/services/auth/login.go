package auth

import (
	"auth-service/internal/domain/dto/auth/commands"
	"auth-service/internal/domain/dto/auth/results"
	tokenCommands "auth-service/internal/domain/dto/tokens/commands"
	userCommands "auth-service/internal/domain/dto/user/commands"
	"auth-service/internal/domain/entities"
	authErrors "auth-service/internal/domain/entities/errors"
	sloglib "auth-service/internal/lib/log/slog"
	"auth-service/internal/lib/refreshToken"
	"context"
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"log/slog"
)

func (s *service) Login(ctx context.Context, command commands.Login) (*results.Login, error) {
	const fn = "services.auth.service.Login"
	log := s.log.With(slog.String("fn", fn))

	tx, err := s.userRepo.BeginTx(ctx)
	if err != nil {
		log.Error("failed to begin tx", sloglib.Error(err))
		return nil, fmt.Errorf("%s: failed to begin tx: %w", fn, err)
	}

	defer func() {
		if err := tx.Rollback(); err != nil {
			log.Error("failed to rollback tx", sloglib.Error(err))
		}
	}()

	result, err := s.userRepo.GetByLogin(ctx, userCommands.GetByLogin{
		Login: command.Login,
	})

	if err != nil {
		if errors.Is(err, authErrors.ErrUserNotFound) {
			log.Info("failed to get user by login", sloglib.Error(err))
			return nil, authErrors.ErrUserNotFound
		}

		log.Error("failed to get user by login", sloglib.Error(err))
		return nil, fmt.Errorf("%s: failed to get user by login: %w", fn, err)
	}

	err = bcrypt.CompareHashAndPassword([]byte(result.User.PasswordHash), []byte(command.Password))
	if err != nil {
		log.Info("password hashes are different", slog.Int64("user_id", result.User.ID))
		return nil, authErrors.ErrInvalidPassword
	}

	newRefreshToken := refreshToken.Generate()
	_, err = s.tokenRepo.UpdateByUserIDTx(ctx, tx, tokenCommands.UpdateByUserID{
		UserID:              result.User.ID,
		NewRefreshTokenHash: refreshToken.Hash(newRefreshToken, s.hmacSecret),
	})

	if err != nil {
		log.Error("failed to update refresh token", sloglib.Error(err))
		return nil, fmt.Errorf("%s: failed to update refresh token: %w", fn, err)
	}

	accessToken, err := s.accessTokens.Generate(tokenCommands.Generate{
		UserID: result.User.ID,
		Roles:  result.User.Roles,
	})

	if err != nil {
		log.Error("failed to generate access token", sloglib.Error(err))
		return nil, fmt.Errorf("%s: failed to generate access token: %w", fn, err)
	}

	if err := tx.Commit(); err != nil {
		log.Error("failed to commit tx", sloglib.Error(err))
		return nil, fmt.Errorf("%s: failed to commit tx: %w", fn, err)
	}

	log.Info("user successfully logged in", slog.Int64("user_id", result.User.ID))

	return &results.Login{
		Tokens: entities.TokenPair{
			AccessToken:  accessToken.Token,
			RefreshToken: newRefreshToken,
		},
	}, nil
}
