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
	"time"
)

func (s *service) Register(ctx context.Context, command commands.Register) (*results.Register, error) {
	const fn = "services.auth.service.Register"
	log := s.log.With(slog.String("fn", fn))

	tx, err := s.users.BeginTx(ctx)
	if err != nil {
		log.Error("failed to begin tx", sloglib.Error(err))
		return nil, fmt.Errorf("%s: failed to begin tx: %w", fn, err)
	}

	defer func() {
		if err := tx.Rollback(); err != nil {
			log.Error("failed to rollback tx", sloglib.Error(err))
		}
	}()

	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(command.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Error("failed to hash password", sloglib.Error(err))
		return nil, fmt.Errorf("%s: failed to hash password: %w", fn, err)
	}

	result, err := s.users.AddTx(ctx, tx, userCommands.Add{
		User: entities.User{
			Login:        command.Login,
			Email:        command.Email,
			PasswordHash: string(hashedBytes),
			Roles:        []string{entities.RoleUser},
			CreatedAt:    time.Now(),
		},
	})

	if err != nil {
		if errors.Is(err, authErrors.ErrUserAlreadyExists) {
			log.Info("failed to add user", sloglib.Error(err))
			return nil, authErrors.ErrUserAlreadyExists
		}

		log.Error("failed to add user", sloglib.Error(err))
		return nil, fmt.Errorf("%s: failed to add user: %w", fn, err)
	}

	refreshTokenHash := refreshToken.Hash(refreshToken.Generate(), s.hmacSecret)

	err = s.tokens.AddTx(ctx, tx, tokenCommands.Add{
		UserID:           result.UserID,
		RefreshTokenHash: refreshTokenHash,
		ExpiresAt:        time.Now().Add(s.config.RefreshTokenTTL),
	})

	if err != nil {
		if errors.Is(err, authErrors.ErrRefreshTokenAlreadyExists) {
			log.Warn("failed to add refresh token", sloglib.Error(err))
			return nil, authErrors.ErrRefreshTokenAlreadyExists
		}

		log.Error("failed to add refresh token", sloglib.Error(err))
		return nil, fmt.Errorf("%s: failed to add refresh token: %w", fn, err)
	}

	if err = tx.Commit(); err != nil {
		log.Error("failed to commit tx", sloglib.Error(err))
		return nil, fmt.Errorf("%s: failed to commit tx: %w", fn, err)
	}

	log.Info("user was registered successfully", slog.Int64("user_id", result.UserID))

	return &results.Register{
		UserID: result.UserID,
	}, nil
}
