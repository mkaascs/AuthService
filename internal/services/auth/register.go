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

	tx, err := s.userRepo.BeginTx(ctx)
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

	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(command.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Error("failed to hash password", sloglib.Error(err))
		return nil, fmt.Errorf("%s: failed to hash password: %w", fn, err)
	}

	result, err := s.userRepo.AddTx(ctx, tx, userCommands.Add{
		User: entities.User{
			Login:        command.Login,
			Email:        command.Email,
			PasswordHash: string(hashedBytes),
			Roles:        []string{entities.RoleUser},
			CreatedAt:    time.Now(),
		},
	})

	if err != nil {
		const msg = "failed to add user"
		if errors.Is(err, authErrors.ErrUserAlreadyExists) {
			log.Info(msg, sloglib.Error(err))
			return nil, authErrors.ErrUserAlreadyExists
		}

		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			log.Info(msg, sloglib.Error(err))
			return nil, ctx.Err()
		}

		log.Error(msg, sloglib.Error(err))
		return nil, fmt.Errorf("%s: %s: %w", fn, msg, err)
	}

	refreshTokenHash := refreshToken.Hash(refreshToken.Generate(), s.hmacSecret)

	err = s.tokenRepo.AddTx(ctx, tx, tokenCommands.Add{
		UserID:           result.UserID,
		RefreshTokenHash: refreshTokenHash,
		ExpiresAt:        time.Now().Add(s.config.RefreshTokenTTL),
	})

	if err != nil {
		const msg = "failed to add refresh token"
		if errors.Is(err, authErrors.ErrRefreshTokenAlreadyExists) {
			log.Warn(msg, sloglib.Error(err))
			return nil, authErrors.ErrRefreshTokenAlreadyExists
		}

		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			log.Info(msg, sloglib.Error(err))
			return nil, ctx.Err()
		}

		log.Error(msg, sloglib.Error(err))
		return nil, fmt.Errorf("%s: %s: %w", fn, msg, err)
	}

	if err = tx.Commit(); err != nil {
		log.Error("failed to commit tx", sloglib.Error(err))
		return nil, fmt.Errorf("%s: failed to commit tx: %w", fn, err)
	}

	committed = true

	log.Info("user was registered successfully", slog.Int64("user_id", result.UserID))

	return &results.Register{
		UserID: result.UserID,
	}, nil
}
