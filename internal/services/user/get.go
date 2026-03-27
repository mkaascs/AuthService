package user

import (
	"auth-service/internal/domain/dto/user/commands"
	"auth-service/internal/domain/dto/user/results"
	authErrors "auth-service/internal/domain/entities/errors"
	sloglib "auth-service/internal/lib/log/slog"
	"context"
	"errors"
	"fmt"
	"log/slog"
)

func (s *service) GetUser(ctx context.Context, command commands.GetById) (*results.Get, error) {
	const fn = "services.user.service.GetUser"
	log := s.log.With(slog.String("fn", fn))

	result, err := s.userRepo.GetByID(ctx, command.ID)
	if err != nil {
		if errors.Is(err, authErrors.ErrUserNotFound) {
			log.Info("failed to get user by id", sloglib.Error(err))
			return nil, authErrors.ErrUserNotFound
		}

		log.Error("failed to get user by id", sloglib.Error(err))
		return nil, fmt.Errorf("%s: failed to get user by id: %w", fn, err)
	}

	log.Info("user info received successfully", slog.Int64("user_id", command.ID))

	return result, nil
}
