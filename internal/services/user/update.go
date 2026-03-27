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

func (s *service) UpdateUser(ctx context.Context, command commands.Update) (*results.Update, error) {
	const fn = "services.user.service.UpdateUser"
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

	result, err := s.userRepo.UpdateTx(ctx, tx, command)
	if err != nil {
		if errors.Is(err, authErrors.ErrUserNotFound) {
			log.Info("failed to update user", sloglib.Error(err))
			return nil, authErrors.ErrUserNotFound
		}

		log.Error("failed to update user", sloglib.Error(err))
		return nil, fmt.Errorf("%s: failed to update user: %w", fn, err)
	}

	return result, nil
}
