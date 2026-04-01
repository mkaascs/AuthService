package user

import (
	"auth-service/internal/domain/dto/user/commands"
	"auth-service/internal/domain/dto/user/results"
	sloglib "auth-service/internal/lib/log/slog"
	"context"
	"errors"
	"fmt"
	"log/slog"
)

func (s *service) GetUsers(ctx context.Context, command commands.GetUsers) (*results.GetUsers, error) {
	const fn = "services.user.service.GetUsersTx"
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

	result, err := s.userRepo.GetUsersTx(ctx, tx, command)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			log.Info("failed to get users", sloglib.Error(err))
			return nil, ctx.Err()
		}

		log.Error("failed to get users", sloglib.Error(err))
		return nil, fmt.Errorf("%s: failed to get users: %w", fn, err)
	}

	log.Info("users info received successfully", slog.Int("total", result.Total))

	return result, nil
}
