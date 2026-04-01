package user

import (
	"auth-service/internal/domain/dto/user/commands"
	authErrors "auth-service/internal/domain/entities/errors"
	sloglib "auth-service/internal/lib/log/slog"
	"context"
	"errors"
	"fmt"
	"log/slog"
)

func (s *service) RevokeRole(ctx context.Context, command commands.RevokeRole) error {
	const fn = "services.user.service.RevokeRole"
	log := s.log.With(slog.String("fn", fn))

	tx, err := s.userRepo.BeginTx(ctx)
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

	err = s.userRepo.RemoveRoleTx(ctx, tx, command)
	if err != nil {
		const msg = "failed to remove user role"
		if errors.Is(err, authErrors.ErrUserNotFound) {
			log.Info(msg, sloglib.Error(err), slog.Int64("user_id", command.UserID))
			return authErrors.ErrUserNotFound
		}

		if errors.Is(err, authErrors.ErrRoleNotExist) {
			log.Info(msg, sloglib.Error(err), slog.Int64("user_id", command.UserID), slog.String("role", command.Role))
			return authErrors.ErrRoleNotExist
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

	log.Info("successfully removed role to user", slog.Int64("user_id", command.UserID), slog.String("removed_role", command.Role))

	return nil
}
