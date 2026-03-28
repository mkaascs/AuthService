package user

import (
	"auth-service/internal/domain/dto/user/commands"
	authErrors "auth-service/internal/domain/entities/errors"
	sloglib "auth-service/internal/lib/log/slog"
	"context"
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"log/slog"
)

func (s *service) ChangePassword(ctx context.Context, command commands.ChangePassword) error {
	const fn = "services.user.service.ChangePassword"
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

	user, err := s.userRepo.GetByIDTx(ctx, tx, command.ID)
	if err != nil {
		const msg = "failed to get user"
		if errors.Is(err, authErrors.ErrUserNotFound) {
			log.Info(msg, sloglib.Error(err))
			return authErrors.ErrUserNotFound
		}

		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			log.Info(msg, sloglib.Error(err))
			return ctx.Err()
		}

		log.Error(msg, sloglib.Error(err))
		return fmt.Errorf("%s: %s: %w", fn, msg, err)
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.User.PasswordHash), []byte(command.OldPassword))
	if err != nil {
		log.Info("password hashes are different", slog.Int64("user_id", user.User.ID))
		return authErrors.ErrInvalidPassword
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(command.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		log.Error("failed to hash password", sloglib.Error(err))
		return fmt.Errorf("%s: failed to hash password: %w", fn, err)
	}

	err = s.userRepo.UpdatePasswordTx(ctx, tx, commands.UpdatePassword{
		ID:              command.ID,
		NewPasswordHash: string(hashedPassword),
	})

	if err != nil {
		const msg = "failed to update password"
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

	log.Info("successfully changed user password", slog.Int64("user_id", command.ID))

	return nil
}
