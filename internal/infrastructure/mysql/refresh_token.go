package mysql

import (
	"auth-service/internal/domain/dto/tokens/commands"
	"auth-service/internal/domain/dto/tokens/results"
	authErrors "auth-service/internal/domain/entities/errors"
	"auth-service/internal/domain/interfaces/repositories"
	"auth-service/internal/domain/interfaces/tx"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
)

type RefreshTokenRepo struct {
	db  *sql.DB
	log *slog.Logger
}

func NewRefreshTokenRepo(db *sql.DB, log *slog.Logger) repositories.RefreshTokenRepo {
	return &RefreshTokenRepo{db: db, log: log}
}

func (rtr *RefreshTokenRepo) BeginTx(ctx context.Context) (tx.Tx, error) {
	return rtr.db.BeginTx(ctx, nil)
}

func (rtr *RefreshTokenRepo) AddTx(ctx context.Context, tx tx.Tx, command commands.Add) error {
	const fn = "infrastructure.mysql.RefreshTokenRepo.AddTx"

	sqlTx, ok := tx.(*sql.Tx)
	if !ok {
		return fmt.Errorf("%s: tx is not supported", fn)
	}

	_, err := sqlTx.ExecContext(ctx, `INSERT INTO refresh_tokens (user_id, refresh_token_hash, expires_at) VALUES (?, ?, ?)`,
		command.UserID,
		command.RefreshTokenHash,
		command.ExpiresAt,
	)

	if err != nil {
		return fmt.Errorf("%s: failed to insert refresh token: %w", fn, err)
	}

	return nil
}

func (rtr *RefreshTokenRepo) UpdateByTokenTx(ctx context.Context, tx tx.Tx, command commands.UpdateByToken) (*results.Update, error) {
	const fn = "infrastructure.mysql.RefreshTokenRepo.UpdateByTokenTx"

	sqlTx, ok := tx.(*sql.Tx)
	if !ok {
		return nil, fmt.Errorf("%s: tx is not supported", fn)
	}

	var userID int64
	err := sqlTx.QueryRowContext(ctx, `SELECT user_id FROM refresh_tokens WHERE refresh_token_hash = ?`,
		command.RefreshTokenHash,
	).Scan(&userID)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, authErrors.ErrInvalidRefreshToken
		}

		return nil, fmt.Errorf("%s: failed to get user_id: %w", fn, err)
	}

	return rtr.updateByUserIDTx(ctx, sqlTx, commands.UpdateByUserID{
		UserID:              userID,
		NewRefreshTokenHash: command.NewRefreshTokenHash,
	}, fn)
}

func (rtr *RefreshTokenRepo) UpdateByUserIDTx(ctx context.Context, tx tx.Tx, command commands.UpdateByUserID) (*results.Update, error) {
	const fn = "infrastructure.mysql.RefreshTokenRepo.UpdateByUserIDTx"

	sqlTx, ok := tx.(*sql.Tx)
	if !ok {
		return nil, fmt.Errorf("%s: tx is not supported", fn)
	}

	return rtr.updateByUserIDTx(ctx, sqlTx, command, fn)
}

func (rtr *RefreshTokenRepo) DeleteByTokenTx(ctx context.Context, tx tx.Tx, command commands.DeleteByToken) (*results.Delete, error) {
	const fn = "infrastructure.mysql.RefreshTokenRepo.DeleteByTokenTx"

	sqlTx, ok := tx.(*sql.Tx)
	if !ok {
		return nil, fmt.Errorf("%s: tx is not supported", fn)
	}

	var userID int64
	err := sqlTx.QueryRowContext(ctx, `SELECT user_id FROM refresh_tokens WHERE refresh_token_hash = ?`,
		command.RefreshTokenHash,
	).Scan(&userID)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, authErrors.ErrInvalidRefreshToken
		}

		return nil, fmt.Errorf("%s: failed to get user_id: %w", fn, err)
	}

	res, err := sqlTx.ExecContext(ctx, `DELETE FROM refresh_tokens WHERE refresh_token_hash = ?`,
		command.RefreshTokenHash,
	)

	if err != nil {
		return nil, fmt.Errorf("%s: failed to delete refresh token: %w", fn, err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("%s: failed to get rows affected: %w", fn, err)
	}

	if affected == 0 {
		return nil, authErrors.ErrInvalidRefreshToken
	}

	return &results.Delete{UserID: userID}, nil
}

func (rtr *RefreshTokenRepo) updateByUserIDTx(ctx context.Context, tx *sql.Tx, command commands.UpdateByUserID, fn string) (*results.Update, error) {
	res, err := tx.ExecContext(ctx, `UPDATE refresh_tokens SET refresh_token_hash = ? WHERE user_id = ?`,
		command.NewRefreshTokenHash,
		command.UserID,
	)

	if err != nil {
		return nil, fmt.Errorf("%s: failed to update refresh token: %w", fn, err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("%s: failed to get rows affected: %w", fn, err)
	}

	if affected == 0 {
		return nil, authErrors.ErrInvalidRefreshToken
	}

	return &results.Update{UserID: command.UserID}, nil
}
