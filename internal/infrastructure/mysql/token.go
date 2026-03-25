package mysql

import (
	tokenCommands "auth-service/internal/domain/dto/tokens/commands"
	"auth-service/internal/domain/dto/tokens/results"
	authErrors "auth-service/internal/domain/entities/errors"
	"auth-service/internal/domain/interfaces/repositories"
	"auth-service/internal/domain/interfaces/tx"
	sloglib "auth-service/internal/lib/log/slog"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/go-sql-driver/mysql"
	"log/slog"
)

type tokenRepo struct {
	db  *sql.DB
	log *slog.Logger
}

func (tr tokenRepo) BeginTx(ctx context.Context) (tx.Tx, error) {
	return tr.db.BeginTx(ctx, nil)
}

func (tr tokenRepo) AddTx(ctx context.Context, tx tx.Tx, command tokenCommands.Add) error {
	const fn = "infrastructure.mysql.tokenRepo.AddTx"
	log := tr.log.With(slog.String("fn", fn))

	mysqlTx, ok := tx.(*sql.Tx)
	if !ok {
		log.Error("incorrect transaction type")
		return fmt.Errorf("%s: incorrect transaction type", fn)
	}

	stmt, err := mysqlTx.PrepareContext(ctx, `INSERT INTO tokens(refresh_token_hash, client_id, expires_at, user_id) VALUES(?, ?, ?, ?)`)
	if err != nil {
		log.Error("failed to prepare statement", sloglib.Error(err))
		return fmt.Errorf("%s: failed to prepare statement", fn)
	}

	defer func() {
		if err := stmt.Close(); err != nil {
			log.Error("failed to close statement", sloglib.Error(err))
		}
	}()

	_, err = stmt.ExecContext(ctx,
		command.RefreshTokenHash,
		command.ClientID,
		command.ExpiresAt,
		command.UserID)

	if err != nil {
		var mysqlErr *mysql.MySQLError
		if errors.As(err, &mysqlErr) && mysqlErr.Number == duplicateEntryMysqlErr {
			log.Info("refresh token already exists", slog.Int64("user_id", command.UserID))
			return authErrors.ErrRefreshTokenAlreadyExists
		}

		log.Error("failed to execute statement", sloglib.Error(err))
		return fmt.Errorf("%s: failed to execute statement", fn)
	}

	return nil
}

func (tr tokenRepo) UpdateByTokenTx(ctx context.Context, tx tx.Tx, command tokenCommands.UpdateByToken) (*results.Update, error) {
	const fn = "infrastructure.mysql.tokenRepo.UpdateByToken"
	log := tr.log.With(slog.String("fn", fn))

	mysqlTx, ok := tx.(*sql.Tx)
	if !ok {
		log.Error("incorrect transaction type")
		return nil, fmt.Errorf("%s: incorrect transaction type", fn)
	}

	// TODO: add ExpiresAt in command
	return nil, nil
}

func (tr tokenRepo) UpdateByUserIDTx(ctx context.Context, tx tx.Tx, command tokenCommands.UpdateByUserID) (*results.Update, error) {
}

func NewTokenRepo(db *sql.DB, log *slog.Logger) repositories.RefreshToken {
	return &tokenRepo{db: db, log: log}
}
