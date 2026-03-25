package mysql

import (
	"auth-service/internal/domain/dto/user/commands"
	"auth-service/internal/domain/dto/user/results"
	"auth-service/internal/domain/entities"
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

type userRepo struct {
	db  *sql.DB
	log *slog.Logger
}

const (
	duplicateEntryMysqlErr = 1062
)

func (ur *userRepo) BeginTx(ctx context.Context) (tx.Tx, error) {
	return ur.db.BeginTx(ctx, nil)
}

func (ur *userRepo) AddTx(ctx context.Context, tx tx.Tx, command commands.Add) (*results.Add, error) {
	const fn = "infrastructure.mysql.userRepo.AddTx"
	log := ur.log.With(slog.String("fn", fn))

	mysqlTx, ok := tx.(*sql.Tx)
	if !ok {
		log.Error("incorrect transaction type")
		return nil, fmt.Errorf("%s: incorrect transaction type", fn)
	}

	stmt, err := mysqlTx.PrepareContext(ctx, `INSERT INTO users(login, password_hash, role, client_id) VALUES(?,?,?,?)`)
	if err != nil {
		log.Error("failed to prepare statement", sloglib.Error(err))
		return nil, fmt.Errorf("%s: failed to prepare statement: %w", fn, err)
	}

	defer func() {
		if err := stmt.Close(); err != nil {
			log.Error("failed to close statement", sloglib.Error(err))
		}
	}()

	result, err := stmt.ExecContext(ctx,
		command.Login,
		command.PasswordHash,
		command.Role,
		command.ClientID)

	if err != nil {
		var mysqlErr *mysql.MySQLError
		if errors.As(err, &mysqlErr) && mysqlErr.Number == duplicateEntryMysqlErr {
			log.Info("user already exists", slog.String("username", command.Login))
			return nil, authErrors.ErrUserAlreadyExists
		}

		log.Error("failed to execute statement", sloglib.Error(err))
		return nil, fmt.Errorf("%s: failed to execute statement: %w", fn, err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		log.Error("failed to fetch last insert id", sloglib.Error(err))
		return nil, fmt.Errorf("%s: failed to fetch last insert id: %w", fn, err)
	}

	return &results.Add{
		UserID: id,
	}, nil
}

func (ur *userRepo) GetByID(ctx context.Context, userID int64) (*results.Get, error) {
	const fn = "infrastructure.mysql.userRepo.GetByID"
	log := ur.log.With(slog.String("fn", fn))

	stmt, err := ur.db.PrepareContext(ctx, `SELECT id, login, password_hash, role, client_id FROM users WHERE id = ?`)
	if err != nil {
		log.Error("failed to prepare statement", sloglib.Error(err))
		return nil, fmt.Errorf("%s: failed to prepare statement: %w", fn, err)
	}

	defer func() {
		if err := stmt.Close(); err != nil {
			log.Error("failed to close statement", sloglib.Error(err))
		}
	}()

	user := entities.User{}
	err = stmt.QueryRowContext(ctx, userID).
		Scan(&user.ID, &user.Login, &user.PasswordHash, &user.Role, &user.ClientID)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			log.Info("user does not exist", slog.Int64("user_id", userID))
			return nil, authErrors.ErrUserNotFound
		}

		log.Error("failed to query user", sloglib.Error(err))
		return nil, fmt.Errorf("%s: failed to query user: %w", fn, err)
	}

	return &results.Get{
		User: user,
	}, nil
}

func (ur *userRepo) GetByLogin(ctx context.Context, command commands.GetByLogin) (*results.Get, error) {
	const fn = "infrastructure.mysql.userRepo.GetByLogin"
	log := ur.log.With(slog.String("fn", fn))

	stmt, err := ur.db.PrepareContext(ctx, `SELECT id, password_hash, role FROM users WHERE login = ? AND client_id = ?`)
	if err != nil {
		log.Error("failed to prepare statement", sloglib.Error(err))
		return nil, fmt.Errorf("%s: failed to prepare statement: %w", fn, err)
	}

	defer func() {
		if err := stmt.Close(); err != nil {
			log.Error("failed to close statement", sloglib.Error(err))
		}
	}()

	user := entities.User{
		Login:    command.Login,
		ClientID: command.ClientID,
	}

	err = stmt.QueryRowContext(ctx, command.Login, command.ClientID).
		Scan(&user.ID, &user.PasswordHash, &user.Role)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			log.Info("user does not exist", slog.Int64("user_id", user.ID))
			return nil, authErrors.ErrUserNotFound
		}

		log.Error("failed to query user", sloglib.Error(err))
		return nil, fmt.Errorf("%s: failed to query user: %w", fn, err)
	}

	return &results.Get{
		User: user,
	}, nil
}

func NewUserRepo(db *sql.DB, log *slog.Logger) repositories.User {
	return &userRepo{db: db, log: log}
}
