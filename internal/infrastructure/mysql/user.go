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
	"fmt"
	"log/slog"
	"strings"
)

type UserRepo struct {
	db  *sql.DB
	log *slog.Logger
}

func NewUserRepo(db *sql.DB, log *slog.Logger) repositories.UserRepo {
	return &UserRepo{db: db, log: log}
}

func (ur *UserRepo) BeginTx(ctx context.Context) (tx.Tx, error) {
	return ur.db.BeginTx(ctx, nil)
}

func (ur *UserRepo) AddTx(ctx context.Context, tx tx.Tx, command commands.Add) (*results.Add, error) {
	const fn = "infrastructure.mysql.UserRepo.AddTx"

	sqlTx, ok := tx.(*sql.Tx)
	if !ok {
		return nil, fmt.Errorf("%s: tx is not supported", fn)
	}

	userStmt, err := sqlTx.PrepareContext(ctx, `INSERT INTO users (login, email, password_hash) VALUES (?, ?, ?)`)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to prepare user statement: %w", fn, err)
	}

	defer ur.handleStmtClose(userStmt, fn)

	res, err := userStmt.ExecContext(ctx,
		command.User.Login,
		command.User.Email,
		command.User.PasswordHash,
	)

	if err != nil {
		if isDuplicateErr(err) {
			return nil, authErrors.ErrUserAlreadyExists
		}

		return nil, fmt.Errorf("%s: failed to insert user: %w", fn, err)
	}

	userID, err := res.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("%s: failed to get last insert id: %w", fn, err)
	}

	roleStmt, err := sqlTx.PrepareContext(ctx, `INSERT INTO user_roles (user_id, role) VALUES (?, ?)`)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to prepare role statement: %w", fn, err)
	}

	defer ur.handleStmtClose(roleStmt, fn)

	for _, role := range command.User.Roles {
		_, err = roleStmt.ExecContext(ctx, userID, role)
		if err != nil {
			return nil, fmt.Errorf("%s: failed to insert role %q: %w", fn, role, err)
		}
	}

	return &results.Add{UserID: userID}, nil
}

func (ur *UserRepo) GetByIDTx(ctx context.Context, tx tx.Tx, userID int64) (*results.Get, error) {
	const fn = "infrastructure.mysql.UserRepo.GetByID"

	sqlTx, ok := tx.(*sql.Tx)
	if !ok {
		return nil, fmt.Errorf("%s: tx is not supported", fn)
	}

	return ur.getUser(ctx, sqlTx, `u.id = ?`, userID)
}

func (ur *UserRepo) GetByLoginTx(ctx context.Context, tx tx.Tx, command commands.GetByLogin) (*results.Get, error) {
	const fn = "infrastructure.mysql.UserRepo.GetByLogin"

	sqlTx, ok := tx.(*sql.Tx)
	if !ok {
		return nil, fmt.Errorf("%s: tx is not supported", fn)
	}

	return ur.getUser(ctx, sqlTx, `u.login = ?`, command.Login)
}

func (ur *UserRepo) UpdateTx(ctx context.Context, tx tx.Tx, command commands.Update) (*results.Update, error) {
	const fn = "infrastructure.mysql.UserRepo.UpdateTx"

	sqlTx, ok := tx.(*sql.Tx)
	if !ok {
		return nil, fmt.Errorf("%s: tx is not supported", fn)
	}

	var setClauses []string
	var args []any

	if command.Login != nil {
		setClauses = append(setClauses, "login = ?")
		args = append(args, *command.Login)
	}

	if command.Email != nil {
		setClauses = append(setClauses, "email = ?")
		args = append(args, *command.Email)
	}

	if len(setClauses) == 0 {
		return ur.getUpdateResult(ctx, sqlTx, command.ID, fn)
	}

	args = append(args, command.ID)

	query := fmt.Sprintf(`UPDATE users SET %s WHERE id = ?`, strings.Join(setClauses, ", "))

	res, err := sqlTx.ExecContext(ctx, query, args...)
	if err != nil {
		if isDuplicateErr(err) {
			return nil, authErrors.ErrUserAlreadyExists
		}

		return nil, fmt.Errorf("%s: failed to update user: %w", fn, err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("%s: failed to get rows affected: %w", fn, err)
	}

	if affected == 0 {
		return nil, authErrors.ErrUserNotFound
	}

	return ur.getUpdateResult(ctx, sqlTx, command.ID, fn)
}

func (ur *UserRepo) UpdatePasswordTx(ctx context.Context, tx tx.Tx, command commands.UpdatePassword) error {
	const fn = "infrastructure.mysql.UserRepo.UpdatePasswordTx"

	sqlTx, ok := tx.(*sql.Tx)
	if !ok {
		return fmt.Errorf("%s: tx is not supported", fn)
	}

	res, err := sqlTx.ExecContext(ctx, `UPDATE users SET password_hash = ? WHERE id = ?`,
		command.NewPasswordHash,
		command.ID,
	)

	if err != nil {
		return fmt.Errorf("%s: failed to update password: %w", fn, err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("%s: failed to get rows affected: %w", fn, err)
	}

	if affected == 0 {
		return authErrors.ErrUserNotFound
	}

	return nil
}

func (ur *UserRepo) getUser(ctx context.Context, sqlTx *sql.Tx, whereClause string, arg any) (*results.Get, error) {
	const fn = "infrastructure.mysql.UserRepo.getUser"

	query := fmt.Sprintf(`SELECT u.id, u.login, u.email, u.password_hash, u.created_at, r.role FROM users u LEFT JOIN user_roles r ON r.user_id = u.id WHERE %s`, whereClause)

	rows, err := sqlTx.QueryContext(ctx, query, arg)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to query: %w", fn, err)
	}

	defer func(rows *sql.Rows) {
		if err := rows.Close(); err != nil {
			ur.log.With(slog.String("fn", fn)).
				Error("failed to close rows", sloglib.Error(err))
		}
	}(rows)

	var user entities.User
	found := false

	for rows.Next() {
		var role sql.NullString

		err := rows.Scan(
			&user.ID,
			&user.Login,
			&user.Email,
			&user.PasswordHash,
			&user.CreatedAt,
			&role,
		)

		if err != nil {
			return nil, fmt.Errorf("%s: failed to scan row: %w", fn, err)
		}

		found = true

		if role.Valid {
			user.Roles = append(user.Roles, role.String)
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%s: rows error: %w", fn, err)
	}

	if !found {
		return nil, authErrors.ErrUserNotFound
	}

	return &results.Get{User: user}, nil
}

func (ur *UserRepo) getUpdateResult(ctx context.Context, sqlTx *sql.Tx, userID int64, caller string) (*results.Update, error) {
	got, err := ur.getUser(ctx, sqlTx, "u.id = ?", userID)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to get updated user: %w", caller, err)
	}

	return &results.Update{User: got.User}, nil
}

func (ur *UserRepo) handleStmtClose(stmt *sql.Stmt, fn string) {
	if err := stmt.Close(); err != nil {
		ur.log.With(slog.String("fn", fn)).
			Error("failed to close statement", sloglib.Error(err))
	}
}

func isDuplicateErr(err error) bool {
	return strings.Contains(err.Error(), "1062")
}
