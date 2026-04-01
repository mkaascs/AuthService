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

func (ur *UserRepo) GetUsersTx(ctx context.Context, tx tx.Tx, command commands.GetUsers) (*results.GetUsers, error) {
	const fn = "infrastructure.mysql.UserRepo.GetUsersTx"

	sqlTx, ok := tx.(*sql.Tx)
	if !ok {
		return nil, fmt.Errorf("%s: tx is not supported", fn)
	}

	offset := (command.Page - 1) * command.Limit

	var args []any
	roleFilter := ""
	if command.Role != nil && *command.Role != "" {
		roleFilter = "WHERE r.role = ?"
		args = append(args, *command.Role)
	}

	countQuery := fmt.Sprintf(`
		SELECT COUNT(DISTINCT u.id) 
		FROM users u
		LEFT JOIN user_roles r ON r.user_id = u.id
		%s
	`, roleFilter)

	var total int
	if err := sqlTx.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("%s: failed to get users count: %w", fn, err)
	}

	if total == 0 {
		return &results.GetUsers{
			Users: []entities.User{},
			Total: 0,
		}, nil
	}

	query := fmt.Sprintf(`
		SELECT DISTINCT u.id, u.login, u.email, u.password_hash, u.created_at, r.role 
		FROM users u
		LEFT JOIN user_roles r ON r.user_id = u.id
		%s
		ORDER BY u.id DESC 
		LIMIT ? OFFSET ?
	`, roleFilter)

	args = append(args, command.Limit, offset)
	rows, err := sqlTx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to get users: %w", fn, err)
	}

	defer func(rows *sql.Rows) {
		if err := rows.Close(); err != nil {
			ur.log.Error("failed to close rows", sloglib.Error(err), slog.String("fn", fn))
		}
	}(rows)

	usersMap := make(map[int64]*entities.User)
	var userOrder []int64

	for rows.Next() {
		var user entities.User
		var role sql.NullString

		if err := rows.Scan(
			&user.ID,
			&user.Login,
			&user.Email,
			&user.PasswordHash,
			&user.CreatedAt,
			&role,
		); err != nil {
			return nil, fmt.Errorf("%s: failed to scan row: %w", fn, err)
		}

		if _, exists := usersMap[user.ID]; !exists {
			userOrder = append(userOrder, user.ID)
			usersMap[user.ID] = &user
		}

		if role.Valid {
			usersMap[user.ID].Roles = append(usersMap[user.ID].Roles, role.String)
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%s: failed to scan rows: %w", fn, err)
	}

	users := make([]entities.User, 0, len(userOrder))
	for _, id := range userOrder {
		users = append(users, *usersMap[id])
	}

	return &results.GetUsers{
		Users: users,
		Total: total,
	}, nil
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

func (ur *UserRepo) AddRoleTx(ctx context.Context, tx tx.Tx, command commands.AssignRole) error {
	const fn = "infrastructure.mysql.UserRepo.AddRoleTx"

	sqlTx, ok := tx.(*sql.Tx)
	if !ok {
		return fmt.Errorf("%s: tx is not supported", fn)
	}

	_, err := sqlTx.ExecContext(ctx, `INSERT INTO user_roles (user_id, role) VALUES (?, ?)`,
		command.UserID,
		command.Role)

	if err != nil {
		if isDuplicateErr(err) {
			return nil
		}

		return fmt.Errorf("%s: failed to insert user role: %w", fn, err)
	}

	return nil
}

func (ur *UserRepo) RemoveRoleTx(ctx context.Context, tx tx.Tx, command commands.RevokeRole) error {
	const fn = "infrastructure.mysql.UserRepo.RemoveRoleTx"

	sqlTx, ok := tx.(*sql.Tx)
	if !ok {
		return fmt.Errorf("%s: tx is not supported", fn)
	}

	res, err := sqlTx.ExecContext(ctx, `DELETE FROM user_roles WHERE user_id = ? AND role = ?`,
		command.UserID,
		command.Role)

	if err != nil {
		return fmt.Errorf("%s: failed to remove user role: %w", fn, err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("%s: failed to get rows affected: %w", fn, err)
	}

	if affected == 0 {
		return authErrors.ErrRoleNotExist
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
