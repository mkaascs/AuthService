package repositories

import (
	"auth-service/internal/domain/dto/user/commands"
	"auth-service/internal/domain/dto/user/results"
	"auth-service/internal/domain/interfaces/tx"
	"context"
)

type UserRepo interface {
	tx.Beginner
	AddTx(ctx context.Context, tx tx.Tx, command commands.Add) (*results.Add, error)
	UpdateTx(ctx context.Context, tx tx.Tx, command commands.Update) (*results.Update, error)
	UpdatePasswordTx(ctx context.Context, tx tx.Tx, command commands.UpdatePassword) error
	GetByIDTx(ctx context.Context, tx tx.Tx, userID int64) (*results.Get, error)
	GetByLoginTx(ctx context.Context, tx tx.Tx, command commands.GetByLogin) (*results.Get, error)
}
