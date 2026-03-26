package repositories

import (
	"auth-service/internal/domain/dto/tokens/commands"
	"auth-service/internal/domain/dto/tokens/results"
	"auth-service/internal/domain/interfaces/tx"
	"context"
)

type RefreshTokenRepo interface {
	tx.Beginner
	AddTx(ctx context.Context, tx tx.Tx, command commands.Add) error
	UpdateByTokenTx(ctx context.Context, tx tx.Tx, command commands.UpdateByToken) (*results.Update, error)
	UpdateByUserIDTx(ctx context.Context, tx tx.Tx, command commands.UpdateByUserID) (*results.Update, error)
}
