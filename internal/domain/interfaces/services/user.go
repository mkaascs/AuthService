package services

import (
	"auth-service/internal/domain/dto/user/commands"
	"auth-service/internal/domain/dto/user/results"
	"context"
)

type User interface {
	GetUser(ctx context.Context, command commands.GetById) (*results.Get, error)
	ChangePassword(ctx context.Context, command commands.ChangePassword) error
	UpdateUser(ctx context.Context, command commands.Update) (*results.Update, error)
}
