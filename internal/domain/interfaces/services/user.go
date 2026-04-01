package services

import (
	"auth-service/internal/domain/dto/user/commands"
	"auth-service/internal/domain/dto/user/results"
	"context"
)

type User interface {
	GetUser(ctx context.Context, command commands.GetById) (*results.Get, error)
	GetUsers(ctx context.Context, command commands.GetUsers) (*results.GetUsers, error)
	ChangePassword(ctx context.Context, command commands.ChangePassword) error
	UpdateUser(ctx context.Context, command commands.Update) (*results.Update, error)
	AssignRole(ctx context.Context, command commands.AssignRole) error
	RevokeRole(ctx context.Context, command commands.RevokeRole) error
}
