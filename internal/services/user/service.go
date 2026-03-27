package user

import (
	"auth-service/internal/domain/interfaces/repositories"
	"auth-service/internal/domain/interfaces/services"
	"log/slog"
)

type service struct {
	userRepo repositories.UserRepo
	log      *slog.Logger
}

func New(userRepo repositories.UserRepo, log *slog.Logger) services.User {
	return &service{
		userRepo: userRepo,
		log:      log,
	}
}
