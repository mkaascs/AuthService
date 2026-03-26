package auth

import (
	"auth-service/internal/config"
	"auth-service/internal/domain/interfaces/repositories"
	"auth-service/internal/domain/interfaces/services"
	"log/slog"
)

type RepoArgs struct {
	UserRepo  repositories.UserRepo
	TokenRepo repositories.RefreshTokenRepo
}

type ServiceArgs struct {
	AccessTokens services.AccessToken
	Config       config.AuthConfig
	HmacSecret   []byte
}

type service struct {
	userRepo     repositories.UserRepo
	tokenRepo    repositories.RefreshTokenRepo
	accessTokens services.AccessToken
	log          *slog.Logger
	config       config.AuthConfig
	hmacSecret   []byte
}

func New(serviceArgs ServiceArgs, repoArgs RepoArgs, log *slog.Logger) services.Auth {
	return &service{
		userRepo:     repoArgs.UserRepo,
		tokenRepo:    repoArgs.TokenRepo,
		accessTokens: serviceArgs.AccessTokens,
		config:       serviceArgs.Config,
		hmacSecret:   serviceArgs.HmacSecret,
		log:          log,
	}
}
