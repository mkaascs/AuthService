package auth

import (
	"auth-service/internal/config"
	"auth-service/internal/domain/interfaces/repositories"
	"auth-service/internal/domain/interfaces/services"
	"log/slog"
)

type RepoArgs struct {
	UserRepo        repositories.UserRepo
	TokenRepo       repositories.RefreshTokenRepo
	AccessTokenRepo repositories.AccessTokenRepo
}

type ServiceArgs struct {
	AccessTokenSvc services.AccessToken
	Config         config.AuthConfig
	HmacSecret     []byte
}

type service struct {
	userRepo        repositories.UserRepo
	tokenRepo       repositories.RefreshTokenRepo
	accessTokenRepo repositories.AccessTokenRepo
	accessTokenSvc  services.AccessToken
	log             *slog.Logger
	config          config.AuthConfig
	hmacSecret      []byte
}

func New(serviceArgs ServiceArgs, repoArgs RepoArgs, log *slog.Logger) services.Auth {
	return &service{
		userRepo:        repoArgs.UserRepo,
		tokenRepo:       repoArgs.TokenRepo,
		accessTokenRepo: repoArgs.AccessTokenRepo,
		accessTokenSvc:  serviceArgs.AccessTokenSvc,
		config:          serviceArgs.Config,
		hmacSecret:      serviceArgs.HmacSecret,
		log:             log,
	}
}
