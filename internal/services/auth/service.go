package auth

import (
	"auth-service/internal/config"
	"auth-service/internal/domain/interfaces/repositories"
	"auth-service/internal/domain/interfaces/services"
	"log/slog"
)

type service struct {
	users        repositories.User
	tokens       repositories.RefreshToken
	accessTokens services.AccessToken
	log          *slog.Logger
	config       config.AuthConfig
	hmacSecret   []byte
}

func New(users repositories.User, tokens repositories.RefreshToken, accessTokens services.AccessToken, log *slog.Logger, config config.AuthConfig, hmacSecret []byte) services.Auth {
	return &service{
		users:        users,
		tokens:       tokens,
		accessTokens: accessTokens,
		log:          log,
		config:       config,
		hmacSecret:   hmacSecret,
	}
}
