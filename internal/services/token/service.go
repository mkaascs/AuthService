package token

import (
	"auth-service/internal/domain/interfaces/services"
	"log/slog"
)

type service struct {
	accessTokens services.AccessToken
	log          *slog.Logger
}

func New(accessTokens services.AccessToken, log *slog.Logger) services.Token {
	return &service{
		accessTokens: accessTokens,
		log:          log,
	}
}
