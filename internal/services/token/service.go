package token

import (
	"auth-service/internal/domain/interfaces/repositories"
	"auth-service/internal/domain/interfaces/services"
	"log/slog"
)

type service struct {
	accessTokenSvc  services.AccessToken
	accessTokenRepo repositories.AccessTokenRepo
	log             *slog.Logger
}

func New(accessTokenSvc services.AccessToken, accessTokenRepo repositories.AccessTokenRepo, log *slog.Logger) services.Token {
	return &service{
		accessTokenSvc:  accessTokenSvc,
		accessTokenRepo: accessTokenRepo,
		log:             log,
	}
}
