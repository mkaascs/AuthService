package jwt

import (
	"auth-service/internal/config"
	"auth-service/internal/domain/interfaces/services"
	"encoding/base64"
	"fmt"
	"os"
)

type service struct {
	secret []byte
	config config.AuthConfig
}

func New(config config.AuthConfig) (services.AccessToken, error) {
	secret, err := base64.StdEncoding.DecodeString(os.Getenv("JWT_SECRET_BASE64"))
	if err != nil || len(secret) == 0 {
		return nil, fmt.Errorf("failed to load JWT_SECRET_BASE64")
	}

	return &service{secret: secret, config: config}, nil
}
