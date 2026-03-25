package jwt

import (
	"auth-service/internal/config"
	"auth-service/internal/domain/interfaces/services"
	"fmt"
	"github.com/joho/godotenv"
	"os"
)

type service struct {
	secret []byte
	config config.AuthConfig
}

func New(config config.AuthConfig) (services.AccessToken, error) {
	if err := godotenv.Load(); err != nil {
		return nil, fmt.Errorf("failed to load .env file: %w", err)
	}

	secret := []byte(os.Getenv("JWT_SECRET_BASE64"))
	if secret == nil {
		return nil, fmt.Errorf("failed to load JWT_SECRET_BASE64")
	}

	return &service{secret: secret, config: config}, nil
}
