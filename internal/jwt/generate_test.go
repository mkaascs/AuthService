package jwt

import (
	"auth-service/internal/config"
	"auth-service/internal/domain/interfaces/services"
	"testing"
	"time"
)

func TestService_Generate(t *testing.T) {
	suite := services.AccessTokenTestSuite{
		New: func(t *testing.T, tokenTTL time.Duration) services.AccessToken {
			issuer := "test-auth"
			secret := []byte("93RmM4BWwZ4WhhF1n7+Pl1w1nPKlVbNMPWcj6jFrV7Y=")
			return &service{
				secret: secret,
				config: config.AuthConfig{
					AccessTokenTTL: tokenTTL,
					Issuer:         issuer,
				},
			}
		},

		Cleanup: nil,
	}

	suite.RunGenerateTests(t)
}
