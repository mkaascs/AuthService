package jwt

import (
	"auth-service/internal/config"
	"auth-service/internal/domain/interfaces/services"
	"testing"
	"time"
)

func TestService_Parse(t *testing.T) {
	suite := services.AccessTokenTestSuite{
		New: func(t *testing.T, tokenTTL time.Duration) services.AccessToken {
			issuer := "test-auth"
			secret := []byte("LPKCsOO6CzbXjpFUGdgZ8EtQA+oULGU+faKC60aS1Qk=")
			return &service{
				secret: secret,
				config: config.AuthConfig{
					Issuer:         issuer,
					AccessTokenTTL: tokenTTL,
				},
			}
		},

		Cleanup: nil,
	}

	suite.RunParseTests(t)
}
