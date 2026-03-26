package jwt

import (
	"auth-service/internal/domain/dto/tokens/commands"
	"auth-service/internal/domain/dto/tokens/results"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"time"
)

type Claims struct {
	UserID int64    `json:"sub"`
	Roles  []string `json:"roles"`
	jwt.RegisteredClaims
}

func (s *service) Generate(command commands.Generate) (*results.Generate, error) {
	now := time.Now()
	claims := Claims{
		UserID: command.UserID,
		Roles:  command.Roles,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(s.config.AccessTokenTTL)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    s.config.Issuer,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(s.secret)
	if err != nil {
		return nil, fmt.Errorf("failed to sign token: %w", err)
	}

	return &results.Generate{
		Token: tokenString,
	}, nil
}
