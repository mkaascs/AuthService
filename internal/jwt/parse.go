package jwt

import (
	"auth-service/internal/domain/dto/tokens/commands"
	"auth-service/internal/domain/dto/tokens/results"
	authErrors "auth-service/internal/domain/entities/errors"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
)

func (s *service) Parse(command commands.Parse) (*results.Parse, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(command.Token, claims, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return s.secret, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, authErrors.ErrAccessTokenExpired
		}

		return nil, authErrors.ErrInvalidAccessToken
	}

	if !token.Valid {
		return nil, authErrors.ErrInvalidAccessToken
	}

	return &results.Parse{
		UserID:    claims.UserID,
		Roles:     claims.Roles,
		ExpiresAt: claims.ExpiresAt.Time,
		JTI:       claims.JTI,
	}, nil
}
