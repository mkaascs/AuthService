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

		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("failed to parse jwt claims: token is not valid")
	}

	return &results.Parse{
		UserID: claims.UserID,
		Roles:  claims.Roles,
	}, nil
}
