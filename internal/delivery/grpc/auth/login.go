package auth

import (
	"auth-service/internal/domain/dto/auth/commands"
	authErrors "auth-service/internal/domain/entities/errors"
	"context"
	"errors"
	authv1 "github.com/mkaascs/AuthProto/gen/go/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *server) Login(ctx context.Context, request *authv1.LoginRequest) (*authv1.LoginResponse, error) {
	// TODO: validate

	result, err := s.auth.Login(ctx, commands.Login{
		Base: commands.Base{
			Login:    request.Login,
			Password: request.Password,
			ClientID: request.ClientId,
		},
	})

	if err != nil {
		if errors.Is(err, authErrors.ErrUserNotFound) || errors.Is(err, authErrors.ErrInvalidPassword) {
			return nil, status.Error(codes.Unauthenticated, "invalid login or password")
		}

		return nil, status.Error(codes.Internal, "internal server error")
	}

	return &authv1.LoginResponse{
		AccessToken:  result.Tokens.AccessToken,
		RefreshToken: result.Tokens.RefreshToken,
	}, nil
}
