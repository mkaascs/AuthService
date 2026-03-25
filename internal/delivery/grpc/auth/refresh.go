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

func (s *server) Refresh(ctx context.Context, request *authv1.RefreshRequest) (*authv1.RefreshResponse, error) {
	// TODO: validate

	result, err := s.auth.Refresh(ctx, commands.Refresh{
		RefreshToken: request.RefreshToken,
		ClientID:     request.ClientId,
	})

	if err != nil {
		if errors.Is(err, authErrors.ErrInvalidRefreshToken) {
			return nil, status.Error(codes.Unauthenticated, "invalid refresh token")
		}

		return nil, status.Error(codes.Internal, "internal server error")
	}

	return &authv1.RefreshResponse{
		AccessToken:  result.Tokens.AccessToken,
		RefreshToken: result.Tokens.RefreshToken,
	}, nil
}
