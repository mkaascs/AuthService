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

func (s *server) Register(ctx context.Context, request *authv1.RegisterRequest) (*authv1.RegisterResponse, error) {
	// TODO: validate

	result, err := s.auth.Register(ctx, commands.Register{
		Base: commands.Base{
			Login:    request.Login,
			Password: request.Password,
			ClientID: request.ClientId,
		},
	})

	if err != nil {
		if errors.Is(err, authErrors.ErrUserAlreadyExists) {
			return nil, status.Error(codes.AlreadyExists, "user with this login already exists")
		}

		return nil, status.Error(codes.Internal, "internal server error")
	}

	return &authv1.RegisterResponse{
		UserId: result.UserID,
	}, nil
}
