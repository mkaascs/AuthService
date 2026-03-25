package auth

import (
	"auth-service/internal/domain/dto/auth/commands"
	authErrors "auth-service/internal/domain/entities/errors"
	"auth-service/internal/domain/interfaces/services"
	"context"
	"errors"
	authv1 "github.com/mkaascs/AuthProto/gen/go/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type authServer struct {
	authv1.UnimplementedAuthServer
	auth services.Auth
}

func (as *authServer) Login(ctx context.Context, request *authv1.LoginRequest) (*authv1.LoginResponse, error) {
	// TODO: validate

	result, err := as.auth.Login(ctx, commands.Login{
		Login:    request.Login,
		Password: request.Password,
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
		ExpiresIn:    int64(result.ExpiresIn.Seconds()),
	}, nil
}

func (as *authServer) Refresh(ctx context.Context, request *authv1.RefreshRequest) (*authv1.RefreshResponse, error) {
	// TODO: validate

	result, err := as.auth.Refresh(ctx, commands.Refresh{
		RefreshToken: request.RefreshToken,
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
		ExpiresIn:    int64(result.ExpiresIn.Seconds()),
	}, nil
}

func (as *authServer) Register(ctx context.Context, request *authv1.RegisterRequest) (*authv1.RegisterResponse, error) {
	// TODO: validate

	result, err := as.auth.Register(ctx, commands.Register{
		Login:    request.Login,
		Email:    request.Email,
		Password: request.Password,
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

func RegisterAuthServer(gRPC *grpc.Server, auth services.Auth) {
	authv1.RegisterAuthServer(gRPC, &authServer{auth: auth})
}
