package auth

import (
	"auth-service/internal/delivery/grpc/util"
	"auth-service/internal/domain/dto/auth/commands"
	authErrors "auth-service/internal/domain/entities/errors"
	"auth-service/internal/domain/interfaces/services"
	"context"
	"errors"
	authv1 "github.com/mkaascs/AuthProto/gen/go/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	"time"
)

type authServer struct {
	authv1.UnimplementedAuthServer
	service services.Auth
}

func (as *authServer) Login(ctx context.Context, request *authv1.LoginRequest) (*authv1.LoginResponse, error) {
	if err := util.ValidateLoginRequest(request); err != nil {
		return nil, err
	}

	result, err := as.service.Login(ctx, commands.Login{
		Login:    request.Login,
		Password: request.Password,
	})

	if err != nil {
		if errors.Is(err, authErrors.ErrUserNotFound) || errors.Is(err, authErrors.ErrInvalidPassword) {
			return nil, status.Error(codes.Unauthenticated, "invalid login or password")
		}

		return nil, util.MapError(err)
	}

	return &authv1.LoginResponse{
		AccessToken:  result.Tokens.AccessToken,
		RefreshToken: result.Tokens.RefreshToken,
		ExpiresIn:    int64(result.ExpiresIn / time.Second),
		User: &authv1.UserInfo{
			UserId:    result.User.ID,
			Login:     result.User.Login,
			Email:     result.User.Email,
			Roles:     result.User.Roles,
			IsAdmin:   result.User.IsAdmin(),
			CreatedAt: timestamppb.New(result.User.CreatedAt),
		},
	}, nil
}

func (as *authServer) Refresh(ctx context.Context, request *authv1.RefreshRequest) (*authv1.RefreshResponse, error) {
	result, err := as.service.Refresh(ctx, commands.Refresh{
		RefreshToken: request.RefreshToken,
	})

	if err != nil {
		return nil, util.MapError(err)
	}

	return &authv1.RefreshResponse{
		AccessToken:  result.Tokens.AccessToken,
		RefreshToken: result.Tokens.RefreshToken,
		ExpiresIn:    int64(result.ExpiresIn / time.Second),
	}, nil
}

func (as *authServer) Register(ctx context.Context, request *authv1.RegisterRequest) (*authv1.RegisterResponse, error) {
	if err := util.ValidateRegisterRequest(request); err != nil {
		return nil, err
	}

	result, err := as.service.Register(ctx, commands.Register{
		Login:    request.Login,
		Email:    request.Email,
		Password: request.Password,
	})

	if err != nil {
		return nil, util.MapError(err)
	}

	return &authv1.RegisterResponse{
		UserId: result.UserID,
	}, nil
}

func (as *authServer) Logout(ctx context.Context, request *authv1.LogoutRequest) (*authv1.LogoutResponse, error) {
	err := as.service.Logout(ctx, commands.Logout{
		RefreshToken: request.RefreshToken,
		AccessToken:  request.AccessToken,
	})

	if err != nil {
		return nil, util.MapError(err)
	}

	return &authv1.LogoutResponse{}, nil
}

func RegisterAuthServer(gRPC *grpc.Server, auth services.Auth) {
	authv1.RegisterAuthServer(gRPC, &authServer{service: auth})
}
