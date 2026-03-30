package auth

import (
	"auth-service/internal/delivery/grpc/util"
	"auth-service/internal/domain/dto/user/commands"
	"auth-service/internal/domain/entities"
	"auth-service/internal/domain/interfaces/services"
	"context"
	authv1 "github.com/mkaascs/AuthProto/gen/go/auth"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type userServer struct {
	authv1.UnimplementedUserServer
	users services.User
}

func (us *userServer) GetUser(ctx context.Context, request *authv1.GetUserRequest) (*authv1.GetUserResponse, error) {
	if err := util.ValidateUserID(request.UserId); err != nil {
		return nil, err
	}

	result, err := us.users.GetUser(ctx, commands.GetById{
		ID: request.UserId,
	})

	if err != nil {
		return nil, util.MapError(err)
	}

	return &authv1.GetUserResponse{
		User: userDomainToPbModel(result.User),
	}, nil
}

func (us *userServer) ChangePassword(ctx context.Context, request *authv1.ChangePasswordRequest) (*authv1.ChangePasswordResponse, error) {
	if err := util.ValidateChangePasswordRequest(request); err != nil {
		return nil, err
	}

	err := us.users.ChangePassword(ctx, commands.ChangePassword{
		ID:          request.UserId,
		OldPassword: request.OldPassword,
		NewPassword: request.NewPassword,
	})

	if err != nil {
		return nil, util.MapError(err)
	}

	return &authv1.ChangePasswordResponse{}, nil
}

func (us *userServer) UpdateUser(ctx context.Context, request *authv1.UpdateUserRequest) (*authv1.UpdateUserResponse, error) {
	if err := util.ValidateUserID(request.UserId); err != nil {
		return nil, err
	}

	result, err := us.users.UpdateUser(ctx, commands.Update{
		ID:    request.UserId,
		Login: request.Login,
		Email: request.Email,
	})

	if err != nil {
		return nil, util.MapError(err)
	}

	return &authv1.UpdateUserResponse{
		User: userDomainToPbModel(result.User),
	}, nil
}

func RegisterUserServer(gRPC *grpc.Server, users services.User) {
	authv1.RegisterUserServer(gRPC, &userServer{users: users})
}

func userDomainToPbModel(user entities.User) *authv1.UserInfo {
	return &authv1.UserInfo{
		UserId:    user.ID,
		Login:     user.Login,
		Email:     user.Email,
		Roles:     user.Roles,
		IsAdmin:   user.IsAdmin(),
		CreatedAt: timestamppb.New(user.CreatedAt),
	}
}
