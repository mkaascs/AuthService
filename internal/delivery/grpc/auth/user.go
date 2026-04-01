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

func (us *userServer) GetUsers(ctx context.Context, request *authv1.GetUsersRequest) (*authv1.GetUsersResponse, error) {
	if err := util.ValidateGetUsersRequest(request); err != nil {
		return nil, err
	}

	result, err := us.users.GetUsers(ctx, commands.GetUsers{
		Role:  request.Role,
		Page:  int(request.Page),
		Limit: int(request.Limit),
	})

	if err != nil {
		return nil, util.MapError(err)
	}

	return &authv1.GetUsersResponse{
		Users: usersDomainToPbModels(result.Users),
		Total: int32(result.Total),
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

func (us *userServer) AssignRole(ctx context.Context, request *authv1.AssignRoleRequest) (*authv1.AssignRoleResponse, error) {
	if err := util.ValidateAssignRoleRequest(request); err != nil {
		return nil, err
	}

	err := us.users.AssignRole(ctx, commands.AssignRole{
		UserID: request.UserId,
		Role:   request.Role,
	})

	if err != nil {
		return nil, util.MapError(err)
	}

	return &authv1.AssignRoleResponse{}, nil
}

func (us *userServer) RevokeRole(ctx context.Context, request *authv1.RevokeRoleRequest) (*authv1.RevokeRoleResponse, error) {
	if err := util.ValidateRevokeRoleRequest(request); err != nil {
		return nil, err
	}

	err := us.users.RevokeRole(ctx, commands.RevokeRole{
		UserID: request.UserId,
		Role:   request.Role,
	})

	if err != nil {
		return nil, util.MapError(err)
	}

	return &authv1.RevokeRoleResponse{}, nil
}

func RegisterUserServer(gRPC *grpc.Server, users services.User) {
	authv1.RegisterUserServer(gRPC, &userServer{users: users})
}

func usersDomainToPbModels(users []entities.User) []*authv1.UserInfo {
	result := make([]*authv1.UserInfo, len(users))
	for index, user := range users {
		result[index] = userDomainToPbModel(user)
	}

	return result
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
