package util

import (
	authv1 "github.com/mkaascs/AuthProto/gen/go/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"regexp"
	"strings"
)

var (
	loginRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]{3,64}$`)
	emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
)

func validateLogin(login string) error {
	if strings.TrimSpace(login) == "" {
		return status.Error(codes.InvalidArgument, "login is required")
	}

	if !loginRegex.MatchString(login) {
		return status.Error(codes.InvalidArgument, "login must be 3-64 characters, alphanumeric, underscore or hyphen only")
	}

	return nil
}

func validatePassword(password string) error {
	if password == "" {
		return status.Error(codes.InvalidArgument, "password is required")
	}

	if len(password) < 6 {
		return status.Error(codes.InvalidArgument, "password must be at least 6 characters")
	}

	if len(password) > 128 {
		return status.Error(codes.InvalidArgument, "password must not exceed 128 characters")
	}

	return nil
}

func validateEmail(email string) error {
	if strings.TrimSpace(email) == "" {
		return status.Error(codes.InvalidArgument, "email is required")
	}

	if !emailRegex.MatchString(email) {
		return status.Error(codes.InvalidArgument, "email format is invalid")
	}

	if len(email) > 254 {
		return status.Error(codes.InvalidArgument, "email must not exceed 254 characters")
	}

	return nil
}

func validateUserID(userID int64) error {
	if userID <= 0 {
		return status.Error(codes.InvalidArgument, "user_id must be more than 0")
	}

	return nil
}

func ValidateLoginRequest(req *authv1.LoginRequest) error {
	if err := validateLogin(req.Login); err != nil {
		return err
	}

	if err := validatePassword(req.Password); err != nil {
		return err
	}

	return nil
}

func ValidateRegisterRequest(req *authv1.RegisterRequest) error {
	if err := validateLogin(req.Login); err != nil {
		return err
	}

	if err := validateEmail(req.Email); err != nil {
		return err
	}

	if err := validatePassword(req.Password); err != nil {
		return err
	}

	return nil
}

func ValidateUserID(userID int64) error {
	if err := validateUserID(userID); err != nil {
		return err
	}

	return nil
}

func ValidateChangePasswordRequest(req *authv1.ChangePasswordRequest) error {
	if err := validateUserID(req.UserId); err != nil {
		return err
	}

	if err := validatePassword(req.NewPassword); err != nil {
		return err
	}

	return nil
}

func ValidateAssignRoleRequest(req *authv1.AssignRoleRequest) error {
	if err := validateUserID(req.UserId); err != nil {
		return err
	}

	if strings.TrimSpace(req.Role) == "" {
		return status.Error(codes.InvalidArgument, "role is required")
	}

	return nil
}

func ValidateRevokeRoleRequest(req *authv1.RevokeRoleRequest) error {
	return ValidateAssignRoleRequest(&authv1.AssignRoleRequest{
		UserId: req.UserId,
		Role:   req.Role,
	})
}

func ValidateGetUsersRequest(req *authv1.GetUsersRequest) error {
	if req.Limit <= 0 {
		return status.Error(codes.InvalidArgument, "limit is required and must be greater than 0")
	}

	if req.Page <= 0 {
		return status.Error(codes.InvalidArgument, "page is required and must be greater than 0")
	}

	return nil
}
