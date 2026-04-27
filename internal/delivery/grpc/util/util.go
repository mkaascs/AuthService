package util

import (
	authErrors "auth-service/internal/domain/entities/errors"
	"context"
	"errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func MapError(err error) error {
	if err == nil {
		return nil
	}

	if errors.Is(err, authErrors.ErrInvalidRefreshToken) {
		return status.Error(codes.Unauthenticated, "invalid refresh token")
	}

	if errors.Is(err, authErrors.ErrUserAlreadyExists) {
		return status.Error(codes.AlreadyExists, "user already exists")
	}

	if errors.Is(err, authErrors.ErrInvalidAccessToken) {
		return status.Error(codes.Unauthenticated, "invalid access token")
	}

	if errors.Is(err, authErrors.ErrTooManyRequests) {
		return status.Error(codes.ResourceExhausted, "too many requests, try later")
	}

	if errors.Is(err, authErrors.ErrUserNotFound) {
		return status.Error(codes.NotFound, "user not found")
	}

	if errors.Is(err, authErrors.ErrRoleNotExist) {
		return status.Error(codes.NotFound, "role does not exist")
	}

	if errors.Is(err, authErrors.ErrInvalidPassword) {
		return status.Error(codes.Unauthenticated, "invalid password")
	}

	if errors.Is(err, context.Canceled) {
		return status.Error(codes.Canceled, "context canceled")
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return status.Error(codes.DeadlineExceeded, "deadline exceeded")
	}

	return status.Error(codes.Internal, "internal server error")
}
