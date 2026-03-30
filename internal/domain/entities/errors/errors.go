package errors

import "errors"

var (
	ErrUserAlreadyExists         = errors.New("user already exists")
	ErrUserNotFound              = errors.New("user not found")
	ErrInvalidPassword           = errors.New("invalid credentials")
	ErrAccessTokenExpired        = errors.New("access token expired")
	ErrInvalidRefreshToken       = errors.New("invalid refresh token")
	ErrRefreshTokenAlreadyExists = errors.New("refresh token already exists")
	ErrInvalidAccessToken        = errors.New("invalid access token")
	ErrAccessTokenRevoked        = errors.New("access token revoked")
)
