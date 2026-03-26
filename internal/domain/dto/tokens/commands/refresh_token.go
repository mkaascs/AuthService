package commands

import "time"

type Add struct {
	UserID           int64
	RefreshTokenHash string
	ExpiresAt        time.Time
}

type UpdateByToken struct {
	RefreshTokenHash    string
	NewRefreshTokenHash string
}

type UpdateByUserID struct {
	UserID              int64
	NewRefreshTokenHash string
}
