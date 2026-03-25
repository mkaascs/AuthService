package results

import (
	"auth-service/internal/domain/entities"
	"time"
)

type Register struct {
	UserID int64
}

type Login struct {
	Tokens    entities.TokenPair
	ExpiresIn time.Duration
	User      entities.User
}

type Refresh struct {
	Tokens    entities.TokenPair
	ExpiresIn time.Duration
}
