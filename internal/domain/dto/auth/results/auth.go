package results

import "auth-service/internal/domain/entities"

type Register struct {
	UserID int64
}

type Login struct {
	Tokens    entities.TokenPair
	ExpiresIn int64
}

type Refresh struct {
	Tokens    entities.TokenPair
	ExpiresIn int64
}
