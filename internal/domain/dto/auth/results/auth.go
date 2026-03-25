package results

import "auth-service/internal/domain/entities"

type Register struct {
	UserID int64
}

type Login struct {
	Tokens entities.TokenPair
}

type Refresh struct {
	Tokens entities.TokenPair
}
