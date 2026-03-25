package results

import "auth-service/internal/domain/entities"

type Add struct {
	UserID int64
}

type Get struct {
	User entities.User
}

type Update struct {
	User entities.User
}
