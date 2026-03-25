package commands

import "auth-service/internal/domain/entities"

type Add struct {
	User entities.User
}

type GetByLogin struct {
	Login string
}

type GetById struct {
	ID int64
}

type ChangePassword struct {
	ID          int64
	OldPassword string
	NewPassword string
}

type Update struct {
	ID    int64
	Login string
	Email string
}
