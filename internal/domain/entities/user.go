package entities

import "time"

var (
	RoleUser  = "user"
	RoleAdmin = "admin"
	RoleVip   = "vip"
)

type User struct {
	ID           int64
	Login        string
	Email        string
	PasswordHash string
	Roles        []string
	CreatedAt    time.Time
}

func (u *User) IsAdmin() bool {
	for _, role := range u.Roles {
		if role == RoleAdmin {
			return true
		}
	}

	return false
}
