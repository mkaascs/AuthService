package commands

import "time"

type Generate struct {
	UserID int64
	Roles  []string
}

type Parse struct {
	Token string
}

type Revoke struct {
	JTI string
	TTL time.Duration
}
