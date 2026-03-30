package results

import "time"

type Generate struct {
	Token string
}

type Parse struct {
	UserID    int64
	Roles     []string
	JTI       string
	ExpiresAt time.Time
}
