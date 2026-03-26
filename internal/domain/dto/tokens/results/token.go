package results

import "time"

type Validate struct {
	UserID    int64
	Roles     []string
	ExpiresAt time.Time
}
