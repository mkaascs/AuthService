package results

import "time"

type Validate struct {
	Valid     bool
	UserID    int64
	Roles     []string
	ExpiresAt time.Time
}
