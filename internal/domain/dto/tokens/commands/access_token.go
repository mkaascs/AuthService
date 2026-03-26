package commands

type Generate struct {
	UserID int64
	Roles  []string
}

type Parse struct {
	Token string
}
