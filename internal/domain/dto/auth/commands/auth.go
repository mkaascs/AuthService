package commands

type Register struct {
	Login    string
	Email    string
	Password string
}

type Login struct {
	Login    string
	Password string
}

type Refresh struct {
	RefreshToken string
}

type Logout struct {
	RefreshToken string
}
