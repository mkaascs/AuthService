package testutil

import (
	"auth-service/internal/mocks"
	"github.com/golang/mock/gomock"
	"testing"
)

type AuthMocks struct {
	UserRepo    *mocks.MockUserRepo
	TokenRepo   *mocks.MockRefreshTokenRepo
	AccessToken *mocks.MockAccessToken
	Tx          *mocks.MockTx
}

func NewAuthMocks(t *testing.T, ctrl *gomock.Controller) *AuthMocks {
	t.Helper()

	return &AuthMocks{
		UserRepo:    mocks.NewMockUserRepo(ctrl),
		TokenRepo:   mocks.NewMockRefreshTokenRepo(ctrl),
		AccessToken: mocks.NewMockAccessToken(ctrl),
		Tx:          mocks.NewMockTx(ctrl),
	}
}
