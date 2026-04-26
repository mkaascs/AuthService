package testutil

import (
	"auth-service/internal/mocks"
	"github.com/golang/mock/gomock"
	"testing"
)

type AuthMocks struct {
	UserRepo        *mocks.MockUserRepo
	TokenRepo       *mocks.MockRefreshTokenRepo
	AccessTokenRepo *mocks.MockAccessTokenRepo
	AccessTokenSvc  *mocks.MockAccessToken
	Tx              *mocks.MockTx
	RateLimiter     *mocks.MockRateLimiter
}

func NewAuthMocks(t *testing.T, ctrl *gomock.Controller) *AuthMocks {
	t.Helper()

	return &AuthMocks{
		UserRepo:        mocks.NewMockUserRepo(ctrl),
		TokenRepo:       mocks.NewMockRefreshTokenRepo(ctrl),
		AccessTokenRepo: mocks.NewMockAccessTokenRepo(ctrl),
		AccessTokenSvc:  mocks.NewMockAccessToken(ctrl),
		Tx:              mocks.NewMockTx(ctrl),
		RateLimiter:     mocks.NewMockRateLimiter(ctrl),
	}
}
