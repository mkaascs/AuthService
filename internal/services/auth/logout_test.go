package auth

import (
	"auth-service/internal/config"
	"auth-service/internal/domain/dto/auth/commands"
	tokenCommands "auth-service/internal/domain/dto/tokens/commands"
	"auth-service/internal/domain/dto/tokens/results"
	authErrors "auth-service/internal/domain/entities/errors"
	"auth-service/internal/domain/interfaces/tx"
	"auth-service/internal/lib/log"
	"auth-service/internal/lib/refreshToken"
	"auth-service/internal/mocks"
	"context"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestService_Logout(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepo(ctrl)
	mockTokenRepo := mocks.NewMockRefreshTokenRepo(ctrl)
	mockAccessToken := mocks.NewMockAccessToken(ctrl)
	mockTx := mocks.NewMockTx(ctrl)

	cfg := config.AuthConfig{
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 15 * time.Minute,
		Issuer:          "test-auth",
	}

	secret := []byte("LPKCsOO6CzbXjpFUGdgZ8EtQA+oULGU+faKC60aS1Qk=")
	authService := New(ServiceArgs{
		AccessTokens: mockAccessToken,
		HmacSecret:   secret,
		Config:       cfg,
	}, RepoArgs{
		UserRepo:  mockUserRepo,
		TokenRepo: mockTokenRepo},
		log.NewPlugLogger())

	logoutCommand := commands.Logout{
		RefreshToken: "refresh-token",
	}

	tests := []struct {
		name    string
		mockErr error
	}{
		{
			name:    "success",
			mockErr: nil,
		},
		{
			name:    "invalid refresh token",
			mockErr: authErrors.ErrInvalidRefreshToken,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mockTokenRepo.EXPECT().BeginTx(gomock.Any()).Return(mockTx, nil)

			mockTokenRepo.EXPECT().DeleteByTokenTx(gomock.Any(), mockTx, gomock.Any()).
				DoAndReturn(func(ctx context.Context, tx tx.Tx, command tokenCommands.DeleteByToken) (*results.Delete, error) {
					refreshTokenHash := refreshToken.Hash(logoutCommand.RefreshToken, secret)
					require.Equal(t, refreshTokenHash, command.RefreshTokenHash)
					if test.mockErr != nil {
						return nil, test.mockErr
					}

					return &results.Delete{UserID: 1}, nil
				})

			mockTx.EXPECT().Rollback().Return(nil)
			if test.mockErr == nil {
				mockTx.EXPECT().Commit().Return(nil)
			}

			err := authService.Logout(context.Background(), logoutCommand)
			if test.mockErr == nil {
				require.NoError(t, err)
				return
			}

			require.ErrorIs(t, err, test.mockErr)
		})
	}
}
