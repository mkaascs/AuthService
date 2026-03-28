package auth

import (
	"auth-service/internal/config"
	"auth-service/internal/domain/dto/auth/commands"
	tokenCommands "auth-service/internal/domain/dto/tokens/commands"
	"auth-service/internal/domain/dto/tokens/results"
	authErrors "auth-service/internal/domain/entities/errors"
	"auth-service/internal/domain/interfaces/tx"
	"auth-service/internal/lib/refreshToken"
	"auth-service/internal/testutil"
	"context"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestService_Logout(t *testing.T) {
	const TTL = 15 * time.Minute
	cfg := config.AuthConfig{
		AccessTokenTTL:  TTL,
		RefreshTokenTTL: TTL,
		Issuer:          "test-auth",
	}

	secret := []byte("LPKCsOO6CzbXjpFUGdgZ8EtQA+oULGU+faKC60aS1Qk=")

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
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mock := testutil.NewAuthMocks(t, ctrl)
			svc := newTestService(mock, secret, cfg)

			mock.TokenRepo.EXPECT().BeginTx(gomock.Any()).Return(mock.Tx, nil)

			mock.TokenRepo.EXPECT().DeleteByTokenTx(gomock.Any(), mock.Tx, gomock.Any()).
				DoAndReturn(func(ctx context.Context, tx tx.Tx, command tokenCommands.DeleteByToken) (*results.Delete, error) {
					refreshTokenHash := refreshToken.Hash(logoutCommand.RefreshToken, secret)
					require.Equal(t, refreshTokenHash, command.RefreshTokenHash)
					if test.mockErr != nil {
						return nil, test.mockErr
					}

					return &results.Delete{UserID: 1}, nil
				})

			mock.Tx.EXPECT().Rollback().Return(nil).AnyTimes()
			if test.mockErr == nil {
				mock.Tx.EXPECT().Commit().Return(nil)
			}

			err := svc.Logout(context.Background(), logoutCommand)
			if test.mockErr == nil {
				require.NoError(t, err)
				return
			}

			require.ErrorIs(t, err, test.mockErr)
		})
	}

	t.Run("context canceled", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mock := testutil.NewAuthMocks(t, ctrl)
		svc := newTestService(mock, secret, cfg)

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		mock.TokenRepo.EXPECT().BeginTx(gomock.Any()).Return(mock.Tx, nil)

		mock.TokenRepo.EXPECT().DeleteByTokenTx(gomock.Any(), mock.Tx, gomock.Any()).
			Return(nil, context.Canceled)

		mock.Tx.EXPECT().Rollback().Return(nil)

		err := svc.Logout(ctx, logoutCommand)
		require.ErrorIs(t, err, context.Canceled)
	})
}
