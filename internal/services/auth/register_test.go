package auth

import (
	"auth-service/internal/config"
	"auth-service/internal/domain/dto/auth/commands"
	tokenCommands "auth-service/internal/domain/dto/tokens/commands"
	userCommands "auth-service/internal/domain/dto/user/commands"
	"auth-service/internal/domain/dto/user/results"
	"auth-service/internal/domain/entities"
	authErrors "auth-service/internal/domain/entities/errors"
	"auth-service/internal/domain/interfaces/tx"
	"auth-service/internal/lib/log"
	"auth-service/internal/mocks"
	"context"
	"errors"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestService_Register(t *testing.T) {
	bcryptPrefix := "$2a$"

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

	registerCommand := commands.Register{
		Login:    "mkaascs",
		Email:    "email@gmail.com",
		Password: "password123",
	}

	t.Run("success", func(t *testing.T) {
		mockUserRepo.EXPECT().BeginTx(gomock.Any()).Return(mockTx, nil)

		mockUserRepo.EXPECT().AddTx(gomock.Any(), mockTx, gomock.Any()).
			DoAndReturn(func(ctx context.Context, tx tx.Tx, command userCommands.Add) (*results.Add, error) {
				require.Equal(t, command.User.Login, registerCommand.Login)
				require.Contains(t, command.User.PasswordHash, bcryptPrefix)
				require.Equal(t, command.User.Roles, []string{entities.RoleUser})
				require.Equal(t, command.User.Email, registerCommand.Email)
				return &results.Add{UserID: 1}, nil
			})

		expectedExpiresAt := time.Now().Add(cfg.RefreshTokenTTL)
		mockTokenRepo.EXPECT().AddTx(gomock.Any(), mockTx, gomock.Any()).
			DoAndReturn(func(ctx context.Context, tx tx.Tx, command tokenCommands.Add) error {
				require.Equal(t, command.UserID, int64(1))
				require.WithinDuration(t, expectedExpiresAt, command.ExpiresAt, time.Second)
				return nil
			})

		mockTx.EXPECT().Rollback().Return(nil)
		mockTx.EXPECT().Commit().Return(nil)

		result, err := authService.Register(context.Background(), registerCommand)
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, result.UserID, int64(1))
	})

	t.Run("user already exists", func(t *testing.T) {
		mockUserRepo.EXPECT().BeginTx(gomock.Any()).Return(mockTx, nil)

		mockUserRepo.EXPECT().AddTx(gomock.Any(), mockTx, gomock.Any()).
			Return(nil, authErrors.ErrUserAlreadyExists)

		mockTx.EXPECT().Rollback().Return(nil)

		result, err := authService.Register(context.Background(), registerCommand)
		require.ErrorIs(t, err, authErrors.ErrUserAlreadyExists)
		require.Nil(t, result)
	})

	t.Run("db internal error", func(t *testing.T) {
		mockUserRepo.EXPECT().BeginTx(gomock.Any()).Return(mockTx, nil)

		mockUserRepo.EXPECT().AddTx(gomock.Any(), mockTx, gomock.Any()).
			Return(&results.Add{UserID: 1}, nil)

		mockTokenRepo.EXPECT().AddTx(gomock.Any(), mockTx, gomock.Any()).
			Return(errors.New("failed to execute db statement"))

		mockTx.EXPECT().Rollback().Return(nil)

		result, err := authService.Register(context.Background(), registerCommand)
		require.Error(t, err)
		require.Nil(t, result)
	})
}
