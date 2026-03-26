package auth

import (
	"auth-service/internal/config"
	"auth-service/internal/domain/dto/auth/commands"
	tokenCommands "auth-service/internal/domain/dto/tokens/commands"
	jwtResults "auth-service/internal/domain/dto/tokens/results"
	tokenResults "auth-service/internal/domain/dto/tokens/results"
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
	"golang.org/x/crypto/bcrypt"
	"testing"
	"time"
)

func TestService_Login(t *testing.T) {
	const TTL = 15 * time.Minute

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepo(ctrl)
	mockTokenRepo := mocks.NewMockRefreshTokenRepo(ctrl)
	mockAccessToken := mocks.NewMockAccessToken(ctrl)
	mockTx := mocks.NewMockTx(ctrl)

	cfg := config.AuthConfig{
		AccessTokenTTL:  TTL,
		RefreshTokenTTL: TTL,
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

	loginCommand := commands.Login{
		Login:    "mkaascs",
		Password: "password123",
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(loginCommand.Password), bcrypt.DefaultCost)
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		mockUserRepo.EXPECT().BeginTx(gomock.Any()).Return(mockTx, nil)

		mockUserRepo.EXPECT().GetByLogin(gomock.Any(), gomock.Any()).
			DoAndReturn(func(ctx context.Context, command userCommands.GetByLogin) (*results.Get, error) {
				require.Equal(t, loginCommand.Login, command.Login)
				return &results.Get{
					User: entities.User{
						ID:           2,
						Login:        command.Login,
						PasswordHash: string(passwordHash),
						Roles:        []string{entities.RoleAdmin},
					},
				}, nil
			})

		mockTokenRepo.EXPECT().UpdateByUserIDTx(gomock.Any(), mockTx, gomock.Any()).
			DoAndReturn(func(ctx context.Context, tx tx.Tx, command tokenCommands.UpdateByUserID) (*tokenResults.Update, error) {
				require.Equal(t, command.UserID, int64(2))
				require.NotEmpty(t, command.NewRefreshTokenHash)
				return &tokenResults.Update{UserID: 2}, nil
			})

		mockAccessToken.EXPECT().Generate(gomock.Any()).
			DoAndReturn(func(command tokenCommands.Generate) (*jwtResults.Generate, error) {
				require.Equal(t, command.UserID, int64(2))
				require.Equal(t, command.Roles, []string{entities.RoleAdmin})
				return &jwtResults.Generate{
					Token: "access-token",
				}, nil
			})

		mockTx.EXPECT().Commit().Return(nil)
		mockTx.EXPECT().Rollback().Return(nil)

		result, err := authService.Login(context.Background(), loginCommand)
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, "access-token", result.Tokens.AccessToken)
		require.NotEmpty(t, result.Tokens.RefreshToken)

		now := time.Now()
		require.WithinDuration(t, now.Add(TTL), now.Add(result.ExpiresIn), time.Second)
		require.NotNil(t, result.User)
	})

	t.Run("invalid password", func(t *testing.T) {
		userPasswordHash, err := bcrypt.GenerateFromPassword([]byte("password12345"), bcrypt.DefaultCost)
		require.NoError(t, err)

		mockUserRepo.EXPECT().BeginTx(gomock.Any()).Return(mockTx, nil)

		mockUserRepo.EXPECT().GetByLogin(gomock.Any(), gomock.Any()).
			Return(&results.Get{
				User: entities.User{
					ID:           2,
					PasswordHash: string(userPasswordHash),
				},
			}, nil)

		mockTx.EXPECT().Rollback().Return(nil)

		result, err := authService.Login(context.Background(), loginCommand)
		require.ErrorIs(t, err, authErrors.ErrInvalidPassword)
		require.Nil(t, result)
	})

	t.Run("invalid login", func(t *testing.T) {
		mockUserRepo.EXPECT().BeginTx(gomock.Any()).Return(mockTx, nil)

		mockUserRepo.EXPECT().GetByLogin(gomock.Any(), gomock.Any()).
			Return(nil, authErrors.ErrUserNotFound)

		mockTx.EXPECT().Rollback().Return(nil)

		result, err := authService.Login(context.Background(), loginCommand)
		require.ErrorIs(t, err, authErrors.ErrUserNotFound)
		require.Nil(t, result)
	})

	t.Run("fail jwt generating", func(t *testing.T) {
		mockUserRepo.EXPECT().BeginTx(gomock.Any()).Return(mockTx, nil)

		mockUserRepo.EXPECT().GetByLogin(gomock.Any(), gomock.Any()).
			Return(&results.Get{
				User: entities.User{
					ID:           2,
					Login:        loginCommand.Login,
					PasswordHash: string(passwordHash),
					Roles:        []string{entities.RoleAdmin},
				},
			}, nil)

		mockTokenRepo.EXPECT().UpdateByUserIDTx(gomock.Any(), mockTx, gomock.Any()).
			Return(&tokenResults.Update{UserID: 2}, nil)

		mockAccessToken.EXPECT().Generate(gomock.Any()).
			Return(nil, errors.New("incorrect format"))

		mockTx.EXPECT().Rollback().Return(nil)

		result, err := authService.Login(context.Background(), loginCommand)
		require.Nil(t, result)
		require.Error(t, err)
	})
}
