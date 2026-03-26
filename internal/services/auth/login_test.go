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
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
	"testing"
	"time"
)

func TestService_Login(t *testing.T) {
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

	loginCommand := commands.Login{
		Login:    "mkaascs",
		Password: "password123",
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(loginCommand.Password), bcrypt.DefaultCost)
	assert.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		mockUserRepo.EXPECT().BeginTx(gomock.Any()).Return(mockTx, nil)

		mockUserRepo.EXPECT().GetByLogin(gomock.Any(), gomock.Any()).
			DoAndReturn(func(ctx context.Context, command userCommands.GetByLogin) (*results.Get, error) {
				assert.Equal(t, loginCommand.Login, command.Login)
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
				assert.Equal(t, command.UserID, int64(2))
				assert.NotEmpty(t, command.NewRefreshTokenHash)
				return &tokenResults.Update{UserID: 2}, nil
			})

		mockAccessToken.EXPECT().Generate(gomock.Any()).
			DoAndReturn(func(command tokenCommands.Generate) (*jwtResults.Generate, error) {
				assert.Equal(t, command.UserID, int64(2))
				assert.Equal(t, command.Roles, []string{entities.RoleAdmin})
				return &jwtResults.Generate{
					Token: "access-token",
				}, nil
			})

		mockTx.EXPECT().Commit().Return(nil)
		mockTx.EXPECT().Rollback().Return(nil)

		result, err := authService.Login(context.Background(), loginCommand)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "access-token", result.Tokens.AccessToken)
		assert.NotEmpty(t, result.Tokens.RefreshToken)
	})

	t.Run("invalid password", func(t *testing.T) {
		userPasswordHash, err := bcrypt.GenerateFromPassword([]byte("password12345"), bcrypt.DefaultCost)
		assert.NoError(t, err)

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
		assert.ErrorIs(t, err, authErrors.ErrInvalidPassword)
		assert.Nil(t, result)
	})

	t.Run("invalid login", func(t *testing.T) {
		mockUserRepo.EXPECT().BeginTx(gomock.Any()).Return(mockTx, nil)

		mockUserRepo.EXPECT().GetByLogin(gomock.Any(), gomock.Any()).
			Return(nil, authErrors.ErrUserNotFound)

		mockTx.EXPECT().Rollback().Return(nil)

		result, err := authService.Login(context.Background(), loginCommand)
		assert.ErrorIs(t, err, authErrors.ErrUserNotFound)
		assert.Nil(t, result)
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
		assert.Nil(t, result)
		assert.Error(t, err)
	})
}
