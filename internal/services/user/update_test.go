package user

import (
	"auth-service/internal/domain/dto/user/commands"
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
)

func TestService_UpdateUser(t *testing.T) {
	newLogin := "new_login"
	newEmail := "new@gmail.com"

	t.Run("success update both fields", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockUserRepo := mocks.NewMockUserRepo(ctrl)
		mockTx := mocks.NewMockTx(ctrl)
		svc := New(mockUserRepo, log.NewPlugLogger())

		mockUserRepo.EXPECT().BeginTx(gomock.Any()).Return(mockTx, nil)
		mockUserRepo.EXPECT().UpdateTx(gomock.Any(), mockTx, gomock.Any()).
			DoAndReturn(func(ctx context.Context, tx tx.Tx, command commands.Update) (*results.Update, error) {
				require.Equal(t, int64(1), command.ID)
				require.NotNil(t, command.Login)
				require.NotNil(t, command.Email)
				require.Equal(t, newLogin, *command.Login)
				require.Equal(t, newEmail, *command.Email)
				return &results.Update{
					User: entities.User{ID: 1, Login: newLogin, Email: newEmail},
				}, nil
			})

		mockTx.EXPECT().Commit().Return(nil)
		mockTx.EXPECT().Rollback().Return(nil)

		result, err := svc.UpdateUser(context.Background(), commands.Update{
			ID:    1,
			Login: &newLogin,
			Email: &newEmail,
		})

		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, newLogin, result.User.Login)
		require.Equal(t, newEmail, result.User.Email)
	})

	t.Run("success update login only", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockUserRepo := mocks.NewMockUserRepo(ctrl)
		mockTx := mocks.NewMockTx(ctrl)
		svc := New(mockUserRepo, log.NewPlugLogger())

		originalEmail := "original@gmail.com"

		mockUserRepo.EXPECT().BeginTx(gomock.Any()).Return(mockTx, nil)
		mockUserRepo.EXPECT().UpdateTx(gomock.Any(), mockTx, gomock.Any()).
			DoAndReturn(func(ctx context.Context, tx tx.Tx, command commands.Update) (*results.Update, error) {
				require.NotNil(t, command.Login)
				require.Nil(t, command.Email)
				require.Equal(t, newLogin, *command.Login)
				return &results.Update{
					User: entities.User{ID: 1, Login: newLogin, Email: originalEmail},
				}, nil
			})

		mockTx.EXPECT().Commit().Return(nil)
		mockTx.EXPECT().Rollback().Return(nil)

		result, err := svc.UpdateUser(context.Background(), commands.Update{
			ID:    1,
			Login: &newLogin,
			Email: nil,
		})

		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, newLogin, result.User.Login)
		require.Equal(t, originalEmail, result.User.Email)
	})

	t.Run("success update email only", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockUserRepo := mocks.NewMockUserRepo(ctrl)
		mockTx := mocks.NewMockTx(ctrl)
		svc := New(mockUserRepo, log.NewPlugLogger())

		originalLogin := "original_login"

		mockUserRepo.EXPECT().BeginTx(gomock.Any()).Return(mockTx, nil)
		mockUserRepo.EXPECT().UpdateTx(gomock.Any(), mockTx, gomock.Any()).
			DoAndReturn(func(ctx context.Context, tx tx.Tx, command commands.Update) (*results.Update, error) {
				require.Nil(t, command.Login)
				require.NotNil(t, command.Email)
				require.Equal(t, newEmail, *command.Email)
				return &results.Update{
					User: entities.User{ID: 1, Login: originalLogin, Email: newEmail},
				}, nil
			})

		mockTx.EXPECT().Commit().Return(nil)
		mockTx.EXPECT().Rollback().Return(nil)

		result, err := svc.UpdateUser(context.Background(), commands.Update{
			ID:    1,
			Login: nil,
			Email: &newEmail,
		})

		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, originalLogin, result.User.Login)
		require.Equal(t, newEmail, result.User.Email)
	})

	t.Run("user not found", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockUserRepo := mocks.NewMockUserRepo(ctrl)
		mockTx := mocks.NewMockTx(ctrl)
		svc := New(mockUserRepo, log.NewPlugLogger())

		mockUserRepo.EXPECT().BeginTx(gomock.Any()).Return(mockTx, nil)
		mockUserRepo.EXPECT().UpdateTx(gomock.Any(), mockTx, gomock.Any()).
			Return(nil, authErrors.ErrUserNotFound)

		mockTx.EXPECT().Rollback().Return(nil)

		result, err := svc.UpdateUser(context.Background(), commands.Update{
			ID:    1,
			Login: &newLogin,
		})

		require.Nil(t, result)
		require.ErrorIs(t, err, authErrors.ErrUserNotFound)
	})

	t.Run("context canceled", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockUserRepo := mocks.NewMockUserRepo(ctrl)
		mockTx := mocks.NewMockTx(ctrl)
		svc := New(mockUserRepo, log.NewPlugLogger())

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		mockUserRepo.EXPECT().BeginTx(gomock.Any()).Return(mockTx, nil)
		mockUserRepo.EXPECT().UpdateTx(gomock.Any(), mockTx, gomock.Any()).
			Return(nil, context.Canceled)

		mockTx.EXPECT().Rollback().Return(nil)

		result, err := svc.UpdateUser(ctx, commands.Update{
			ID:    1,
			Login: &newLogin,
		})

		require.Nil(t, result)
		require.ErrorIs(t, err, context.Canceled)
	})

	t.Run("internal error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockUserRepo := mocks.NewMockUserRepo(ctrl)
		mockTx := mocks.NewMockTx(ctrl)
		svc := New(mockUserRepo, log.NewPlugLogger())

		mockUserRepo.EXPECT().BeginTx(gomock.Any()).Return(mockTx, nil)
		mockUserRepo.EXPECT().UpdateTx(gomock.Any(), mockTx, gomock.Any()).
			Return(nil, errors.New("internal error"))

		mockTx.EXPECT().Rollback().Return(nil)

		result, err := svc.UpdateUser(context.Background(), commands.Update{
			ID:    1,
			Login: &newLogin,
		})

		require.Nil(t, result)
		require.Error(t, err)
	})
}
