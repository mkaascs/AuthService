package user

import (
	"auth-service/internal/domain/dto/user/commands"
	"auth-service/internal/domain/dto/user/results"
	"auth-service/internal/domain/entities"
	authErrors "auth-service/internal/domain/entities/errors"
	"auth-service/internal/domain/interfaces/tx"
	"auth-service/internal/lib/log"
	"auth-service/internal/mocks"
	"auth-service/internal/testutil"
	"context"
	"errors"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestService_ChangePassword(t *testing.T) {
	oldPassword := "old-password123"
	newPassword := "new-password456"

	changePasswordCommand := commands.ChangePassword{
		ID:          1,
		OldPassword: oldPassword,
		NewPassword: newPassword,
	}

	t.Run("success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockUserRepo := mocks.NewMockUserRepo(ctrl)
		mockTx := mocks.NewMockTx(ctrl)
		svc := New(mockUserRepo, log.NewPlugLogger())

		oldPasswordHash := testutil.HashPassword(t, oldPassword)

		mockUserRepo.EXPECT().BeginTx(gomock.Any()).Return(mockTx, nil)

		mockUserRepo.EXPECT().GetByIDTx(gomock.Any(), mockTx, gomock.Any()).
			DoAndReturn(func(ctx context.Context, tx tx.Tx, id int64) (*results.Get, error) {
				require.Equal(t, changePasswordCommand.ID, id)
				return &results.Get{
					User: entities.User{
						ID:           1,
						PasswordHash: oldPasswordHash,
					},
				}, nil
			})

		mockUserRepo.EXPECT().UpdatePasswordTx(gomock.Any(), mockTx, gomock.Any()).
			DoAndReturn(func(ctx context.Context, tx tx.Tx, command commands.UpdatePassword) error {
				require.Equal(t, int64(1), command.ID)
				require.Contains(t, command.NewPasswordHash, "$2a$")
				return nil
			})

		mockTx.EXPECT().Commit().Return(nil)
		mockTx.EXPECT().Rollback().Return(nil)

		err := svc.ChangePassword(context.Background(), changePasswordCommand)
		require.NoError(t, err)
	})

	t.Run("user not found", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockUserRepo := mocks.NewMockUserRepo(ctrl)
		mockTx := mocks.NewMockTx(ctrl)
		svc := New(mockUserRepo, log.NewPlugLogger())

		mockUserRepo.EXPECT().BeginTx(gomock.Any()).Return(mockTx, nil)
		mockUserRepo.EXPECT().GetByIDTx(gomock.Any(), mockTx, gomock.Any()).
			Return(nil, authErrors.ErrUserNotFound)
		mockTx.EXPECT().Rollback().Return(nil)

		err := svc.ChangePassword(context.Background(), changePasswordCommand)
		require.ErrorIs(t, err, authErrors.ErrUserNotFound)
	})

	t.Run("invalid old password", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockUserRepo := mocks.NewMockUserRepo(ctrl)
		mockTx := mocks.NewMockTx(ctrl)
		svc := New(mockUserRepo, log.NewPlugLogger())

		wrongHash := testutil.HashPassword(t, "completely-different-password")

		mockUserRepo.EXPECT().BeginTx(gomock.Any()).Return(mockTx, nil)
		mockUserRepo.EXPECT().GetByIDTx(gomock.Any(), mockTx, gomock.Any()).
			Return(&results.Get{
				User: entities.User{
					ID:           1,
					PasswordHash: wrongHash,
				},
			}, nil)
		mockTx.EXPECT().Rollback().Return(nil)

		err := svc.ChangePassword(context.Background(), changePasswordCommand)
		require.ErrorIs(t, err, authErrors.ErrInvalidPassword)
	})

	t.Run("context canceled on get user", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockUserRepo := mocks.NewMockUserRepo(ctrl)
		mockTx := mocks.NewMockTx(ctrl)
		svc := New(mockUserRepo, log.NewPlugLogger())

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		mockUserRepo.EXPECT().BeginTx(gomock.Any()).Return(mockTx, nil)
		mockUserRepo.EXPECT().GetByIDTx(gomock.Any(), mockTx, gomock.Any()).
			Return(nil, context.Canceled)

		mockTx.EXPECT().Rollback().Return(nil)

		err := svc.ChangePassword(ctx, changePasswordCommand)
		require.ErrorIs(t, err, context.Canceled)
	})

	t.Run("context canceled on update password", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockUserRepo := mocks.NewMockUserRepo(ctrl)
		mockTx := mocks.NewMockTx(ctrl)
		svc := New(mockUserRepo, log.NewPlugLogger())

		ctx, cancel := context.WithCancel(context.Background())
		oldPasswordHash := testutil.HashPassword(t, oldPassword)

		mockUserRepo.EXPECT().BeginTx(gomock.Any()).Return(mockTx, nil)

		mockUserRepo.EXPECT().GetByIDTx(gomock.Any(), mockTx, gomock.Any()).
			DoAndReturn(func(ctx context.Context, tx tx.Tx, id int64) (*results.Get, error) {
				cancel()
				return &results.Get{
					User: entities.User{
						ID:           1,
						PasswordHash: oldPasswordHash,
					},
				}, nil
			})

		mockUserRepo.EXPECT().UpdatePasswordTx(gomock.Any(), mockTx, gomock.Any()).
			Return(context.Canceled)

		mockTx.EXPECT().Rollback().Return(nil)

		err := svc.ChangePassword(ctx, changePasswordCommand)
		require.ErrorIs(t, err, context.Canceled)
	})

	t.Run("internal error on update password", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockUserRepo := mocks.NewMockUserRepo(ctrl)
		mockTx := mocks.NewMockTx(ctrl)
		svc := New(mockUserRepo, log.NewPlugLogger())

		oldPasswordHash := testutil.HashPassword(t, oldPassword)

		mockUserRepo.EXPECT().BeginTx(gomock.Any()).Return(mockTx, nil)
		mockUserRepo.EXPECT().GetByIDTx(gomock.Any(), mockTx, gomock.Any()).
			Return(&results.Get{
				User: entities.User{
					ID:           1,
					PasswordHash: oldPasswordHash,
				},
			}, nil)

		mockUserRepo.EXPECT().UpdatePasswordTx(gomock.Any(), mockTx, gomock.Any()).
			Return(errors.New("internal error"))

		mockTx.EXPECT().Rollback().Return(nil)

		err := svc.ChangePassword(context.Background(), changePasswordCommand)
		require.Error(t, err)
	})
}
