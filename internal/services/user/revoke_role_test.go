package user

import (
	"auth-service/internal/domain/dto/user/commands"
	authErrors "auth-service/internal/domain/entities/errors"
	"auth-service/internal/lib/log"
	"auth-service/internal/mocks"
	"context"
	"errors"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestService_RevokeRole(t *testing.T) {
	revokeCommand := commands.RevokeRole{
		UserID: 1,
		Role:   "admin",
	}

	t.Run("success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockUserRepo := mocks.NewMockUserRepo(ctrl)
		mockTx := mocks.NewMockTx(ctrl)
		svc := New(mockUserRepo, log.NewPlugLogger())

		mockUserRepo.EXPECT().BeginTx(gomock.Any()).Return(mockTx, nil)

		mockUserRepo.EXPECT().RemoveRoleTx(gomock.Any(), mockTx, gomock.Any()).
			DoAndReturn(func(ctx context.Context, tx interface{}, command commands.RevokeRole) error {
				require.Equal(t, revokeCommand.UserID, command.UserID)
				require.Equal(t, revokeCommand.Role, command.Role)
				return nil
			})

		mockTx.EXPECT().Commit().Return(nil)
		mockTx.EXPECT().Rollback().Return(nil).AnyTimes()

		err := svc.RevokeRole(context.Background(), revokeCommand)
		require.NoError(t, err)
	})

	t.Run("user not found", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockUserRepo := mocks.NewMockUserRepo(ctrl)
		mockTx := mocks.NewMockTx(ctrl)
		svc := New(mockUserRepo, log.NewPlugLogger())

		mockUserRepo.EXPECT().BeginTx(gomock.Any()).Return(mockTx, nil)
		mockUserRepo.EXPECT().RemoveRoleTx(gomock.Any(), mockTx, gomock.Any()).
			Return(authErrors.ErrUserNotFound)

		mockTx.EXPECT().Rollback().Return(nil).AnyTimes()

		err := svc.RevokeRole(context.Background(), revokeCommand)
		require.ErrorIs(t, err, authErrors.ErrUserNotFound)
	})

	t.Run("role not found", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockUserRepo := mocks.NewMockUserRepo(ctrl)
		mockTx := mocks.NewMockTx(ctrl)
		svc := New(mockUserRepo, log.NewPlugLogger())

		mockUserRepo.EXPECT().BeginTx(gomock.Any()).Return(mockTx, nil)
		mockUserRepo.EXPECT().RemoveRoleTx(gomock.Any(), mockTx, gomock.Any()).
			Return(authErrors.ErrRoleNotExist)

		mockTx.EXPECT().Rollback().Return(nil).AnyTimes()

		err := svc.RevokeRole(context.Background(), revokeCommand)
		require.ErrorIs(t, err, authErrors.ErrRoleNotExist)
	})

	t.Run("internal error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockUserRepo := mocks.NewMockUserRepo(ctrl)
		mockTx := mocks.NewMockTx(ctrl)
		svc := New(mockUserRepo, log.NewPlugLogger())

		mockUserRepo.EXPECT().BeginTx(gomock.Any()).Return(mockTx, nil)
		mockUserRepo.EXPECT().RemoveRoleTx(gomock.Any(), mockTx, gomock.Any()).
			Return(errors.New("internal error"))

		mockTx.EXPECT().Rollback().Return(nil).AnyTimes()

		err := svc.RevokeRole(context.Background(), revokeCommand)
		require.Error(t, err)
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
		mockUserRepo.EXPECT().RemoveRoleTx(gomock.Any(), mockTx, gomock.Any()).
			Return(context.Canceled)

		mockTx.EXPECT().Rollback().Return(nil).AnyTimes()

		err := svc.RevokeRole(ctx, revokeCommand)
		require.Error(t, err)
	})
}
