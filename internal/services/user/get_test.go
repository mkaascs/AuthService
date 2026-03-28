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

func TestService_GetUser(t *testing.T) {
	getCommand := commands.GetById{ID: 1}

	t.Run("success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockUserRepo := mocks.NewMockUserRepo(ctrl)
		mockTx := mocks.NewMockTx(ctrl)
		svc := New(mockUserRepo, log.NewPlugLogger())

		mockUserRepo.EXPECT().BeginTx(gomock.Any()).Return(mockTx, nil)

		mockUserRepo.EXPECT().GetByIDTx(gomock.Any(), mockTx, gomock.Any()).
			DoAndReturn(func(ctx context.Context, tx tx.Tx, id int64) (*results.Get, error) {
				require.Equal(t, getCommand.ID, id)
				return &results.Get{
					User: entities.User{
						ID:    1,
						Login: "mkaascs",
						Email: "email@gmail.com",
					},
				}, nil
			})

		result, err := svc.GetUser(context.Background(), getCommand)
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, int64(1), result.User.ID)
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

		result, err := svc.GetUser(context.Background(), getCommand)
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
		mockUserRepo.EXPECT().GetByIDTx(gomock.Any(), mockTx, gomock.Any()).
			Return(nil, context.Canceled)

		result, err := svc.GetUser(ctx, getCommand)
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
		mockUserRepo.EXPECT().GetByIDTx(gomock.Any(), mockTx, gomock.Any()).
			Return(nil, errors.New("internal error"))

		result, err := svc.GetUser(context.Background(), getCommand)
		require.Nil(t, result)
		require.Error(t, err)
	})
}
