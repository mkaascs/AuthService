package user

import (
	"auth-service/internal/domain/dto/user/commands"
	"auth-service/internal/domain/dto/user/results"
	"auth-service/internal/domain/entities"
	"auth-service/internal/lib/log"
	"auth-service/internal/mocks"
	"context"
	"errors"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	"testing"
)

func stringPtr(str string) *string { return &str }

func TestService_GetUsers(t *testing.T) {
	t.Run("success without role filter", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockUserRepo := mocks.NewMockUserRepo(ctrl)
		mockTx := mocks.NewMockTx(ctrl)
		svc := New(mockUserRepo, log.NewPlugLogger())

		expectedUsers := []entities.User{
			{ID: 1, Login: "mkaascs", Roles: []string{entities.RoleAdmin}},
			{ID: 2, Login: "john", Roles: []string{entities.RoleUser}},
			{ID: 3, Login: "jane", Roles: []string{"hr"}},
		}

		mockUserRepo.EXPECT().BeginTx(gomock.Any()).Return(mockTx, nil)
		mockTx.EXPECT().Rollback().Return(nil)

		mockUserRepo.EXPECT().GetUsers(gomock.Any(), mockTx, gomock.Any()).
			DoAndReturn(func(ctx context.Context, tx interface{}, command commands.GetUsers) (*results.GetUsers, error) {
				require.Nil(t, command.Role)
				require.Equal(t, 1, command.Page)
				require.Equal(t, 10, command.Limit)
				return &results.GetUsers{Users: expectedUsers, Total: len(expectedUsers)}, nil
			})

		result, err := svc.GetUsers(context.Background(), commands.GetUsers{
			Role: nil, Page: 1, Limit: 10,
		})

		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, len(expectedUsers), result.Total)
		require.Len(t, result.Users, len(expectedUsers))
	})

	t.Run("success with role filter", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockUserRepo := mocks.NewMockUserRepo(ctrl)
		mockTx := mocks.NewMockTx(ctrl)
		svc := New(mockUserRepo, log.NewPlugLogger())

		expectedUsers := []entities.User{
			{ID: 3, Login: "jane", Roles: []string{"hr"}},
			{ID: 5, Login: "alice", Roles: []string{"hr"}},
		}

		mockUserRepo.EXPECT().BeginTx(gomock.Any()).Return(mockTx, nil)
		mockTx.EXPECT().Rollback().Return(nil)

		mockUserRepo.EXPECT().GetUsers(gomock.Any(), mockTx, gomock.Any()).
			DoAndReturn(func(ctx context.Context, tx interface{}, command commands.GetUsers) (*results.GetUsers, error) {
				require.NotNil(t, command.Role)
				require.Equal(t, "hr", *command.Role)
				return &results.GetUsers{Users: expectedUsers, Total: len(expectedUsers)}, nil
			})

		result, err := svc.GetUsers(context.Background(), commands.GetUsers{
			Role: stringPtr("hr"), Page: 1, Limit: 10,
		})

		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, 2, result.Total)
		for _, u := range result.Users {
			require.Contains(t, u.Roles, "hr")
		}
	})

	t.Run("success empty result", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockUserRepo := mocks.NewMockUserRepo(ctrl)
		mockTx := mocks.NewMockTx(ctrl)
		svc := New(mockUserRepo, log.NewPlugLogger())

		mockUserRepo.EXPECT().BeginTx(gomock.Any()).Return(mockTx, nil)
		mockTx.EXPECT().Rollback().Return(nil)
		mockUserRepo.EXPECT().GetUsers(gomock.Any(), mockTx, gomock.Any()).
			Return(&results.GetUsers{Users: []entities.User{}, Total: 0}, nil)

		result, err := svc.GetUsers(context.Background(), commands.GetUsers{
			Role: stringPtr("interviewer"), Page: 1, Limit: 10,
		})

		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, 0, result.Total)
		require.Empty(t, result.Users)
	})

	t.Run("success second page", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockUserRepo := mocks.NewMockUserRepo(ctrl)
		mockTx := mocks.NewMockTx(ctrl)
		svc := New(mockUserRepo, log.NewPlugLogger())

		mockUserRepo.EXPECT().BeginTx(gomock.Any()).Return(mockTx, nil)
		mockTx.EXPECT().Rollback().Return(nil)

		mockUserRepo.EXPECT().GetUsers(gomock.Any(), mockTx, gomock.Any()).
			DoAndReturn(func(ctx context.Context, tx interface{}, command commands.GetUsers) (*results.GetUsers, error) {
				require.Equal(t, 2, command.Page)
				require.Equal(t, 5, command.Limit)
				return &results.GetUsers{
					Users: []entities.User{{ID: 6, Login: "user6"}},
					Total: 6,
				}, nil
			})

		result, err := svc.GetUsers(context.Background(), commands.GetUsers{
			Role: nil, Page: 2, Limit: 5,
		})

		require.NoError(t, err)
		require.Equal(t, 6, result.Total)
		require.Len(t, result.Users, 1)
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
		mockTx.EXPECT().Rollback().Return(nil)
		mockUserRepo.EXPECT().GetUsers(gomock.Any(), mockTx, gomock.Any()).
			Return(nil, context.Canceled)

		result, err := svc.GetUsers(ctx, commands.GetUsers{Page: 1, Limit: 10})
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
		mockTx.EXPECT().Rollback().Return(nil)
		mockUserRepo.EXPECT().GetUsers(gomock.Any(), mockTx, gomock.Any()).
			Return(nil, errors.New("internal error"))

		result, err := svc.GetUsers(context.Background(), commands.GetUsers{Page: 1, Limit: 10})
		require.Nil(t, result)
		require.Error(t, err)
	})
}
