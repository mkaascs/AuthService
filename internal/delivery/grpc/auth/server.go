package auth

import (
	"auth-service/internal/domain/interfaces/services"
	authv1 "github.com/mkaascs/AuthProto/gen/go/auth"
	"google.golang.org/grpc"
)

type server struct {
	authv1.UnimplementedAuthServer
	auth services.Auth
}

func Register(gRPC *grpc.Server, auth services.Auth) {
	authv1.RegisterAuthServer(gRPC, &server{auth: auth})
}
