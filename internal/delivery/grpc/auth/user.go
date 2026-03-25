package auth

import (
	authv1 "github.com/mkaascs/AuthProto/gen/go/auth"
	"google.golang.org/grpc"
)

type userServer struct {
	authv1.UnimplementedUserServer
}

func RegisterUserServer(gRPC *grpc.Server) {
	authv1.RegisterUserServer(gRPC, &userServer{})
}
