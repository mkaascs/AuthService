package auth

import (
	authv1 "github.com/mkaascs/AuthProto/gen/go/auth"
	"google.golang.org/grpc"
)

type tokenServer struct {
	authv1.UnimplementedTokenServer
}

func RegisterTokenServer(gRPC *grpc.Server) {
	authv1.RegisterTokenServer(gRPC, &tokenServer{})
}
