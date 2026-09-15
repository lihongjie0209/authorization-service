package grpctransport

import (
	"context"
	"testing"
	"time"

	"github.com/lihongjie0209/authorization-service/internal/auth"
	"github.com/lihongjie0209/authorization-service/internal/config"
	platformauthz "github.com/lihongjie0209/microservice-platform-go/authz"
	"github.com/lihongjie0209/microservice-platform-go/principal"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestDatabaseAuthorizationInterceptorFailsClosed(t *testing.T) {
	t.Parallel()
	interceptor := databaseAuthorizationInterceptor(true, "authorization-service", grpcRoutePolicyStub{err: platformauthz.ErrDenied}, authorizationStub{})
	_, err := interceptor(t.Context(), nil, &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}, func(context.Context, any) (any, error) { return "ok", nil })
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("status = %v", status.Code(err))
	}
}

type grpcRoutePolicyStub struct{ err error }

func (s grpcRoutePolicyStub) EvaluateRoute(context.Context, string, string, string, string, platformauthz.Authorizer) error {
	return s.err
}

type authorizationStub struct{}

func (authorizationStub) Authorize(context.Context, principal.Principal, platformauthz.Requirement) error {
	return nil
}

func TestAuthenticateGRPC_PSKWildcard(t *testing.T) {
	t.Parallel()
	const key = "01234567890123456789012345678901"
	authService := auth.New(config.Config{JWT: config.JWT{Issuer: "test", Secret: key, TTL: time.Hour}})
	cfg := config.Auth{
		SkipGRPCMethods: []string{"/hello.v1.UserService/*"},
		PSK:             config.PSK{Enabled: true, Key: key, GRPCMethods: []string{"/hello.v1.UserService/*"}},
	}
	for _, test := range []struct {
		name   string
		header string
		code   codes.Code
	}{
		{name: "valid", header: "PSK " + key, code: codes.OK},
		{name: "PSK precedes skip", code: codes.Unauthenticated},
		{name: "bearer rejected", header: "Bearer " + key, code: codes.Unauthenticated},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ctx := metadata.NewIncomingContext(t.Context(), metadata.Pairs("authorization", test.header))
			authCtx, err := authenticateGRPC(ctx, "/hello.v1.UserService/GetUser", authService, cfg)
			if got := status.Code(err); got != test.code {
				t.Fatalf("status code = %s, want %s", got, test.code)
			}
			if test.code == codes.OK {
				actor, ok := principal.FromContext(authCtx)
				if !ok || actor.ID != "psk" {
					t.Fatalf("principal = %+v, found=%v", actor, ok)
				}
			}
		})
	}
}
