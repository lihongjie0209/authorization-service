package grpctransport

import (
	"testing"
	"time"

	"github.com/lihongjie0209/authorization-service/internal/auth"
	"github.com/lihongjie0209/authorization-service/internal/config"
	platformauthz "github.com/lihongjie0209/microservice-platform-go/authz"
	"github.com/lihongjie0209/microservice-platform-go/principal"
	authorizationv1 "github.com/lihongjie0209/platform-protos/gen/go/platform/authorization/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestAuthorizationGRPCRequirementCoversManagementAndExcludesDecisions(t *testing.T) {
	t.Parallel()
	resolve := authorizationGRPCRequirement(true)
	protected := []string{authorizationv1.AuthorizationService_CreatePermission_FullMethodName, authorizationv1.AuthorizationService_UpdatePermission_FullMethodName, authorizationv1.AuthorizationService_ListPermissions_FullMethodName, authorizationv1.AuthorizationService_CreateRole_FullMethodName, authorizationv1.AuthorizationService_UpdateRole_FullMethodName, authorizationv1.AuthorizationService_ListRoles_FullMethodName, authorizationv1.AuthorizationService_GrantRolePermission_FullMethodName, authorizationv1.AuthorizationService_RevokeRolePermission_FullMethodName, authorizationv1.AuthorizationService_ListRolePermissions_FullMethodName, authorizationv1.AuthorizationService_CreateBinding_FullMethodName, authorizationv1.AuthorizationService_RevokeBinding_FullMethodName, authorizationv1.AuthorizationService_ListBindings_FullMethodName}
	for _, method := range protected {
		requirement, ok := resolve(method)
		if !ok || requirement.Resource == "" || requirement.Action == "" || requirement.Scope != platformauthz.ScopePrincipal {
			t.Fatalf("method %q requirement = %+v, %v", method, requirement, ok)
		}
	}
	for _, method := range []string{authorizationv1.AuthorizationService_Check_FullMethodName, authorizationv1.AuthorizationService_BatchCheck_FullMethodName, authorizationv1.AuthorizationService_ResolveDataScope_FullMethodName, authorizationv1.AuthorizationService_InvalidateSubject_FullMethodName} {
		if _, ok := resolve(method); ok {
			t.Fatalf("decision method %q must not recurse", method)
		}
	}
	if _, ok := authorizationGRPCRequirement(false)(protected[0]); ok {
		t.Fatal("disabled authorization must not enforce")
	}
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
