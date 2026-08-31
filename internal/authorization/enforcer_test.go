package authorization

import (
	"errors"
	"testing"

	"github.com/lihongjie0209/authorization-service/internal/database"
	platformauthz "github.com/lihongjie0209/microservice-platform-go/authz"
	"github.com/lihongjie0209/microservice-platform-go/principal"
)

func TestLocalAuthorizerResolvesPrincipalScopeWithoutRecursion(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name            string
		identity        principal.Principal
		wantTenant      string
		wantSubject     string
		wantSubjectType string
	}{
		{name: "tenant administrator", identity: principal.Principal{ID: "user-1", Type: principal.TypeUser, TenantID: "tenant-1", MembershipID: "membership-1"}, wantTenant: "tenant-1", wantSubject: "membership-1", wantSubjectType: "membership"},
		{name: "platform administrator", identity: principal.Principal{ID: "user-1", Type: principal.TypeUser}, wantTenant: platformauthz.PlatformTenantID, wantSubject: "user-1", wantSubjectType: "user"},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository := &fakeRepository{grants: []resolvedGrant{{DataScope: "all"}}}
			authorizer := NewLocalAuthorizer(NewService(repository, &database.Transactor{}))
			err := authorizer.Authorize(t.Context(), test.identity, platformauthz.Requirement{Resource: "authorization.role", Action: "list", Scope: platformauthz.ScopePrincipal})
			if err != nil {
				t.Fatal(err)
			}
			if repository.resolvedTenant != test.wantTenant || repository.resolvedSubject != test.wantSubject || repository.resolvedSubjectType != test.wantSubjectType {
				t.Fatalf("resolved = %q/%q/%q", repository.resolvedTenant, repository.resolvedSubject, repository.resolvedSubjectType)
			}
		})
	}
}

func TestLocalAuthorizerDeniesMissingGrant(t *testing.T) {
	t.Parallel()
	authorizer := NewLocalAuthorizer(NewService(&fakeRepository{}, &database.Transactor{}))
	err := authorizer.Authorize(t.Context(), principal.Principal{ID: "user-1", Type: principal.TypeUser}, platformauthz.Requirement{Resource: "authorization.role", Action: "list", Scope: platformauthz.ScopePrincipal})
	if !errors.Is(err, platformauthz.ErrDenied) {
		t.Fatalf("Authorize() error = %v, want denied", err)
	}
}
