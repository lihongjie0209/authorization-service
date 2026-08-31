package authorization

import (
	"context"
	"fmt"
	"strings"

	platformauthz "github.com/lihongjie0209/microservice-platform-go/authz"
	"github.com/lihongjie0209/microservice-platform-go/principal"
)

type localAuthorizer struct{ service *Service }

func NewLocalAuthorizer(service *Service) platformauthz.Authorizer {
	return &localAuthorizer{service: service}
}

func (a *localAuthorizer) Authorize(ctx context.Context, identity principal.Principal, requirement platformauthz.Requirement) error {
	tenantID, subjectID, subjectType, err := localAuthorizationTarget(identity, requirement.Scope)
	if err != nil {
		return err
	}
	decision, err := a.service.CheckWithAttributes(ctx, tenantID, subjectID, subjectType, requirement.Resource, requirement.ResourceID, requirement.Action, requirement.Attributes)
	if err != nil {
		return fmt.Errorf("%w: %v", platformauthz.ErrDecisionUnavailable, err)
	}
	if !decision.Allowed {
		return platformauthz.ErrDenied
	}
	return nil
}

func localAuthorizationTarget(identity principal.Principal, scope platformauthz.Scope) (string, string, string, error) {
	if scope == platformauthz.ScopePrincipal {
		if strings.TrimSpace(identity.TenantID) == "" {
			scope = platformauthz.ScopePlatform
		} else {
			scope = platformauthz.ScopeTenant
		}
	}
	if scope == platformauthz.ScopePlatform {
		switch identity.Type {
		case principal.TypeUser:
			if identity.ID != "" {
				return platformauthz.PlatformTenantID, identity.ID, "user", nil
			}
		case principal.TypeServiceAccount, principal.TypeSystem:
			if identity.ID != "" {
				return platformauthz.PlatformTenantID, identity.ID, "service_account", nil
			}
		}
		return "", "", "", platformauthz.ErrInvalidPrincipal
	}
	if scope != platformauthz.ScopeTenant || strings.TrimSpace(identity.TenantID) == "" {
		return "", "", "", platformauthz.ErrInvalidPrincipal
	}
	switch identity.Type {
	case principal.TypeUser:
		if identity.MembershipID != "" {
			return identity.TenantID, identity.MembershipID, "membership", nil
		}
	case principal.TypeServiceAccount, principal.TypeSystem:
		if identity.ID != "" {
			return identity.TenantID, identity.ID, "service_account", nil
		}
	}
	return "", "", "", platformauthz.ErrInvalidPrincipal
}
