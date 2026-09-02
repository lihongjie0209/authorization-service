package httptransport

import (
	"encoding/json"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/lihongjie0209/authorization-service/internal/authorization"
)

func TestPermissionBodyPublicJSONContract(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.September, 2, 8, 0, 0, 0, time.UTC)
	encoded, err := json.Marshal(permissionBody(authorization.Permission{
		ID: "permission-1", TenantID: "tenant-1", Code: "orders.read", Name: "Read orders",
		ResourceType: "order", Action: "read", ConditionExpression: "true", Status: "active",
		AuditFields: authorization.AuditFields{
			Version: 2, CreatedAt: now, UpdatedAt: now, CreatedBy: "user-1", UpdatedBy: "user-2",
		},
	}))
	if err != nil {
		t.Fatalf("marshal permission body: %v", err)
	}
	assertAuthorizationJSONKeys(t, encoded, []string{
		"action", "code", "condition_expression", "created_at", "created_by", "id", "name", "resource_type",
		"status", "tenant_id", "updated_at", "updated_by", "version",
	})
}

func TestDecisionBodyCopiesOrganizationScope(t *testing.T) {
	t.Parallel()

	organizationIDs := []string{"org-1"}
	body := decisionBody(authorization.Decision{OrganizationUnitIDs: organizationIDs})
	organizationIDs[0] = "mutated"
	if body.OrganizationUnitIDs[0] != "org-1" {
		t.Fatal("decision body retained mutable domain slice")
	}
}

func assertAuthorizationJSONKeys(t *testing.T, encoded []byte, expected []string) {
	t.Helper()

	var body map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &body); err != nil {
		t.Fatalf("unmarshal response body: %v", err)
	}
	actual := make([]string, 0, len(body))
	for key := range body {
		actual = append(actual, key)
	}
	sort.Strings(actual)
	sort.Strings(expected)
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("public json keys = %v, want %v", actual, expected)
	}
}
