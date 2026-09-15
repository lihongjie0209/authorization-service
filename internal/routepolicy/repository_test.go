package routepolicy

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jmoiron/sqlx"
	appdb "github.com/lihongjie0209/authorization-service/internal/database"
	"github.com/lihongjie0209/microservice-platform-go/authz"
	"github.com/lihongjie0209/microservice-platform-go/principal"
	platformpolicy "github.com/lihongjie0209/microservice-platform-go/routepolicy"
)

func TestRepositoryLoadsDenormalizedPermissionReferences(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	db := sqlx.NewDb(database, "sqlmock")
	repository := NewRepository(db, appdb.NewTransactor(db))
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT id,route_id,expression,version FROM route_policy_definitions WHERE status='active' AND deleted_at IS NULL ORDER BY route_id`)).WillReturnRows(sqlmock.NewRows([]string{"id", "route_id", "expression", "version"}).AddRow("policy-1", "route-1", `permissions["application.read"]`, 2))
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT r.policy_id,r.id,r.permission_key,r.resource,r.action,r.scope FROM route_policy_permission_refs r JOIN route_policy_definitions d ON d.id=r.policy_id AND d.deleted_at IS NULL AND d.status='active' WHERE r.deleted_at IS NULL ORDER BY r.policy_id,r.permission_key`)).WillReturnRows(sqlmock.NewRows([]string{"policy_id", "id", "permission_key", "resource", "action", "scope"}).AddRow("policy-1", "ref-1", "application.read", "application.catalog", "read", "platform"))
	definitions, err := repository.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	permission := definitions[0].Permissions["application.read"]
	if len(definitions) != 1 || definitions[0].RouteID != "route-1" || permission.Scope != authz.ScopePlatform || permission.Resource != "application.catalog" {
		t.Fatalf("definitions = %+v", definitions)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestServiceRejectsInvalidExpressionBeforePersistence(t *testing.T) {
	compiler, err := platformpolicy.NewCompiler()
	if err != nil {
		t.Fatal(err)
	}
	service := NewService(nil, nil, compiler, nil, nil)
	ctx := principal.WithContext(t.Context(), principal.Principal{ID: "admin", Type: principal.TypeUser})
	_, err = service.Set(ctx, SetInput{RouteID: "route-1", Expression: `permissions["missing"]`, Status: "active"})
	if err == nil || !errors.Is(err, platformpolicy.ErrInvalid) {
		t.Fatalf("error = %v, want invalid expression", err)
	}
}

func TestRoutePolicyWhereKeepsCountAndItemsFiltersEquivalent(t *testing.T) {
	where, args := routePolicyWhere(Filter{Keyword: "Menu", Protocol: "http", RouteStatus: "active", PolicyStatus: "disabled"})
	want := `r.deleted_at IS NULL AND (LOWER(r.path) LIKE ? OR LOWER(r.operation) LIKE ?) AND r.protocol=? AND r.status=? AND p.status=?`
	if where != want {
		t.Fatalf("where = %q", where)
	}
	if len(args) != 5 || args[0] != "%menu%" || args[2] != "http" || args[4] != "disabled" {
		t.Fatalf("args = %#v", args)
	}
}

func TestBootstrapRouteIDsMatchSharedStableIdentity(t *testing.T) {
	t.Parallel()
	content, err := os.ReadFile(filepath.Join("..", "..", "migrations", "postgres", "000008_route_policies.up.sql"))
	if err != nil {
		t.Fatal(err)
	}
	matches := regexp.MustCompile(`\('([0-9a-f-]{36})','(http|grpc)','(post|call)','([^']+)'`).FindAllStringSubmatch(string(content), -1)
	if len(matches) != 57 {
		t.Fatalf("seeded route count = %d, want 57", len(matches))
	}
	seen := make(map[string]struct{}, len(matches))
	for _, match := range matches {
		route, err := platformpolicy.NewRoute(match[2], match[3], match[4], "authorization-service", "")
		if err != nil || route.ID != match[1] {
			t.Fatalf("route %s id = %q, %v; want %q", match[4], route.ID, err, match[1])
		}
		if _, duplicate := seen[route.ID]; duplicate {
			t.Fatalf("duplicate route id %s", route.ID)
		}
		seen[route.ID] = struct{}{}
	}
	text := string(content)
	for _, expression := range []string{`anonymous || authenticated`, `authenticated && permissions["authorization.permission.create"]`, `authenticated && permissions["authorization.binding.revoke"]`} {
		if !strings.Contains(text, expression) {
			t.Fatalf("bootstrap policies lack %q", expression)
		}
	}
}
