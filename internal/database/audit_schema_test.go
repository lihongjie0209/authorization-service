package database

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuthorizationTablesHaveDatabaseOwnedAuditShapeForEveryDialect(t *testing.T) {
	t.Parallel()
	for _, dialect := range []string{"postgres", "kingbase", "mysql"} {
		dialect := dialect
		t.Run(dialect, func(t *testing.T) {
			t.Parallel()
			content, err := os.ReadFile(filepath.Join("..", "..", "migrations", dialect, "000007_database_audit.up.sql"))
			if err != nil {
				t.Fatal(err)
			}
			text := strings.ToLower(string(content))
			for _, table := range []string{"permissions", "roles", "role_permissions", "role_bindings", "authorization_policy_versions", "authorization_subject_groups", "authorization_processed_events", "authorization_outbox_events"} {
				if !strings.Contains(text, "alter table "+table) || !strings.Contains(text, "deleted_at") || !strings.Contains(text, "deleted_by") {
					t.Fatalf("%s migration lacks complete logical-delete shape for %s", dialect, table)
				}
			}
			if dialect == "mysql" {
				for _, suffix := range []string{"_audit_bi", "_audit_bu", "_audit_bd"} {
					if strings.Count(text, suffix) != 7 {
						t.Fatalf("%s migration has %d %s triggers, want 7", dialect, strings.Count(text, suffix), suffix)
					}
				}
			} else if strings.Count(text, "execute function authorization_audit_row()") != 7 {
				t.Fatalf("%s migration lacks database trigger coverage", dialect)
			}
			if !strings.Contains(text, "bounded-retention exception") {
				t.Fatal("outbox audit exception must be explicit")
			}
		})
	}
}

func TestAuthorizationRepositoryQueriesExcludeLogicallyDeletedRows(t *testing.T) {
	t.Parallel()
	content, err := os.ReadFile(filepath.Join("..", "authorization", "repository.go"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(content)
	for _, table := range []string{"permissions", "roles", "role_permissions", "role_bindings", "authorization_subject_groups", "authorization_policy_versions"} {
		if !strings.Contains(text, table) || !strings.Contains(text, "deleted_at IS NULL") {
			t.Fatalf("repository lacks logical-delete filtering for %s", table)
		}
	}
}

func TestRoutePolicyTablesHaveDatabaseOwnedAuditShapeForEveryDialect(t *testing.T) {
	t.Parallel()
	for _, dialect := range []string{"postgres", "kingbase", "mysql"} {
		dialect := dialect
		t.Run(dialect, func(t *testing.T) {
			t.Parallel()
			content, err := os.ReadFile(filepath.Join("..", "..", "migrations", dialect, "000008_route_policies.up.sql"))
			if err != nil {
				t.Fatal(err)
			}
			text := strings.ToLower(string(content))
			if !strings.Contains(text, "authorization-service:migration") {
				t.Fatal("route policy bootstrap ownership is not authorization-service")
			}
			for _, table := range []string{"route_definitions", "route_policy_definitions", "route_policy_permission_refs"} {
				for _, field := range []string{"created_at", "created_by", "updated_at", "updated_by", "version", "deleted_at", "deleted_by"} {
					if !strings.Contains(text, table) || !strings.Contains(text, field) {
						t.Fatalf("%s migration lacks %s on %s", dialect, field, table)
					}
				}
			}
			if dialect == "mysql" {
				for _, suffix := range []string{"_audit_bi", "_audit_bu", "_audit_bd"} {
					if strings.Count(text, suffix) != 3 {
						t.Fatalf("%s migration has %d %s triggers, want 3", dialect, strings.Count(text, suffix), suffix)
					}
				}
			} else if strings.Count(text, "execute function authorization_audit_row()") != 3 {
				t.Fatalf("%s migration lacks route policy trigger coverage", dialect)
			}
		})
	}
}
