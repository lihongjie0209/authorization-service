//go:build integration

package integration

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/lihongjie0209/authorization-service/internal/config"
	appdb "github.com/lihongjie0209/authorization-service/internal/database"
	"github.com/lihongjie0209/authorization-service/internal/migration"
	"github.com/lihongjie0209/authorization-service/internal/routepolicy"
	"github.com/lihongjie0209/microservice-platform-go/principal"
	platformpolicy "github.com/lihongjie0209/microservice-platform-go/routepolicy"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/mysql"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

func TestRepositoryAndMigrations(t *testing.T) {
	for _, databaseType := range []string{"postgres", "mysql"} {
		t.Run(databaseType, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()
			dsn, migrationURL := startDatabase(t, ctx, databaseType)
			migrationPath, err := filepath.Abs(filepath.Join("..", "migrations", databaseType))
			if err != nil {
				t.Fatal(err)
			}
			schema := ""
			if databaseType == "postgres" {
				schema = "integration_postgres"
			}
			migrationCfg := config.Migration{Path: migrationPath, DatabaseURL: migrationURL, Table: "integration_" + databaseType + "_schema_migrations", Schema: schema, CreateSchema: schema != ""}
			migrationErrors := make(chan error, 3)
			var migrations sync.WaitGroup
			for range 3 {
				migrations.Add(1)
				go func() {
					defer migrations.Done()
					migrationErrors <- migration.Run(migrationCfg, "up", 0)
				}()
			}
			migrations.Wait()
			close(migrationErrors)
			for err := range migrationErrors {
				if err != nil {
					t.Fatalf("concurrent migration up: %v", err)
				}
			}

			db, err := appdb.Open(ctx, config.Database{Type: databaseType, DSN: dsn, Schema: schema, MaxOpenConns: 5, MaxIdleConns: 2, ConnMaxLifetime: time.Minute, ConnMaxIdleTime: time.Minute, PingTimeout: 10 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = db.Close() })
			policyRepository := routepolicy.NewRepository(db, appdb.NewTransactor(db))
			definitions, err := policyRepository.Load(ctx)
			if err != nil || len(definitions) != 60 {
				t.Fatalf("load bootstrap route policies count=%d err=%v", len(definitions), err)
			}
			versionRoute, err := platformpolicy.NewRoute("http", "post", "/api/v1/version", "authorization-service", "")
			if err != nil {
				t.Fatal(err)
			}
			versionPolicy, err := policyRepository.Get(ctx, versionRoute.ID)
			if err != nil || versionPolicy.Expression != "anonymous || authenticated" {
				t.Fatalf("version route policy=%+v err=%v", versionPolicy, err)
			}
			var bootstrapActor string
			if err := db.GetContext(ctx, &bootstrapActor, db.Rebind(`SELECT created_by FROM route_policy_definitions WHERE id=?`), versionPolicy.PolicyID); err != nil || bootstrapActor != "authorization-service:migration" {
				t.Fatalf("bootstrap actor=%q err=%v", bootstrapActor, err)
			}
			writeCtx := principal.WithContext(ctx, principal.Principal{ID: "integration-auditor", Type: principal.TypeSystem})
			if err := appdb.NewTransactor(db).Within(writeCtx, nil, func(tx *sqlx.Tx) error {
				_, err := tx.ExecContext(writeCtx, db.Rebind(`INSERT INTO permissions(id,tenant_id,code,name,resource_type,action,status,version,created_at,updated_at,created_by,updated_by,condition_expression) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`), "permission-audit", "tenant-1", "audit.test", "Audit test", "audit", "read", "active", 99, time.Unix(1, 0), time.Unix(1, 0), "spoofed", "spoofed", "")
				return err
			}); err != nil {
				t.Fatalf("insert audited permission: %v", err)
			}
			var audited struct {
				CreatedBy string `db:"created_by"`
				UpdatedBy string `db:"updated_by"`
				Version   int64  `db:"version"`
			}
			if err := db.GetContext(ctx, &audited, db.Rebind(`SELECT created_by,updated_by,version FROM permissions WHERE id=?`), "permission-audit"); err != nil {
				t.Fatal(err)
			}
			if audited.CreatedBy != "integration-auditor" || audited.UpdatedBy != "integration-auditor" || audited.Version != 1 {
				t.Fatalf("database-owned audit fields = %+v", audited)
			}
			if err := appdb.NewTransactor(db).Within(writeCtx, nil, func(tx *sqlx.Tx) error {
				_, err := tx.ExecContext(writeCtx, db.Rebind(`DELETE FROM permissions WHERE id=?`), "permission-audit")
				return err
			}); err == nil {
				t.Fatal("physical delete unexpectedly succeeded")
			}
			var count int
			if databaseType == "postgres" {
				var timezone string
				if err := db.GetContext(ctx, &timezone, "SHOW TIMEZONE"); err != nil || timezone != "Asia/Shanghai" {
					t.Fatalf("timezone=%q err=%v", timezone, err)
				}
			}
			if err := db.GetContext(ctx, &count, "SELECT COUNT(*) FROM permissions"); err != nil {
				t.Fatalf("authorization domain table: %v", err)
			}
			if err := db.GetContext(ctx, &count, "SELECT COUNT(*) FROM users"); err == nil {
				t.Fatal("authorization service must not own a users table")
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			if err := migration.Run(migrationCfg, "down", 0); err != nil {
				t.Fatalf("migration down: %v", err)
			}
		})
	}
}

func startDatabase(t *testing.T, ctx context.Context, databaseType string) (string, string) {
	t.Helper()
	switch databaseType {
	case "postgres":
		container, err := postgres.Run(ctx, "postgres:17-alpine", postgres.WithDatabase("app"), postgres.WithUsername("app"), postgres.WithPassword("app"), postgres.BasicWaitStrategies(), postgres.WithSQLDriver("pgx"))
		if err != nil {
			t.Fatal(err)
		}
		testcontainers.CleanupContainer(t, container)
		dsn, err := container.ConnectionString(ctx, "sslmode=disable")
		if err != nil {
			t.Fatal(err)
		}
		return dsn, dsn
	case "mysql":
		container, err := mysql.Run(
			ctx,
			"mysql:8.4",
			mysql.WithDatabase("app"),
			mysql.WithUsername("app"),
			mysql.WithPassword("app"),
			mysql.WithConfigFile(filepath.Join("testdata", "mysql.cnf")),
		)
		if err != nil {
			t.Fatal(err)
		}
		testcontainers.CleanupContainer(t, container)
		// Match the runtime database.Open configuration. MySQL DATETIME values do
		// not carry timezone information, so the driver location must be explicit
		// for audit timestamps and time-range filters to use the same wall clock.
		dsn, err := container.ConnectionString(ctx, "parseTime=true&loc=Asia%2FShanghai&time_zone=%27%2B08%3A00%27")
		if err != nil {
			t.Fatal(err)
		}
		migrationDSN, err := container.ConnectionString(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return dsn, "mysql://" + migrationDSN
	default:
		t.Fatal(fmt.Errorf("unsupported database %q", databaseType))
		return "", ""
	}
}
