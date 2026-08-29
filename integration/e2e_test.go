//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/lihongjie0209/authorization-service/internal/app"
	"github.com/lihongjie0209/authorization-service/internal/auth"
	"github.com/lihongjie0209/authorization-service/internal/config"
	authorizationv1 "github.com/lihongjie0209/platform-protos/gen/go/platform/authorization/v1"
	commonv1 "github.com/lihongjie0209/platform-protos/gen/go/platform/common/v1"
	goredis "github.com/redis/go-redis/v9"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	rediscontainer "github.com/testcontainers/testcontainers-go/modules/redis"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	grpc_health_v1 "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
)

func TestHTTPAndGRPCEndToEnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	postgresContainer, err := postgres.Run(ctx, "postgres:17-alpine", postgres.WithDatabase("app"), postgres.WithUsername("app"), postgres.WithPassword("app"), postgres.BasicWaitStrategies(), postgres.WithSQLDriver("pgx"))
	if err != nil {
		t.Fatal(err)
	}
	testcontainers.CleanupContainer(t, postgresContainer)
	dsn, err := postgresContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	migrationPath, _ := filepath.Abs(filepath.Join("..", "migrations", "postgres"))

	redisContainer, err := rediscontainer.Run(ctx, "redis:7.4-alpine")
	if err != nil {
		t.Fatal(err)
	}
	testcontainers.CleanupContainer(t, redisContainer)
	redisURL, err := redisContainer.ConnectionString(ctx)
	if err != nil {
		t.Fatal(err)
	}
	redisOptions, err := goredis.ParseURL(redisURL)
	if err != nil {
		t.Fatal(err)
	}

	httpAddress := freeAddress(t)
	grpcAddress := freeAddress(t)
	const secret = "01234567890123456789012345678901"
	cfg := config.Config{
		Runtime:       config.Runtime{ActiveProfile: "integration"},
		App:           config.App{Name: "integration", Env: "integration", ShutdownTimeout: 10 * time.Second},
		HTTP:          config.HTTP{Address: httpAddress, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, RequestTimeout: 5 * time.Second, MaxBodyBytes: 1 << 20},
		GRPC:          config.GRPC{Enabled: true, Address: grpcAddress, MaxReceiveBytes: 4 << 20},
		Log:           config.Log{Level: "error", Format: "json", File: filepath.Join(t.TempDir(), "app.log"), MaxSizeMB: 1, MaxBackups: 1, MaxAgeDays: 1},
		Database:      config.Database{Enabled: true, Type: "postgres", DSN: dsn, MaxOpenConns: 5, MaxIdleConns: 2, ConnMaxLifetime: time.Minute, ConnMaxIdleTime: time.Minute, PingTimeout: 10 * time.Second},
		Migration:     config.Migration{AutoUp: true, Path: migrationPath, DatabaseURL: dsn, Table: "integration_e2e_schema_migrations"},
		Redis:         config.Redis{Enabled: true, Address: redisOptions.Addr, DB: redisOptions.DB, DialTimeout: 5 * time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second},
		Health:        config.Health{DatabaseTimeout: 2 * time.Second, RedisTimeout: 2 * time.Second},
		Observability: config.Observability{MetricsEnabled: true},
		JWT:           config.JWT{Issuer: "integration", Secret: secret, TTL: time.Hour},
		Auth:          config.Auth{ClientID: "client", ClientSecret: "secret", SkipHTTPPaths: []string{"/api/v1/version"}, SkipGRPCMethods: []string{"/grpc.health.v1.Health/*"}, PSK: config.PSK{Enabled: true, Key: secret, HTTPPaths: []string{"/api/v1/authorization/permissions/list"}, GRPCMethods: []string{"/platform.authorization.v1.AuthorizationService/ListPermissions"}}},
		Cron:          config.Cron{Enabled: false, Timezone: "UTC"},
		User:          config.User{CacheTTL: time.Minute, LockTTL: 10 * time.Second, LockRetryDelay: 20 * time.Millisecond},
		Idempotency:   config.Idempotency{Enabled: true, ProcessingTTL: 30 * time.Second, ResultTTL: time.Hour, FailureTTL: time.Minute},
	}
	application := app.New(cfg)
	if err := application.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stopCtx, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		_ = application.Stop(stopCtx)
	})
	token, err := auth.New(cfg).Issue("client")
	if err != nil {
		t.Fatal(err)
	}

	baseURL := "http://" + httpAddress
	if status := postJSON(t, baseURL+"/api/v1/version", "", "", `{}`); status != http.StatusOK {
		t.Fatalf("public version status = %d", status)
	}
	if status := postJSON(t, baseURL+"/api/v1/me", "Bearer "+token, "", `{}`); status != http.StatusOK {
		t.Fatalf("JWT status = %d", status)
	}
	if status := postRawStatus(t, baseURL+"/api/v1/auth/login", `{}`); status != http.StatusNotFound {
		t.Fatalf("authorization service must not expose login, status = %d", status)
	}
	if status := postJSON(t, baseURL+"/api/v1/authorization/permissions/list", "", "", `{"tenant_id":"tenant-1","page":1}`); status != http.StatusUnauthorized {
		t.Fatalf("missing PSK status = %d", status)
	}
	if status := postJSON(t, baseURL+"/api/v1/authorization/permissions/list", "PSK "+secret, "", `{"tenant_id":"tenant-1","page":1}`); status != http.StatusOK {
		t.Fatalf("PSK status = %d", status)
	}

	connection, err := grpc.NewClient(grpcAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	healthResponse, err := grpc_health_v1.NewHealthClient(connection).Check(ctx, &grpc_health_v1.HealthCheckRequest{})
	if err != nil || healthResponse.GetStatus() != grpc_health_v1.HealthCheckResponse_SERVING {
		t.Fatalf("health = %v, %v", healthResponse, err)
	}
	pskCtx := metadata.AppendToOutgoingContext(ctx, "authorization", "PSK "+secret)
	authorizationClient := authorizationv1.NewAuthorizationServiceClient(connection)
	if _, err := authorizationClient.ListPermissions(pskCtx, &authorizationv1.ListPermissionsRequest{TenantId: "tenant-1", Page: &commonv1.PageRequest{Page: 1}}); err != nil {
		t.Fatalf("PSK ListPermissions: %v", err)
	}
	jwtCtx := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)

	permissionBody, status := postJSONBody(t, baseURL+"/api/v1/authorization/permissions/create", "Bearer "+token, "", `{"tenant_id":"tenant-1","code":"invoice.read","name":"Read invoices","resource_type":"invoice","action":"read"}`)
	if status != http.StatusOK {
		t.Fatalf("create permission status=%d body=%s", status, permissionBody)
	}
	permissionID := responseStringField(t, permissionBody, "id")
	roleBody, status := postJSONBody(t, baseURL+"/api/v1/authorization/roles/create", "Bearer "+token, "", `{"tenant_id":"tenant-1","code":"auditor","name":"Auditor","description":"Read-only","data_scope":"tenant"}`)
	if status != http.StatusOK {
		t.Fatalf("create role status=%d body=%s", status, roleBody)
	}
	roleID := responseStringField(t, roleBody, "id")
	grantResponse, err := authorizationClient.GrantRolePermission(jwtCtx, &authorizationv1.GrantRolePermissionRequest{TenantId: "tenant-1", RoleId: roleID, PermissionId: permissionID})
	if err != nil || grantResponse.GetRolePermission().GetId() == "" {
		t.Fatalf("GrantRolePermission() = (%v, %v)", grantResponse, err)
	}
	if _, err := authorizationClient.CreateBinding(jwtCtx, &authorizationv1.CreateBindingRequest{TenantId: "tenant-1", Subject: &authorizationv1.Subject{Id: "membership-1", Type: authorizationv1.SubjectType_SUBJECT_TYPE_MEMBERSHIP}, RoleId: roleID}); err != nil {
		t.Fatalf("CreateBinding: %v", err)
	}
	decision, err := authorizationClient.Check(jwtCtx, &authorizationv1.CheckRequest{TenantId: "tenant-1", Subject: &authorizationv1.Subject{Id: "membership-1", Type: authorizationv1.SubjectType_SUBJECT_TYPE_MEMBERSHIP}, ResourceType: "invoice", Action: "read"})
	if err != nil || !decision.GetAllowed() || decision.GetDataScope() != authorizationv1.DataScopeType_DATA_SCOPE_TYPE_TENANT {
		t.Fatalf("Check() = (%v, %v)", decision, err)
	}
}

func responseStringField(t *testing.T, data []byte, field string) string {
	t.Helper()
	var response struct {
		Body map[string]any `json:"body"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		t.Fatal(err)
	}
	value, _ := response.Body[field].(string)
	if value == "" {
		t.Fatalf("response body field %q missing: %s", field, data)
	}
	return value
}

func freeAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func postJSON(t *testing.T, target, authorization, key, body string) int {
	t.Helper()
	_, status := postJSONBody(t, target, authorization, key, body)
	return status
}

func postRawStatus(t *testing.T, target, body string) int {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, target, bytes.NewBufferString(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	return response.StatusCode
}
func postJSONBody(t *testing.T, target, authorization, key, body string) ([]byte, int) {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, target, bytes.NewBufferString(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	if key != "" {
		request.Header.Set("Idempotency-Key", key)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	var validJSON any
	if err := json.Unmarshal(data, &validJSON); err != nil {
		t.Fatalf("invalid JSON response: %v (%s)", err, data)
	}
	return data, response.StatusCode
}

var _ = fmt.Sprintf
