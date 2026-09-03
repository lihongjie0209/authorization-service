package httptransport

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lihongjie0209/authorization-service/internal/auth"
	"github.com/lihongjie0209/authorization-service/internal/config"
	"github.com/lihongjie0209/authorization-service/internal/idempotency"
	platformauthz "github.com/lihongjie0209/microservice-platform-go/authz"
	"github.com/lihongjie0209/microservice-platform-go/principal"
)

type fakeIdempotencyManager struct {
	decision  idempotency.Decision
	beginKey  string
	completed *Response
}

func (*fakeIdempotencyManager) Enabled() bool { return true }
func (m *fakeIdempotencyManager) Begin(_ context.Context, key, _ string) (idempotency.Decision, error) {
	m.beginKey = key
	return m.decision, nil
}
func (m *fakeIdempotencyManager) Complete(_ context.Context, _, _ string, response any) error {
	value, ok := response.(Response)
	if ok {
		m.completed = &value
	}
	return nil
}
func (*fakeIdempotencyManager) Fail(context.Context, string, string, idempotency.Failure) error {
	return nil
}

func TestIdempotencyExecutionCompletesAndReplaysAuthorizationMutation(t *testing.T) {
	t.Parallel()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager := &fakeIdempotencyManager{decision: idempotency.Decision{State: idempotency.StateAcquired, Owner: "owner-1"}}
	calls := 0
	router := gin.New()
	router.Use(RequestID(), func(c *gin.Context) {
		c.Set("subject", "administrator-1")
		c.Request = c.Request.WithContext(idempotency.WithContext(c.Request.Context(), "operation-1"))
		c.Next()
	}, IdempotencyExecution(manager, []string{"/api/v1/authorization/bindings/create"}, logger))
	router.POST("/api/v1/authorization/bindings/create", func(c *gin.Context) { calls++; OK(c, gin.H{"id": "binding-1"}) })
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/authorization/bindings/create", strings.NewReader(`{"subject_id":"user-1"}`)))
	if calls != 1 || manager.beginKey != "operation-1" || manager.completed == nil || manager.completed.RequestID != "" {
		t.Fatalf("calls=%d key=%q completed=%+v", calls, manager.beginKey, manager.completed)
	}
	stored, err := json.Marshal(*manager.completed)
	if err != nil {
		t.Fatal(err)
	}
	manager.decision = idempotency.Decision{State: idempotency.StateCompleted, Response: stored}
	replay := httptest.NewRequest(http.MethodPost, "/api/v1/authorization/bindings/create", strings.NewReader(`{"subject_id":"user-1"}`))
	replay.Header.Set("X-Request-ID", "current-request")
	replayRecorder := httptest.NewRecorder()
	router.ServeHTTP(replayRecorder, replay)
	var response Response
	if err := json.Unmarshal(replayRecorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || response.RequestID != "current-request" {
		t.Fatalf("calls=%d response=%+v", calls, response)
	}
}

func TestIdempotencyExecutionBypassesAuthorizationDecisions(t *testing.T) {
	t.Parallel()
	manager := &fakeIdempotencyManager{decision: idempotency.Decision{State: idempotency.StateConflict}}
	for _, route := range []string{"/api/v1/authorization/check", "/api/v1/authorization/batch-check", "/api/v1/authorization/my-permission-catalog/list"} {
		t.Run(route, func(t *testing.T) {
			t.Parallel()
			calls := 0
			router := gin.New()
			router.Use(func(c *gin.Context) {
				c.Request = c.Request.WithContext(idempotency.WithContext(c.Request.Context(), "operation-1"))
				c.Next()
			}, IdempotencyExecution(manager, []string{"/api/v1/authorization/bindings/create"}, slog.New(slog.NewTextHandler(io.Discard, nil))))
			router.POST(route, func(c *gin.Context) { calls++; OK(c, nil) })
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, route, nil))
			if calls != 1 || recorder.Code != http.StatusOK {
				t.Fatalf("calls=%d status=%d", calls, recorder.Code)
			}
		})
	}
	if manager.beginKey != "" {
		t.Fatalf("unexpected idempotency begin key %q", manager.beginKey)
	}
}

type authorizationStub struct{ err error }

func (a authorizationStub) Authorize(context.Context, principal.Principal, platformauthz.Requirement) error {
	return a.err
}

func TestAuthorizationHTTPRequirementCoversManagementAndExcludesDecisions(t *testing.T) {
	t.Parallel()
	protected := []string{"/api/v1/authorization/permissions/create", "/api/v1/authorization/permissions/update", "/api/v1/authorization/permissions/list", "/api/v1/authorization/roles/create", "/api/v1/authorization/roles/update", "/api/v1/authorization/roles/list", "/api/v1/authorization/role-permissions/grant", "/api/v1/authorization/role-permissions/revoke", "/api/v1/authorization/role-permissions/list", "/api/v1/authorization/bindings/create", "/api/v1/authorization/bindings/get", "/api/v1/authorization/bindings/revoke", "/api/v1/authorization/bindings/list"}
	for _, route := range protected {
		requirement, ok := authorizationHTTPRequirement(route)
		if !ok || requirement.Resource == "" || requirement.Action == "" || requirement.Scope != platformauthz.ScopePrincipal {
			t.Fatalf("route %q requirement = %+v, %v", route, requirement, ok)
		}
	}
	for _, route := range []string{"/api/v1/authorization/check", "/api/v1/authorization/batch-check", "/api/v1/authorization/my-permissions/check", "/api/v1/authorization/my-permission-catalog/list", "/api/v1/authorization/my-permissions/create", "/api/v1/authorization/my-permissions/update", "/api/v1/authorization/my-permissions/list", "/api/v1/authorization/my-roles/create", "/api/v1/authorization/my-roles/update", "/api/v1/authorization/my-roles/list", "/api/v1/authorization/my-role-permissions/grant", "/api/v1/authorization/my-role-permissions/revoke", "/api/v1/authorization/my-role-permissions/list", "/api/v1/authorization/my-bindings/create", "/api/v1/authorization/my-bindings/get", "/api/v1/authorization/my-bindings/revoke", "/api/v1/authorization/my-bindings/list", "/api/v1/version", "/api/v1/me"} {
		if _, ok := authorizationHTTPRequirement(route); ok {
			t.Fatalf("decision/operational route %q must not recurse", route)
		}
	}
}

func TestBindDecisionToCallerUsesTrustedTenantMembership(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)
	context, _ := gin.CreateTestContext(httptest.NewRecorder())
	context.Request = httptest.NewRequest(http.MethodPost, "/", nil)
	context.Request = context.Request.WithContext(principal.WithContext(context.Request.Context(), principal.Principal{ID: "user-1", Type: principal.TypeUser, TenantID: "tenant-1", MembershipID: "membership-1"}))
	request := CheckAuthorizationRequest{TenantID: "tenant-1", SubjectID: "other", SubjectType: "user"}
	if err := bindDecisionToCaller(context, &request); err != nil {
		t.Fatal(err)
	}
	if request.SubjectID != "membership-1" || request.SubjectType != "membership" {
		t.Fatalf("request = %+v", request)
	}
	request.TenantID = "tenant-2"
	if err := bindDecisionToCaller(context, &request); err == nil {
		t.Fatal("tenant mismatch must be rejected")
	}
}

func TestCurrentPermissionSubjectSeparatesTenantAndPlatformScopes(t *testing.T) {
	t.Parallel()
	caller := principal.Principal{ID: "user-1", Type: principal.TypeUser, TenantID: "tenant-1", MembershipID: "membership-1"}
	for _, test := range []struct {
		name        string
		scope       string
		wantTenant  string
		wantSubject string
		wantType    string
	}{
		{name: "legacy defaults to tenant", wantTenant: "tenant-1", wantSubject: "membership-1", wantType: "membership"},
		{name: "tenant", scope: "tenant", wantTenant: "tenant-1", wantSubject: "membership-1", wantType: "membership"},
		{name: "platform", scope: "platform", wantTenant: "__platform__", wantSubject: "user-1", wantType: "user"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			tenantID, subjectID, subjectType, err := currentPermissionSubject(caller, "tenant-1", test.scope)
			if err != nil || tenantID != test.wantTenant || subjectID != test.wantSubject || subjectType != test.wantType {
				t.Fatalf("subject=(%q,%q,%q) err=%v", tenantID, subjectID, subjectType, err)
			}
		})
	}
	if _, _, _, err := currentPermissionSubject(caller, "tenant-2", "platform"); err == nil {
		t.Fatal("platform lookup must still require the selected tenant token context")
	}
	if _, _, _, err := currentPermissionSubject(caller, "tenant-1", "global"); err == nil {
		t.Fatal("unknown scope must fail")
	}
}

func TestAuthorizationFailsClosedAndClassifiesOutage(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)
	for _, test := range []struct {
		name   string
		err    error
		status int
	}{{name: "denied", err: platformauthz.ErrDenied, status: http.StatusForbidden}, {name: "unavailable", err: platformauthz.ErrDecisionUnavailable, status: http.StatusServiceUnavailable}} {
		t.Run(test.name, func(t *testing.T) {
			router := gin.New()
			router.Use(RequestID(), func(c *gin.Context) {
				c.Request = c.Request.WithContext(principal.WithContext(c.Request.Context(), principal.Principal{ID: "user-1", Type: principal.TypeUser}))
				c.Next()
			}, Authorization(true, authorizationStub{err: test.err}, slog.New(slog.NewTextHandler(io.Discard, nil))))
			router.POST("/api/v1/authorization/roles/list", func(c *gin.Context) { OK(c, nil) })
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/authorization/roles/list", nil))
			if recorder.Code != test.status {
				t.Fatalf("status = %d, want %d", recorder.Code, test.status)
			}
		})
	}
}

func TestRequestID(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(RequestID())
	router.POST("/test", func(c *gin.Context) { OK(c, nil) })
	request := httptest.NewRequest(http.MethodPost, "/test", nil)
	request.Header.Set("X-Request-ID", "client-request-1")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if got := recorder.Header().Get("X-Request-ID"); got != "client-request-1" {
		t.Fatalf("X-Request-ID = %q", got)
	}
	var response Response
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.RequestID != "client-request-1" {
		t.Fatalf("request_id = %q", response.RequestID)
	}
}

func TestAuthentication_InjectsSharedPrincipal(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)
	const key = "01234567890123456789012345678901"
	service := auth.New(config.Config{JWT: config.JWT{Issuer: "test", Secret: key, TTL: time.Hour}, Auth: config.Auth{ClientID: "client", ClientSecret: "secret"}})
	token, err := service.Issue("service-1")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, header, wantID string
		cfg                  config.Auth
	}{
		{name: "JWT", header: "Bearer " + token, wantID: "service-1"},
		{name: "PSK", header: "PSK " + key, wantID: "psk", cfg: config.Auth{PSK: config.PSK{Enabled: true, Key: key, HTTPPaths: []string{"/api/v1/test"}}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			router := gin.New()
			router.Use(Authentication(service, slog.New(slog.NewTextHandler(io.Discard, nil)), test.cfg))
			router.POST("/api/v1/test", func(c *gin.Context) {
				actor, ok := principal.FromContext(c.Request.Context())
				if !ok || actor.ID != test.wantID {
					c.Status(http.StatusInternalServerError)
					return
				}
				c.Status(http.StatusOK)
			})
			request := httptest.NewRequest(http.MethodPost, "/api/v1/test", nil)
			request.Header.Set("Authorization", test.header)
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusOK {
				t.Fatalf("status = %d", recorder.Code)
			}
		})
	}
}

func TestAuthentication_PSKPrecedesSkipAndJWT(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)
	const key = "01234567890123456789012345678901"
	service := auth.New(config.Config{JWT: config.JWT{Issuer: "test", Secret: key, TTL: time.Hour}})
	for _, test := range []struct {
		name   string
		header string
		status int
	}{
		{name: "valid PSK", header: "PSK " + key, status: http.StatusOK},
		{name: "PSK route does not become public", status: http.StatusUnauthorized},
		{name: "bearer cannot access PSK route", header: "Bearer invalid", status: http.StatusUnauthorized},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			router := gin.New()
			router.Use(RequestID(), Authentication(service, slog.New(slog.NewTextHandler(io.Discard, nil)), config.Auth{
				SkipHTTPPaths: []string{"/api/v1/external/*"},
				PSK:           config.PSK{Enabled: true, Key: key, HTTPPaths: []string{"/api/v1/external/*"}},
			}))
			router.POST("/api/v1/external/callback", func(c *gin.Context) { OK(c, nil) })
			request := httptest.NewRequest(http.MethodPost, "/api/v1/external/callback", nil)
			request.Header.Set("Authorization", test.header)
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, request)
			if recorder.Code != test.status {
				t.Fatalf("status = %d, want %d", recorder.Code, test.status)
			}
		})
	}
}

func TestRequireJSON(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(RequestID(), RequireJSON())
	router.POST("/test", func(c *gin.Context) { OK(c, nil) })
	request := httptest.NewRequest(http.MethodPost, "/test", io.NopCloser(&oneByteReader{}))
	request.ContentLength = 1
	request.Header.Set("Content-Type", "text/plain")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d", recorder.Code)
	}
}

func TestTimeoutPropagatesCancellation(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	router := gin.New()
	router.Use(RequestID(), Timeout(time.Millisecond, logger))
	router.POST("/test", func(c *gin.Context) { <-c.Request.Context().Done() })
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/test", nil))
	if recorder.Code != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusGatewayTimeout)
	}
}

type oneByteReader struct{}

func (*oneByteReader) Read(buffer []byte) (int, error) { buffer[0] = 'x'; return 1, io.EOF }
