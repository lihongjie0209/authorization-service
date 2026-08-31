package httptransport

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lihongjie0209/authorization-service/internal/auth"
	"github.com/lihongjie0209/authorization-service/internal/config"
	platformauthz "github.com/lihongjie0209/microservice-platform-go/authz"
	"github.com/lihongjie0209/microservice-platform-go/principal"
)

type authorizationStub struct{ err error }

func (a authorizationStub) Authorize(context.Context, principal.Principal, platformauthz.Requirement) error {
	return a.err
}

func TestAuthorizationHTTPRequirementCoversManagementAndExcludesDecisions(t *testing.T) {
	t.Parallel()
	protected := []string{"/api/v1/authorization/permissions/create", "/api/v1/authorization/permissions/update", "/api/v1/authorization/permissions/list", "/api/v1/authorization/roles/create", "/api/v1/authorization/roles/update", "/api/v1/authorization/roles/list", "/api/v1/authorization/role-permissions/grant", "/api/v1/authorization/role-permissions/revoke", "/api/v1/authorization/role-permissions/list", "/api/v1/authorization/bindings/create", "/api/v1/authorization/bindings/revoke", "/api/v1/authorization/bindings/list"}
	for _, route := range protected {
		requirement, ok := authorizationHTTPRequirement(route)
		if !ok || requirement.Resource == "" || requirement.Action == "" || requirement.Scope != platformauthz.ScopePrincipal {
			t.Fatalf("route %q requirement = %+v, %v", route, requirement, ok)
		}
	}
	for _, route := range []string{"/api/v1/authorization/check", "/api/v1/authorization/batch-check", "/api/v1/version", "/api/v1/me"} {
		if _, ok := authorizationHTTPRequirement(route); ok {
			t.Fatalf("decision/operational route %q must not recurse", route)
		}
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
