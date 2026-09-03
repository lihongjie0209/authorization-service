package httptransport

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	stdpprof "net/http/pprof"
	"strings"

	"github.com/gin-gonic/gin"
	docs "github.com/lihongjie0209/authorization-service/docs"
	"github.com/lihongjie0209/authorization-service/internal/auth"
	"github.com/lihongjie0209/authorization-service/internal/buildinfo"
	"github.com/lihongjie0209/authorization-service/internal/config"
	"github.com/lihongjie0209/authorization-service/internal/health"
	"github.com/lihongjie0209/authorization-service/internal/idempotency"
	"github.com/lihongjie0209/authorization-service/internal/observability"
	"github.com/lihongjie0209/authorization-service/internal/ratelimit"
	platformauthz "github.com/lihongjie0209/microservice-platform-go/authz"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
	"go.uber.org/fx"
)

func NewServer(lc fx.Lifecycle, cfg config.Config, handler *Handler, authService *auth.Service, authorizer platformauthz.Authorizer, limiter *ratelimit.Limiter, idempotencyManager *idempotency.Manager, metrics *observability.Metrics, tracing *observability.Tracing, logger *slog.Logger) (*http.Server, error) {
	if cfg.App.Env == "production" {
		gin.SetMode(gin.ReleaseMode)
	}
	router := gin.New()
	if err := router.SetTrustedProxies(cfg.HTTP.TrustedProxies); err != nil {
		return nil, fmt.Errorf("configure trusted proxies: %w", err)
	}
	_ = tracing
	router.Use(RequestID(), IdempotencyKey(logger), Environment(cfg.Runtime.ActiveProfile), otelgin.Middleware(cfg.App.Name), RequestLogger(logger), Recovery(logger), HTTPMetrics(metrics), SecurityHeaders(), CORS(cfg.HTTP.CORS), MaxBody(cfg.HTTP.MaxBodyBytes), Timeout(cfg.HTTP.RequestTimeout, logger), RequireJSON())
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		router.Handle(method, "/live", handler.Live)
		router.Handle(method, "/ready", handler.Ready)
	}
	if metrics.Enabled() {
		router.GET("/metrics", gin.WrapH(metrics.Handler()))
	}
	if cfg.Observability.PprofEnabled {
		registerPprof(router.Group("/debug/pprof", pprofAuth(cfg.Observability.PprofToken)))
	}
	if cfg.Swagger.Enabled {
		docs.SwaggerInfo.Version = buildinfo.Version
		swagger := router.Group("/swagger")
		if cfg.Swagger.RequireAuth {
			swagger.Use(JWT(authService, logger))
		}
		swagger.GET("/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	}
	api := router.Group("/api/v1", RateLimit(limiter, cfg.RateLimit.IP, "ip", func(c *gin.Context) string { return c.ClientIP() }, logger), RateLimit(limiter, cfg.RateLimit.API, "api", func(c *gin.Context) string { return c.FullPath() }, logger), Authentication(authService, logger, cfg.Auth), Authorization(cfg.Authorization.Enabled, authorizer, logger), RateLimit(limiter, cfg.RateLimit.User, "user", func(c *gin.Context) string {
		value, _ := c.Get("subject")
		subject, _ := value.(string)
		return subject
	}, logger))
	api.Use(IdempotencyExecution(idempotencyManager, cfg.Idempotency.HTTPPaths, logger))
	api.POST("/version", handler.Version)
	api.POST("/me", handler.Me)
	api.POST("/authorization/permissions/create", handler.CreatePermission)
	api.POST("/authorization/permissions/update", handler.UpdatePermission)
	api.POST("/authorization/permissions/list", handler.ListPermissions)
	api.POST("/authorization/my-permission-catalog/list", handler.ListMyPermissionCatalog)
	api.POST("/authorization/my-permissions/create", handler.CreateMyPermission)
	api.POST("/authorization/my-permissions/update", handler.UpdateMyPermission)
	api.POST("/authorization/my-permissions/list", handler.ListMyPermissions)
	api.POST("/authorization/roles/create", handler.CreateRole)
	api.POST("/authorization/roles/update", handler.UpdateRole)
	api.POST("/authorization/roles/list", handler.ListRoles)
	api.POST("/authorization/my-roles/create", handler.CreateMyRole)
	api.POST("/authorization/my-roles/update", handler.UpdateMyRole)
	api.POST("/authorization/my-roles/list", handler.ListMyRoles)
	api.POST("/authorization/my-roles/batch-get", handler.BatchGetMyRoles)
	api.POST("/authorization/role-permissions/grant", handler.GrantRolePermission)
	api.POST("/authorization/role-permissions/revoke", handler.RevokeRolePermission)
	api.POST("/authorization/role-permissions/list", handler.ListRolePermissions)
	api.POST("/authorization/my-role-permissions/grant", handler.GrantMyRolePermission)
	api.POST("/authorization/my-role-permissions/revoke", handler.RevokeMyRolePermission)
	api.POST("/authorization/my-role-permissions/list", handler.ListMyRolePermissions)
	api.POST("/authorization/bindings/create", handler.CreateBinding)
	api.POST("/authorization/bindings/revoke", handler.RevokeBinding)
	api.POST("/authorization/bindings/list", handler.ListBindings)
	api.POST("/authorization/my-bindings/create", handler.CreateMyBinding)
	api.POST("/authorization/my-bindings/revoke", handler.RevokeMyBinding)
	api.POST("/authorization/my-bindings/list", handler.ListMyBindings)
	api.POST("/authorization/check", handler.CheckAuthorization)
	api.POST("/authorization/batch-check", handler.BatchCheckAuthorization)
	api.POST("/authorization/my-permissions/check", handler.CheckMyPermissionCodes)
	server := &http.Server{Addr: cfg.HTTP.Address, Handler: router, ReadTimeout: cfg.HTTP.ReadTimeout, WriteTimeout: cfg.HTTP.WriteTimeout, IdleTimeout: cfg.HTTP.IdleTimeout}
	var listener net.Listener
	lc.Append(fx.Hook{OnStart: func(context.Context) error {
		var err error
		listener, err = net.Listen("tcp", server.Addr)
		if err != nil {
			return fmt.Errorf("listen http: %w", err)
		}
		go func() {
			if serveErr := server.Serve(listener); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
				logger.Error("http server stopped unexpectedly", "error", serveErr)
			}
		}()
		logger.Info("http server started", "address", server.Addr)
		return nil
	}, OnStop: func(ctx context.Context) error { return server.Shutdown(ctx) }})
	return server, nil
}

func pprofAuth(expected string) gin.HandlerFunc {
	return func(c *gin.Context) {
		scheme, token, ok := strings.Cut(c.GetHeader("Authorization"), " ")
		if !ok || !strings.EqualFold(scheme, "Bearer") || subtle.ConstantTimeCompare([]byte(token), []byte(expected)) != 1 {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.Next()
	}
}

func registerPprof(group *gin.RouterGroup) {
	group.GET("/", gin.WrapF(stdpprof.Index))
	group.GET("/cmdline", gin.WrapF(stdpprof.Cmdline))
	group.GET("/profile", gin.WrapF(stdpprof.Profile))
	group.POST("/symbol", gin.WrapF(stdpprof.Symbol))
	group.GET("/symbol", gin.WrapF(stdpprof.Symbol))
	group.GET("/trace", gin.WrapF(stdpprof.Trace))
	for _, profile := range []string{"allocs", "block", "goroutine", "heap", "mutex", "threadcreate"} {
		group.GET("/"+profile, gin.WrapH(stdpprof.Handler(profile)))
	}
}

var Module = fx.Module("http", fx.Provide(auth.NewRuntime, health.New, ratelimit.New, NewHandler, NewServer), fx.Invoke(func(*http.Server) {}))
