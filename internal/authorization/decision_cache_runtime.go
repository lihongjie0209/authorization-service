package authorization

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/lihongjie0209/authorization-service/internal/config"
	"github.com/lihongjie0209/authorization-service/internal/observability"
	"github.com/redis/go-redis/v9"
	"go.uber.org/fx"
)

type decisionInvalidation struct {
	TenantID      string `json:"tenant_id"`
	PolicyVersion uint64 `json:"policy_version"`
}

type DecisionCacheRuntime struct {
	service    *Service
	repository Repository
	redis      *redis.Client
	channel    string
	interval   time.Duration
	logger     *slog.Logger
	metrics    *observability.Metrics
	cancel     context.CancelFunc
	wg         sync.WaitGroup
}

func NewDecisionCacheRuntime(lifecycle fx.Lifecycle, service *Service, repository Repository, client *redis.Client, cfg config.Config, logger *slog.Logger, metrics *observability.Metrics) *DecisionCacheRuntime {
	interval := cfg.Authorization.PolicyRefreshInterval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	runtime := &DecisionCacheRuntime{service: service, repository: repository, redis: client, channel: cfg.Runtime.ActiveProfile + ":" + cfg.App.Name + ":decision-cache:changed", interval: interval, logger: logger, metrics: metrics}
	if cfg.Authorization.DecisionCacheTTL > 0 {
		service.cacheTTL = cfg.Authorization.DecisionCacheTTL
	}
	service.notify = runtime.Notify
	lifecycle.Append(fx.Hook{OnStart: runtime.start, OnStop: runtime.stop})
	return runtime
}

func (r *DecisionCacheRuntime) start(context.Context) error {
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.wg.Go(func() { r.run(ctx) })
	return nil
}

func (r *DecisionCacheRuntime) stop(context.Context) error {
	if r.cancel != nil {
		r.cancel()
		r.wg.Wait()
	}
	return nil
}

func (r *DecisionCacheRuntime) Notify(ctx context.Context, tenantID string, policyVersion uint64) {
	if r.redis == nil {
		return
	}
	payload, err := json.Marshal(decisionInvalidation{TenantID: tenantID, PolicyVersion: policyVersion})
	if err == nil {
		err = r.redis.Publish(ctx, r.channel, payload).Err()
	}
	r.observe("publish", err)
	if err != nil {
		r.logger.WarnContext(ctx, "publish decision cache invalidation", "tenant_id", tenantID, "error", err)
	}
}

func (r *DecisionCacheRuntime) run(ctx context.Context) {
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	var messages <-chan *redis.Message
	if r.redis != nil {
		subscription := r.redis.Subscribe(ctx, r.channel)
		defer func() { _ = subscription.Close() }()
		messages = subscription.Channel()
	}
	for {
		select {
		case <-ctx.Done():
			return
		case message := <-messages:
			if message != nil {
				r.handleMessage(message.Payload)
			}
		case <-ticker.C:
			r.repair(ctx)
		}
	}
}

func (r *DecisionCacheRuntime) handleMessage(payload string) {
	var message decisionInvalidation
	err := json.Unmarshal([]byte(payload), &message)
	if err == nil && message.TenantID != "" {
		r.service.invalidateTenant(message.TenantID)
	} else if err == nil {
		err = errors.New("empty tenant id")
	}
	r.observe("redis", err)
	if err != nil {
		r.logger.Warn("decode decision cache invalidation", "error", err)
	}
}

func (r *DecisionCacheRuntime) repair(ctx context.Context) {
	for tenantID, cachedVersion := range r.service.cachedTenantVersions() {
		currentVersion, err := r.repository.PolicyVersion(ctx, tenantID)
		if err == nil && currentVersion != cachedVersion {
			r.service.invalidateTenant(tenantID)
		}
		r.observe("poll", err)
		if err != nil {
			r.logger.WarnContext(ctx, "check authorization policy version", "tenant_id", tenantID, "error", err)
		}
	}
}

func (r *DecisionCacheRuntime) observe(source string, err error) {
	if r.metrics == nil || !r.metrics.Enabled() {
		return
	}
	status := "success"
	if err != nil {
		status = "failure"
	}
	r.metrics.DecisionCacheInvalidation.WithLabelValues(source, status).Inc()
}
