package app

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/jmoiron/sqlx"
	authorizationdomain "github.com/lihongjie0209/authorization-service/internal/authorization"
	"github.com/lihongjie0209/authorization-service/internal/config"
	"github.com/lihongjie0209/microservice-platform-go/eventbus"
	platformoutbox "github.com/lihongjie0209/microservice-platform-go/outbox"
	"go.uber.org/fx"
)

type eventRuntime struct {
	config  config.Config
	store   *platformoutbox.SQLStore
	groups  *authorizationdomain.GroupProjection
	tenants *authorizationdomain.TenantBootstrapProjection
	logger  *slog.Logger
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	bus     *eventbus.Bus
}

func newEventRuntime(lifecycle fx.Lifecycle, cfg config.Config, store *platformoutbox.SQLStore, groups *authorizationdomain.GroupProjection, tenants *authorizationdomain.TenantBootstrapProjection, logger *slog.Logger) *eventRuntime {
	runtime := &eventRuntime{config: cfg, store: store, groups: groups, tenants: tenants, logger: logger}
	lifecycle.Append(fx.Hook{OnStart: runtime.start, OnStop: runtime.stop})
	return runtime
}
func (r *eventRuntime) start(ctx context.Context) error {
	if !r.config.EventBus.Enabled {
		r.logger.Info("event bus is disabled")
		return nil
	}
	if r.store == nil {
		return errors.New("enabled event bus requires database outbox")
	}
	bus, err := eventbus.New(ctx, eventbus.Config{URLs: r.config.EventBus.URLs, ClientName: r.config.App.Name, StreamName: r.config.EventBus.StreamName, Subjects: []string{"platform.>"}, Storage: r.config.EventBus.Storage, MaxAge: r.config.EventBus.MaxAge, DuplicateWindow: r.config.EventBus.DuplicateWindow, ConnectTimeout: r.config.EventBus.ConnectTimeout, PublishTimeout: r.config.EventBus.PublishTimeout})
	if err != nil {
		return err
	}
	dispatcher, err := platformoutbox.New(r.store, bus, platformoutbox.Config{BatchSize: r.config.EventBus.DispatchBatchSize, Lease: r.config.EventBus.DispatchLease, RetryDelay: r.config.EventBus.DispatchRetryDelay})
	if err != nil {
		_ = bus.Close()
		return err
	}
	r.bus = bus
	runCtx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	cleaner, err := platformoutbox.NewRetentionCleaner(r.store, platformoutbox.RetentionConfig{Retention: r.config.EventBus.PublishedRetention, BatchSize: r.config.EventBus.CleanupBatchSize})
	if err != nil {
		cancel()
		_ = bus.Close()
		return err
	}
	r.wg.Go(func() { r.dispatch(runCtx, dispatcher) })
	r.wg.Go(func() { r.clean(runCtx, cleaner) })
	r.wg.Go(func() {
		if err := bus.Consume(runCtx, "authorization-tenant-groups-v1", "platform.tenant.group.changed.v1", r.groups.Apply); err != nil && !errors.Is(err, context.Canceled) {
			r.logger.ErrorContext(runCtx, "consume tenant group events failed", "error", err)
		}
	})
	r.wg.Go(func() {
		if err := bus.Consume(runCtx, "authorization-tenant-bootstrap-v1", "platform.tenant.tenant.created.v1", r.tenants.Apply); err != nil && !errors.Is(err, context.Canceled) {
			r.logger.ErrorContext(runCtx, "consume tenant created events failed", "error", err)
		}
	})
	r.logger.Info("event bus started", "stream", r.config.EventBus.StreamName)
	return nil
}
func (r *eventRuntime) clean(ctx context.Context, cleaner *platformoutbox.RetentionCleaner) {
	ticker := time.NewTicker(r.config.EventBus.CleanupInterval)
	defer ticker.Stop()
	for {
		if deleted, err := cleaner.RunOnce(ctx); err != nil && !errors.Is(err, context.Canceled) {
			r.logger.ErrorContext(ctx, "clean published authorization outbox events", "error", err)
		} else if deleted > 0 {
			r.logger.InfoContext(ctx, "published authorization outbox events cleaned", "deleted", deleted)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
func (r *eventRuntime) dispatch(ctx context.Context, dispatcher *platformoutbox.Dispatcher) {
	ticker := time.NewTicker(r.config.EventBus.DispatchInterval)
	defer ticker.Stop()
	for {
		if _, err := dispatcher.RunOnce(ctx); err != nil && !errors.Is(err, context.Canceled) {
			r.logger.ErrorContext(ctx, "dispatch authorization outbox failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
func (r *eventRuntime) stop(context.Context) error {
	if r.cancel != nil {
		r.cancel()
		r.wg.Wait()
	}
	if r.bus != nil {
		return r.bus.Close()
	}
	return nil
}

func newAuthorizationOutboxStore(db *sqlx.DB) (*platformoutbox.SQLStore, error) {
	if db == nil {
		return nil, nil
	}
	return platformoutbox.NewSQLStore(db, "authorization_outbox_events")
}

var EventBusModule = fx.Module("event-bus", fx.Provide(newAuthorizationOutboxStore, newEventRuntime), fx.Invoke(func(*eventRuntime) {}))
