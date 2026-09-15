package authorization

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/lihongjie0209/authorization-service/internal/database"
)

func TestDecisionCacheRuntimeRedisInvalidation(t *testing.T) {
	repository := &fakeRepository{policyVersion: 1}
	service := NewService(repository, &database.Transactor{})
	if _, err := service.Check(t.Context(), "tenant-1", "membership-1", "membership", "invoice", "read"); err != nil {
		t.Fatal(err)
	}
	runtime := &DecisionCacheRuntime{service: service, repository: repository, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	runtime.handleMessage(`{"tenant_id":"tenant-1","policy_version":2}`)
	if _, err := service.Check(t.Context(), "tenant-1", "membership-1", "membership", "invoice", "read"); err != nil {
		t.Fatal(err)
	}
	if repository.resolveCalls != 2 {
		t.Fatalf("Resolve calls = %d, want 2", repository.resolveCalls)
	}
}

func TestDecisionCacheRuntimePollRepairsMissedInvalidation(t *testing.T) {
	repository := &fakeRepository{policyVersion: 1}
	service := NewService(repository, &database.Transactor{})
	service.cacheTTL = time.Hour
	if _, err := service.Check(t.Context(), "tenant-1", "membership-1", "membership", "invoice", "read"); err != nil {
		t.Fatal(err)
	}
	repository.policyVersion = 2
	runtime := &DecisionCacheRuntime{service: service, repository: repository, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	runtime.repair(context.Background())
	decision, err := service.Check(t.Context(), "tenant-1", "membership-1", "membership", "invoice", "read")
	if err != nil {
		t.Fatal(err)
	}
	if repository.resolveCalls != 2 || decision.PolicyVersion != 2 {
		t.Fatalf("Resolve calls = %d, policy version = %d", repository.resolveCalls, decision.PolicyVersion)
	}
}
