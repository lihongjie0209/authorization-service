package authorization

import (
	"testing"
	"time"

	"github.com/lihongjie0209/microservice-platform-go/eventbus"
	tenantv1 "github.com/lihongjie0209/platform-protos/gen/go/platform/tenant/v1"
)

func TestTenantBootstrapProjectionRejectsIncompleteOwnerEventBeforeDatabaseWork(t *testing.T) {
	t.Parallel()
	projection := &TenantBootstrapProjection{}
	if err := projection.Apply(t.Context(), nil); err == nil {
		t.Fatal("nil envelope must fail")
	}
	envelope, err := eventbus.NewEnvelope(eventbus.Metadata{
		EventID:       "event-1",
		EventType:     "platform.tenant.v1.TenantCreated",
		AggregateID:   "tenant-1",
		AggregateType: "tenant",
		TenantID:      "tenant-1",
		SchemaVersion: 1,
		OccurredAt:    time.Now(),
	}, &tenantv1.TenantCreatedEvent{Tenant: &tenantv1.Tenant{Id: "tenant-1"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := projection.Apply(t.Context(), envelope); err == nil {
		t.Fatal("missing owner membership must fail before transaction")
	}
}
