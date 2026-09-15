package requestmeta

import "testing"

func TestContextRoundTrip(t *testing.T) {
	ctx := WithContext(t.Context(), "203.0.113.8", "test-agent/1.0")
	clientIP, userAgent := FromContext(ctx)
	if clientIP != "203.0.113.8" || userAgent != "test-agent/1.0" {
		t.Fatalf("FromContext() = %q, %q", clientIP, userAgent)
	}
}
