package requestmeta

import "context"

type metadata struct {
	clientIP  string
	userAgent string
}

type contextKey struct{}

func WithContext(ctx context.Context, clientIP, userAgent string) context.Context {
	return context.WithValue(ctx, contextKey{}, metadata{clientIP: clientIP, userAgent: userAgent})
}

func FromContext(ctx context.Context) (clientIP, userAgent string) {
	value, _ := ctx.Value(contextKey{}).(metadata)
	return value.clientIP, value.userAgent
}
