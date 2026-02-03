package maestro

import "context"

// ClientInterface defines the interface for Maestro API operations
type ClientInterface interface {
	CreateConsumer(ctx context.Context, req *ConsumerCreateRequest) (*Consumer, error)
	ListConsumers(ctx context.Context, page, size int) (*ConsumerList, error)
	GetConsumer(ctx context.Context, id string) (*Consumer, error)
	ListResourceBundles(ctx context.Context, page, size int, search, orderBy, fields string) (*ResourceBundleList, error)
}

// Ensure Client implements ClientInterface
var _ ClientInterface = (*Client)(nil)
