package dynamodb

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/openshift/rosa-regional-frontend-api/pkg/config"
)

const (
	defaultCacheTTL = 5 * time.Minute
)

type cacheEntry struct {
	account   *CustomerAccount
	expiresAt time.Time
}

// Client provides access to customer account data in DynamoDB
type Client struct {
	client    *dynamodb.Client
	tableName string
	logger    *slog.Logger

	// Cache for hits only (misses are not cached)
	cache   map[string]cacheEntry
	cacheMu sync.RWMutex
	ttl     time.Duration
}

// NewClient creates a new DynamoDB client
func NewClient(ctx context.Context, cfg config.DynamoDBConfig, logger *slog.Logger) (*Client, error) {
	var opts []func(*awsconfig.LoadOptions) error
	opts = append(opts, awsconfig.WithRegion(cfg.Region))

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, err
	}

	var ddbOpts []func(*dynamodb.Options)
	if cfg.Endpoint != "" {
		ddbOpts = append(ddbOpts, func(o *dynamodb.Options) {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
		})
	}

	client := dynamodb.NewFromConfig(awsCfg, ddbOpts...)

	return &Client{
		client:    client,
		tableName: cfg.TableName,
		logger:    logger,
		cache:     make(map[string]cacheEntry),
		ttl:       defaultCacheTTL,
	}, nil
}

// GetAccount retrieves a customer account by AWS account ID
// Returns nil if the account is not found (not an error)
// Caches hits for performance
func (c *Client) GetAccount(ctx context.Context, accountID string) (*CustomerAccount, error) {
	// Check cache first
	if account := c.getFromCache(accountID); account != nil {
		c.logger.Debug("cache hit for account", "account_id", accountID)
		return account, nil
	}

	c.logger.Debug("cache miss, querying DynamoDB", "account_id", accountID)

	result, err := c.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(c.tableName),
		Key: map[string]types.AttributeValue{
			"account_id": &types.AttributeValueMemberS{Value: accountID},
		},
	})
	if err != nil {
		return nil, err
	}

	if result.Item == nil {
		// Account not found - do not cache misses
		return nil, nil
	}

	var account CustomerAccount
	if err := attributevalue.UnmarshalMap(result.Item, &account); err != nil {
		return nil, err
	}

	// Cache the hit
	c.putInCache(accountID, &account)

	return &account, nil
}

func (c *Client) getFromCache(accountID string) *CustomerAccount {
	c.cacheMu.RLock()
	defer c.cacheMu.RUnlock()

	entry, ok := c.cache[accountID]
	if !ok {
		return nil
	}

	if time.Now().After(entry.expiresAt) {
		return nil
	}

	return entry.account
}

func (c *Client) putInCache(accountID string, account *CustomerAccount) {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()

	c.cache[accountID] = cacheEntry{
		account:   account,
		expiresAt: time.Now().Add(c.ttl),
	}
}

// InvalidateCache removes an account from the cache
func (c *Client) InvalidateCache(accountID string) {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()

	delete(c.cache, accountID)
}
