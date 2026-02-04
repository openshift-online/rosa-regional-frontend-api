package privileged

import (
	"bufio"
	"context"
	"log/slog"
	"os"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/openshift/rosa-regional-frontend-api/pkg/authz/client"
)

// Checker provides privileged account checking from configmap and database
type Checker struct {
	configmapPath     string
	accountsTableName string
	dynamoClient      client.DynamoDBClient
	logger            *slog.Logger

	// Cache of configmap accounts (loaded once at startup)
	configmapAccounts map[string]struct{}
	configmapOnce     sync.Once
	configmapErr      error
}

// NewChecker creates a new privileged account checker
func NewChecker(configmapPath, accountsTableName string, dynamoClient client.DynamoDBClient, logger *slog.Logger) *Checker {
	return &Checker{
		configmapPath:     configmapPath,
		accountsTableName: accountsTableName,
		dynamoClient:      dynamoClient,
		logger:            logger,
	}
}

// IsPrivileged checks if an account is privileged (from configmap or database)
func (c *Checker) IsPrivileged(ctx context.Context, accountID string) (bool, error) {
	// Check configmap first (in-memory, no I/O after first load)
	if c.isInConfigmap(accountID) {
		return true, nil
	}

	// Check database
	return c.isPrivilegedInDB(ctx, accountID)
}

// isInConfigmap checks if the account is in the bootstrap configmap file
func (c *Checker) isInConfigmap(accountID string) bool {
	c.configmapOnce.Do(func() {
		c.configmapAccounts, c.configmapErr = c.loadConfigmap()
	})

	if c.configmapErr != nil {
		c.logger.Warn("failed to load privileged accounts configmap", "error", c.configmapErr)
		return false
	}

	_, exists := c.configmapAccounts[accountID]
	return exists
}

// loadConfigmap reads the configmap file containing privileged account IDs
func (c *Checker) loadConfigmap() (map[string]struct{}, error) {
	accounts := make(map[string]struct{})

	file, err := os.Open(c.configmapPath)
	if err != nil {
		if os.IsNotExist(err) {
			c.logger.Info("privileged accounts configmap not found, using empty list", "path", c.configmapPath)
			return accounts, nil
		}
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		accounts[line] = struct{}{}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	c.logger.Info("loaded privileged accounts from configmap", "count", len(accounts), "path", c.configmapPath)
	return accounts, nil
}

// isPrivilegedInDB checks if the account is marked as privileged in DynamoDB
func (c *Checker) isPrivilegedInDB(ctx context.Context, accountID string) (bool, error) {
	result, err := c.dynamoClient.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(c.accountsTableName),
		Key: map[string]types.AttributeValue{
			"accountId": &types.AttributeValueMemberS{Value: accountID},
		},
		ProjectionExpression: aws.String("privileged"),
	})
	if err != nil {
		return false, err
	}

	if result.Item == nil {
		return false, nil
	}

	var account struct {
		Privileged bool `dynamodbav:"privileged"`
	}
	if err := attributevalue.UnmarshalMap(result.Item, &account); err != nil {
		return false, err
	}

	return account.Privileged, nil
}

// ReloadConfigmap forces a reload of the configmap file (useful for testing or config updates)
func (c *Checker) ReloadConfigmap() error {
	accounts, err := c.loadConfigmap()
	if err != nil {
		return err
	}
	c.configmapAccounts = accounts
	return nil
}

// GetConfigmapAccounts returns the list of accounts from the configmap (for debugging)
func (c *Checker) GetConfigmapAccounts() []string {
	c.configmapOnce.Do(func() {
		c.configmapAccounts, c.configmapErr = c.loadConfigmap()
	})

	if c.configmapErr != nil {
		return nil
	}

	accounts := make([]string, 0, len(c.configmapAccounts))
	for acc := range c.configmapAccounts {
		accounts = append(accounts, acc)
	}
	return accounts
}
