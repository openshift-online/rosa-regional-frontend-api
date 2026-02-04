package store

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/google/uuid"

	"github.com/openshift/rosa-regional-frontend-api/pkg/authz/client"
	"github.com/openshift/rosa-regional-frontend-api/pkg/authz/policy"
)

// Policy represents a stored policy template
type Policy struct {
	AccountID   string `dynamodbav:"accountId" json:"accountId"`
	PolicyID    string `dynamodbav:"policyId" json:"policyId"`
	Name        string `dynamodbav:"name" json:"name"`
	Description string `dynamodbav:"description,omitempty" json:"description,omitempty"`
	V0PolicyRaw string `dynamodbav:"v0Policy" json:"-"`
	CreatedAt   string `dynamodbav:"createdAt" json:"createdAt"`
}

// GetV0Policy deserializes the v0 policy from JSON
func (p *Policy) GetV0Policy() (*policy.V0Policy, error) {
	var v0 policy.V0Policy
	if err := json.Unmarshal([]byte(p.V0PolicyRaw), &v0); err != nil {
		return nil, fmt.Errorf("failed to unmarshal v0 policy: %w", err)
	}
	return &v0, nil
}

// PolicyStore provides CRUD operations for policy templates
type PolicyStore struct {
	tableName    string
	dynamoClient client.DynamoDBClient
	logger       *slog.Logger
}

// NewPolicyStore creates a new policy store
func NewPolicyStore(tableName string, dynamoClient client.DynamoDBClient, logger *slog.Logger) *PolicyStore {
	return &PolicyStore{
		tableName:    tableName,
		dynamoClient: dynamoClient,
		logger:       logger,
	}
}

// Create creates a new policy template
func (s *PolicyStore) Create(ctx context.Context, accountID, name, description string, v0Policy *policy.V0Policy) (*Policy, error) {
	v0PolicyJSON, err := json.Marshal(v0Policy)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal v0 policy: %w", err)
	}

	p := &Policy{
		AccountID:   accountID,
		PolicyID:    uuid.New().String(),
		Name:        name,
		Description: description,
		V0PolicyRaw: string(v0PolicyJSON),
		CreatedAt:   time.Now().UTC().Format(time.RFC3339),
	}

	item, err := attributevalue.MarshalMap(p)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal policy: %w", err)
	}

	_, err = s.dynamoClient.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(s.tableName),
		Item:      item,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create policy: %w", err)
	}

	s.logger.Info("policy created", "account_id", accountID, "policy_id", p.PolicyID, "name", name)
	return p, nil
}

// Get retrieves a policy by ID
func (s *PolicyStore) Get(ctx context.Context, accountID, policyID string) (*Policy, error) {
	result, err := s.dynamoClient.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(s.tableName),
		Key: map[string]types.AttributeValue{
			"accountId": &types.AttributeValueMemberS{Value: accountID},
			"policyId":  &types.AttributeValueMemberS{Value: policyID},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get policy: %w", err)
	}

	if result.Item == nil {
		return nil, nil
	}

	var p Policy
	if err := attributevalue.UnmarshalMap(result.Item, &p); err != nil {
		return nil, fmt.Errorf("failed to unmarshal policy: %w", err)
	}

	return &p, nil
}

// Update updates a policy template
func (s *PolicyStore) Update(ctx context.Context, accountID, policyID, name, description string, v0Policy *policy.V0Policy) (*Policy, error) {
	v0PolicyJSON, err := json.Marshal(v0Policy)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal v0 policy: %w", err)
	}

	result, err := s.dynamoClient.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(s.tableName),
		Key: map[string]types.AttributeValue{
			"accountId": &types.AttributeValueMemberS{Value: accountID},
			"policyId":  &types.AttributeValueMemberS{Value: policyID},
		},
		UpdateExpression: aws.String("SET #n = :name, description = :desc, v0Policy = :v0p"),
		ExpressionAttributeNames: map[string]string{
			"#n": "name",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":name": &types.AttributeValueMemberS{Value: name},
			":desc": &types.AttributeValueMemberS{Value: description},
			":v0p":  &types.AttributeValueMemberS{Value: string(v0PolicyJSON)},
		},
		ReturnValues: types.ReturnValueAllNew,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to update policy: %w", err)
	}

	var p Policy
	if err := attributevalue.UnmarshalMap(result.Attributes, &p); err != nil {
		return nil, fmt.Errorf("failed to unmarshal policy: %w", err)
	}

	s.logger.Info("policy updated", "account_id", accountID, "policy_id", policyID)
	return &p, nil
}

// Delete removes a policy template
func (s *PolicyStore) Delete(ctx context.Context, accountID, policyID string) error {
	_, err := s.dynamoClient.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(s.tableName),
		Key: map[string]types.AttributeValue{
			"accountId": &types.AttributeValueMemberS{Value: accountID},
			"policyId":  &types.AttributeValueMemberS{Value: policyID},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to delete policy: %w", err)
	}

	s.logger.Info("policy deleted", "account_id", accountID, "policy_id", policyID)
	return nil
}

// List returns all policies for an account
func (s *PolicyStore) List(ctx context.Context, accountID string) ([]*Policy, error) {
	result, err := s.dynamoClient.Query(ctx, &dynamodb.QueryInput{
		TableName:              aws.String(s.tableName),
		KeyConditionExpression: aws.String("accountId = :aid"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":aid": &types.AttributeValueMemberS{Value: accountID},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list policies: %w", err)
	}

	policies := make([]*Policy, 0, len(result.Items))
	for _, item := range result.Items {
		var p Policy
		if err := attributevalue.UnmarshalMap(item, &p); err != nil {
			return nil, fmt.Errorf("failed to unmarshal policy: %w", err)
		}
		policies = append(policies, &p)
	}

	return policies, nil
}
