package store

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/google/uuid"

	"github.com/openshift/rosa-regional-frontend-api/pkg/authz/client"
)

// TargetType represents the type of attachment target
type TargetType string

const (
	TargetTypeUser  TargetType = "user"
	TargetTypeGroup TargetType = "group"
)

// Attachment represents a policy attachment to a user or group
type Attachment struct {
	AccountID    string     `dynamodbav:"accountId" json:"accountId"`
	AttachmentID string     `dynamodbav:"attachmentId" json:"attachmentId"`
	PolicyID     string     `dynamodbav:"policyId" json:"policyId"`
	TargetType   TargetType `dynamodbav:"targetType" json:"targetType"`
	TargetID     string     `dynamodbav:"targetId" json:"targetId"`
	AVPPolicyID  string     `dynamodbav:"avpPolicyId" json:"avpPolicyId"`
	CreatedAt    string     `dynamodbav:"createdAt" json:"createdAt"`
	// GSI attributes
	AccountIDTargetTypeTargetID string `dynamodbav:"accountId#targetType#targetId" json:"-"`
	AccountIDPolicyID           string `dynamodbav:"accountId#policyId" json:"-"`
}

// AttachmentFilter defines filter options for listing attachments
type AttachmentFilter struct {
	PolicyID   string
	TargetType TargetType
	TargetID   string
}

// AttachmentStore provides CRUD operations for policy attachments
type AttachmentStore struct {
	tableName    string
	dynamoClient client.DynamoDBClient
	logger       *slog.Logger
}

// NewAttachmentStore creates a new attachment store
func NewAttachmentStore(tableName string, dynamoClient client.DynamoDBClient, logger *slog.Logger) *AttachmentStore {
	return &AttachmentStore{
		tableName:    tableName,
		dynamoClient: dynamoClient,
		logger:       logger,
	}
}

// Create creates a new policy attachment
func (s *AttachmentStore) Create(ctx context.Context, accountID, policyID string, targetType TargetType, targetID, avpPolicyID string) (*Attachment, error) {
	a := &Attachment{
		AccountID:                   accountID,
		AttachmentID:                uuid.New().String(),
		PolicyID:                    policyID,
		TargetType:                  targetType,
		TargetID:                    targetID,
		AVPPolicyID:                 avpPolicyID,
		CreatedAt:                   time.Now().UTC().Format(time.RFC3339),
		AccountIDTargetTypeTargetID: fmt.Sprintf("%s#%s#%s", accountID, targetType, targetID),
		AccountIDPolicyID:           fmt.Sprintf("%s#%s", accountID, policyID),
	}

	item, err := attributevalue.MarshalMap(a)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal attachment: %w", err)
	}

	_, err = s.dynamoClient.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(s.tableName),
		Item:      item,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create attachment: %w", err)
	}

	s.logger.Info("attachment created",
		"account_id", accountID,
		"attachment_id", a.AttachmentID,
		"policy_id", policyID,
		"target_type", targetType,
		"target_id", targetID,
	)
	return a, nil
}

// Get retrieves an attachment by ID
func (s *AttachmentStore) Get(ctx context.Context, accountID, attachmentID string) (*Attachment, error) {
	result, err := s.dynamoClient.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(s.tableName),
		Key: map[string]types.AttributeValue{
			"accountId":    &types.AttributeValueMemberS{Value: accountID},
			"attachmentId": &types.AttributeValueMemberS{Value: attachmentID},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get attachment: %w", err)
	}

	if result.Item == nil {
		return nil, nil
	}

	var a Attachment
	if err := attributevalue.UnmarshalMap(result.Item, &a); err != nil {
		return nil, fmt.Errorf("failed to unmarshal attachment: %w", err)
	}

	return &a, nil
}

// Delete removes an attachment
func (s *AttachmentStore) Delete(ctx context.Context, accountID, attachmentID string) error {
	_, err := s.dynamoClient.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(s.tableName),
		Key: map[string]types.AttributeValue{
			"accountId":    &types.AttributeValueMemberS{Value: accountID},
			"attachmentId": &types.AttributeValueMemberS{Value: attachmentID},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to delete attachment: %w", err)
	}

	s.logger.Info("attachment deleted", "account_id", accountID, "attachment_id", attachmentID)
	return nil
}

// List returns all attachments for an account
func (s *AttachmentStore) List(ctx context.Context, accountID string) ([]*Attachment, error) {
	result, err := s.dynamoClient.Query(ctx, &dynamodb.QueryInput{
		TableName:              aws.String(s.tableName),
		KeyConditionExpression: aws.String("accountId = :aid"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":aid": &types.AttributeValueMemberS{Value: accountID},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list attachments: %w", err)
	}

	attachments := make([]*Attachment, 0, len(result.Items))
	for _, item := range result.Items {
		var a Attachment
		if err := attributevalue.UnmarshalMap(item, &a); err != nil {
			return nil, fmt.Errorf("failed to unmarshal attachment: %w", err)
		}
		attachments = append(attachments, &a)
	}

	return attachments, nil
}

// ListByTarget returns attachments for a specific target using the target-index GSI
func (s *AttachmentStore) ListByTarget(ctx context.Context, accountID string, targetType TargetType, targetID string) ([]*Attachment, error) {
	result, err := s.dynamoClient.Query(ctx, &dynamodb.QueryInput{
		TableName:              aws.String(s.tableName),
		IndexName:              aws.String("target-index"),
		KeyConditionExpression: aws.String("#pk = :pk"),
		ExpressionAttributeNames: map[string]string{
			"#pk": "accountId#targetType#targetId",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": &types.AttributeValueMemberS{Value: fmt.Sprintf("%s#%s#%s", accountID, targetType, targetID)},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list attachments by target: %w", err)
	}

	attachments := make([]*Attachment, 0, len(result.Items))
	for _, item := range result.Items {
		var a Attachment
		if err := attributevalue.UnmarshalMap(item, &a); err != nil {
			return nil, fmt.Errorf("failed to unmarshal attachment: %w", err)
		}
		attachments = append(attachments, &a)
	}

	return attachments, nil
}

// ListByPolicy returns attachments for a specific policy using the policy-index GSI
func (s *AttachmentStore) ListByPolicy(ctx context.Context, accountID, policyID string) ([]*Attachment, error) {
	result, err := s.dynamoClient.Query(ctx, &dynamodb.QueryInput{
		TableName:              aws.String(s.tableName),
		IndexName:              aws.String("policy-index"),
		KeyConditionExpression: aws.String("#pk = :pk"),
		ExpressionAttributeNames: map[string]string{
			"#pk": "accountId#policyId",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": &types.AttributeValueMemberS{Value: fmt.Sprintf("%s#%s", accountID, policyID)},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list attachments by policy: %w", err)
	}

	attachments := make([]*Attachment, 0, len(result.Items))
	for _, item := range result.Items {
		var a Attachment
		if err := attributevalue.UnmarshalMap(item, &a); err != nil {
			return nil, fmt.Errorf("failed to unmarshal attachment: %w", err)
		}
		attachments = append(attachments, &a)
	}

	return attachments, nil
}

// ListFiltered returns attachments matching the filter criteria
func (s *AttachmentStore) ListFiltered(ctx context.Context, accountID string, filter AttachmentFilter) ([]*Attachment, error) {
	// If filtering by target, use the GSI
	if filter.TargetType != "" && filter.TargetID != "" {
		return s.ListByTarget(ctx, accountID, filter.TargetType, filter.TargetID)
	}

	// If filtering by policy, use the GSI
	if filter.PolicyID != "" {
		return s.ListByPolicy(ctx, accountID, filter.PolicyID)
	}

	// Otherwise, list all
	return s.List(ctx, accountID)
}
