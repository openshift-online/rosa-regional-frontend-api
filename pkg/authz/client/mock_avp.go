package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/verifiedpermissions"
	avptypes "github.com/aws/aws-sdk-go-v2/service/verifiedpermissions/types"
	"github.com/google/uuid"
)

// MockAVPClient implements AVPClient using cedar-agent for local testing.
// It delegates all policy storage and authorization to cedar-agent.
type MockAVPClient struct {
	cedarAgentURL string
	httpClient    *http.Client
	logger        *slog.Logger
}

// NewMockAVPClient creates a new MockAVPClient that uses cedar-agent for policy evaluation.
func NewMockAVPClient(cedarAgentURL string, logger *slog.Logger) *MockAVPClient {
	return &MockAVPClient{
		cedarAgentURL: strings.TrimSuffix(cedarAgentURL, "/"),
		httpClient:    &http.Client{Timeout: 30 * time.Second},
		logger:        logger,
	}
}

// clearPolicies removes all policies from cedar-agent.
func (m *MockAVPClient) clearPolicies(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, m.cedarAgentURL+"/v1/policies", strings.NewReader("[]"))
	if err != nil {
		return fmt.Errorf("failed to create clear request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to clear policies: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("clear policies failed with status %d: %s", resp.StatusCode, string(body))
	}

	m.logger.Debug("cleared all policies from cedar-agent")
	return nil
}

// postPolicy adds a single policy to cedar-agent.
func (m *MockAVPClient) postPolicy(ctx context.Context, policyID, cedarPolicy string) error {
	payload := map[string]string{
		"id":      policyID,
		"content": cedarPolicy,
	}

	reqBody, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal policy: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.cedarAgentURL+"/v1/policies", bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("failed to create policy request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("policy request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("post policy failed with status %d: %s", resp.StatusCode, string(body))
	}

	m.logger.Debug("posted policy to cedar-agent", "policy_id", policyID)
	return nil
}

// CreatePolicyStore returns a dummy policy store ID.
// Cedar-agent doesn't have the concept of policy stores.
func (m *MockAVPClient) CreatePolicyStore(ctx context.Context, params *verifiedpermissions.CreatePolicyStoreInput, optFns ...func(*verifiedpermissions.Options)) (*verifiedpermissions.CreatePolicyStoreOutput, error) {
	storeID := uuid.New().String()

	m.logger.Debug("created mock policy store", "policy_store_id", storeID)

	now := time.Now()
	return &verifiedpermissions.CreatePolicyStoreOutput{
		PolicyStoreId:   aws.String(storeID),
		Arn:             aws.String(fmt.Sprintf("arn:aws:verifiedpermissions::local:policy-store/%s", storeID)),
		CreatedDate:     &now,
		LastUpdatedDate: &now,
	}, nil
}

// DeletePolicyStore is a no-op since we don't track stores.
func (m *MockAVPClient) DeletePolicyStore(ctx context.Context, params *verifiedpermissions.DeletePolicyStoreInput, optFns ...func(*verifiedpermissions.Options)) (*verifiedpermissions.DeletePolicyStoreOutput, error) {
	return &verifiedpermissions.DeletePolicyStoreOutput{}, nil
}

// GetPolicyStore returns dummy policy store info.
func (m *MockAVPClient) GetPolicyStore(ctx context.Context, params *verifiedpermissions.GetPolicyStoreInput, optFns ...func(*verifiedpermissions.Options)) (*verifiedpermissions.GetPolicyStoreOutput, error) {
	storeID := aws.ToString(params.PolicyStoreId)
	now := time.Now()
	return &verifiedpermissions.GetPolicyStoreOutput{
		PolicyStoreId:   aws.String(storeID),
		Arn:             aws.String(fmt.Sprintf("arn:aws:verifiedpermissions::local:policy-store/%s", storeID)),
		CreatedDate:     &now,
		LastUpdatedDate: &now,
	}, nil
}

// CreatePolicy clears cedar-agent and adds the new policy.
func (m *MockAVPClient) CreatePolicy(ctx context.Context, params *verifiedpermissions.CreatePolicyInput, optFns ...func(*verifiedpermissions.Options)) (*verifiedpermissions.CreatePolicyOutput, error) {
	storeID := aws.ToString(params.PolicyStoreId)
	policyID := uuid.New().String()

	// Extract Cedar policy from the definition
	var cedarPolicy string
	if staticDef, ok := params.Definition.(*avptypes.PolicyDefinitionMemberStatic); ok {
		cedarPolicy = aws.ToString(staticDef.Value.Statement)
	} else {
		return nil, fmt.Errorf("only static policy definitions are supported")
	}

	// Clear all existing policies first
	if err := m.clearPolicies(ctx); err != nil {
		m.logger.Warn("failed to clear policies", "error", err)
	}

	// Post the new policy
	if err := m.postPolicy(ctx, policyID, cedarPolicy); err != nil {
		return nil, fmt.Errorf("failed to post policy: %w", err)
	}

	m.logger.Info("created policy", "policy_store_id", storeID, "policy_id", policyID)

	now := time.Now()
	return &verifiedpermissions.CreatePolicyOutput{
		PolicyStoreId:   aws.String(storeID),
		PolicyId:        aws.String(policyID),
		PolicyType:      avptypes.PolicyTypeStatic,
		CreatedDate:     &now,
		LastUpdatedDate: &now,
	}, nil
}

// DeletePolicy clears all policies from cedar-agent.
func (m *MockAVPClient) DeletePolicy(ctx context.Context, params *verifiedpermissions.DeletePolicyInput, optFns ...func(*verifiedpermissions.Options)) (*verifiedpermissions.DeletePolicyOutput, error) {
	if err := m.clearPolicies(ctx); err != nil {
		m.logger.Warn("failed to clear policies on delete", "error", err)
	}

	m.logger.Debug("deleted policy", "policy_id", aws.ToString(params.PolicyId))
	return &verifiedpermissions.DeletePolicyOutput{}, nil
}

// GetPolicy is not fully implemented - returns empty policy.
func (m *MockAVPClient) GetPolicy(ctx context.Context, params *verifiedpermissions.GetPolicyInput, optFns ...func(*verifiedpermissions.Options)) (*verifiedpermissions.GetPolicyOutput, error) {
	storeID := aws.ToString(params.PolicyStoreId)
	policyID := aws.ToString(params.PolicyId)

	now := time.Now()
	return &verifiedpermissions.GetPolicyOutput{
		PolicyStoreId: aws.String(storeID),
		PolicyId:      aws.String(policyID),
		PolicyType:    avptypes.PolicyTypeStatic,
		Definition: &avptypes.PolicyDefinitionDetailMemberStatic{
			Value: avptypes.StaticPolicyDefinitionDetail{
				Statement: aws.String(""),
			},
		},
		CreatedDate:     &now,
		LastUpdatedDate: &now,
	}, nil
}

// UpdatePolicy clears and re-adds the policy.
func (m *MockAVPClient) UpdatePolicy(ctx context.Context, params *verifiedpermissions.UpdatePolicyInput, optFns ...func(*verifiedpermissions.Options)) (*verifiedpermissions.UpdatePolicyOutput, error) {
	storeID := aws.ToString(params.PolicyStoreId)
	policyID := aws.ToString(params.PolicyId)

	// Extract Cedar policy from the definition
	var cedarPolicy string
	if staticDef, ok := params.Definition.(*avptypes.UpdatePolicyDefinitionMemberStatic); ok {
		cedarPolicy = aws.ToString(staticDef.Value.Statement)
	} else {
		return nil, fmt.Errorf("only static policy definitions are supported")
	}

	// Clear and re-add
	if err := m.clearPolicies(ctx); err != nil {
		m.logger.Warn("failed to clear policies", "error", err)
	}

	if err := m.postPolicy(ctx, policyID, cedarPolicy); err != nil {
		return nil, fmt.Errorf("failed to post policy: %w", err)
	}

	m.logger.Info("updated policy", "policy_store_id", storeID, "policy_id", policyID)

	now := time.Now()
	return &verifiedpermissions.UpdatePolicyOutput{
		PolicyStoreId:   aws.String(storeID),
		PolicyId:        aws.String(policyID),
		PolicyType:      avptypes.PolicyTypeStatic,
		CreatedDate:     &now,
		LastUpdatedDate: &now,
	}, nil
}

// IsAuthorized delegates authorization to cedar-agent.
func (m *MockAVPClient) IsAuthorized(ctx context.Context, params *verifiedpermissions.IsAuthorizedInput, optFns ...func(*verifiedpermissions.Options)) (*verifiedpermissions.IsAuthorizedOutput, error) {
	// Build cedar-agent request
	cedarReq := m.buildCedarAgentRequest(params)

	reqBody, err := json.Marshal(cedarReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal cedar-agent request: %w", err)
	}

	m.logger.Debug("sending authorization request to cedar-agent", "request_body", string(reqBody))

	// Send request to cedar-agent
	url := m.cedarAgentURL + "/v1/is_authorized"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create cedar-agent request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cedar-agent request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read cedar-agent response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cedar-agent returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var cedarResp struct {
		Decision    string `json:"decision"`
		Diagnostics struct {
			Reason []string `json:"reason"`
			Errors []string `json:"errors"`
		} `json:"diagnostics"`
	}
	if err := json.Unmarshal(body, &cedarResp); err != nil {
		return nil, fmt.Errorf("failed to parse cedar-agent response: %w", err)
	}

	m.logger.Debug("received authorization response from cedar-agent",
		"decision", cedarResp.Decision,
		"reasons", cedarResp.Diagnostics.Reason,
	)

	// Convert to AVP response
	decision := avptypes.DecisionDeny
	if strings.EqualFold(cedarResp.Decision, "allow") {
		decision = avptypes.DecisionAllow
	}

	return &verifiedpermissions.IsAuthorizedOutput{
		Decision: decision,
	}, nil
}

// PutSchema is a no-op - cedar-agent schema upload often fails due to unsupported features.
func (m *MockAVPClient) PutSchema(ctx context.Context, params *verifiedpermissions.PutSchemaInput, optFns ...func(*verifiedpermissions.Options)) (*verifiedpermissions.PutSchemaOutput, error) {
	now := time.Now()
	return &verifiedpermissions.PutSchemaOutput{
		PolicyStoreId:   params.PolicyStoreId,
		CreatedDate:     &now,
		LastUpdatedDate: &now,
	}, nil
}

// buildCedarAgentRequest converts an AVP IsAuthorizedInput to cedar-agent format.
func (m *MockAVPClient) buildCedarAgentRequest(params *verifiedpermissions.IsAuthorizedInput) map[string]any {
	req := make(map[string]any)

	var principalUID string

	// Principal: ROSA::Principal::"principal-id"
	if params.Principal != nil {
		principalType := aws.ToString(params.Principal.EntityType)
		principalID := aws.ToString(params.Principal.EntityId)
		principalUID = fmt.Sprintf("%s::\"%s\"", principalType, principalID)
		req["principal"] = principalUID
	}

	// Action: ROSA::Action::"action-name"
	if params.Action != nil {
		actionID := aws.ToString(params.Action.ActionId)
		// Strip "rosa:" prefix if present to match Cedar policy format
		actionID = strings.TrimPrefix(actionID, "rosa:")
		req["action"] = fmt.Sprintf("ROSA::Action::\"%s\"", actionID)
	}

	// Resource: ROSA::Resource::"resource-id"
	if params.Resource != nil {
		resourceType := aws.ToString(params.Resource.EntityType)
		resourceID := aws.ToString(params.Resource.EntityId)
		req["resource"] = fmt.Sprintf("%s::\"%s\"", resourceType, resourceID)
	}

	// Context
	if params.Context != nil {
		if contextMap, ok := params.Context.(*avptypes.ContextDefinitionMemberContextMap); ok {
			context := make(map[string]any)
			for key, val := range contextMap.Value {
				context[key] = convertAttributeValue(val)
			}
			req["context"] = context
		}
	}

	// Entities - build entity hierarchy for group membership
	var entities []map[string]any

	if params.Entities != nil {
		if entityList, ok := params.Entities.(*avptypes.EntitiesDefinitionMemberEntityList); ok {
			var groupUIDs []string

			for _, entity := range entityList.Value {
				entityType := aws.ToString(entity.Identifier.EntityType)
				entityID := aws.ToString(entity.Identifier.EntityId)
				uid := fmt.Sprintf("%s::\"%s\"", entityType, entityID)

				// Track group UIDs for principal parents
				if entityType == "ROSA::Group" || entityType == "Group" {
					groupUIDs = append(groupUIDs, uid)
					entities = append(entities, map[string]any{
						"uid":     uid,
						"attrs":   map[string]any{},
						"parents": []string{},
					})
				}
			}

			// Add principal entity with group parents
			if principalUID != "" && len(groupUIDs) > 0 {
				entities = append(entities, map[string]any{
					"uid":     principalUID,
					"attrs":   map[string]any{},
					"parents": groupUIDs,
				})
			}
		}
	}

	// Add resource entity with arn attribute for wildcard matching
	if params.Resource != nil {
		resourceType := aws.ToString(params.Resource.EntityType)
		resourceID := aws.ToString(params.Resource.EntityId)
		resourceUID := fmt.Sprintf("%s::\"%s\"", resourceType, resourceID)
		entities = append(entities, map[string]any{
			"uid": resourceUID,
			"attrs": map[string]any{
				"arn": resourceID,
			},
			"parents": []string{},
		})
	}

	if len(entities) > 0 {
		req["entities"] = entities
	}

	return req
}

// convertAttributeValue converts AVP AttributeValue to a Go value.
func convertAttributeValue(val avptypes.AttributeValue) any {
	switch v := val.(type) {
	case *avptypes.AttributeValueMemberString:
		return v.Value
	case *avptypes.AttributeValueMemberLong:
		return v.Value
	case *avptypes.AttributeValueMemberBoolean:
		return v.Value
	case *avptypes.AttributeValueMemberSet:
		result := make([]any, len(v.Value))
		for i, item := range v.Value {
			result[i] = convertAttributeValue(item)
		}
		return result
	case *avptypes.AttributeValueMemberRecord:
		result := make(map[string]any)
		for key, item := range v.Value {
			result[key] = convertAttributeValue(item)
		}
		return result
	default:
		return nil
	}
}
