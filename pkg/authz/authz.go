package authz

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/verifiedpermissions"
	avptypes "github.com/aws/aws-sdk-go-v2/service/verifiedpermissions/types"

	"github.com/openshift/rosa-regional-frontend-api/pkg/authz/client"
	"github.com/openshift/rosa-regional-frontend-api/pkg/authz/policy"
	"github.com/openshift/rosa-regional-frontend-api/pkg/authz/privileged"
	"github.com/openshift/rosa-regional-frontend-api/pkg/authz/schema"
	"github.com/openshift/rosa-regional-frontend-api/pkg/authz/store"
)

// AuthzRequest represents an authorization request
type AuthzRequest struct {
	AccountID    string
	CallerARN    string
	Action       string
	Resource     string
	ResourceTags map[string]string
	RequestTags  map[string]string
	Context      map[string]any
}

// Authorizer provides the main authorization interface
type Authorizer interface {
	// Authorization check - called by middleware
	Authorize(ctx context.Context, req *AuthzRequest) (bool, error)

	// Privilege check
	IsPrivileged(ctx context.Context, accountID string) (bool, error)

	// Account operations (privileged only)
	EnableAccount(ctx context.Context, accountID, createdBy string, isPrivileged bool) (*store.Account, error)
	DisableAccount(ctx context.Context, accountID string) error
	GetAccount(ctx context.Context, accountID string) (*store.Account, error)
	ListAccounts(ctx context.Context) ([]*store.Account, error)
	IsAccountProvisioned(ctx context.Context, accountID string) (bool, error)

	// Admin operations
	IsAdmin(ctx context.Context, accountID, principalARN string) (bool, error)
	AddAdmin(ctx context.Context, accountID, principalARN, createdBy string) error
	RemoveAdmin(ctx context.Context, accountID, principalARN string) error
	ListAdmins(ctx context.Context, accountID string) ([]string, error)

	// Group operations
	CreateGroup(ctx context.Context, accountID, name, description string) (*store.Group, error)
	GetGroup(ctx context.Context, accountID, groupID string) (*store.Group, error)
	DeleteGroup(ctx context.Context, accountID, groupID string) error
	ListGroups(ctx context.Context, accountID string) ([]*store.Group, error)
	AddGroupMember(ctx context.Context, accountID, groupID, memberARN string) error
	RemoveGroupMember(ctx context.Context, accountID, groupID, memberARN string) error
	ListGroupMembers(ctx context.Context, accountID, groupID string) ([]string, error)
	GetUserGroups(ctx context.Context, accountID, memberARN string) ([]string, error)

	// Policy operations
	CreatePolicy(ctx context.Context, accountID, name, description string, v0Policy *policy.V0Policy) (*store.Policy, error)
	GetPolicy(ctx context.Context, accountID, policyID string) (*store.Policy, error)
	UpdatePolicy(ctx context.Context, accountID, policyID, name, description string, v0Policy *policy.V0Policy) (*store.Policy, error)
	DeletePolicy(ctx context.Context, accountID, policyID string) error
	ListPolicies(ctx context.Context, accountID string) ([]*store.Policy, error)

	// Attachment operations
	AttachPolicy(ctx context.Context, accountID, policyID string, targetType store.TargetType, targetID string) (*store.Attachment, error)
	DetachPolicy(ctx context.Context, accountID, attachmentID string) error
	ListAttachments(ctx context.Context, accountID string, filter store.AttachmentFilter) ([]*store.Attachment, error)
}

// authorizerImpl implements the Authorizer interface
type authorizerImpl struct {
	cfg              *Config
	logger           *slog.Logger
	avpClient        client.AVPClient
	privilegedCheck  *privileged.Checker
	accountStore     *store.AccountStore
	adminStore       *store.AdminStore
	groupStore       *store.GroupStore
	memberStore      *store.MemberStore
	policyStore      *store.PolicyStore
	attachmentStore  *store.AttachmentStore
	policyTranslator *policy.Translator
	policyValidator  *policy.Validator
}

// New creates a new Authorizer
func New(cfg *Config, dynamoClient client.DynamoDBClient, avpClient client.AVPClient, logger *slog.Logger) Authorizer {
	privilegedChecker := privileged.NewChecker(
		cfg.PrivilegedAccountsFile,
		cfg.AccountsTableName,
		dynamoClient,
		logger,
	)

	return &authorizerImpl{
		cfg:              cfg,
		logger:           logger,
		avpClient:        avpClient,
		privilegedCheck:  privilegedChecker,
		accountStore:     store.NewAccountStore(cfg.AccountsTableName, dynamoClient, logger),
		adminStore:       store.NewAdminStore(cfg.AdminsTableName, dynamoClient, logger),
		groupStore:       store.NewGroupStore(cfg.GroupsTableName, dynamoClient, logger),
		memberStore:      store.NewMemberStore(cfg.MembersTableName, dynamoClient, logger),
		policyStore:      store.NewPolicyStore(cfg.PoliciesTableName, dynamoClient, logger),
		attachmentStore:  store.NewAttachmentStore(cfg.AttachmentsTableName, dynamoClient, logger),
		policyTranslator: policy.NewTranslator(),
		policyValidator:  policy.NewValidator(),
	}
}

// Authorize performs the authorization check
func (a *authorizerImpl) Authorize(ctx context.Context, req *AuthzRequest) (bool, error) {
	// Check if privileged (bypass all)
	isPriv, err := a.IsPrivileged(ctx, req.AccountID)
	if err != nil {
		a.logger.Error("failed to check privileged status", "error", err, "account_id", req.AccountID)
		return false, err
	}
	if isPriv {
		a.logger.Debug("privileged account bypass", "account_id", req.AccountID)
		return true, nil
	}

	// Check if account is provisioned
	account, err := a.accountStore.Get(ctx, req.AccountID)
	if err != nil {
		return false, fmt.Errorf("failed to get account: %w", err)
	}
	if account == nil {
		a.logger.Warn("account not provisioned", "account_id", req.AccountID)
		return false, fmt.Errorf("account not provisioned: %s", req.AccountID)
	}

	// Check if caller is admin (bypass Cedar)
	isAdm, err := a.IsAdmin(ctx, req.AccountID, req.CallerARN)
	if err != nil {
		return false, err
	}
	if isAdm {
		a.logger.Debug("admin bypass", "account_id", req.AccountID, "caller_arn", req.CallerARN)
		return true, nil
	}

	// Get user's group memberships
	groups, err := a.memberStore.GetUserGroups(ctx, req.AccountID, req.CallerARN)
	if err != nil {
		return false, fmt.Errorf("failed to get user groups: %w", err)
	}

	// Build AVP request
	avpReq := a.buildAVPRequest(req, groups, account.PolicyStoreID)

	// Call AVP
	resp, err := a.avpClient.IsAuthorized(ctx, avpReq)
	if err != nil {
		a.logger.Error("AVP authorization failed", "error", err, "account_id", req.AccountID)
		return false, fmt.Errorf("authorization check failed: %w", err)
	}

	decision := resp.Decision == avptypes.DecisionAllow
	a.logger.Info("authorization decision",
		"account_id", req.AccountID,
		"caller_arn", req.CallerARN,
		"action", req.Action,
		"resource", req.Resource,
		"decision", decision,
	)

	return decision, nil
}

// buildAVPRequest creates the AVP IsAuthorized request
func (a *authorizerImpl) buildAVPRequest(req *AuthzRequest, groups []string, policyStoreID string) *verifiedpermissions.IsAuthorizedInput {
	// Build principal
	principal := &avptypes.EntityIdentifier{
		EntityType: aws.String("ROSA::Principal"),
		EntityId:   aws.String(req.CallerARN),
	}

	// Build action
	action := &avptypes.ActionIdentifier{
		ActionType: aws.String("ROSA::Action"),
		ActionId:   aws.String(req.Action),
	}

	// Build resource
	resource := &avptypes.EntityIdentifier{
		EntityType: aws.String("ROSA::Resource"),
		EntityId:   aws.String(req.Resource),
	}

	// Build context
	contextMap := make(map[string]avptypes.AttributeValue)

	// Add principal info to context
	contextMap["principalArn"] = &avptypes.AttributeValueMemberString{Value: req.CallerARN}
	contextMap["principalAccount"] = &avptypes.AttributeValueMemberString{Value: req.AccountID}

	// Add request tags to context
	if len(req.RequestTags) > 0 {
		requestTagsMap := make(map[string]avptypes.AttributeValue)
		for k, v := range req.RequestTags {
			requestTagsMap[k] = &avptypes.AttributeValueMemberString{Value: v}
		}
		contextMap["requestTags"] = &avptypes.AttributeValueMemberRecord{Value: requestTagsMap}
	}

	// Add tag keys to context
	if len(req.RequestTags) > 0 {
		var tagKeys []avptypes.AttributeValue
		for k := range req.RequestTags {
			tagKeys = append(tagKeys, &avptypes.AttributeValueMemberString{Value: k})
		}
		contextMap["tagKeys"] = &avptypes.AttributeValueMemberSet{Value: tagKeys}
	}

	// Add custom context
	for k, v := range req.Context {
		if strVal, ok := v.(string); ok {
			contextMap[k] = &avptypes.AttributeValueMemberString{Value: strVal}
		}
	}

	// Build entities (for group membership)
	var entities []avptypes.EntityItem
	entities = append(entities, avptypes.EntityItem{
		Identifier: principal,
	})

	// Add group memberships
	for _, groupID := range groups {
		entities = append(entities, avptypes.EntityItem{
			Identifier: &avptypes.EntityIdentifier{
				EntityType: aws.String("ROSA::Group"),
				EntityId:   aws.String(groupID),
			},
		})
	}

	// Add resource with tags
	if len(req.ResourceTags) > 0 {
		tagsMap := make(map[string]avptypes.AttributeValue)
		for k, v := range req.ResourceTags {
			tagsMap[k] = &avptypes.AttributeValueMemberString{Value: v}
		}
		entities = append(entities, avptypes.EntityItem{
			Identifier: resource,
			Attributes: map[string]avptypes.AttributeValue{
				"tags": &avptypes.AttributeValueMemberRecord{Value: tagsMap},
			},
		})
	}

	return &verifiedpermissions.IsAuthorizedInput{
		PolicyStoreId: aws.String(policyStoreID),
		Principal:     principal,
		Action:        action,
		Resource:      resource,
		Context: &avptypes.ContextDefinitionMemberContextMap{
			Value: contextMap,
		},
		Entities: &avptypes.EntitiesDefinitionMemberEntityList{
			Value: entities,
		},
	}
}

// IsPrivileged checks if an account is privileged
func (a *authorizerImpl) IsPrivileged(ctx context.Context, accountID string) (bool, error) {
	return a.privilegedCheck.IsPrivileged(ctx, accountID)
}

// EnableAccount creates a new account with an optional policy store
func (a *authorizerImpl) EnableAccount(ctx context.Context, accountID, createdBy string, isPrivileged bool) (*store.Account, error) {
	account := &store.Account{
		AccountID:  accountID,
		Privileged: isPrivileged,
		CreatedBy:  createdBy,
	}

	// If not privileged, create a policy store
	if !isPrivileged {
		psResp, err := a.avpClient.CreatePolicyStore(ctx, &verifiedpermissions.CreatePolicyStoreInput{
			ValidationSettings: &avptypes.ValidationSettings{
				Mode: avptypes.ValidationModeStrict,
			},
			Description: aws.String(fmt.Sprintf("ROSA authorization policy store for account %s", accountID)),
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create policy store: %w", err)
		}

		account.PolicyStoreID = *psResp.PolicyStoreId

		// Set up the schema
		_, err = a.avpClient.PutSchema(ctx, &verifiedpermissions.PutSchemaInput{
			PolicyStoreId: psResp.PolicyStoreId,
			Definition: &avptypes.SchemaDefinitionMemberCedarJson{
				Value: schema.CedarSchemaJSON,
			},
		})
		if err != nil {
			// Try to clean up the policy store
			_, _ = a.avpClient.DeletePolicyStore(ctx, &verifiedpermissions.DeletePolicyStoreInput{
				PolicyStoreId: psResp.PolicyStoreId,
			})
			return nil, fmt.Errorf("failed to set policy store schema: %w", err)
		}
	}

	if err := a.accountStore.Create(ctx, account); err != nil {
		// Clean up policy store if we created one
		if account.PolicyStoreID != "" {
			_, _ = a.avpClient.DeletePolicyStore(ctx, &verifiedpermissions.DeletePolicyStoreInput{
				PolicyStoreId: aws.String(account.PolicyStoreID),
			})
		}
		return nil, err
	}

	a.logger.Info("account enabled", "account_id", accountID, "privileged", isPrivileged)
	return account, nil
}

// DisableAccount removes an account and its policy store
func (a *authorizerImpl) DisableAccount(ctx context.Context, accountID string) error {
	account, err := a.accountStore.Get(ctx, accountID)
	if err != nil {
		return err
	}
	if account == nil {
		return fmt.Errorf("account not found: %s", accountID)
	}

	// Delete policy store if exists
	if account.PolicyStoreID != "" {
		_, err = a.avpClient.DeletePolicyStore(ctx, &verifiedpermissions.DeletePolicyStoreInput{
			PolicyStoreId: aws.String(account.PolicyStoreID),
		})
		if err != nil {
			a.logger.Warn("failed to delete policy store", "error", err, "policy_store_id", account.PolicyStoreID)
		}
	}

	return a.accountStore.Delete(ctx, accountID)
}

// GetAccount retrieves an account
func (a *authorizerImpl) GetAccount(ctx context.Context, accountID string) (*store.Account, error) {
	return a.accountStore.Get(ctx, accountID)
}

// ListAccounts returns all accounts
func (a *authorizerImpl) ListAccounts(ctx context.Context) ([]*store.Account, error) {
	return a.accountStore.List(ctx)
}

// IsAccountProvisioned checks if an account is provisioned
func (a *authorizerImpl) IsAccountProvisioned(ctx context.Context, accountID string) (bool, error) {
	// Privileged accounts are always considered provisioned
	isPriv, err := a.IsPrivileged(ctx, accountID)
	if err != nil {
		return false, err
	}
	if isPriv {
		return true, nil
	}

	return a.accountStore.Exists(ctx, accountID)
}

// IsAdmin checks if a principal is an admin
func (a *authorizerImpl) IsAdmin(ctx context.Context, accountID, principalARN string) (bool, error) {
	return a.adminStore.IsAdmin(ctx, accountID, principalARN)
}

// AddAdmin adds an admin
func (a *authorizerImpl) AddAdmin(ctx context.Context, accountID, principalARN, createdBy string) error {
	admin := &store.Admin{
		AccountID:    accountID,
		PrincipalARN: principalARN,
		CreatedBy:    createdBy,
	}
	return a.adminStore.Add(ctx, admin)
}

// RemoveAdmin removes an admin
func (a *authorizerImpl) RemoveAdmin(ctx context.Context, accountID, principalARN string) error {
	return a.adminStore.Remove(ctx, accountID, principalARN)
}

// ListAdmins returns all admin ARNs for an account
func (a *authorizerImpl) ListAdmins(ctx context.Context, accountID string) ([]string, error) {
	return a.adminStore.ListARNs(ctx, accountID)
}

// CreateGroup creates a new group
func (a *authorizerImpl) CreateGroup(ctx context.Context, accountID, name, description string) (*store.Group, error) {
	return a.groupStore.Create(ctx, accountID, name, description)
}

// GetGroup retrieves a group
func (a *authorizerImpl) GetGroup(ctx context.Context, accountID, groupID string) (*store.Group, error) {
	return a.groupStore.Get(ctx, accountID, groupID)
}

// DeleteGroup removes a group and its members
func (a *authorizerImpl) DeleteGroup(ctx context.Context, accountID, groupID string) error {
	// First remove all members
	if err := a.memberStore.RemoveAllGroupMembers(ctx, accountID, groupID); err != nil {
		return err
	}

	// Then delete the group
	return a.groupStore.Delete(ctx, accountID, groupID)
}

// ListGroups returns all groups for an account
func (a *authorizerImpl) ListGroups(ctx context.Context, accountID string) ([]*store.Group, error) {
	return a.groupStore.List(ctx, accountID)
}

// AddGroupMember adds a member to a group
func (a *authorizerImpl) AddGroupMember(ctx context.Context, accountID, groupID, memberARN string) error {
	return a.memberStore.Add(ctx, accountID, groupID, memberARN)
}

// RemoveGroupMember removes a member from a group
func (a *authorizerImpl) RemoveGroupMember(ctx context.Context, accountID, groupID, memberARN string) error {
	return a.memberStore.Remove(ctx, accountID, groupID, memberARN)
}

// ListGroupMembers returns all members of a group
func (a *authorizerImpl) ListGroupMembers(ctx context.Context, accountID, groupID string) ([]string, error) {
	return a.memberStore.ListGroupMembers(ctx, accountID, groupID)
}

// GetUserGroups returns all groups a user belongs to
func (a *authorizerImpl) GetUserGroups(ctx context.Context, accountID, memberARN string) ([]string, error) {
	return a.memberStore.GetUserGroups(ctx, accountID, memberARN)
}

// CreatePolicy creates a new policy template
func (a *authorizerImpl) CreatePolicy(ctx context.Context, accountID, name, description string, v0Policy *policy.V0Policy) (*store.Policy, error) {
	// Validate the policy
	result := a.policyValidator.Validate(v0Policy)
	if !result.Valid {
		var errs []string
		for _, e := range result.Errors {
			errs = append(errs, e.Error())
		}
		return nil, fmt.Errorf("invalid policy: %v", errs)
	}

	return a.policyStore.Create(ctx, accountID, name, description, v0Policy)
}

// GetPolicy retrieves a policy
func (a *authorizerImpl) GetPolicy(ctx context.Context, accountID, policyID string) (*store.Policy, error) {
	return a.policyStore.Get(ctx, accountID, policyID)
}

// UpdatePolicy updates a policy template
func (a *authorizerImpl) UpdatePolicy(ctx context.Context, accountID, policyID, name, description string, v0Policy *policy.V0Policy) (*store.Policy, error) {
	// Validate the policy
	result := a.policyValidator.Validate(v0Policy)
	if !result.Valid {
		var errs []string
		for _, e := range result.Errors {
			errs = append(errs, e.Error())
		}
		return nil, fmt.Errorf("invalid policy: %v", errs)
	}

	// TODO: Update all attachments in AVP with new policy

	return a.policyStore.Update(ctx, accountID, policyID, name, description, v0Policy)
}

// DeletePolicy removes a policy template
func (a *authorizerImpl) DeletePolicy(ctx context.Context, accountID, policyID string) error {
	// Check if policy has attachments
	attachments, err := a.attachmentStore.ListByPolicy(ctx, accountID, policyID)
	if err != nil {
		return err
	}
	if len(attachments) > 0 {
		return fmt.Errorf("cannot delete policy with existing attachments")
	}

	return a.policyStore.Delete(ctx, accountID, policyID)
}

// ListPolicies returns all policies for an account
func (a *authorizerImpl) ListPolicies(ctx context.Context, accountID string) ([]*store.Policy, error) {
	return a.policyStore.List(ctx, accountID)
}

// AttachPolicy attaches a policy to a user or group
func (a *authorizerImpl) AttachPolicy(ctx context.Context, accountID, policyID string, targetType store.TargetType, targetID string) (*store.Attachment, error) {
	// Get the account to find the policy store ID
	account, err := a.accountStore.Get(ctx, accountID)
	if err != nil {
		return nil, err
	}
	if account == nil {
		return nil, fmt.Errorf("account not found: %s", accountID)
	}
	if account.PolicyStoreID == "" {
		return nil, fmt.Errorf("account has no policy store (privileged accounts cannot have policies)")
	}

	// Get the policy template
	policyRecord, err := a.policyStore.Get(ctx, accountID, policyID)
	if err != nil {
		return nil, err
	}
	if policyRecord == nil {
		return nil, fmt.Errorf("policy not found: %s", policyID)
	}

	// Parse the v0 policy
	v0Policy, err := policyRecord.GetV0Policy()
	if err != nil {
		return nil, err
	}

	// Translate to Cedar with principal
	cedarPolicies, err := a.policyTranslator.TranslateWithPrincipal(v0Policy, string(targetType), targetID)
	if err != nil {
		return nil, fmt.Errorf("failed to translate policy: %w", err)
	}

	// Create policies in AVP (combine all statements into one policy)
	cedarPolicy := ""
	for i, cp := range cedarPolicies {
		if i > 0 {
			cedarPolicy += "\n\n"
		}
		cedarPolicy += cp
	}

	avpResp, err := a.avpClient.CreatePolicy(ctx, &verifiedpermissions.CreatePolicyInput{
		PolicyStoreId: aws.String(account.PolicyStoreID),
		Definition: &avptypes.PolicyDefinitionMemberStatic{
			Value: avptypes.StaticPolicyDefinition{
				Statement:   aws.String(cedarPolicy),
				Description: aws.String(fmt.Sprintf("Policy %s attached to %s %s", policyID, targetType, targetID)),
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create AVP policy: %w", err)
	}

	// Store the attachment
	return a.attachmentStore.Create(ctx, accountID, policyID, targetType, targetID, *avpResp.PolicyId)
}

// DetachPolicy removes a policy attachment
func (a *authorizerImpl) DetachPolicy(ctx context.Context, accountID, attachmentID string) error {
	// Get the attachment
	attachment, err := a.attachmentStore.Get(ctx, accountID, attachmentID)
	if err != nil {
		return err
	}
	if attachment == nil {
		return fmt.Errorf("attachment not found: %s", attachmentID)
	}

	// Get the account to find the policy store ID
	account, err := a.accountStore.Get(ctx, accountID)
	if err != nil {
		return err
	}
	if account == nil {
		return fmt.Errorf("account not found: %s", accountID)
	}

	// Delete from AVP
	if attachment.AVPPolicyID != "" && account.PolicyStoreID != "" {
		_, err = a.avpClient.DeletePolicy(ctx, &verifiedpermissions.DeletePolicyInput{
			PolicyStoreId: aws.String(account.PolicyStoreID),
			PolicyId:      aws.String(attachment.AVPPolicyID),
		})
		if err != nil {
			a.logger.Warn("failed to delete AVP policy", "error", err, "avp_policy_id", attachment.AVPPolicyID)
		}
	}

	// Delete from store
	return a.attachmentStore.Delete(ctx, accountID, attachmentID)
}

// ListAttachments returns attachments matching the filter
func (a *authorizerImpl) ListAttachments(ctx context.Context, accountID string, filter store.AttachmentFilter) ([]*store.Attachment, error) {
	return a.attachmentStore.ListFiltered(ctx, accountID, filter)
}
