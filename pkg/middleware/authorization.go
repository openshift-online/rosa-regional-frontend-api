package middleware

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/openshift/rosa-regional-frontend-api/pkg/clients/dynamodb"
)

const (
	// ContextKeyCustomerAccount is the context key for the customer account
	ContextKeyCustomerAccount contextKey = "customer_account"
)

// Authorization provides DynamoDB-based authorization middleware
type Authorization struct {
	dynamoClient *dynamodb.Client
	logger       *slog.Logger
}

// NewAuthorization creates a new Authorization middleware
func NewAuthorization(dynamoClient *dynamodb.Client, logger *slog.Logger) *Authorization {
	return &Authorization{
		dynamoClient: dynamoClient,
		logger:       logger,
	}
}

// RequireAccount verifies that the AWS account exists in DynamoDB (has accepted ToS)
func (a *Authorization) RequireAccount(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		accountID := GetAccountID(ctx)

		if accountID == "" {
			a.logger.Warn("missing account ID in request")
			a.writeError(w, http.StatusForbidden, "missing-account-id", "Account ID header is required")
			return
		}

		account, err := a.dynamoClient.GetAccount(ctx, accountID)
		if err != nil {
			a.logger.Error("failed to query DynamoDB", "error", err, "account_id", accountID)
			a.writeError(w, http.StatusInternalServerError, "internal-error", "Internal server error")
			return
		}

		if account == nil {
			a.logger.Warn("account not found in DynamoDB", "account_id", accountID)
			a.writeError(w, http.StatusForbidden, "account-not-registered", "Account is not registered")
			return
		}

		// Store account in context for downstream handlers
		ctx = context.WithValue(ctx, ContextKeyCustomerAccount, account)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequirePrivileged verifies that the account has privileged (admin) access
// Must be used after RequireAccount
func (a *Authorization) RequirePrivileged(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		account := GetCustomerAccount(ctx)

		if account == nil {
			a.logger.Error("RequirePrivileged called without account in context")
			a.writeError(w, http.StatusInternalServerError, "internal-error", "Internal server error")
			return
		}

		if !account.Privileged {
			accountID := GetAccountID(ctx)
			a.logger.Warn("non-privileged account attempted admin action", "account_id", accountID)
			a.writeError(w, http.StatusForbidden, "not-privileged", "Admin access required")
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (a *Authorization) writeError(w http.ResponseWriter, status int, code, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	resp := map[string]interface{}{
		"kind":   "Error",
		"code":   code,
		"reason": reason,
	}

	json.NewEncoder(w).Encode(resp)
}

// GetCustomerAccount retrieves the customer account from context
func GetCustomerAccount(ctx context.Context) *dynamodb.CustomerAccount {
	if v := ctx.Value(ContextKeyCustomerAccount); v != nil {
		return v.(*dynamodb.CustomerAccount)
	}
	return nil
}
