package policy

import (
	"fmt"
	"regexp"
	"strings"
)

// ValidationError represents a policy validation error
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

// ValidationResult contains the results of policy validation
type ValidationResult struct {
	Valid  bool
	Errors []ValidationError
}

// Validator validates v0 policies
type Validator struct {
	actionPattern   *regexp.Regexp
	resourcePattern *regexp.Regexp
}

// NewValidator creates a new policy validator
func NewValidator() *Validator {
	return &Validator{
		// Action pattern: rosa:ActionName or rosa:Action* or *
		actionPattern: regexp.MustCompile(`^(\*|rosa:[A-Za-z\*]+)$`),
		// Resource pattern: * or ARN (allows wildcards in region, account, and resource path)
		resourcePattern: regexp.MustCompile(`^(\*|arn:aws:rosa:([a-z0-9\-]+|\*):[0-9*]*:[a-z\-]+/.+)$`),
	}
}

// Validate validates a v0 policy
func (v *Validator) Validate(policy *V0Policy) *ValidationResult {
	result := &ValidationResult{Valid: true}

	if policy == nil {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Field:   "policy",
			Message: "policy is nil",
		})
		return result
	}

	// Validate version
	if policy.Version != "v0" && policy.Version != "" {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Field:   "version",
			Message: fmt.Sprintf("unsupported version: %s (expected v0 or empty)", policy.Version),
		})
	}

	// Validate statements
	if len(policy.Statements) == 0 {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Field:   "statements",
			Message: "at least one statement is required",
		})
	}

	sids := make(map[string]struct{})
	for i, stmt := range policy.Statements {
		stmtErrors := v.validateStatement(stmt, i, sids)
		if len(stmtErrors) > 0 {
			result.Valid = false
			result.Errors = append(result.Errors, stmtErrors...)
		}
	}

	return result
}

// validateStatement validates a single statement
func (v *Validator) validateStatement(stmt Statement, index int, sids map[string]struct{}) []ValidationError {
	var errors []ValidationError
	prefix := fmt.Sprintf("statements[%d]", index)

	// Validate Sid uniqueness
	if stmt.Sid != "" {
		if _, exists := sids[stmt.Sid]; exists {
			errors = append(errors, ValidationError{
				Field:   prefix + ".sid",
				Message: fmt.Sprintf("duplicate sid: %s", stmt.Sid),
			})
		}
		sids[stmt.Sid] = struct{}{}
	}

	// Validate Effect
	if stmt.Effect != EffectAllow && stmt.Effect != EffectDeny {
		errors = append(errors, ValidationError{
			Field:   prefix + ".effect",
			Message: fmt.Sprintf("invalid effect: %s (must be Allow or Deny)", stmt.Effect),
		})
	}

	// Validate Actions
	if len(stmt.Actions) == 0 {
		errors = append(errors, ValidationError{
			Field:   prefix + ".actions",
			Message: "at least one action is required",
		})
	}
	for j, action := range stmt.Actions {
		if !v.isValidAction(action) {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("%s.actions[%d]", prefix, j),
				Message: fmt.Sprintf("invalid action format: %s", action),
			})
		}
	}

	// Validate Resources
	if len(stmt.Resources) == 0 {
		errors = append(errors, ValidationError{
			Field:   prefix + ".resources",
			Message: "at least one resource is required",
		})
	}
	for j, resource := range stmt.Resources {
		if !v.isValidResource(resource) {
			errors = append(errors, ValidationError{
				Field:   fmt.Sprintf("%s.resources[%d]", prefix, j),
				Message: fmt.Sprintf("invalid resource format: %s", resource),
			})
		}
	}

	// Validate Conditions
	if stmt.Conditions != nil {
		condErrors := v.validateConditions(stmt.Conditions, prefix)
		errors = append(errors, condErrors...)
	}

	return errors
}

// isValidAction checks if an action string is valid
func (v *Validator) isValidAction(action string) bool {
	if action == "*" {
		return true
	}
	return v.actionPattern.MatchString(action)
}

// isValidResource checks if a resource string is valid
func (v *Validator) isValidResource(resource string) bool {
	if resource == "*" {
		return true
	}
	return v.resourcePattern.MatchString(resource)
}

// validateConditions validates the conditions block
func (v *Validator) validateConditions(conditions map[string]Condition, prefix string) []ValidationError {
	var errors []ValidationError

	validOperators := map[string]bool{
		string(ConditionStringEquals):             true,
		string(ConditionStringNotEquals):          true,
		string(ConditionStringLike):               true,
		string(ConditionStringNotLike):            true,
		string(ConditionArnEquals):                true,
		string(ConditionArnLike):                  true,
		string(ConditionArnNotEquals):             true,
		string(ConditionArnNotLike):               true,
		string(ConditionBool):                     true,
		string(ConditionForAllValuesStringEquals): true,
		string(ConditionForAnyValueStringEquals):  true,
	}

	for operator, condition := range conditions {
		if !validOperators[operator] {
			errors = append(errors, ValidationError{
				Field:   prefix + ".conditions",
				Message: fmt.Sprintf("unsupported condition operator: %s", operator),
			})
			continue
		}

		for key := range condition {
			if !v.isValidConditionKey(key) {
				errors = append(errors, ValidationError{
					Field:   prefix + ".conditions." + operator,
					Message: fmt.Sprintf("unsupported condition key: %s", key),
				})
			}
		}
	}

	return errors
}

// isValidConditionKey checks if a condition key is supported
func (v *Validator) isValidConditionKey(key string) bool {
	// Check exact matches
	supportedKeys := []string{
		"rosa:TagKeys",
		"aws:PrincipalArn",
		"aws:PrincipalAccount",
		"rosa:principalArn",
	}

	for _, supported := range supportedKeys {
		if key == supported {
			return true
		}
	}

	// Check prefix matches
	supportedPrefixes := []string{
		"rosa:ResourceTag/",
		"rosa:RequestTag/",
	}

	for _, prefix := range supportedPrefixes {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}

	return false
}

// ValidateAndTranslate validates a policy and returns the Cedar translation if valid
func ValidateAndTranslate(p *V0Policy, principalType, principalID string) ([]string, error) {
	validator := NewValidator()
	result := validator.Validate(p)

	if !result.Valid {
		var errMsgs []string
		for _, err := range result.Errors {
			errMsgs = append(errMsgs, err.Error())
		}
		return nil, fmt.Errorf("policy validation failed: %s", strings.Join(errMsgs, "; "))
	}

	translator := NewTranslator()
	return translator.TranslateWithPrincipal(p, principalType, principalID)
}
