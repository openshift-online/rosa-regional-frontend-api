package policy

import (
	"testing"
)

func TestValidator_Validate_ValidPolicy(t *testing.T) {
	validator := NewValidator()

	policy := &V0Policy{
		Version: "v0",
		Statements: []Statement{
			{
				Sid:       "AllowListClusters",
				Effect:    EffectAllow,
				Actions:   []string{"rosa:ListClusters"},
				Resources: []string{"*"},
			},
		},
	}

	result := validator.Validate(policy)

	if !result.Valid {
		t.Errorf("expected valid policy, got errors: %v", result.Errors)
	}
}

func TestValidator_Validate_NilPolicy(t *testing.T) {
	validator := NewValidator()

	result := validator.Validate(nil)

	if result.Valid {
		t.Error("expected invalid result for nil policy")
	}

	if len(result.Errors) != 1 {
		t.Errorf("expected 1 error, got %d", len(result.Errors))
	}
}

func TestValidator_Validate_EmptyStatements(t *testing.T) {
	validator := NewValidator()

	policy := &V0Policy{
		Version:    "v0",
		Statements: []Statement{},
	}

	result := validator.Validate(policy)

	if result.Valid {
		t.Error("expected invalid result for empty statements")
	}

	found := false
	for _, err := range result.Errors {
		if err.Field == "statements" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected error about statements")
	}
}

func TestValidator_Validate_InvalidEffect(t *testing.T) {
	validator := NewValidator()

	policy := &V0Policy{
		Version: "v0",
		Statements: []Statement{
			{
				Effect:    "Invalid",
				Actions:   []string{"rosa:ListClusters"},
				Resources: []string{"*"},
			},
		},
	}

	result := validator.Validate(policy)

	if result.Valid {
		t.Error("expected invalid result for invalid effect")
	}

	found := false
	for _, err := range result.Errors {
		if err.Field == "statements[0].effect" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected error about effect")
	}
}

func TestValidator_Validate_MissingActions(t *testing.T) {
	validator := NewValidator()

	policy := &V0Policy{
		Version: "v0",
		Statements: []Statement{
			{
				Effect:    EffectAllow,
				Actions:   []string{},
				Resources: []string{"*"},
			},
		},
	}

	result := validator.Validate(policy)

	if result.Valid {
		t.Error("expected invalid result for missing actions")
	}

	found := false
	for _, err := range result.Errors {
		if err.Field == "statements[0].actions" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected error about actions")
	}
}

func TestValidator_Validate_InvalidAction(t *testing.T) {
	validator := NewValidator()

	policy := &V0Policy{
		Version: "v0",
		Statements: []Statement{
			{
				Effect:    EffectAllow,
				Actions:   []string{"invalid-action"},
				Resources: []string{"*"},
			},
		},
	}

	result := validator.Validate(policy)

	if result.Valid {
		t.Error("expected invalid result for invalid action format")
	}
}

func TestValidator_Validate_MissingResources(t *testing.T) {
	validator := NewValidator()

	policy := &V0Policy{
		Version: "v0",
		Statements: []Statement{
			{
				Effect:    EffectAllow,
				Actions:   []string{"rosa:ListClusters"},
				Resources: []string{},
			},
		},
	}

	result := validator.Validate(policy)

	if result.Valid {
		t.Error("expected invalid result for missing resources")
	}

	found := false
	for _, err := range result.Errors {
		if err.Field == "statements[0].resources" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected error about resources")
	}
}

func TestValidator_Validate_DuplicateSids(t *testing.T) {
	validator := NewValidator()

	policy := &V0Policy{
		Version: "v0",
		Statements: []Statement{
			{
				Sid:       "SameSid",
				Effect:    EffectAllow,
				Actions:   []string{"rosa:ListClusters"},
				Resources: []string{"*"},
			},
			{
				Sid:       "SameSid",
				Effect:    EffectAllow,
				Actions:   []string{"rosa:DescribeCluster"},
				Resources: []string{"*"},
			},
		},
	}

	result := validator.Validate(policy)

	if result.Valid {
		t.Error("expected invalid result for duplicate sids")
	}
}

func TestValidator_Validate_ValidConditions(t *testing.T) {
	validator := NewValidator()

	policy := &V0Policy{
		Version: "v0",
		Statements: []Statement{
			{
				Effect:    EffectAllow,
				Actions:   []string{"rosa:CreateCluster"},
				Resources: []string{"*"},
				Conditions: map[string]Condition{
					"StringEquals": {
						"rosa:ResourceTag/Environment": "development",
					},
				},
			},
		},
	}

	result := validator.Validate(policy)

	if !result.Valid {
		t.Errorf("expected valid policy with conditions, got errors: %v", result.Errors)
	}
}

func TestValidator_Validate_UnsupportedConditionOperator(t *testing.T) {
	validator := NewValidator()

	policy := &V0Policy{
		Version: "v0",
		Statements: []Statement{
			{
				Effect:    EffectAllow,
				Actions:   []string{"rosa:CreateCluster"},
				Resources: []string{"*"},
				Conditions: map[string]Condition{
					"InvalidOperator": {
						"rosa:ResourceTag/Environment": "development",
					},
				},
			},
		},
	}

	result := validator.Validate(policy)

	if result.Valid {
		t.Error("expected invalid result for unsupported condition operator")
	}
}

func TestValidator_Validate_UnsupportedConditionKey(t *testing.T) {
	validator := NewValidator()

	policy := &V0Policy{
		Version: "v0",
		Statements: []Statement{
			{
				Effect:    EffectAllow,
				Actions:   []string{"rosa:CreateCluster"},
				Resources: []string{"*"},
				Conditions: map[string]Condition{
					"StringEquals": {
						"aws:unsupportedKey": "value",
					},
				},
			},
		},
	}

	result := validator.Validate(policy)

	if result.Valid {
		t.Error("expected invalid result for unsupported condition key")
	}
}

func TestValidator_Validate_AllSupportedConditionKeys(t *testing.T) {
	validator := NewValidator()

	testCases := []struct {
		key   string
		valid bool
	}{
		{"rosa:ResourceTag/Environment", true},
		{"rosa:RequestTag/Owner", true},
		{"rosa:TagKeys", true},
		{"aws:PrincipalArn", true},
		{"aws:PrincipalAccount", true},
		{"rosa:principalArn", true},
		{"aws:unsupported", false},
		{"custom:key", false},
	}

	for _, tc := range testCases {
		policy := &V0Policy{
			Version: "v0",
			Statements: []Statement{
				{
					Effect:    EffectAllow,
					Actions:   []string{"rosa:CreateCluster"},
					Resources: []string{"*"},
					Conditions: map[string]Condition{
						"StringEquals": {
							tc.key: "value",
						},
					},
				},
			},
		}

		result := validator.Validate(policy)

		if result.Valid != tc.valid {
			t.Errorf("key %s: expected valid=%v, got valid=%v", tc.key, tc.valid, result.Valid)
		}
	}
}

func TestValidateAndTranslate_Success(t *testing.T) {
	policy := &V0Policy{
		Version: "v0",
		Statements: []Statement{
			{
				Sid:       "AllowListClusters",
				Effect:    EffectAllow,
				Actions:   []string{"rosa:ListClusters"},
				Resources: []string{"*"},
			},
		},
	}

	cedarPolicies, err := ValidateAndTranslate(policy, "user", "arn:aws:iam::111122223333:user/alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cedarPolicies) != 1 {
		t.Errorf("expected 1 policy, got %d", len(cedarPolicies))
	}
}

func TestValidateAndTranslate_ValidationFailure(t *testing.T) {
	policy := &V0Policy{
		Version:    "v0",
		Statements: []Statement{},
	}

	_, err := ValidateAndTranslate(policy, "user", "arn:aws:iam::111122223333:user/alice")
	if err == nil {
		t.Error("expected error for invalid policy")
	}
}
