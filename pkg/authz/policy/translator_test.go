package policy

import (
	"strings"
	"testing"
)

func TestTranslator_TranslateWithPrincipal_User(t *testing.T) {
	translator := NewTranslator()

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

	cedarPolicies, err := translator.TranslateWithPrincipal(policy, "user", "arn:aws:iam::111122223333:user/alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cedarPolicies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(cedarPolicies))
	}

	cedar := cedarPolicies[0]

	// Check effect
	if !strings.HasPrefix(cedar, "permit") {
		t.Errorf("expected policy to start with 'permit', got: %s", cedar[:20])
	}

	// Check principal
	if !strings.Contains(cedar, `principal == ROSA::Principal::"arn:aws:iam::111122223333:user/alice"`) {
		t.Errorf("expected user principal clause, got: %s", cedar)
	}

	// Check action
	if !strings.Contains(cedar, "ListClusters") {
		t.Errorf("expected ListClusters action, got: %s", cedar)
	}
}

func TestTranslator_TranslateWithPrincipal_Group(t *testing.T) {
	translator := NewTranslator()

	policy := &V0Policy{
		Version: "v0",
		Statements: []Statement{
			{
				Effect:    EffectAllow,
				Actions:   []string{"rosa:CreateCluster"},
				Resources: []string{"*"},
			},
		},
	}

	cedarPolicies, err := translator.TranslateWithPrincipal(policy, "group", "developers-group-id")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cedar := cedarPolicies[0]

	// Check group principal
	if !strings.Contains(cedar, `principal in ROSA::Group::"developers-group-id"`) {
		t.Errorf("expected group principal clause, got: %s", cedar)
	}
}

func TestTranslator_TranslateWithPrincipal_Deny(t *testing.T) {
	translator := NewTranslator()

	policy := &V0Policy{
		Version: "v0",
		Statements: []Statement{
			{
				Sid:       "DenyDelete",
				Effect:    EffectDeny,
				Actions:   []string{"rosa:DeleteCluster"},
				Resources: []string{"*"},
			},
		},
	}

	cedarPolicies, err := translator.TranslateWithPrincipal(policy, "user", "arn:aws:iam::111122223333:user/alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cedar := cedarPolicies[0]

	// Check effect is forbid
	if !strings.HasPrefix(cedar, "forbid") {
		t.Errorf("expected policy to start with 'forbid', got: %s", cedar[:20])
	}
}

func TestTranslator_TranslateWithPrincipal_WildcardActions(t *testing.T) {
	translator := NewTranslator()

	policy := &V0Policy{
		Version: "v0",
		Statements: []Statement{
			{
				Effect:    EffectAllow,
				Actions:   []string{"*"},
				Resources: []string{"*"},
			},
		},
	}

	cedarPolicies, err := translator.TranslateWithPrincipal(policy, "user", "arn:aws:iam::111122223333:user/admin")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cedar := cedarPolicies[0]

	// Wildcard actions should translate to just "action"
	if !strings.Contains(cedar, "action,") || strings.Contains(cedar, "action ==") {
		t.Errorf("expected bare 'action' clause for wildcard, got: %s", cedar)
	}
}

func TestTranslator_TranslateWithPrincipal_PrefixActions(t *testing.T) {
	translator := NewTranslator()

	policy := &V0Policy{
		Version: "v0",
		Statements: []Statement{
			{
				Effect:    EffectAllow,
				Actions:   []string{"rosa:Describe*"},
				Resources: []string{"*"},
			},
		},
	}

	cedarPolicies, err := translator.TranslateWithPrincipal(policy, "user", "arn:aws:iam::111122223333:user/alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cedar := cedarPolicies[0]

	// Should expand to multiple actions
	if !strings.Contains(cedar, "DescribeCluster") {
		t.Errorf("expected DescribeCluster in expanded actions, got: %s", cedar)
	}
	if !strings.Contains(cedar, "DescribeNodePool") {
		t.Errorf("expected DescribeNodePool in expanded actions, got: %s", cedar)
	}
}

func TestTranslator_TranslateWithPrincipal_Conditions(t *testing.T) {
	translator := NewTranslator()

	policy := &V0Policy{
		Version: "v0",
		Statements: []Statement{
			{
				Effect:    EffectAllow,
				Actions:   []string{"rosa:CreateCluster", "rosa:DeleteCluster"},
				Resources: []string{"*"},
				Conditions: map[string]Condition{
					"StringEquals": {
						"rosa:ResourceTag/Environment": "development",
					},
				},
			},
		},
	}

	cedarPolicies, err := translator.TranslateWithPrincipal(policy, "user", "arn:aws:iam::111122223333:user/alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cedar := cedarPolicies[0]

	// Check when clause
	if !strings.Contains(cedar, "when {") {
		t.Errorf("expected 'when' clause, got: %s", cedar)
	}

	// Check condition translation
	if !strings.Contains(cedar, `resource.tags["Environment"]`) {
		t.Errorf("expected resource tag condition, got: %s", cedar)
	}

	if !strings.Contains(cedar, `"development"`) {
		t.Errorf("expected condition value, got: %s", cedar)
	}
}

func TestTranslator_TranslateWithPrincipal_MultipleStatements(t *testing.T) {
	translator := NewTranslator()

	policy := &V0Policy{
		Version: "v0",
		Statements: []Statement{
			{
				Sid:       "AllowRead",
				Effect:    EffectAllow,
				Actions:   []string{"rosa:ListClusters", "rosa:DescribeCluster"},
				Resources: []string{"*"},
			},
			{
				Sid:       "DenyDelete",
				Effect:    EffectDeny,
				Actions:   []string{"rosa:DeleteCluster"},
				Resources: []string{"*"},
			},
		},
	}

	cedarPolicies, err := translator.TranslateWithPrincipal(policy, "user", "arn:aws:iam::111122223333:user/alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cedarPolicies) != 2 {
		t.Fatalf("expected 2 policies, got %d", len(cedarPolicies))
	}

	// First should be permit
	if !strings.HasPrefix(cedarPolicies[0], "permit") {
		t.Errorf("expected first policy to be permit")
	}

	// Second should be forbid
	if !strings.HasPrefix(cedarPolicies[1], "forbid") {
		t.Errorf("expected second policy to be forbid")
	}
}

func TestTranslator_TranslateWithPrincipal_StringLike(t *testing.T) {
	translator := NewTranslator()

	policy := &V0Policy{
		Version: "v0",
		Statements: []Statement{
			{
				Effect:    EffectAllow,
				Actions:   []string{"rosa:CreateAccessEntry"},
				Resources: []string{"*"},
				Conditions: map[string]Condition{
					"ArnLike": {
						"rosa:principalArn": "arn:aws:iam::111122223333:role/developers-*",
					},
				},
			},
		},
	}

	cedarPolicies, err := translator.TranslateWithPrincipal(policy, "user", "arn:aws:iam::111122223333:user/alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cedar := cedarPolicies[0]

	// Check like clause
	if !strings.Contains(cedar, "like") {
		t.Errorf("expected 'like' operator, got: %s", cedar)
	}
}

func TestTranslator_NumericEquals(t *testing.T) {
	translator := NewTranslator()

	policy := &V0Policy{
		Version: "v0",
		Statements: []Statement{
			{
				Effect:    EffectAllow,
				Actions:   []string{"rosa:ListClusters"},
				Resources: []string{"*"},
				Conditions: map[string]Condition{
					"NumericEquals": {
						"rosa:maxResults": 100,
					},
				},
			},
		},
	}

	cedarPolicies, err := translator.TranslateWithPrincipal(policy, "user", "arn:aws:iam::111122223333:user/alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cedar := cedarPolicies[0]
	if !strings.Contains(cedar, "== 100") {
		t.Errorf("expected '== 100' in condition, got: %s", cedar)
	}
}

func TestTranslator_NumericLessThan(t *testing.T) {
	translator := NewTranslator()

	policy := &V0Policy{
		Version: "v0",
		Statements: []Statement{
			{
				Effect:    EffectAllow,
				Actions:   []string{"rosa:ListClusters"},
				Resources: []string{"*"},
				Conditions: map[string]Condition{
					"NumericLessThan": {
						"rosa:maxResults": "50",
					},
				},
			},
		},
	}

	cedarPolicies, err := translator.TranslateWithPrincipal(policy, "user", "arn:aws:iam::111122223333:user/alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cedar := cedarPolicies[0]
	if !strings.Contains(cedar, "< 50") {
		t.Errorf("expected '< 50' in condition, got: %s", cedar)
	}
}

func TestTranslator_NumericGreaterThanEquals(t *testing.T) {
	translator := NewTranslator()

	policy := &V0Policy{
		Version: "v0",
		Statements: []Statement{
			{
				Effect:    EffectAllow,
				Actions:   []string{"rosa:ListClusters"},
				Resources: []string{"*"},
				Conditions: map[string]Condition{
					"NumericGreaterThanEquals": {
						"rosa:minVersion": float64(4),
					},
				},
			},
		},
	}

	cedarPolicies, err := translator.TranslateWithPrincipal(policy, "user", "arn:aws:iam::111122223333:user/alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cedar := cedarPolicies[0]
	if !strings.Contains(cedar, ">= 4") {
		t.Errorf("expected '>= 4' in condition, got: %s", cedar)
	}
}

func TestTranslator_DateEquals(t *testing.T) {
	translator := NewTranslator()

	policy := &V0Policy{
		Version: "v0",
		Statements: []Statement{
			{
				Effect:    EffectAllow,
				Actions:   []string{"rosa:ListClusters"},
				Resources: []string{"*"},
				Conditions: map[string]Condition{
					"DateEquals": {
						"rosa:createdAt": "2024-01-01T00:00:00Z",
					},
				},
			},
		},
	}

	cedarPolicies, err := translator.TranslateWithPrincipal(policy, "user", "arn:aws:iam::111122223333:user/alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cedar := cedarPolicies[0]
	if !strings.Contains(cedar, "datetime(") {
		t.Errorf("expected 'datetime(' in condition, got: %s", cedar)
	}
	if !strings.Contains(cedar, "2024-01-01T00:00:00Z") {
		t.Errorf("expected date value in condition, got: %s", cedar)
	}
}

func TestTranslator_DateGreaterThan(t *testing.T) {
	translator := NewTranslator()

	policy := &V0Policy{
		Version: "v0",
		Statements: []Statement{
			{
				Effect:    EffectAllow,
				Actions:   []string{"rosa:ListClusters"},
				Resources: []string{"*"},
				Conditions: map[string]Condition{
					"DateGreaterThan": {
						"rosa:expiresAt": "2025-12-31T23:59:59Z",
					},
				},
			},
		},
	}

	cedarPolicies, err := translator.TranslateWithPrincipal(policy, "user", "arn:aws:iam::111122223333:user/alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cedar := cedarPolicies[0]
	if !strings.Contains(cedar, "> datetime(") {
		t.Errorf("expected '> datetime(' in condition, got: %s", cedar)
	}
}

func TestTranslator_IpAddress(t *testing.T) {
	translator := NewTranslator()

	policy := &V0Policy{
		Version: "v0",
		Statements: []Statement{
			{
				Effect:    EffectAllow,
				Actions:   []string{"rosa:ListClusters"},
				Resources: []string{"*"},
				Conditions: map[string]Condition{
					"IpAddress": {
						"aws:SourceIp": "192.168.1.100",
					},
				},
			},
		},
	}

	cedarPolicies, err := translator.TranslateWithPrincipal(policy, "user", "arn:aws:iam::111122223333:user/alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cedar := cedarPolicies[0]
	if !strings.Contains(cedar, "ip(") {
		t.Errorf("expected 'ip(' in condition, got: %s", cedar)
	}
	if !strings.Contains(cedar, ".isInRange(") {
		t.Errorf("expected '.isInRange(' in condition, got: %s", cedar)
	}
}

func TestTranslator_IpAddress_CIDR(t *testing.T) {
	translator := NewTranslator()

	policy := &V0Policy{
		Version: "v0",
		Statements: []Statement{
			{
				Effect:    EffectAllow,
				Actions:   []string{"rosa:ListClusters"},
				Resources: []string{"*"},
				Conditions: map[string]Condition{
					"IpAddress": {
						"aws:SourceIp": "10.0.0.0/8",
					},
				},
			},
		},
	}

	cedarPolicies, err := translator.TranslateWithPrincipal(policy, "user", "arn:aws:iam::111122223333:user/alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cedar := cedarPolicies[0]
	if !strings.Contains(cedar, "10.0.0.0/8") {
		t.Errorf("expected CIDR notation in condition, got: %s", cedar)
	}
}

func TestTranslator_NotIpAddress(t *testing.T) {
	translator := NewTranslator()

	policy := &V0Policy{
		Version: "v0",
		Statements: []Statement{
			{
				Effect:    EffectDeny,
				Actions:   []string{"rosa:DeleteCluster"},
				Resources: []string{"*"},
				Conditions: map[string]Condition{
					"NotIpAddress": {
						"aws:SourceIp": "192.168.0.0/16",
					},
				},
			},
		},
	}

	cedarPolicies, err := translator.TranslateWithPrincipal(policy, "user", "arn:aws:iam::111122223333:user/alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cedar := cedarPolicies[0]
	if !strings.Contains(cedar, "!ip(") {
		t.Errorf("expected '!ip(' in condition for negation, got: %s", cedar)
	}
}

func TestTranslator_Null_True(t *testing.T) {
	translator := NewTranslator()

	policy := &V0Policy{
		Version: "v0",
		Statements: []Statement{
			{
				Effect:    EffectAllow,
				Actions:   []string{"rosa:ListClusters"},
				Resources: []string{"*"},
				Conditions: map[string]Condition{
					"Null": {
						"rosa:ResourceTag/Owner": true,
					},
				},
			},
		},
	}

	cedarPolicies, err := translator.TranslateWithPrincipal(policy, "user", "arn:aws:iam::111122223333:user/alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cedar := cedarPolicies[0]
	if !strings.Contains(cedar, "!has") {
		t.Errorf("expected '!has' for Null:true condition, got: %s", cedar)
	}
}

func TestTranslator_Null_False(t *testing.T) {
	translator := NewTranslator()

	policy := &V0Policy{
		Version: "v0",
		Statements: []Statement{
			{
				Effect:    EffectAllow,
				Actions:   []string{"rosa:ListClusters"},
				Resources: []string{"*"},
				Conditions: map[string]Condition{
					"Null": {
						"rosa:ResourceTag/Owner": false,
					},
				},
			},
		},
	}

	cedarPolicies, err := translator.TranslateWithPrincipal(policy, "user", "arn:aws:iam::111122223333:user/alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cedar := cedarPolicies[0]
	if !strings.Contains(cedar, "has resource.tags") {
		t.Errorf("expected 'has resource.tags' for Null:false condition, got: %s", cedar)
	}
	if strings.Contains(cedar, "!has") {
		t.Errorf("should not contain '!has' for Null:false condition, got: %s", cedar)
	}
}

func TestTranslator_StringEqualsIfExists(t *testing.T) {
	translator := NewTranslator()

	policy := &V0Policy{
		Version: "v0",
		Statements: []Statement{
			{
				Effect:    EffectAllow,
				Actions:   []string{"rosa:ListClusters"},
				Resources: []string{"*"},
				Conditions: map[string]Condition{
					"StringEqualsIfExists": {
						"rosa:ResourceTag/Environment": "production",
					},
				},
			},
		},
	}

	cedarPolicies, err := translator.TranslateWithPrincipal(policy, "user", "arn:aws:iam::111122223333:user/alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cedar := cedarPolicies[0]
	if !strings.Contains(cedar, "!has") {
		t.Errorf("expected '!has' in IfExists condition, got: %s", cedar)
	}
	if !strings.Contains(cedar, "||") {
		t.Errorf("expected '||' in IfExists condition, got: %s", cedar)
	}
	if !strings.Contains(cedar, `"production"`) {
		t.Errorf("expected condition value in IfExists condition, got: %s", cedar)
	}
}

func TestTranslator_NumericLessThanIfExists(t *testing.T) {
	translator := NewTranslator()

	policy := &V0Policy{
		Version: "v0",
		Statements: []Statement{
			{
				Effect:    EffectAllow,
				Actions:   []string{"rosa:ListClusters"},
				Resources: []string{"*"},
				Conditions: map[string]Condition{
					"NumericLessThanIfExists": {
						"rosa:maxResults": 100,
					},
				},
			},
		},
	}

	cedarPolicies, err := translator.TranslateWithPrincipal(policy, "user", "arn:aws:iam::111122223333:user/alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cedar := cedarPolicies[0]
	if !strings.Contains(cedar, "!has") {
		t.Errorf("expected '!has' in IfExists condition, got: %s", cedar)
	}
	if !strings.Contains(cedar, "< 100") {
		t.Errorf("expected '< 100' in IfExists condition, got: %s", cedar)
	}
}

func TestTranslator_ForAllValuesStringLike(t *testing.T) {
	translator := NewTranslator()

	policy := &V0Policy{
		Version: "v0",
		Statements: []Statement{
			{
				Effect:    EffectAllow,
				Actions:   []string{"rosa:ListClusters"},
				Resources: []string{"*"},
				Conditions: map[string]Condition{
					"ForAllValues:StringLike": {
						"rosa:TagKeys": []interface{}{"env-*", "team-*"},
					},
				},
			},
		},
	}

	cedarPolicies, err := translator.TranslateWithPrincipal(policy, "user", "arn:aws:iam::111122223333:user/alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cedar := cedarPolicies[0]
	if !strings.Contains(cedar, "like") {
		t.Errorf("expected 'like' operator, got: %s", cedar)
	}
	if !strings.Contains(cedar, "env-*") {
		t.Errorf("expected 'env-*' pattern, got: %s", cedar)
	}
}

func TestTranslator_ForAnyValueStringLike(t *testing.T) {
	translator := NewTranslator()

	policy := &V0Policy{
		Version: "v0",
		Statements: []Statement{
			{
				Effect:    EffectAllow,
				Actions:   []string{"rosa:ListClusters"},
				Resources: []string{"*"},
				Conditions: map[string]Condition{
					"ForAnyValue:StringLike": {
						"rosa:TagKeys": "admin-*",
					},
				},
			},
		},
	}

	cedarPolicies, err := translator.TranslateWithPrincipal(policy, "user", "arn:aws:iam::111122223333:user/alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cedar := cedarPolicies[0]
	if !strings.Contains(cedar, "like") {
		t.Errorf("expected 'like' operator, got: %s", cedar)
	}
	if !strings.Contains(cedar, "admin-*") {
		t.Errorf("expected 'admin-*' pattern, got: %s", cedar)
	}
}

func TestTranslator_ForAllValuesStringNotEquals(t *testing.T) {
	translator := NewTranslator()

	policy := &V0Policy{
		Version: "v0",
		Statements: []Statement{
			{
				Effect:    EffectAllow,
				Actions:   []string{"rosa:TagResource"},
				Resources: []string{"*"},
				Conditions: map[string]Condition{
					"ForAllValues:StringNotEquals": {
						"rosa:TagKeys": []interface{}{"protected", "readonly"},
					},
				},
			},
		},
	}

	cedarPolicies, err := translator.TranslateWithPrincipal(policy, "user", "arn:aws:iam::111122223333:user/alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cedar := cedarPolicies[0]
	if !strings.Contains(cedar, "!") {
		t.Errorf("expected negation in condition, got: %s", cedar)
	}
	if !strings.Contains(cedar, "containsAny") {
		t.Errorf("expected 'containsAny' in negated condition, got: %s", cedar)
	}
}

func TestTranslator_ForAnyValueStringNotEquals(t *testing.T) {
	translator := NewTranslator()

	policy := &V0Policy{
		Version: "v0",
		Statements: []Statement{
			{
				Effect:    EffectAllow,
				Actions:   []string{"rosa:TagResource"},
				Resources: []string{"*"},
				Conditions: map[string]Condition{
					"ForAnyValue:StringNotEquals": {
						"rosa:TagKeys": []interface{}{"required1", "required2"},
					},
				},
			},
		},
	}

	cedarPolicies, err := translator.TranslateWithPrincipal(policy, "user", "arn:aws:iam::111122223333:user/alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cedar := cedarPolicies[0]
	if !strings.Contains(cedar, "!") {
		t.Errorf("expected negation in condition, got: %s", cedar)
	}
	if !strings.Contains(cedar, "containsAll") {
		t.Errorf("expected 'containsAll' in negated condition, got: %s", cedar)
	}
}

func TestTranslator_BinaryEquals(t *testing.T) {
	translator := NewTranslator()

	policy := &V0Policy{
		Version: "v0",
		Statements: []Statement{
			{
				Effect:    EffectAllow,
				Actions:   []string{"rosa:ListClusters"},
				Resources: []string{"*"},
				Conditions: map[string]Condition{
					"BinaryEquals": {
						"rosa:binaryData": "dGVzdA==",
					},
				},
			},
		},
	}

	cedarPolicies, err := translator.TranslateWithPrincipal(policy, "user", "arn:aws:iam::111122223333:user/alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cedar := cedarPolicies[0]
	if !strings.Contains(cedar, `"dGVzdA=="`) {
		t.Errorf("expected base64 value in condition, got: %s", cedar)
	}
}
