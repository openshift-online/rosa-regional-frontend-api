package policy

// V0Policy represents an IAM-like policy in v0 format
type V0Policy struct {
	Version    string      `json:"version"`
	Statements []Statement `json:"statements"`
}

// Statement represents a single policy statement
type Statement struct {
	Sid        string            `json:"sid,omitempty"`
	Effect     Effect            `json:"effect"`
	Actions    []string          `json:"actions"`
	Resources  []string          `json:"resources"`
	Conditions map[string]Condition `json:"conditions,omitempty"`
}

// Effect is either Allow or Deny
type Effect string

const (
	EffectAllow Effect = "Allow"
	EffectDeny  Effect = "Deny"
)

// Condition represents a condition in a policy statement
// The key is the condition operator (StringEquals, StringLike, etc.)
// The value maps condition keys to their expected values
type Condition map[string]interface{}

// ConditionOperator represents the type of condition comparison
type ConditionOperator string

const (
	// String operators
	ConditionStringEquals    ConditionOperator = "StringEquals"
	ConditionStringNotEquals ConditionOperator = "StringNotEquals"
	ConditionStringLike      ConditionOperator = "StringLike"
	ConditionStringNotLike   ConditionOperator = "StringNotLike"

	// ARN operators
	ConditionArnEquals    ConditionOperator = "ArnEquals"
	ConditionArnLike      ConditionOperator = "ArnLike"
	ConditionArnNotEquals ConditionOperator = "ArnNotEquals"
	ConditionArnNotLike   ConditionOperator = "ArnNotLike"

	// Boolean operator
	ConditionBool ConditionOperator = "Bool"

	// Numeric operators
	ConditionNumericEquals            ConditionOperator = "NumericEquals"
	ConditionNumericNotEquals         ConditionOperator = "NumericNotEquals"
	ConditionNumericLessThan          ConditionOperator = "NumericLessThan"
	ConditionNumericLessThanEquals    ConditionOperator = "NumericLessThanEquals"
	ConditionNumericGreaterThan       ConditionOperator = "NumericGreaterThan"
	ConditionNumericGreaterThanEquals ConditionOperator = "NumericGreaterThanEquals"

	// Date operators
	ConditionDateEquals            ConditionOperator = "DateEquals"
	ConditionDateNotEquals         ConditionOperator = "DateNotEquals"
	ConditionDateLessThan          ConditionOperator = "DateLessThan"
	ConditionDateLessThanEquals    ConditionOperator = "DateLessThanEquals"
	ConditionDateGreaterThan       ConditionOperator = "DateGreaterThan"
	ConditionDateGreaterThanEquals ConditionOperator = "DateGreaterThanEquals"

	// IP operators
	ConditionIpAddress    ConditionOperator = "IpAddress"
	ConditionNotIpAddress ConditionOperator = "NotIpAddress"

	// Binary operator
	ConditionBinaryEquals ConditionOperator = "BinaryEquals"

	// Null operator
	ConditionNull ConditionOperator = "Null"

	// Set operators - StringEquals variants
	ConditionForAllValuesStringEquals    ConditionOperator = "ForAllValues:StringEquals"
	ConditionForAnyValueStringEquals     ConditionOperator = "ForAnyValue:StringEquals"
	ConditionForAllValuesStringNotEquals ConditionOperator = "ForAllValues:StringNotEquals"
	ConditionForAnyValueStringNotEquals  ConditionOperator = "ForAnyValue:StringNotEquals"

	// Set operators - StringLike variants
	ConditionForAllValuesStringLike ConditionOperator = "ForAllValues:StringLike"
	ConditionForAnyValueStringLike  ConditionOperator = "ForAnyValue:StringLike"
)

// SupportedConditionKeys defines the condition keys supported in MVP
var SupportedConditionKeys = map[string]bool{
	"rosa:ResourceTag/":  true, // rosa:ResourceTag/${TagKey}
	"rosa:RequestTag/":   true, // rosa:RequestTag/${TagKey}
	"rosa:TagKeys":       true,
	"aws:PrincipalArn":   true,
	"aws:PrincipalAccount": true,
	"rosa:principalArn":  true, // For access entry conditions
}

// IsConditionKeySupported checks if a condition key is supported
func IsConditionKeySupported(key string) bool {
	// Check exact matches first
	if SupportedConditionKeys[key] {
		return true
	}

	// Check prefix matches for tag conditions
	for prefix := range SupportedConditionKeys {
		if len(key) > len(prefix) && key[:len(prefix)] == prefix {
			return true
		}
	}

	return false
}

// PolicyWithPrincipal represents a policy with an attached principal
type PolicyWithPrincipal struct {
	Policy        *V0Policy
	PrincipalType string // "user" or "group"
	PrincipalID   string // ARN for user, groupId for group
}

// TranslatedPolicy represents a Cedar policy ready for AVP
type TranslatedPolicy struct {
	CedarPolicy string
	Effect      Effect
}
