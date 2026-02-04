package policy

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Translator converts v0 IAM-like policies to Cedar format
type Translator struct{}

// NewTranslator creates a new policy translator
func NewTranslator() *Translator {
	return &Translator{}
}

// TranslateWithPrincipal translates a v0 policy to Cedar format with a specific principal
func (t *Translator) TranslateWithPrincipal(policy *V0Policy, principalType, principalID string) ([]string, error) {
	var cedarPolicies []string

	for _, stmt := range policy.Statements {
		cedarPolicy, err := t.translateStatement(stmt, principalType, principalID)
		if err != nil {
			return nil, fmt.Errorf("failed to translate statement %s: %w", stmt.Sid, err)
		}
		cedarPolicies = append(cedarPolicies, cedarPolicy)
	}

	return cedarPolicies, nil
}

// translateStatement translates a single v0 statement to Cedar
func (t *Translator) translateStatement(stmt Statement, principalType, principalID string) (string, error) {
	var sb strings.Builder

	// Effect - Cedar uses permit/forbid, not allow/deny
	var cedarEffect string
	switch stmt.Effect {
	case EffectAllow:
		cedarEffect = "permit"
	case EffectDeny:
		cedarEffect = "forbid"
	default:
		cedarEffect = "permit"
	}
	sb.WriteString(cedarEffect)
	sb.WriteString(" (\n")

	// Principal clause
	principalClause := t.buildPrincipalClause(principalType, principalID)
	sb.WriteString("  ")
	sb.WriteString(principalClause)
	sb.WriteString(",\n")

	// Action clause
	actionClause, err := t.buildActionClause(stmt.Actions)
	if err != nil {
		return "", err
	}
	sb.WriteString("  ")
	sb.WriteString(actionClause)
	sb.WriteString(",\n")

	// Resource clause (scope) and any wildcard conditions
	resourceScope, resourceCondition := t.buildResourceClauses(stmt.Resources)
	sb.WriteString("  ")
	sb.WriteString(resourceScope)
	sb.WriteString("\n)")

	// Build combined when clause from conditions and resource wildcards
	var whenClauses []string

	// Add resource wildcard conditions
	if resourceCondition != "" {
		whenClauses = append(whenClauses, resourceCondition)
	}

	// Add statement conditions
	if len(stmt.Conditions) > 0 {
		whenClause, err := t.buildWhenClause(stmt.Conditions)
		if err != nil {
			return "", err
		}
		if whenClause != "" {
			whenClauses = append(whenClauses, whenClause)
		}
	}

	// Write when clause if we have any conditions
	if len(whenClauses) > 0 {
		sb.WriteString("\nwhen {\n  ")
		sb.WriteString(strings.Join(whenClauses, " && "))
		sb.WriteString("\n}")
	}

	sb.WriteString(";")
	return sb.String(), nil
}

// buildPrincipalClause creates the Cedar principal clause
func (t *Translator) buildPrincipalClause(principalType, principalID string) string {
	switch principalType {
	case "user":
		return fmt.Sprintf("principal == ROSA::Principal::\"%s\"", principalID)
	case "group":
		return fmt.Sprintf("principal in ROSA::Group::\"%s\"", principalID)
	default:
		return "principal"
	}
}

// buildActionClause creates the Cedar action clause
func (t *Translator) buildActionClause(actions []string) (string, error) {
	if len(actions) == 0 {
		return "", fmt.Errorf("no actions specified")
	}

	// Handle wildcard
	if len(actions) == 1 && actions[0] == "*" {
		return "action", nil
	}

	// Expand action patterns and collect unique actions
	expandedActions := make(map[string]struct{})
	for _, action := range actions {
		expanded := t.expandAction(action)
		for _, a := range expanded {
			expandedActions[a] = struct{}{}
		}
	}

	if len(expandedActions) == 1 {
		for action := range expandedActions {
			return fmt.Sprintf("action == ROSA::Action::\"%s\"", action), nil
		}
	}

	// Multiple actions
	var actionList []string
	for action := range expandedActions {
		actionList = append(actionList, fmt.Sprintf("ROSA::Action::\"%s\"", action))
	}

	return fmt.Sprintf("action in [%s]", strings.Join(actionList, ", ")), nil
}

// expandAction expands action patterns like rosa:Describe* to actual actions
func (t *Translator) expandAction(action string) []string {
	// Remove rosa: prefix if present
	action = strings.TrimPrefix(action, "rosa:")

	// Handle wildcards
	if action == "*" {
		return allActions
	}

	// Handle prefix wildcards (e.g., Describe*)
	if strings.HasSuffix(action, "*") {
		prefix := strings.TrimSuffix(action, "*")
		var matching []string
		for _, a := range allActions {
			if strings.HasPrefix(a, prefix) {
				matching = append(matching, a)
			}
		}
		if len(matching) > 0 {
			return matching
		}
	}

	// Single action
	return []string{action}
}

// buildResourceClauses creates the Cedar resource scope clause and any wildcard conditions
// Returns (scopeClause, conditionClause) - conditionClause goes in "when" block
func (t *Translator) buildResourceClauses(resources []string) (string, string) {
	if len(resources) == 0 || (len(resources) == 1 && resources[0] == "*") {
		return "resource", ""
	}

	// Separate exact matches from wildcard patterns
	var exactMatches []string
	var wildcardPatterns []string
	for _, r := range resources {
		if strings.Contains(r, "*") {
			wildcardPatterns = append(wildcardPatterns, r)
		} else {
			exactMatches = append(exactMatches, r)
		}
	}

	// If we have wildcards, we need to use "resource" in scope and put conditions in when clause
	if len(wildcardPatterns) > 0 {
		var conditions []string

		// Add exact match conditions
		for _, r := range exactMatches {
			conditions = append(conditions, fmt.Sprintf("resource.arn == \"%s\"", r))
		}

		// Add wildcard pattern conditions
		for _, pattern := range wildcardPatterns {
			conditions = append(conditions, fmt.Sprintf("resource.arn like \"%s\"", pattern))
		}

		// Combine with OR
		if len(conditions) == 1 {
			return "resource", conditions[0]
		}
		return "resource", "(" + strings.Join(conditions, " || ") + ")"
	}

	// Only exact matches - can use scope clause
	if len(exactMatches) == 1 {
		return fmt.Sprintf("resource == ROSA::Resource::\"%s\"", exactMatches[0]), ""
	}

	var resourceList []string
	for _, r := range exactMatches {
		resourceList = append(resourceList, fmt.Sprintf("ROSA::Resource::\"%s\"", r))
	}
	return fmt.Sprintf("resource in [%s]", strings.Join(resourceList, ", ")), ""
}

// buildWhenClause creates the Cedar when clause from conditions
func (t *Translator) buildWhenClause(conditions map[string]Condition) (string, error) {
	var clauses []string

	for operator, condition := range conditions {
		for key, value := range condition {
			clause, err := t.translateCondition(ConditionOperator(operator), key, value)
			if err != nil {
				return "", err
			}
			if clause != "" {
				clauses = append(clauses, clause)
			}
		}
	}

	if len(clauses) == 0 {
		return "", nil
	}

	return strings.Join(clauses, " && "), nil
}

// translateCondition translates a single condition to Cedar
func (t *Translator) translateCondition(operator ConditionOperator, key string, value any) (string, error) {
	// Check for IfExists suffix
	opStr := string(operator)
	if strings.HasSuffix(opStr, "IfExists") {
		baseOp := ConditionOperator(strings.TrimSuffix(opStr, "IfExists"))
		return t.translateIfExists(baseOp, key, value)
	}

	switch operator {
	// String operators
	case ConditionStringEquals:
		return t.translateStringEquals(key, value, false)
	case ConditionStringNotEquals:
		return t.translateStringEquals(key, value, true)
	case ConditionStringLike, ConditionArnLike:
		return t.translateStringLike(key, value, false)
	case ConditionStringNotLike, ConditionArnNotLike:
		return t.translateStringLike(key, value, true)
	case ConditionArnEquals:
		return t.translateStringEquals(key, value, false)
	case ConditionArnNotEquals:
		return t.translateStringEquals(key, value, true)

	// Boolean operator
	case ConditionBool:
		return t.translateBool(key, value)

	// Numeric operators
	case ConditionNumericEquals:
		return t.translateNumeric(key, value, "==")
	case ConditionNumericNotEquals:
		return t.translateNumeric(key, value, "!=")
	case ConditionNumericLessThan:
		return t.translateNumeric(key, value, "<")
	case ConditionNumericLessThanEquals:
		return t.translateNumeric(key, value, "<=")
	case ConditionNumericGreaterThan:
		return t.translateNumeric(key, value, ">")
	case ConditionNumericGreaterThanEquals:
		return t.translateNumeric(key, value, ">=")

	// Date operators
	case ConditionDateEquals:
		return t.translateDate(key, value, "==")
	case ConditionDateNotEquals:
		return t.translateDate(key, value, "!=")
	case ConditionDateLessThan:
		return t.translateDate(key, value, "<")
	case ConditionDateLessThanEquals:
		return t.translateDate(key, value, "<=")
	case ConditionDateGreaterThan:
		return t.translateDate(key, value, ">")
	case ConditionDateGreaterThanEquals:
		return t.translateDate(key, value, ">=")

	// IP operators
	case ConditionIpAddress:
		return t.translateIpAddress(key, value, false)
	case ConditionNotIpAddress:
		return t.translateIpAddress(key, value, true)

	// Binary operator
	case ConditionBinaryEquals:
		return t.translateStringEquals(key, value, false)

	// Null operator
	case ConditionNull:
		return t.translateNull(key, value)

	// Set operators - StringEquals variants
	case ConditionForAllValuesStringEquals:
		return t.translateForAllValues(key, value)
	case ConditionForAnyValueStringEquals:
		return t.translateForAnyValue(key, value)
	case ConditionForAllValuesStringNotEquals:
		return t.translateForAllValuesNot(key, value)
	case ConditionForAnyValueStringNotEquals:
		return t.translateForAnyValueNot(key, value)

	// Set operators - StringLike variants
	case ConditionForAllValuesStringLike:
		return t.translateForAllValuesLike(key, value)
	case ConditionForAnyValueStringLike:
		return t.translateForAnyValueLike(key, value)

	default:
		return "", fmt.Errorf("unsupported condition operator: %s", operator)
	}
}

// translateStringEquals handles StringEquals conditions
func (t *Translator) translateStringEquals(key string, value any, negate bool) (string, error) {
	cedarKey := t.translateConditionKey(key)
	op := "=="
	if negate {
		op = "!="
	}

	switch v := value.(type) {
	case string:
		return fmt.Sprintf("%s %s \"%s\"", cedarKey, op, v), nil
	case []interface{}:
		// Multiple values (OR)
		if negate {
			// For NotEquals with multiple values, all must not match (AND)
			var clauses []string
			for _, val := range v {
				clauses = append(clauses, fmt.Sprintf("%s != \"%v\"", cedarKey, val))
			}
			return strings.Join(clauses, " && "), nil
		}
		// For Equals with multiple values, any can match (OR)
		var clauses []string
		for _, val := range v {
			clauses = append(clauses, fmt.Sprintf("%s == \"%v\"", cedarKey, val))
		}
		return "(" + strings.Join(clauses, " || ") + ")", nil
	default:
		return fmt.Sprintf("%s %s \"%v\"", cedarKey, op, v), nil
	}
}

// translateStringLike handles StringLike/ArnLike conditions
func (t *Translator) translateStringLike(key string, value any, negate bool) (string, error) {
	cedarKey := t.translateConditionKey(key)

	switch v := value.(type) {
	case string:
		return t.buildLikeClause(cedarKey, v, negate), nil
	case []interface{}:
		var clauses []string
		for _, val := range v {
			clauses = append(clauses, t.buildLikeClause(cedarKey, fmt.Sprintf("%v", val), negate))
		}
		if negate {
			return strings.Join(clauses, " && "), nil
		}
		return "(" + strings.Join(clauses, " || ") + ")", nil
	default:
		return t.buildLikeClause(cedarKey, fmt.Sprintf("%v", v), negate), nil
	}
}

// buildLikeClause creates a Cedar like clause
func (t *Translator) buildLikeClause(key, pattern string, negate bool) string {
	// Convert IAM wildcards to Cedar wildcards
	// IAM uses * and ?, Cedar uses * only
	cedarPattern := strings.ReplaceAll(pattern, "?", "*")

	if negate {
		return fmt.Sprintf("!(%s like \"%s\")", key, cedarPattern)
	}
	return fmt.Sprintf("%s like \"%s\"", key, cedarPattern)
}

// translateBool handles Bool conditions
func (t *Translator) translateBool(key string, value any) (string, error) {
	cedarKey := t.translateConditionKey(key)
	boolVal := "false"
	if v, ok := value.(bool); ok && v {
		boolVal = "true"
	} else if v, ok := value.(string); ok && v == "true" {
		boolVal = "true"
	}
	return fmt.Sprintf("%s == %s", cedarKey, boolVal), nil
}

// translateForAllValues handles ForAllValues:StringEquals
func (t *Translator) translateForAllValues(key string, value any) (string, error) {
	cedarKey := t.translateConditionKey(key)
	values, ok := value.([]interface{})
	if !ok {
		return "", fmt.Errorf("ForAllValues requires array value")
	}

	var valueStrings []string
	for _, v := range values {
		valueStrings = append(valueStrings, fmt.Sprintf("\"%v\"", v))
	}

	return fmt.Sprintf("%s.containsAll([%s])", cedarKey, strings.Join(valueStrings, ", ")), nil
}

// translateForAnyValue handles ForAnyValue:StringEquals
func (t *Translator) translateForAnyValue(key string, value any) (string, error) {
	cedarKey := t.translateConditionKey(key)
	values, ok := value.([]interface{})
	if !ok {
		return "", fmt.Errorf("ForAnyValue requires array value")
	}

	var valueStrings []string
	for _, v := range values {
		valueStrings = append(valueStrings, fmt.Sprintf("\"%v\"", v))
	}

	return fmt.Sprintf("%s.containsAny([%s])", cedarKey, strings.Join(valueStrings, ", ")), nil
}

// translateForAllValuesNot handles ForAllValues:StringNotEquals
// All values in the request set must NOT be in the specified set
func (t *Translator) translateForAllValuesNot(key string, value any) (string, error) {
	cedarKey := t.translateConditionKey(key)
	values, ok := value.([]interface{})
	if !ok {
		return "", fmt.Errorf("ForAllValues:StringNotEquals requires array value")
	}

	var valueStrings []string
	for _, v := range values {
		valueStrings = append(valueStrings, fmt.Sprintf("\"%v\"", v))
	}

	// None of the values in the set should match any of the specified values
	return fmt.Sprintf("!%s.containsAny([%s])", cedarKey, strings.Join(valueStrings, ", ")), nil
}

// translateForAnyValueNot handles ForAnyValue:StringNotEquals
// At least one value in the request set must NOT equal any of the specified values
func (t *Translator) translateForAnyValueNot(key string, value any) (string, error) {
	cedarKey := t.translateConditionKey(key)
	values, ok := value.([]interface{})
	if !ok {
		return "", fmt.Errorf("ForAnyValue:StringNotEquals requires array value")
	}

	var valueStrings []string
	for _, v := range values {
		valueStrings = append(valueStrings, fmt.Sprintf("\"%v\"", v))
	}

	// Not all values in the set are contained in the specified values
	return fmt.Sprintf("!%s.containsAll([%s])", cedarKey, strings.Join(valueStrings, ", ")), nil
}

// translateForAllValuesLike handles ForAllValues:StringLike
// All values in the request set must match at least one of the patterns
func (t *Translator) translateForAllValuesLike(key string, value any) (string, error) {
	cedarKey := t.translateConditionKey(key)

	var patterns []string
	switch v := value.(type) {
	case string:
		patterns = []string{v}
	case []interface{}:
		for _, p := range v {
			patterns = append(patterns, fmt.Sprintf("%v", p))
		}
	default:
		return "", fmt.Errorf("ForAllValues:StringLike requires string or array value")
	}

	// Build pattern matches with OR logic
	var patternClauses []string
	for _, pattern := range patterns {
		cedarPattern := strings.ReplaceAll(pattern, "?", "*")
		patternClauses = append(patternClauses, fmt.Sprintf("%s like \"%s\"", cedarKey, cedarPattern))
	}

	if len(patternClauses) == 1 {
		return patternClauses[0], nil
	}
	return "(" + strings.Join(patternClauses, " || ") + ")", nil
}

// translateForAnyValueLike handles ForAnyValue:StringLike
// At least one value in the request set must match at least one pattern
func (t *Translator) translateForAnyValueLike(key string, value any) (string, error) {
	cedarKey := t.translateConditionKey(key)

	var patterns []string
	switch v := value.(type) {
	case string:
		patterns = []string{v}
	case []interface{}:
		for _, p := range v {
			patterns = append(patterns, fmt.Sprintf("%v", p))
		}
	default:
		return "", fmt.Errorf("ForAnyValue:StringLike requires string or array value")
	}

	// Build pattern matches with OR logic
	var patternClauses []string
	for _, pattern := range patterns {
		cedarPattern := strings.ReplaceAll(pattern, "?", "*")
		patternClauses = append(patternClauses, fmt.Sprintf("%s like \"%s\"", cedarKey, cedarPattern))
	}

	if len(patternClauses) == 1 {
		return patternClauses[0], nil
	}
	return "(" + strings.Join(patternClauses, " || ") + ")", nil
}

// translateNumeric handles numeric comparison operators
func (t *Translator) translateNumeric(key string, value any, op string) (string, error) {
	cedarKey := t.translateConditionKey(key)

	// Parse the value to an integer
	var numValue int64
	switch v := value.(type) {
	case float64:
		numValue = int64(v)
	case int:
		numValue = int64(v)
	case int64:
		numValue = v
	case string:
		parsed, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return "", fmt.Errorf("invalid numeric value: %v", v)
		}
		numValue = parsed
	default:
		return "", fmt.Errorf("unsupported numeric value type: %T", v)
	}

	return fmt.Sprintf("%s %s %d", cedarKey, op, numValue), nil
}

// translateDate handles date comparison operators
func (t *Translator) translateDate(key string, value any, op string) (string, error) {
	cedarKey := t.translateConditionKey(key)

	dateStr, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("date value must be a string")
	}

	return fmt.Sprintf("datetime(%s) %s datetime(\"%s\")", cedarKey, op, dateStr), nil
}

// translateIpAddress handles IP address/CIDR conditions
func (t *Translator) translateIpAddress(key string, value any, negate bool) (string, error) {
	cedarKey := t.translateConditionKey(key)

	switch v := value.(type) {
	case string:
		return t.buildIpClause(cedarKey, v, negate), nil
	case []interface{}:
		var clauses []string
		for _, val := range v {
			clauses = append(clauses, t.buildIpClause(cedarKey, fmt.Sprintf("%v", val), negate))
		}
		if negate {
			// For NotIpAddress, all must not match (AND)
			return strings.Join(clauses, " && "), nil
		}
		// For IpAddress, any can match (OR)
		return "(" + strings.Join(clauses, " || ") + ")", nil
	default:
		return t.buildIpClause(cedarKey, fmt.Sprintf("%v", v), negate), nil
	}
}

// buildIpClause creates a Cedar IP range check clause
func (t *Translator) buildIpClause(key, ipOrCidr string, negate bool) string {
	if negate {
		return fmt.Sprintf("!ip(%s).isInRange(ip(\"%s\"))", key, ipOrCidr)
	}
	return fmt.Sprintf("ip(%s).isInRange(ip(\"%s\"))", key, ipOrCidr)
}

// translateNull handles Null condition (existence check)
func (t *Translator) translateNull(key string, value any) (string, error) {
	cedarKey := t.translateConditionKey(key)

	// Null: true means key should NOT exist
	// Null: false means key should exist
	isNull := false
	switch v := value.(type) {
	case bool:
		isNull = v
	case string:
		isNull = v == "true"
	default:
		return "", fmt.Errorf("Null condition value must be boolean or string")
	}

	if isNull {
		// Key should not exist
		return fmt.Sprintf("!has %s", cedarKey), nil
	}
	// Key should exist
	return fmt.Sprintf("has %s", cedarKey), nil
}

// translateIfExists handles the IfExists suffix for any operator
// Pattern: if key doesn't exist, condition passes; otherwise evaluate normally
func (t *Translator) translateIfExists(baseOperator ConditionOperator, key string, value any) (string, error) {
	cedarKey := t.translateConditionKey(key)

	// Get the base condition
	baseCondition, err := t.translateCondition(baseOperator, key, value)
	if err != nil {
		return "", fmt.Errorf("failed to translate base condition for IfExists: %w", err)
	}

	// If key doesn't exist, condition passes; otherwise evaluate the base condition
	return fmt.Sprintf("(!has %s || (%s))", cedarKey, baseCondition), nil
}

// translateConditionKey converts IAM condition keys to Cedar attribute paths
func (t *Translator) translateConditionKey(key string) string {
	// Handle resource tag conditions
	if strings.HasPrefix(key, "rosa:ResourceTag/") {
		tagKey := strings.TrimPrefix(key, "rosa:ResourceTag/")
		return fmt.Sprintf("resource.tags[\"%s\"]", tagKey)
	}

	// Handle request tag conditions
	if strings.HasPrefix(key, "rosa:RequestTag/") {
		tagKey := strings.TrimPrefix(key, "rosa:RequestTag/")
		return fmt.Sprintf("context.requestTags[\"%s\"]", tagKey)
	}

	// Handle tag keys condition
	if key == "rosa:TagKeys" {
		return "context.tagKeys"
	}

	// Handle principal conditions
	if key == "aws:PrincipalArn" || key == "rosa:principalArn" {
		return "context.principalArn"
	}

	if key == "aws:PrincipalAccount" {
		return "context.principalAccount"
	}

	// Default: use as-is in context
	return fmt.Sprintf("context.%s", sanitizeKey(key))
}

// sanitizeKey converts a condition key to a valid Cedar identifier
func sanitizeKey(key string) string {
	// Replace invalid characters with underscores
	re := regexp.MustCompile(`[^a-zA-Z0-9_]`)
	return re.ReplaceAllString(key, "_")
}

// allActions is the list of all ROSA actions
var allActions = []string{
	"CreateCluster",
	"DeleteCluster",
	"DescribeCluster",
	"ListClusters",
	"UpdateCluster",
	"UpdateClusterConfig",
	"UpdateClusterVersion",
	"CreateNodePool",
	"DeleteNodePool",
	"DescribeNodePool",
	"ListNodePools",
	"UpdateNodePool",
	"ScaleNodePool",
	"CreateAccessEntry",
	"DeleteAccessEntry",
	"DescribeAccessEntry",
	"ListAccessEntries",
	"UpdateAccessEntry",
	"TagResource",
	"UntagResource",
	"ListTagsForResource",
	"ListAccessPolicies",
}
