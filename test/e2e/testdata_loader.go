package e2e_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
)

// PolicyTestFile represents a test policy file from testdata
type PolicyTestFile struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Source      string     `json:"source,omitempty"`
	Policy      V0Policy   `json:"policy"`
	TestCases   []TestCase `json:"testCases"`
	Notes       string     `json:"notes,omitempty"`
}

// V0Policy represents the server's v0 policy format
type V0Policy struct {
	Version    string      `json:"version"`
	Statements []Statement `json:"statements"`
}

// Statement represents a single policy statement
type Statement struct {
	Sid        string                 `json:"sid,omitempty"`
	Effect     string                 `json:"effect"`
	Actions    []string               `json:"actions"`
	Resources  []string               `json:"resources"`
	Conditions map[string]interface{} `json:"conditions,omitempty"`
}

// TestCase represents a single authorization test case
type TestCase struct {
	Description      string                 `json:"description"`
	Principal        *TestPrincipal         `json:"principal,omitempty"`
	Request          TestRequest            `json:"request"`
	ExpectedResult   string                 `json:"expectedResult"` // "ALLOW", "DENY", "NOT_EVALUATED"
	PolicyEvaluation map[string]interface{} `json:"policyEvaluation,omitempty"`
	AdditionalPolicies []V0Policy           `json:"additionalPolicies,omitempty"`
}

// TestPrincipal represents the principal for a test case
type TestPrincipal struct {
	Username string `json:"username,omitempty"`
}

// TestRequest represents the authorization request for a test case
type TestRequest struct {
	Action       string         `json:"action"`
	Resource     string         `json:"resource"`
	Context      map[string]any `json:"context,omitempty"`
	ResourceTags map[string]any `json:"resourceTags,omitempty"`
}

// getTestDataDir returns the path to the testdata directory
func getTestDataDir() string {
	_, filename, _, _ := runtime.Caller(0)
	testDir := filepath.Dir(filename)
	return filepath.Join(testDir, "..", "..", "pkg", "authz", "testdata", "policies")
}

// LoadAllTestPolicies loads all test policy files from testdata
func LoadAllTestPolicies() ([]PolicyTestFile, error) {
	baseDir := getTestDataDir()
	var policies []PolicyTestFile

	err := filepath.Walk(baseDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if filepath.Ext(path) != ".json" {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		var policy PolicyTestFile
		if err := json.Unmarshal(data, &policy); err != nil {
			return err
		}

		// Add relative path for debugging
		relPath, _ := filepath.Rel(baseDir, path)
		if policy.Name == "" {
			policy.Name = relPath
		}

		policies = append(policies, policy)
		return nil
	})

	return policies, err
}

// LoadTestPoliciesByCategory loads test policies from a specific category
func LoadTestPoliciesByCategory(category string) ([]PolicyTestFile, error) {
	baseDir := filepath.Join(getTestDataDir(), category)
	var policies []PolicyTestFile

	entries, err := os.ReadDir(baseDir)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		data, err := os.ReadFile(filepath.Join(baseDir, entry.Name()))
		if err != nil {
			return nil, err
		}

		var policy PolicyTestFile
		if err := json.Unmarshal(data, &policy); err != nil {
			return nil, err
		}

		policies = append(policies, policy)
	}

	return policies, nil
}

// GetActions extracts all actions from a policy
func (p *V0Policy) GetActions() []string {
	var actions []string
	for _, stmt := range p.Statements {
		actions = append(actions, stmt.Actions...)
	}
	return actions
}

// GetResources extracts all resources from a policy
func (p *V0Policy) GetResources() []string {
	var resources []string
	for _, stmt := range p.Statements {
		resources = append(resources, stmt.Resources...)
	}
	return resources
}
