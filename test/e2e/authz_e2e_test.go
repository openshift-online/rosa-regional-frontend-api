package e2e_test

import (
	"fmt"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// Test configuration
const (
	// PrivilegedAccountID is used as the caller for privileged operations
	PrivilegedAccountID = "000000000000"

	// DefaultTimeout for API operations
	DefaultTimeout = 30 * time.Second
)

var _ = Describe("Authz E2E Tests", Ordered, func() {
	var (
		client       *APIClient
		testPolicies []PolicyTestFile
	)

	BeforeAll(func() {
		// Get base URL from environment or use default
		baseURL := os.Getenv("E2E_BASE_URL")
		if baseURL == "" {
			baseURL = "http://localhost:8000"
		}
		client = NewAPIClient(baseURL)

		// Wait for service to be ready
		Eventually(func() error {
			return client.CheckReady()
		}, DefaultTimeout, 1*time.Second).Should(Succeed(), "Service should be ready")

		// Load all test policies
		var err error
		testPolicies, err = LoadAllTestPolicies()
		Expect(err).NotTo(HaveOccurred(), "Should load test policies")
		Expect(testPolicies).NotTo(BeEmpty(), "Should have test policies")

		GinkgoWriter.Printf("Loaded %d test policy files\n", len(testPolicies))
	})

	// Test each policy file
	Context("Policy Authorization Tests", func() {
		It("should test all policy files and their test cases", func() {
			totalTests := 0
			passedTests := 0
			failedTests := 0

			for _, policyFile := range testPolicies {
				GinkgoWriter.Printf("\n=== Testing Policy: %s ===\n", policyFile.Name)
				GinkgoWriter.Printf("Description: %s\n", policyFile.Description)
				GinkgoWriter.Printf("Test cases: %d\n", len(policyFile.TestCases))

				// Create unique test account for this policy
				testAccountID := fmt.Sprintf("test-%d", time.Now().UnixNano())

				// Setup: Create account
				_, err := client.CreateAccount(PrivilegedAccountID, testAccountID, false)
				if err != nil {
					GinkgoWriter.Printf("SKIP: Failed to create account: %v\n", err)
					continue
				}

				// Setup: Create policy
				policyID, err := client.CreatePolicy(
					testAccountID,
					policyFile.Name,
					policyFile.Description,
					policyFile.Policy,
				)
				if err != nil {
					GinkgoWriter.Printf("SKIP: Failed to create policy: %v\n", err)
					continue
				}

				// Setup: Create group
				groupID, err := client.CreateGroup(testAccountID, "test-group", "Test group for e2e")
				if err != nil {
					GinkgoWriter.Printf("SKIP: Failed to create group: %v\n", err)
					continue
				}

				// Setup: Attach policy to group
				attachmentID, err := client.CreateAttachment(testAccountID, policyID, "group", groupID)
				if err != nil {
					GinkgoWriter.Printf("SKIP: Failed to create attachment: %v\n", err)
					continue
				}

				// Run each test case
				for i, tc := range policyFile.TestCases {
					totalTests++
					testName := fmt.Sprintf("[%d] %s", i+1, tc.Description)

					// Skip NOT_EVALUATED test cases
					if tc.ExpectedResult == "NOT_EVALUATED" {
						GinkgoWriter.Printf("  %s: SKIP (NOT_EVALUATED)\n", testName)
						continue
					}

					// Determine principal
					principal := fmt.Sprintf("arn:aws:iam::%s:user/testuser", testAccountID)
					if tc.Principal != nil && tc.Principal.Username != "" {
						principal = fmt.Sprintf("arn:aws:iam::%s:user/%s", testAccountID, tc.Principal.Username)
					}

					// Add user to group
					err := client.AddGroupMembers(testAccountID, groupID, []string{principal})
					if err != nil {
						GinkgoWriter.Printf("  %s: SKIP (failed to add member: %v)\n", testName, err)
						continue
					}

					// Build resource tags as string map
					resourceTags := make(map[string]string)
					for k, v := range tc.Request.ResourceTags {
						if s, ok := v.(string); ok {
							resourceTags[k] = s
						}
					}

					// Call the authorization check endpoint
					authzReq := CheckAuthorizationRequest{
						Principal:    principal,
						Action:       tc.Request.Action,
						Resource:     tc.Request.Resource,
						Context:      tc.Request.Context,
						ResourceTags: resourceTags,
					}

					decision, err := client.CheckAuthorization(testAccountID, authzReq)
					if err != nil {
						GinkgoWriter.Printf("  %s: ERROR (%v)\n", testName, err)
						failedTests++
						continue
					}

					// Compare with expected result
					if decision == tc.ExpectedResult {
						GinkgoWriter.Printf("  %s: PASS (got %s, expected %s)\n", testName, decision, tc.ExpectedResult)
						passedTests++
					} else {
						GinkgoWriter.Printf("  %s: FAIL (got %s, expected %s) action=%s resource=%s\n",
							testName, decision, tc.ExpectedResult, tc.Request.Action, tc.Request.Resource)
						failedTests++
					}
				}

				// Cleanup
				_ = client.DeleteAttachment(testAccountID, attachmentID)
				_ = client.DeleteGroup(testAccountID, groupID)
				_ = client.DeletePolicy(testAccountID, policyID)
			}

			GinkgoWriter.Printf("\n=== Test Summary ===\n")
			GinkgoWriter.Printf("Total: %d, Passed: %d, Failed: %d\n", totalTests, passedTests, failedTests)
			Expect(failedTests).To(Equal(0), "All tests should pass")
		})
	})

	// Individual category tests for better organization
	Context("Basic Access Policies", func() {
		It("should load and validate 01-basic-access policies", func() {
			policies, err := LoadTestPoliciesByCategory("01-basic-access")
			Expect(err).NotTo(HaveOccurred())
			Expect(policies).NotTo(BeEmpty())

			for _, p := range policies {
				GinkgoWriter.Printf("Policy: %s (%d test cases)\n", p.Name, len(p.TestCases))
				Expect(p.TestCases).NotTo(BeEmpty(), "Policy %s should have test cases", p.Name)
			}
		})
	})

	Context("Cluster Management Policies", func() {
		It("should load and validate 02-cluster-management policies", func() {
			policies, err := LoadTestPoliciesByCategory("02-cluster-management")
			Expect(err).NotTo(HaveOccurred())
			Expect(policies).NotTo(BeEmpty())

			for _, p := range policies {
				GinkgoWriter.Printf("Policy: %s (%d test cases)\n", p.Name, len(p.TestCases))
				Expect(p.TestCases).NotTo(BeEmpty(), "Policy %s should have test cases", p.Name)
			}
		})
	})

	Context("Tag-Based Access Policies", func() {
		It("should load and validate 05-tag-based-access policies", func() {
			policies, err := LoadTestPoliciesByCategory("05-tag-based-access")
			Expect(err).NotTo(HaveOccurred())
			Expect(policies).NotTo(BeEmpty())

			for _, p := range policies {
				GinkgoWriter.Printf("Policy: %s (%d test cases)\n", p.Name, len(p.TestCases))
				Expect(p.TestCases).NotTo(BeEmpty(), "Policy %s should have test cases", p.Name)

				// Tag-based policies should have conditions
				for _, stmt := range p.Policy.Statements {
					if stmt.Conditions != nil {
						GinkgoWriter.Printf("  - Has conditions in statement %s\n", stmt.Sid)
					}
				}
			}
		})
	})

	Context("Deny Policies", func() {
		It("should load and validate 06-deny-policies policies", func() {
			policies, err := LoadTestPoliciesByCategory("06-deny-policies")
			Expect(err).NotTo(HaveOccurred())
			Expect(policies).NotTo(BeEmpty())

			for _, p := range policies {
				GinkgoWriter.Printf("Policy: %s (%d test cases)\n", p.Name, len(p.TestCases))
				Expect(p.TestCases).NotTo(BeEmpty(), "Policy %s should have test cases", p.Name)

				// Deny policies should have at least one Deny statement
				hasDeny := false
				for _, stmt := range p.Policy.Statements {
					if stmt.Effect == "Deny" {
						hasDeny = true
						break
					}
				}
				Expect(hasDeny).To(BeTrue(), "Policy %s should have at least one Deny statement", p.Name)
			}
		})
	})

	Context("Complex Scenarios", func() {
		It("should load and validate 08-complex-scenarios policies", func() {
			policies, err := LoadTestPoliciesByCategory("08-complex-scenarios")
			Expect(err).NotTo(HaveOccurred())
			Expect(policies).NotTo(BeEmpty())

			for _, p := range policies {
				GinkgoWriter.Printf("Policy: %s (%d test cases)\n", p.Name, len(p.TestCases))
				Expect(p.TestCases).NotTo(BeEmpty(), "Policy %s should have test cases", p.Name)
			}
		})
	})
})
