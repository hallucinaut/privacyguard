// Package compliance provides privacy compliance checking.
package compliance

import (
	"fmt"
	"math"
	"time"
)

// Regulation represents a privacy regulation.
type Regulation string

const (
	RegulationGDPR     Regulation = "GDPR"
	RegulationHIPAA    Regulation = "HIPAA"
	RegulationCCPA     Regulation = "CCPA"
	RegulationPCI_DSS  Regulation = "PCI-DSS"
	RegulationPIPEDA   Regulation = "PIPEDA"
	RegulationLGPD     Regulation = "LGPD"
)

// ComplianceRequirement represents a compliance requirement.
type ComplianceRequirement struct {
	Regulation  Regulation
	ID          string
	Name        string
	Description string
	Requirement string
	Scope       string
}

// ComplianceStatus represents compliance status.
type ComplianceStatus struct {
	Regulation  Regulation
	Status      string // COMPLIANT, NON_COMPLIANT, AT_RISK, REVIEW
	Score       float64
	Issues      []string
	Recommendations []string
	LastChecked time.Time
}

// ComplianceChecker checks privacy compliance.
type ComplianceChecker struct {
	requirements []ComplianceRequirement
}

// NewComplianceChecker creates a new compliance checker.
func NewComplianceChecker() *ComplianceChecker {
	return &ComplianceChecker{
		requirements: make([]ComplianceRequirement, 0),
	}
}

// InitializeRequirements initializes compliance requirements.
func (c *ComplianceChecker) InitializeRequirements() {
	c.requirements = []ComplianceRequirement{
		{
			Regulation:  RegulationGDPR,
			ID:          "GDPR-001",
			Name:        "Data Minimization",
			Description: "Collect only necessary data",
			Requirement: "Data collection must be limited to what is necessary",
			Scope:       "all",
		},
		{
			Regulation:  RegulationGDPR,
			ID:          "GDPR-002",
			Name:        "Purpose Limitation",
			Description: "Use data only for specified purposes",
			Requirement: "Data must not be used for incompatible purposes",
			Scope:       "all",
		},
		{
			Regulation:  RegulationGDPR,
			ID:          "GDPR-003",
			Name:        "Data Subject Rights",
			Description: "Enable data subject access rights",
			Requirement: "Individuals must be able to access, correct, delete their data",
			Scope:       "processing",
		},
		{
			Regulation:  RegulationHIPAA,
			ID:          "HIPAA-001",
			Name:        "Protected Health Information",
			Description: "Protect PHI data",
			Requirement: "PHI must be encrypted and access controlled",
			Scope:       "healthcare",
		},
		{
			Regulation:  RegulationHIPAA,
			ID:          "HIPAA-002",
			Name:        "Audit Logging",
			Description: "Log access to PHI",
			Requirement: "All access to PHI must be logged and monitored",
			Scope:       "healthcare",
		},
		{
			Regulation:  RegulationCCPA,
			ID:          "CCPA-001",
			Name:        "Consumer Rights",
			Description: "Enable consumer privacy rights",
			Requirement: "California residents can opt-out of data sale",
			Scope:       "california",
		},
		{
			Regulation:  RegulationPCI_DSS,
			ID:          "PCI-001",
			Name:        "Cardholder Data Protection",
			Description: "Protect cardholder data",
			Requirement: "Cardholder data must be encrypted at rest and in transit",
			Scope:       "payment",
		},
	}
}

// CheckCompliance checks compliance for a regulation.
func (c *ComplianceChecker) CheckCompliance(regulation Regulation, piiData map[string]int) *ComplianceStatus {
	status := &ComplianceStatus{
		Regulation:  regulation,
		Status:      "REVIEW",
		Score:       0.0,
		Issues:      make([]string, 0),
		Recommendations: make([]string, 0),
		LastChecked: time.Now(),
	}

	c.InitializeRequirements()

	// Check requirements based on regulation
	for _, req := range c.requirements {
		if req.Regulation == regulation {
			issue := c.evaluateRequirement(req, piiData)
			if issue != nil {
				status.Issues = append(status.Issues, issue.Issue)
				status.Recommendations = append(status.Recommendations, issue.Recommendation)
			}
		}
	}

	// Calculate score and status
	status.Score = c.calculateComplianceScore(status)
	status.Status = determineStatus(status.Score)

	return status
}

// ComplianceIssue represents a compliance issue.
type ComplianceIssue struct {
	Issue         string
	Recommendation string
}

// evaluateRequirement evaluates a compliance requirement.
func (c *ComplianceChecker) evaluateRequirement(req ComplianceRequirement, piiData map[string]int) *ComplianceIssue {
	switch req.Regulation {
	case RegulationGDPR:
		return c.evaluateGDPR(req, piiData)
	case RegulationHIPAA:
		return c.evaluateHIPAA(req, piiData)
	case RegulationCCPA:
		return c.evaluateCCPA(req, piiData)
	case RegulationPCI_DSS:
		return c.evaluatePCIDSS(req, piiData)
	}

	return nil
}

// evaluateGDPR evaluates GDPR requirements.
func (c *ComplianceChecker) evaluateGDPR(req ComplianceRequirement, piiData map[string]int) *ComplianceIssue {
	switch req.ID {
	case "GDPR-001":
		if totalPII := sumPII(piiData); totalPII > 100 {
			return &ComplianceIssue{
				Issue:         "Excessive data collection detected",
				Recommendation: "Review data collection practices and minimize data collection",
			}
		}
	case "GDPR-002":
		if _, exists := piiData["sensitive"]; exists && piiData["sensitive"] > 50 {
			return &ComplianceIssue{
				Issue:         "Sensitive data processing detected",
				Recommendation: "Ensure legal basis for sensitive data processing",
			}
		}
	case "GDPR-003":
		// GDPR compliance requires data subject rights
		return &ComplianceIssue{
			Issue:         "Data subject rights implementation required",
			Recommendation: "Implement data access, deletion, and correction mechanisms",
		}
	}

	return nil
}

// evaluateHIPAA evaluates HIPAA requirements.
func (c *ComplianceChecker) evaluateHIPAA(req ComplianceRequirement, piiData map[string]int) *ComplianceIssue {
	switch req.ID {
	case "HIPAA-001":
		if _, exists := piiData["medical"]; exists && piiData["medical"] > 0 {
			return &ComplianceIssue{
				Issue:         "Protected Health Information detected",
				Recommendation: "Ensure PHI is encrypted and access controlled",
			}
		}
	case "HIPAA-002":
		return &ComplianceIssue{
			Issue:         "Audit logging required for PHI access",
			Recommendation: "Implement comprehensive audit logging for PHI access",
		}
	}

	return nil
}

// evaluateCCPA evaluates CCPA requirements.
func (c *ComplianceChecker) evaluateCCPA(req ComplianceRequirement, piiData map[string]int) *ComplianceIssue {
	switch req.ID {
	case "CCPA-001":
		if _, exists := piiData["california"]; exists && piiData["california"] > 10 {
			return &ComplianceIssue{
				Issue:         "California consumer data detected",
				Recommendation: "Implement CCPA opt-out mechanisms",
			}
		}
	}

	return nil
}

// evaluatePCIDSS evaluates PCI-DSS requirements.
func (c *ComplianceChecker) evaluatePCIDSS(req ComplianceRequirement, piiData map[string]int) *ComplianceIssue {
	switch req.ID {
	case "PCI-001":
		if _, exists := piiData["credit_card"]; exists && piiData["credit_card"] > 0 {
			return &ComplianceIssue{
				Issue:         "Cardholder data detected",
				Recommendation: "Ensure cardholder data is encrypted at rest and in transit",
			}
		}
	}

	return nil
}

// calculateComplianceScore calculates compliance score.
func (c *ComplianceChecker) calculateComplianceScore(status *ComplianceStatus) float64 {
	totalRequirements := 8 // Approximate number of requirements checked
	issuesCount := len(status.Issues)

	if totalRequirements == 0 {
		return 100.0
	}

	score := float64(totalRequirements-issuesCount) / float64(totalRequirements) * 100.0

	return math.Max(score, 0.0)
}

// determineStatus determines status from score.
func determineStatus(score float64) string {
	if score >= 90 {
		return "COMPLIANT"
	} else if score >= 70 {
		return "AT_RISK"
	} else if score >= 50 {
		return "REVIEW"
	}
	return "NON_COMPLIANT"
}

// sumPII sums all PII counts.
func sumPII(piiData map[string]int) int {
	total := 0
	for _, count := range piiData {
		total += count
	}
	return total
}

// GenerateComplianceReport generates compliance report.
func GenerateComplianceReport(status *ComplianceStatus) string {
	var report string

	report += "=== Compliance Report ===\n\n"
	report += "Regulation: " + string(status.Regulation) + "\n"
	report += "Status: " + status.Status + "\n"
	report += "Score: " + fmt.Sprintf("%.0f%%", status.Score) + "%\n"
	report += "Last Checked: " + status.LastChecked.Format("2006-01-02 15:04:05") + "\n\n"

	if len(status.Issues) > 0 {
		report += "Issues Found:\n"
		for i, issue := range status.Issues {
			report += "  [" + string(rune(i+49)) + "] " + issue + "\n"
		}
		report += "\n"
	}

	if len(status.Recommendations) > 0 {
		report += "Recommendations:\n"
		for i, rec := range status.Recommendations {
			report += "  [" + string(rune(i+49)) + "] " + rec + "\n"
		}
	}

	return report
}

// CheckAllRegulations checks all regulations.
func CheckAllRegulations(piiData map[string]int) map[Regulation]*ComplianceStatus {
	checker := NewComplianceChecker()
	
	results := make(map[Regulation]*ComplianceStatus)
	
	for _, reg := range []Regulation{RegulationGDPR, RegulationHIPAA, RegulationCCPA, RegulationPCI_DSS} {
		results[reg] = checker.CheckCompliance(reg, piiData)
	}
	
	return results
}

// GetOverallCompliance calculates overall compliance.
func GetOverallCompliance(statuses map[Regulation]*ComplianceStatus) float64 {
	if len(statuses) == 0 {
		return 0.0
	}

	totalScore := 0.0
	for _, status := range statuses {
		totalScore += status.Score
	}

	return totalScore / float64(len(statuses))
}

// GetComplianceStatus returns compliance status.
func GetComplianceStatus(status *ComplianceStatus) ComplianceStatus {
	return *status
}