// Package scan provides privacy scanning capabilities.
package scan

import (
	"regexp"
	"strings"
)

// PIIType represents a type of personally identifiable information.
type PIIType string

const (
	TypeEmail         PIIType = "email"
	TypePhone         PIIType = "phone"
	TypeSSN           PIIType = "ssn"
	TypeCreditCard    PIIType = "credit_card"
	TypeBankAccount   PIIType = "bank_account"
	TypeIPAddress     PIIType = "ip_address"
	TypeName          PIIType = "name"
	TypeDateOfBirth   PIIType = "date_of_birth"
	TypeAddress       PIIType = "address"
	TypeMedicalRecord PIIType = "medical_record"
	TypeFinancialInfo PIIType = "financial_info"
	TypeBiometric     PIIType = "biometric"
)

// PIIRecord represents a found PII record.
type PIIRecord struct {
	Type        PIIType
	Value       string
	Location    string
	Line        int
	Context     string
	Confidence  float64
	Redaction   string
	RiskLevel   string
}

// ScanResult contains scanning results.
type ScanResult struct {
	TotalFound    int
	PIIRecords    []PIIRecord
	Summary       map[string]int
	Compliance    map[string]string
}

// Scanner scans for PII and privacy violations.
type Scanner struct {
	patterns map[PIIType]*Pattern
}

// Pattern defines a PII detection pattern.
type Pattern struct {
	Name        string
	Regex       *regexp.Regexp
	PIIType     PIIType
	Replacement string
}

// NewScanner creates a new privacy scanner.
func NewScanner() *Scanner {
	return &Scanner{
		patterns: make(map[PIIType]*Pattern),
	}
}

// InitializePatterns initializes PII detection patterns.
func (s *Scanner) InitializePatterns() {
	// Email pattern
	s.patterns[TypeEmail] = &Pattern{
		Name:  "Email Address",
		Regex: regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`),
		PIIType: TypeEmail,
		Replacement: "[EMAIL]",
	}

	// Phone number pattern (US format)
	s.patterns[TypePhone] = &Pattern{
		Name:  "Phone Number",
		Regex: regexp.MustCompile(`\+?1?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}`),
		PIIType: TypePhone,
		Replacement: "[PHONE]",
	}

	// SSN pattern
	s.patterns[TypeSSN] = &Pattern{
		Name:  "Social Security Number",
		Regex: regexp.MustCompile(`\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b`),
		PIIType: TypeSSN,
		Replacement: "[SSN]",
	}

	// Credit card pattern
	s.patterns[TypeCreditCard] = &Pattern{
		Name:  "Credit Card Number",
		Regex: regexp.MustCompile(`\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b`),
		PIIType: TypeCreditCard,
		Replacement: "[CC]",
	}

	// IP address pattern
	s.patterns[TypeIPAddress] = &Pattern{
		Name:  "IP Address",
		Regex: regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`),
		PIIType: TypeIPAddress,
		Replacement: "[IP]",
	}

	// Bank account pattern
	s.patterns[TypeBankAccount] = &Pattern{
		Name:  "Bank Account Number",
		Regex: regexp.MustCompile(`\b(?:ACC|Account|Bank)\s*[:\s]+[0-9]{8,15}\b`),
		PIIType: TypeBankAccount,
		Replacement: "[BANK]",
	}

	// Medical record number pattern
	s.patterns[TypeMedicalRecord] = &Pattern{
		Name:  "Medical Record Number",
		Regex: regexp.MustCompile(`\b(?:MRN|MedicalRecord|PatientID)\s*[:\s]+[A-Za-z0-9]{6,15}\b`),
		PIIType: TypeMedicalRecord,
		Replacement: "[MED]",
	}

	// Date of birth pattern
	s.patterns[TypeDateOfBirth] = &Pattern{
		Name:  "Date of Birth",
		Regex: regexp.MustCompile(`\b(?:DOB|DateOfBirth|BirthDate)\s*[:\s]+(?:[0-9]{1,2}/[0-9]{1,2}/[0-9]{4}|[0-9]{4}-[0-9]{2}-[0-9]{2})\b`),
		PIIType: TypeDateOfBirth,
		Replacement: "[DOB]",
	}
}

// Scan scans content for PII.
func (s *Scanner) Scan(content, location string) *ScanResult {
	result := &ScanResult{
		PIIRecords: make([]PIIRecord, 0),
		Summary:    make(map[string]int),
		Compliance: make(map[string]string),
	}

	s.InitializePatterns()

	for _, pattern := range s.patterns {
		matches := pattern.Regex.FindAllString(content, -1)
		for _, match := range matches {
			record := PIIRecord{
				Type:       pattern.PIIType,
				Value:      match,
				Location:   location,
				Context:    s.extractContext(content, match),
				Confidence: 0.95,
				Redaction:  pattern.Replacement,
				RiskLevel:  getRiskLevel(pattern.PIIType),
			}
			result.PIIRecords = append(result.PIIRecords, record)
			result.Summary[string(pattern.PIIType)]++
		}
	}

	result.TotalFound = len(result.PIIRecords)

	// Calculate compliance status
	result.Compliance = s.calculateCompliance(result)

	return result
}

// extractContext extracts context around match.
func (s *Scanner) extractContext(content, match string) string {
	idx := strings.Index(content, match)
	if idx == -1 {
		return ""
	}

	start := max(0, idx-50)
	end := min(len(content), idx+len(match)+50)

	return content[start:end]
}

// calculateCompliance calculates compliance status.
func (s *Scanner) calculateCompliance(result *ScanResult) map[string]string {
	compliance := make(map[string]string)

	totalPII := result.TotalFound

	if totalPII == 0 {
		compliance["GDPR"] = "COMPLIANT"
		compliance["HIPAA"] = "COMPLIANT"
		compliance["CCPA"] = "COMPLIANT"
		compliance["PCI-DSS"] = "COMPLIANT"
		return compliance
	}

	// Check for high-risk PII
	ssnCount := result.Summary[string(TypeSSN)]
	creditCardCount := result.Summary[string(TypeCreditCard)]
	medicalCount := result.Summary[string(TypeMedicalRecord)]

	if ssnCount > 0 {
		compliance["GDPR"] = "NON_COMPLIANT"
		compliance["HIPAA"] = "AT_RISK"
		compliance["CCPA"] = "NON_COMPLIANT"
		compliance["PCI-DSS"] = "N/A"
	}

	if creditCardCount > 0 {
		compliance["PCI-DSS"] = "NON_COMPLIANT"
		compliance["GDPR"] = "AT_RISK"
		compliance["HIPAA"] = "N/A"
		compliance["CCPA"] = "NON_COMPLIANT"
	}

	if medicalCount > 0 {
		compliance["HIPAA"] = "NON_COMPLIANT"
		compliance["GDPR"] = "AT_RISK"
		compliance["CCPA"] = "AT_RISK"
		compliance["PCI-DSS"] = "N/A"
	}

	// Default compliance
	if compliance["GDPR"] == "" {
		compliance["GDPR"] = "REVIEW"
	}
	if compliance["HIPAA"] == "" {
		compliance["HIPAA"] = "REVIEW"
	}
	if compliance["CCPA"] == "" {
		compliance["CCPA"] = "REVIEW"
	}
	if compliance["PCI-DSS"] == "" {
		compliance["PCI-DSS"] = "REVIEW"
	}

	return compliance
}

// getRiskLevel gets risk level for PII type.
func getRiskLevel(piitype PIIType) string {
	riskLevels := map[PIIType]string{
		TypeSSN:           "CRITICAL",
		TypeCreditCard:    "CRITICAL",
		TypeMedicalRecord: "HIGH",
		TypeBankAccount:   "HIGH",
		TypeName:          "MEDIUM",
		TypePhone:         "MEDIUM",
		TypeEmail:         "MEDIUM",
		TypeIPAddress:     "LOW",
		TypeDateOfBirth:   "MEDIUM",
		TypeAddress:       "MEDIUM",
		TypeFinancialInfo: "HIGH",
		TypeBiometric:     "CRITICAL",
	}

	if level, exists := riskLevels[piitype]; exists {
		return level
	}
	return "MEDIUM"
}

// max returns maximum of two ints.
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// min returns minimum of two ints.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// GenerateReport generates scanning report.
func GenerateReport(result *ScanResult) string {
	var report string

	report += "=== Privacy Scanning Report ===\n\n"
	report += "Total PII Found: " + string(rune(result.TotalFound+48)) + "\n\n"

	if result.TotalFound > 0 {
		report += "PII Summary:\n"
		for piiType, count := range result.Summary {
			report += "  " + piiType + ": " + string(rune(count+48)) + "\n"
		}
		report += "\n"

		report += "Compliance Status:\n"
		for regulation, status := range result.Compliance {
			report += "  " + regulation + ": " + status + "\n"
		}
		report += "\n"

		report += "Detailed Findings:\n"
		for i, record := range result.PIIRecords {
			if i >= 10 {
				report += "  ... and " + string(rune(result.TotalFound-10+48)) + " more\n"
				break
			}
			report += "[" + string(rune(i+49)) + "] " + record.RiskLevel + " - " + string(record.Type) + "\n"
			report += "    Value: " + record.Value[:min(len(record.Value), 20)] + "...\n"
			report += "    Location: " + record.Location + "\n"
			report += "    Redaction: " + record.Redaction + "\n\n"
		}
	} else {
		report += "✓ No PII detected\n"
	}

	return report
}

// GetComplianceStatus returns compliance status.
func GetComplianceStatus(result *ScanResult, regulation string) string {
	if status, exists := result.Compliance[regulation]; exists {
		return status
	}
	return "UNKNOWN"
}