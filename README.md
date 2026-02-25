# privacyguard - Privacy Engineering Scanner

[![Go](https://img.shields.io/badge/Go-1.21-blue)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

**Scan for PII and check privacy compliance across your codebase and data.**

Automate privacy scanning and ensure compliance with major privacy regulations.

## 🚀 Features

- **PII Detection**: Detect emails, phone numbers, SSN, credit cards, and more
- **Compliance Checking**: Check GDPR, HIPAA, CCPA, PCI-DSS compliance
- **Privacy Scanning**: Scan code and data for privacy violations
- **Risk Assessment**: Calculate privacy risk scores
- **Automated Reporting**: Generate detailed compliance reports
- **Multi-Regulation Support**: Support for major privacy regulations

## 📦 Installation

### Build from Source

```bash
git clone https://github.com/hallucinaut/privacyguard.git
cd privacyguard
go build -o privacyguard ./cmd/privacyguard
sudo mv privacyguard /usr/local/bin/
```

### Install via Go

```bash
go install github.com/hallucinaut/privacyguard/cmd/privacyguard@latest
```

## 🎯 Usage

### Scan for PII

```bash
# Scan directory for PII
privacyguard scan /path/to/code
privacyguard scan /path/to/data
```

### Check Compliance

```bash
# Check GDPR compliance
privacyguard compliance GDPR

# Check HIPAA compliance
privacyguard compliance HIPAA
```

### Check Privacy Posture

```bash
# Check overall privacy posture
privacyguard check
```

### Generate Report

```bash
# Generate compliance report
privacyguard report
```

### Programmatic Usage

```go
package main

import (
    "fmt"
    "github.com/hallucinaut/privacyguard/pkg/scan"
    "github.com/hallucinaut/privacyguard/pkg/compliance"
)

func main() {
    // Create scanner
    s := scan.NewScanner()
    
    // Scan content for PII
    result := s.Scan(content, "file.txt")
    
    fmt.Printf("PII Found: %d\n", result.TotalFound)
    
    // Check compliance
    checker := compliance.NewComplianceChecker()
    piiData := map[string]int{"email": 100, "phone": 50}
    
    status := checker.CheckCompliance(compliance.RegulationGDPR, piiData)
    
    fmt.Printf("GDPR Status: %s\n", status.Status)
    fmt.Printf("Score: %.0f%%\n", status.Score)
}
```

## 🔍 PII Types Detected

| PII Type | Example | Risk Level |
|----------|---------|------------|
| Email | user@example.com | MEDIUM |
| Phone | +1-555-555-5555 | MEDIUM |
| SSN | 123-45-6789 | CRITICAL |
| Credit Card | 4111-1111-1111-1111 | CRITICAL |
| Bank Account | ACC123456789 | HIGH |
| IP Address | 192.168.1.1 | LOW |
| Medical Record | MRN123456 | HIGH |
| Date of Birth | 1990-01-01 | MEDIUM |

## 🛡️ Supported Regulations

### GDPR (General Data Protection Regulation)
- EU privacy regulation
- Applies to all EU citizen data
- Requires consent and data subject rights

### HIPAA (Health Insurance Portability)
- US healthcare privacy
- Protects medical information
- Requires encryption and access control

### CCPA (California Consumer Privacy Act)
- California consumer privacy
- Right to know and opt-out
- Applies to California residents

### PCI-DSS (Payment Card Industry)
- Payment card security
- Protects cardholder data
- Requires encryption and logging

### PIPEDA (Personal Information Protection)
- Canadian privacy law
- Similar to GDPR
- Applies to Canadian organizations

### LGPD (Lei Geral de Proteção de Dados)
- Brazilian privacy law
- Similar to GDPR
- Applies to Brazilian data processing

## 📊 Compliance Status

| Status | Score | Action |
|--------|-------|--------|
| COMPLIANT | 90-100% | No action needed |
| AT_RISK | 70-89% | Address issues |
| REVIEW | 50-69% | Review and fix |
| NON_COMPLIANT | <50% | Immediate action |

## 🧪 Testing

```bash
# Run all tests
go test ./...

# Run with coverage
go test -cover ./...

# Run specific test
go test -v ./pkg/scan -run TestScanPII
```

## 📋 Example Output

```
Scanning for PII: /path/to/code

=== Privacy Scanning Report ===

Total PII Found: 25

PII Summary:
  email: 10
  phone: 5
  credit_card: 2
  ip_address: 8

Compliance Status:
  GDPR: AT_RISK
  HIPAA: REVIEW
  CCPA: AT_RISK
  PCI-DSS: NON_COMPLIANT

Detailed Findings:
[1] MEDIUM - email
    Value: user@example.com...
    Location: /path/to/file.txt
    Redaction: [EMAIL]
```

## 🔒 Privacy Use Cases

- **Code Audits**: Scan codebases for PII
- **Data Assessments**: Evaluate data privacy
- **Compliance Checks**: Verify regulation compliance
- **Risk Assessment**: Identify privacy risks
- **Remediation Planning**: Plan privacy improvements

## 🛡️ Best Practices

1. **Regular PII scanning** of code and data
2. **Implement data minimization**
3. **Encrypt sensitive data**
4. **Implement access controls**
5. **Maintain audit logs**
6. **Train employees on privacy**
7. **Regular compliance assessments**

## 🏗️ Architecture

```
privacyguard/
├── cmd/
│   └── privacyguard/
│       └── main.go          # CLI entry point
├── pkg/
│   ├── scan/
│   │   ├── scan.go         # PII scanning
│   │   └── scan_test.go    # Unit tests
│   └── compliance/
│       ├── compliance.go   # Compliance checking
│       └── compliance_test.go # Unit tests
└── README.md
```

## 📄 License

MIT License

## 🙏 Acknowledgments

- Privacy engineering community
- Data protection researchers
- Compliance experts

## 🔗 Resources

- [GDPR Guidelines](https://gdpr.eu/)
- [HIPAA Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/index.html)
- [CCPA Guide](https://oag.ca.gov/privacy/ccpa)
- [PCI-DSS Requirements](https://docs PCI-DSS.org/)

---

**Built with ❤️ by [hallucinaut](https://github.com/hallucinaut)**