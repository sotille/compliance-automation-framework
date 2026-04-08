# Changelog

All notable changes to the Compliance Automation Framework are documented here.
Format: `[version] — [date] — [summary of changes]`

---

## [Unreleased]

- Added CHANGELOG.md (this file) for version tracking
- Added "Learning Resources" section to README.md linking to Book 3, techstream-learn labs, and techstream.app
- [2026-04-07] Added Section 10: GDPR Technical and Organizational Measures to regulatory-controls-matrix.md — covers Articles 5, 25, 32, 33, 34 with Techstream control mappings, evidence automation table, and ROPA guidance
- [2026-04-08] Added Section 11: AI Regulatory Frameworks to regulatory-controls-matrix.md — covers EU AI Act (Regulation 2024/1689) Articles 9, 13, 14, 15, 53 with Techstream control mappings; NIST AI RMF 1.0 GOVERN/MAP/MEASURE/EVALUATE function alignment; ISO 42001:2023 Annex A control mappings; AI-regulated organization quick-reference profile table; cross-links to ai-devsecops-framework/docs/regulatory-mapping.md and iso-42001-certification-roadmap.md
- [2026-04-08] Created docs/continuous-compliance-operations.md — operational model for maintaining compliance posture continuously rather than episodically: five primary metrics (Control Coverage Rate, Control Pass Rate, MTTR by severity, Evidence Freshness Rate, Finding Recurrence Rate) and two derived metrics (Compliance Risk Score, Time-to-Audit-Ready); three-tier continuous scanning architecture (cloud infrastructure, container/IaC, application/secrets); compliance event pipeline with normalized finding schema; alert thresholds and escalation model; drift detection alert configuration; review cadence (daily automated, weekly engineering, monthly CISO, quarterly executive, annual); evidence aging and refresh requirements by control category with freshness monitoring Python implementation; executive Compliance Risk Score dashboard; monthly report template; GRC platform integration pattern (Vanta API example); five common failure modes

## [1.0.0] — 2024-01-15

- Initial public release of the Compliance Automation Framework
- Core framework documentation: introduction, architecture, framework, implementation, best-practices, roadmap
- Regulatory controls matrix mapping SOC 2, PCI-DSS v4, ISO 27001, and NIST 800-53 to automated controls
- Evidence collection automation architecture for continuous compliance
- FedRAMP implementation guide for cloud service providers
- Geographic compliance guidance covering GDPR, CCPA, and regional data residency requirements
- Exception management framework for policy deviations
- On-premises compliance guide for hybrid environments
- Apache 2.0 license and contribution guidelines
