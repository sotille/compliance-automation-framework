# Contributing to the Techstream Compliance Automation Framework

Thank you for your interest in contributing. This repository provides Policy as Code patterns, automated evidence collection strategies, and control mapping guidance for SOC 2, ISO 27001, PCI DSS, HIPAA, FedRAMP, NIST 800-53, and CIS Benchmarks. The regulatory landscape changes continuously — contributions that keep compliance mappings current and expand automation patterns to new frameworks and tooling are particularly valuable.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [What We Welcome](#what-we-welcome)
- [What We Do Not Accept](#what-we-do-not-accept)
- [How to Contribute](#how-to-contribute)
- [Documentation Standards](#documentation-standards)
- [Regulatory Accuracy Requirements](#regulatory-accuracy-requirements)
- [Review Process](#review-process)
- [License](#license)

---

## Code of Conduct

All contributors are expected to engage professionally and constructively. Contributions that are dismissive, personal, or unprofessional will not be reviewed.

---

## What We Welcome

- **New compliance framework mappings** — if an important regulatory framework (DORA, NIS2, ISO 27017, CMMC) is not covered, well-researched control mapping contributions are welcome.
- **Control mapping corrections** — compliance control numbering and requirement language changes between framework versions. Corrections that maintain accuracy with current published standards are essential.
- **Policy as Code examples** — working OPA Rego policies, Kyverno ClusterPolicies, Checkov custom checks, and Prowler custom checks for specific compliance controls.
- **Cloud-provider-specific automation** — AWS Config Rules, Azure Policy definitions, and GCP Organization Policies that automate specific compliance controls.
- **Evidence automation patterns** — new patterns for automatically collecting audit-ready evidence from CI/CD pipelines, infrastructure, and cloud environments.
- **Audit tooling guidance** — integration patterns for GRC platforms (Vanta, Drata, Tugboat Logic, ServiceNow GRC) that consume automated compliance evidence.

---

## What We Do Not Accept

- **Legal or audit advice** — this framework provides technical automation patterns. It does not constitute legal advice or audit guidance. Contributions should not be framed as definitive legal interpretations of regulatory requirements.
- **Vendor promotional content** — tool references must reflect accurate technical capability.
- **Unvalidated policy configurations** — Policy as Code examples should be tested against real environments. Policies with known false positive rates that would cause operational disruption in enforce mode should be clearly labeled as audit-mode examples.
- Scope beyond compliance automation (CI/CD pipeline design, runtime security, release governance → respective Techstream repositories).

---

## Regulatory Accuracy Requirements

Contributions that map technical controls to regulatory requirements must:

- Reference the specific control ID and requirement text from the published standard (not paraphrased from third-party summaries).
- Indicate which version of the standard is being mapped (e.g., PCI DSS v4.0, SOC 2 Trust Service Criteria 2017).
- Be reviewed against the current published version of the standard — contributors are responsible for checking that the standard has not been revised since the existing mapping was written.

The core team will perform a technical review but may not have deep expertise in every regulatory framework. Regulatory domain experts who review and confirm accuracy of mappings are especially valuable contributors.

---

## How to Contribute

### Reporting Issues

Use GitHub Issues to report: outdated control numbers or requirement text, gaps in compliance framework coverage, Policy as Code examples that do not work as described, or GRC platform integration inaccuracies.

### Submitting Pull Requests

1. Fork and branch from `main`.
2. For Policy as Code contributions, include the tool version the policy was validated against.
3. For new compliance framework mappings, include the standard version and publication date in the mapping table.
4. Open a pull request with a description of the change and references to the relevant sections of the compliance standard.

---

## Documentation Standards

- Professional tone for compliance officers, security architects, and auditors.
- Control mapping tables: Control ID, Requirement Summary, Technical Control, Automation Tool, Evidence Type.
- Mermaid diagrams for evidence collection flows and compliance reporting pipelines.
- ATX headers, fenced code blocks (` ```rego `, ` ```yaml `, ` ```json `), relative internal links.

---

## Review Process

Pull requests are reviewed for technical accuracy, regulatory accuracy, scope alignment, and documentation standards. Initial responses within 5 business days.

---

## License

By contributing, you agree your contributions will be licensed under the [Apache License 2.0](LICENSE).
