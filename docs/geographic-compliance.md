# Geographic and Jurisdictional Compliance Guide

The [Regulatory Controls Matrix](regulatory-controls-matrix.md) covers the major US and international security frameworks (NIST 800-53, SOC 2, ISO 27001, PCI DSS, CIS Controls). This guide extends that coverage with jurisdiction-specific requirements for organizations operating in or serving markets in the European Union, United Kingdom, Australia, Canada, Singapore, and Brazil. It focuses on requirements that are not fully addressed by the base framework matrix and that have direct implications for DevSecOps practices.

---

## How to Use This Guide

1. Identify which jurisdictions apply to your organization based on where you process personal data, where your customers are located, and where you operate infrastructure.
2. For each applicable jurisdiction, review the requirements listed and cross-reference them against your [control implementation status](framework.md).
3. Use the gap analysis table at the end of each jurisdiction section to identify controls that require addition or strengthening.
4. Document jurisdiction-specific controls as separate policy layers within your compliance automation framework, layered on top of the common control baseline.

---

## European Union

### GDPR (General Data Protection Regulation)

**Applicability:** Any organization that processes personal data of EU data subjects, regardless of where the organization is located.

**Key principles with DevSecOps implications:**

| Principle | GDPR Requirement | DevSecOps Control |
|-----------|-----------------|-------------------|
| **Data minimization** | Only collect data necessary for the stated purpose | Data classification in API design; field-level masking in logs and SBOMs |
| **Security by design** | Implement appropriate technical and organizational measures from the start | Threat modeling at design phase; security requirements in Definition of Done |
| **Pseudonymization** | Separate identifying data from other personal data where feasible | Test data management: production data never used in dev/staging environments |
| **Breach notification** | Notify supervisory authority within 72 hours of becoming aware of a breach | Incident response playbook with notification workflow; SIEM alert to on-call |
| **Records of processing** | Maintain records of data processing activities | SBOM and data flow documentation; automated discovery of new data stores |
| **Transfers outside EEA** | Adequate legal basis required for data transfers outside the European Economic Area | CI/CD runners and artifact registries must be in EU regions (or SCCs in place) |

**EU Standard Contractual Clauses (SCCs) for CI/CD:** If your CI/CD pipeline runs workloads in non-EEA regions (e.g., GitHub Actions on US-based runners) and processes personal data during builds or tests, evaluate whether SCCs are in place with your pipeline provider. In practice, the safest approach is to use EU-region runners for pipelines that process EU personal data.

**Technical measures required by Article 32:**

GDPR Article 32 requires "appropriate technical and organisational measures" including:
- Pseudonymisation and encryption of personal data
- Ensuring ongoing confidentiality, integrity, availability, and resilience
- Ability to restore availability in a timely manner after an incident
- Process for regularly testing and evaluating security measures

These map directly to DevSecOps capabilities:

| Article 32 Requirement | DevSecOps Implementation |
|-----------------------|--------------------------|
| Pseudonymization and encryption | Encryption at rest and in transit; secrets manager; data masking in non-production environments |
| Confidentiality and integrity | Access controls; artifact signing; SBOM; audit logs |
| Resilience | Deployment pipeline with automated rollback; redundant infrastructure as code |
| Regular testing and evaluation | Continuous security scanning; penetration testing; maturity assessments |

### GDPR Technical Controls Implementation Guide

The table above identifies which GDPR principles have DevSecOps implications. This section provides concrete implementation guidance for each technical control required under GDPR Articles 5, 25, and 32.

#### Encryption at Rest and in Transit (Article 32)

Encryption is explicitly cited in GDPR Article 32(1)(a) as an appropriate technical measure. "Appropriate" is context-dependent — for personal data, the following baseline is defensible:

| Data State | Minimum Requirement | Recommended |
|-----------|---------------------|-------------|
| In transit | TLS 1.2 | TLS 1.3 with forward secrecy |
| At rest (database) | AES-128 | AES-256 with BYOK |
| At rest (object storage) | SSE with provider-managed keys | SSE-KMS with customer-managed keys |
| At rest (backups) | Encryption required | Encrypted + geographically separated |
| Application secrets | Secrets manager (not env vars) | HSM-backed secrets manager |

**Enforcement in CI/CD:**

```yaml
# Example: Checkov policy enforcing encryption at rest for all S3 buckets
- name: IaC Security Scan (Checkov)
  run: |
    checkov -d terraform/ \
      --check CKV_AWS_19 \  # S3 encryption enabled
      --check CKV_AWS_145 \ # S3 KMS encryption
      --check CKV_AWS_21 \  # S3 versioning (supports right to rectification evidence)
      --soft-fail-on CKV_AWS_21  # warning only for versioning
```

#### Pseudonymization and Data Masking (Article 25, 32)

Pseudonymization separates identifying fields from other personal data, reducing breach impact. It is required "where possible" under Article 25 (privacy by design).

**Test data management (critical gap in most organizations):**

Production data must never be used in development or staging environments without pseudonymization. This is a recurring GDPR enforcement finding.

```python
# Example: pseudonymization pipeline for test data generation
import hashlib
import secrets

def pseudonymize_record(record: dict, salt: str) -> dict:
    """
    Pseudonymize PII fields while preserving referential integrity
    across tables (same input → same output with consistent salt).
    """
    pii_fields = ["email", "name", "phone", "ip_address", "user_id"]
    pseudonymized = record.copy()

    for field in pii_fields:
        if field in record and record[field]:
            # Deterministic pseudonymization: consistent across tables
            value = f"{salt}:{record[field]}"
            pseudonymized[field] = hashlib.sha256(value.encode()).hexdigest()[:16]

    return pseudonymized

# Non-PII fields (dates, amounts, categories) pass through unchanged
# preserving analytical utility of the dataset
```

**Log sanitization:**

GDPR prohibits retaining personal data longer than necessary and requires it to be protected. Application logs frequently contain personal data (email addresses, IP addresses, user identifiers).

```python
# Example: structured log filter to mask PII before log shipment
import re

PII_PATTERNS = {
    "email": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
    "ip_address": re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
    "credit_card": re.compile(r'\b(?:\d[ -]?){13,16}\b'),
}

def sanitize_log_message(message: str) -> str:
    for pii_type, pattern in PII_PATTERNS.items():
        message = pattern.sub(f'[REDACTED:{pii_type}]', message)
    return message
```

#### Data Subject Rights Technical Implementation

GDPR Articles 15–22 grant data subjects rights that require technical implementation. These rights must be fulfillable within regulatory timelines (typically 30 days).

| Right | Article | Technical Requirement | Implementation Pattern |
|-------|---------|----------------------|----------------------|
| Right of access | Art. 15 | Export all personal data held about a subject in portable format | Data subject access request (DSAR) pipeline: query all datastores, aggregate, export |
| Right to rectification | Art. 16 | Correct inaccurate personal data | Audit trail for corrections; update propagation to all datastores holding the record |
| Right to erasure | Art. 17 | Delete personal data when no longer necessary or when consent withdrawn | Cascading delete pipeline; verify deletion across all datastores (primary, backups, analytics) |
| Right to data portability | Art. 20 | Provide personal data in machine-readable format (JSON, CSV) | DSAR export in structured format; avoid proprietary formats |
| Right to restriction | Art. 18 | Restrict processing while dispute is resolved | Processing-freeze flag in user record; propagate to all consuming services |
| Right to object | Art. 21 | Stop processing for specific purposes | Consent flag management; downstream service propagation |

**Right to erasure implementation — the hard part:**

Erasure must cover all copies including: primary database, read replicas, backup copies, analytics warehouses, search indexes, caches, logs, and audit trails. Audit trails are an exception — where retention is legally required for compliance, pseudonymization may substitute for full erasure.

```sql
-- Example: erasure verification query
-- Run after deletion pipeline completes to verify no PII residue

-- 1. Primary tables
SELECT COUNT(*) as remaining FROM users WHERE user_id = :subject_id;

-- 2. Event store (if using event sourcing)
SELECT COUNT(*) as events_remaining FROM event_log WHERE actor_id = :subject_id;

-- 3. Search index (Elasticsearch example via API)
-- GET /users/_search { "query": { "term": { "user_id": "<subject_id>" } } }

-- If any count > 0 and the data is not legally required to be retained,
-- the erasure pipeline has a gap — escalate to data engineering team
```

#### Data Protection Impact Assessment (DPIA) Integration

GDPR Article 35 requires a DPIA before any processing that is "likely to result in a high risk" to individuals. Practically, DPIAs are required for: large-scale processing of special categories of data, systematic monitoring of public areas, and novel processing using new technologies.

**Integrating DPIA into the development process:**

1. **Trigger:** Security review checklist includes a DPIA trigger assessment for any new feature that: (a) processes a new category of personal data, (b) processes personal data at new scale, (c) introduces AI/ML processing of personal data, or (d) shares personal data with new third parties

2. **DPIA as part of threat modeling:** Run the DPIA alongside the threat model. The DPIA addresses data protection risks; the threat model addresses security risks. The outputs complement each other.

3. **Definition of Done:** For features processing personal data, the Definition of Done must include: DPIA completed (if triggered) + data flow documentation updated + appropriate technical controls verified

**Minimum DPIA questions for engineering teams:**

```markdown
## DPIA Trigger Assessment

1. Does this feature collect new types of personal data? (Y/N)
2. Does this feature process personal data at greater scale than existing features? (Y/N)
3. Does this feature use automated decision-making that affects individuals? (Y/N)
4. Does this feature share personal data with new third parties or processors? (Y/N)
5. Does this feature process special category data (health, biometric, ethnic origin, etc.)? (Y/N)

If any answer is Y: escalate to Privacy Officer for full DPIA before launch.
```

#### Privacy by Design — CI/CD Gate Controls

GDPR Article 25 requires technical measures implementing data protection principles to be embedded "at the time of the determination of the means for processing." In DevSecOps terms, this means privacy controls must be verified in CI before code reaches production.

```yaml
# Example: privacy control verification as CI gate

privacy-gates:
  # 1. Detect new database columns with potential PII field names
  - name: PII Column Detection
    run: |
      git diff HEAD~1 -- migrations/ | grep -E "ADD COLUMN (email|phone|name|address|dob|ssn|ip_)" \
        && echo "::warning::Potential PII column detected. Ensure field is included in DSAR export and erasure pipeline."

  # 2. Detect logging of request bodies (common PII leakage vector)
  - name: Log PII Detection
    run: |
      grep -rn "request\.body\|req\.body" app/ | grep -i "log\|print\|console" \
        && echo "::error::Logging of request body detected. Review for PII before merging." || true

  # 3. Verify encryption at rest for new datastores in IaC
  - name: IaC Encryption Compliance
    run: checkov -d terraform/ --check CKV_AWS_19,CKV_AWS_145,CKV_GCP_38,CKV_AZURE_33

  # 4. Detect hardcoded data retention periods > GDPR maximum
  - name: Retention Policy Check
    run: |
      grep -rn "retention.*days\|ttl.*[0-9]" app/config/ \
        && python scripts/validate_retention_limits.py --max-days 365 --personal-data-max-days 90
```

#### Data Transfer Mechanisms (Chapter V)

For organizations using SaaS CI/CD platforms, cloud providers, or sub-processors outside the EEA, the appropriate transfer mechanism must be in place. Common scenarios:

| Transfer Scenario | Applicable Mechanism |
|------------------|---------------------|
| GitHub Actions (US-based runners) processing EU user data during tests | SCCs with GitHub / use EU-region self-hosted runners |
| AWS S3 in us-east-1 storing EU user SBOM data | SCCs already in AWS DPA; choose EU region instead if possible |
| Third-party analytics SaaS receiving EU user events | SCCs or adequacy decision; verify DPA addendum is signed |
| Developer laptops (non-EEA) with access to EU user data | Not a transfer per se; covered by access control and endpoint security |

**Automated transfer compliance check:**

```python
# Verify that all datastores processing EU personal data are in approved regions
def verify_eu_data_residency(infrastructure_map: dict) -> list[str]:
    EU_APPROVED_REGIONS = {
        "aws": ["eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1", "eu-south-1"],
        "azure": ["westeurope", "northeurope", "germanywestcentral", "swedencentral"],
        "gcp": ["europe-west1", "europe-west2", "europe-west3", "europe-west4", "europe-north1"],
    }

    violations = []
    for resource in infrastructure_map.get("personal_data_stores", []):
        provider = resource["cloud_provider"]
        region = resource["region"]
        if region not in EU_APPROVED_REGIONS.get(provider, []):
            violations.append(f"{resource['name']} ({provider}/{region}) not in EU-approved region")

    return violations
```

---

### EU NIS2 Directive (Network and Information Security 2)

**Applicability:** Organizations classified as "essential" or "important" entities in EU member states. Categories include energy, transport, banking, financial infrastructure, health, drinking water, wastewater, digital infrastructure, ICT service management (B2B), public administration, and space. Also applies to digital providers including DNS, cloud computing, data centers, CDN, trust services, online marketplaces, and search engines.

**Transposition deadline:** October 2024 (member states); enforcement varies by member state.

**Key requirements with DevSecOps implications:**

| NIS2 Requirement | Article | DevSecOps Control |
|-----------------|---------|-------------------|
| Risk management measures | Art. 21 | Threat modeling; vulnerability management; risk register |
| Supply chain security | Art. 21(2)(d) | SBOM; vendor risk assessment; third-party dependency controls; supply chain security framework |
| Incident handling | Art. 21(2)(b) | Incident response playbook; SIEM; detection and alerting |
| Business continuity and crisis management | Art. 21(2)(c) | DR plan; automated failover; tested recovery procedures |
| Cybersecurity hygiene and training | Art. 21(2)(g) | Security champion program; mandatory developer training; secure coding standards |
| Cryptography and encryption | Art. 21(2)(h) | TLS enforcement; artifact signing; secrets management; key management policy |
| Significant incident reporting | Art. 23 | < 24 hours: early warning; < 72 hours: incident notification; < 1 month: final report |

**Supply chain security requirements (NIS2 Art. 21(2)(d)):**
NIS2 explicitly requires assessing and managing cybersecurity risks in supply chains and supplier relationships. This includes:
- Assessing the security practices of direct suppliers
- Including cybersecurity requirements in contracts with suppliers
- Maintaining an inventory of critical software dependencies (SBOM)
- Monitoring for supply chain compromises

This aligns directly with the [Software Supply Chain Security Framework](../../software-supply-chain-security-framework/docs/framework.md) requirements.

---

### EU Cyber Resilience Act (CRA)

**Applicability:** Manufacturers, importers, and distributors of products with digital elements (hardware and software) placed on the EU market. Includes commercial software, IoT devices, and cloud services with a direct connection to end-user devices.

**Expected applicability date:** 2027 (phased implementation; vulnerability reporting requirements apply from 2026).

**Key requirements:**

| CRA Requirement | Category | DevSecOps Implementation |
|---|---|---|
| Security by design and default | Essential requirements | Threat modeling; security requirements in design phase; secure defaults in product configuration |
| No known exploitable vulnerabilities at release | Essential requirements | SCA blocking on Critical CVEs; SAST; DAST before release |
| SBOM | Essential requirements | CycloneDX or SPDX SBOM for every release; machine-readable; complete transitive dependency coverage |
| Vulnerability disclosure | Essential requirements | Coordinated vulnerability disclosure policy; CVE assignment process |
| Security updates throughout support period | Essential requirements | Automated dependency update process (Renovate/Dependabot); EOL component tracking |
| Incident and vulnerability reporting | Reporting | Active exploitation reports to ENISA within 24 hours |

**SBOM requirements under CRA:** The CRA requires SBOM to be machine-readable and align with commonly used formats. CycloneDX 1.4+ or SPDX 2.3+ satisfy this requirement. SBOMs must include all components, not just direct dependencies — transitive dependency coverage is required.

---

## United Kingdom

### UK GDPR and Data Protection Act 2018

UK GDPR is substantively equivalent to EU GDPR post-Brexit, with the following differences:

| Area | EU GDPR | UK GDPR | DevSecOps Impact |
|------|---------|---------|------------------|
| Supervisory authority | National data protection authorities (e.g., CNIL, BfDI) | ICO (Information Commissioner's Office) | Breach notifications go to ICO, not EU DPA |
| International transfers | Adequacy decisions by European Commission | UK adequacy regulations (maintained separately) | EU→UK transfer has EU adequacy decision; UK→other requires UK IDTA or addendum |
| Enforcement | Up to €20M or 4% global turnover | Up to £17.5M or 4% global turnover | Equivalent financial exposure |

From a DevSecOps control perspective, UK GDPR requirements are identical to EU GDPR controls. The primary difference is operational: breach notification goes to the ICO, and the legal basis for international transfers requires UK-specific mechanisms.

### UK Cyber Essentials and Cyber Essentials Plus

**Applicability:** Required for UK government contracts handling sensitive and personal information. Increasingly required by commercial clients and insurers.

**Five technical controls:**

| Control | Requirement | DevSecOps Implementation |
|---------|------------|--------------------------|
| Firewalls | Boundary firewalls and internet gateways configured securely | Network policy; security group / firewall-as-code; no unnecessary inbound ports |
| Secure configuration | Devices and software securely configured | Hardened container images; CIS-benchmarked configurations; IaC scanning |
| User access control | Only authorized individuals have user accounts; admin accounts used only when needed | RBAC; principle of least privilege; OIDC; no shared accounts |
| Malware protection | Protection against malware | Container scanning; runtime threat detection; SBOM + vulnerability monitoring |
| Security update management | Devices updated with latest security patches | Automated dependency updates; OS patch management; CVE SLAs |

**Cyber Essentials Plus:** Requires independent verification of all five controls through vulnerability scanning and internal assessment. Align your [Pipeline Security Hardening Checklist](../../secure-pipeline-templates/docs/hardening-checklist.md) with CE+ requirements to simplify annual assessment.

---

## Australia

### Australian Privacy Act 1988 and Privacy Principles

**Applicability:** Organizations with annual turnover > AUD 3M, or regardless of turnover if handling health information, government contracts, or credit reporting information.

**Notifiable Data Breaches (NDB) Scheme:**
- Organizations must notify the OAIC and affected individuals where a breach is likely to result in serious harm
- No fixed notification deadline, but must be "as soon as practicable" — aim for 30 days from awareness
- Notification obligation triggers when: (a) unauthorized access or disclosure of personal information occurs, and (b) serious harm to individuals is likely

**DevSecOps implications:**
- Incident response playbook must include a NDB assessment step
- SIEM must be configured to detect unauthorized access to personal data stores
- Data classification must be maintained to quickly assess breach scope

### Australian Signals Directorate (ASD) Essential Eight

The ASD Essential Eight is Australia's mandatory baseline for government systems and is widely adopted by critical infrastructure and defense contractors.

**Alignment with DevSecOps controls:**

| Essential Eight Strategy | ASD Maturity Level 3 Requirement | DevSecOps Control |
|---|---|---|
| **Application control** | Approved software allowlist enforced; unauthorized execution blocked | OPA/Kyverno admission control; container image allowlist policy |
| **Patch applications** | Applications patched within 48 hours for critical vulnerabilities; 2 weeks for non-critical | SCA with CVE alerting; automated patch PRs; enforced SLAs |
| **Configure Microsoft Office macro settings** | Macros blocked except from trusted locations | IaC configuration policy; endpoint configuration management |
| **User application hardening** | Web browsers, PDF viewers, and Office hardened | Hardened container base images; CIS benchmark enforcement |
| **Restrict administrative privileges** | Admin accounts not used for email/web; purpose-specific accounts | RBAC; separate admin identities; OIDC federation; no shared admin accounts |
| **Patch operating systems** | Operating systems patched within 48 hours for critical; 2 weeks for non-critical | Automated OS base image updates; Trivy scanning of base images; CI gate |
| **Multi-factor authentication** | Phishing-resistant MFA for all users accessing important systems | Hardware MFA for privileged access; OIDC + MFA for CI/CD platform access |
| **Regular backups** | Backups taken at least daily; tested at least annually; offline copies retained | Infrastructure-as-code for disaster recovery; tested restore procedures |

**ASD Essential Eight Maturity Levels** map to the [DevSecOps Maturity Model](../../devsecops-maturity-model/docs/framework.md) as follows:
- ASD ML1 ≈ Techstream Maturity Level 2 (Managed)
- ASD ML2 ≈ Techstream Maturity Level 3 (Defined)
- ASD ML3 ≈ Techstream Maturity Level 4 (Optimizing)

---

## Canada

### PIPEDA and Bill C-27 (Consumer Privacy Protection Act)

**Applicability:** Federal private-sector organizations engaged in commercial activities across provincial borders. All provinces except Quebec, Alberta, and BC (which have their own substantially equivalent legislation) are covered by PIPEDA for federally regulated activities. Quebec's Law 25 (effective fully from September 2023) has particularly strict requirements.

**Key requirements:**
- Breach notification to the OPC (Office of the Privacy Commissioner) and affected individuals when there is a real risk of significant harm
- Privacy management program documentation
- Privacy impact assessments for new programs or significant changes

**Quebec Law 25 (Act respecting the protection of personal information in the private sector):**
- Requires a Privacy Officer (Chief Privacy Officer mandatory for some organizations)
- Privacy impact assessments mandatory before collecting personal information using new technology
- Breach notification to CAI (Commission d'accès à l'information) and individuals within 72 hours of becoming aware
- Right to data portability and right to de-indexing

**DevSecOps controls for Canadian compliance:**
- Incident response playbook must include OPC/CAI notification workflow with explicit timelines
- Privacy impact assessment (PIA) process integrated into the design phase (aligns with threat modeling)
- Data flows documented in SBOM and architecture documentation
- Audit logging for all access to personal data

### Canadian Centre for Cyber Security (CCCS)

The CCCS Top 10 IT Security Actions align closely with CIS Controls. Organizations in the federal supply chain often require CCCS alignment:

| CCCS Action | DevSecOps Implementation |
|---|---|
| Consolidate and control privileged accounts | RBAC; just-in-time access; no shared accounts; PAM tooling |
| Establish an incident response plan | Incident response playbook; tabletop exercises |
| Apply security patches quickly | Automated dependency updates; OS patching; enforced CVE SLAs |
| Enable logging and monitoring | SIEM; pipeline audit logs; Kubernetes audit logs; structured logging |
| Isolate web-facing applications | Network segmentation; WAF; API gateway; Kubernetes NetworkPolicy |
| Protect web and email content filtering | Egress filtering; DNS security; anti-phishing controls |
| Encrypt government sensitive data | Encryption at rest and in transit; key management |
| Assess removable media | Controlled access; endpoint management (less relevant for cloud-native) |
| Scan for network vulnerabilities | DAST; infrastructure scanning; continuous vulnerability management |
| Practice IT hygiene (clean installs, configs) | CIS-benchmarked images; ephemeral build environments; configuration-as-code |

---

## Singapore

### Personal Data Protection Act (PDPA)

**Applicability:** All organizations in Singapore that collect, use, or disclose personal data.

**Key requirements:**

| Obligation | Requirement | DevSecOps Implementation |
|---|---|---|
| Notification | Notify PDPC and individuals for breaches causing or likely to cause significant harm, within 3 days | Incident response playbook with PDPC notification workflow |
| Protection | Reasonable security arrangements to protect personal data | Security baseline controls; encryption; access control |
| Retention limitation | Personal data not retained beyond purposes | Data retention policies; automated data lifecycle management |
| Transfer limitation | Personal data transferred to other countries only with comparable protection | CI/CD pipeline regional controls; SCCs or adequacy assessment |

### Cybersecurity Act and Critical Information Infrastructure (CII)

Organizations designated as CII owners in Singapore are subject to mandatory cybersecurity requirements including:
- Reporting cybersecurity incidents to CSA (Cyber Security Agency of Singapore)
- Conducting cybersecurity audits and risk assessments
- Complying with codes of practice issued by the Commissioner

The Operational Technology (OT) Security Masterplan also applies to OT environments and has relevance for industrial or manufacturing organizations.

---

## Brazil

### Lei Geral de Proteção de Dados (LGPD)

**Applicability:** Any organization that processes personal data of individuals in Brazil, regardless of where the organization is established.

LGPD is substantively modeled on GDPR. Key differences:

| Area | GDPR | LGPD | DevSecOps Impact |
|------|------|------|------------------|
| Supervisory authority | National DPAs | ANPD (National Data Protection Authority) | Breach notifications go to ANPD |
| Breach notification | 72 hours | "Reasonable time" (ANPD guidance suggests 2 business days) | IR playbook must include ANPD notification |
| Legal basis | Six legal bases | Ten legal bases (includes legitimate interest, credit protection, judicial proceedings) | Legal basis documentation in data mapping |
| Children's data | Explicit consent of parents/guardians | Same | Data classification must flag children's data |

**DevSecOps controls specific to LGPD:**
- Data Privacy Officer (Encarregado) designation and contact information publicly disclosed
- Data protection impact assessment (DPIA) for high-risk processing activities — integrate into threat modeling
- Data mapping (ROPA equivalent) maintained — automate via SBOM data flow tagging

---

## India

### Digital Personal Data Protection Act (DPDP Act) 2023

**Applicability:** Any organization that processes digital personal data of individuals in India, or that processes data of Indian data principals outside India in connection with offering goods or services to them. This applies to organizations outside India that target Indian users — there is no establishment threshold.

**Status:** The DPDP Act received Presidential assent in August 2023. Core provisions are in force; the Data Protection Board of India (DPBI) operationalization and specific rules are being phased in.

**Key definitions:**
- **Data Principal**: The individual to whom personal data relates (equivalent to "data subject" in GDPR)
- **Data Fiduciary**: The organization that determines the purpose and means of processing (equivalent to "controller")
- **Significant Data Fiduciary (SDF)**: Organizations designated by the central government based on volume, sensitivity of data, or national security risk. SDFs have additional obligations including DPIA, data audits, and appointment of a Data Protection Officer.

**Key requirements with DevSecOps implications:**

| DPDP Requirement | Section | DevSecOps Control |
|---|---|---|
| Notice and consent for personal data processing | S. 5–6 | Privacy-by-design in APIs; consent capture logging; audit trail for consent decisions |
| Purpose limitation and storage limitation | S. 6(1)(b), S. 8(7) | Data lifecycle management; automated data retention enforcement; data classification |
| Reasonable security safeguards | S. 8(5) | Encryption at rest and in transit; access controls; vulnerability management; incident response |
| Breach notification to DPBI and data principals | S. 8(6) | Incident response playbook with DPBI notification workflow; breach detection automation in SIEM |
| Data localization for SDFs and specified data | S. 16 (if applicable) | CI/CD runners, data stores, and analytics pipelines must use India-region infrastructure for designated data |
| Children's data protection (consent from guardian) | S. 9 | Age verification controls; guardian consent workflows; data classification flag for children's data |
| Grievance redressal mechanism | S. 13 | Public-facing privacy portal; audit logs of grievance submissions and resolutions |

**Breach notification under DPDP Act:**

The Act requires notification to both the Data Protection Board of India and affected data principals "in such a form and manner as may be prescribed." Unlike GDPR, there is no fixed 72-hour window in the Act itself — the specific timeline will be set by rules. The DPBI can direct the Fiduciary to notify affected data principals.

**Incident response playbook addition:**

```yaml
# DPDP breach notification trigger (OPA policy)
package dpdp.breach_notification

import future.keywords.if

reportable_breach if {
    # Unauthorized access or disclosure of personal data of Indian data principals
    input.affected_data_subjects_region == "IN"
    input.data_categories[_] == "personal_data"
}

# Notify DPBI as prescribed; notify data principals as directed
# Document breach as: what happened, when, what data, how many principals affected,
# what measures are being taken
notification_recipients := ["dpbi", "affected_data_principals"] if reportable_breach
```

**Significant Data Fiduciary (SDF) additional obligations:**

If your organization is designated as an SDF, the following additional controls apply:

| SDF Obligation | DevSecOps Implementation |
|---|---|
| Data Protection Officer (DPO) appointed | DPO contact integrated into incident response escalation paths |
| Data Protection Impact Assessment (DPIA) | DPIA integrated into threat modeling for high-risk new processing activities |
| Periodic data audits | Annual or bi-annual security assessments; automated compliance scans |
| Prohibition on using data for behavioral tracking of children | Data classification to flag children's data; automated policy enforcement |

**Cross-border data transfer:**

The DPDP Act allows transfer of personal data outside India to countries that the central government does not restrict. Unlike GDPR, DPDP does not require SCCs or adequacy decisions for general transfers — but the government may restrict transfers to specific countries or require certain safeguards for SDFs. Monitor the DPBI for published rules.

For organizations outsourcing data processing to Indian entities: Indian vendors processing personal data on your behalf are Data Processors under the Act. Include DPDP compliance clauses in vendor agreements.

**DevSecOps controls specific to DPDP:**
- Implement data localization controls for any data categories designated by the central government (monitor DPBI notifications for updates to the restricted list)
- Configure SIEM breach detection rules to flag unauthorized access to Indian user data with a high-priority alert
- Add DPBI notification workflow to the incident response playbook alongside GDPR/ICO notification workflows
- Maintain a record of processing activities (ROPA equivalent) as data mapping documentation, which supports DPIA and audit obligations for SDFs

---

## Multi-Jurisdiction Compliance Matrix

For organizations operating across multiple jurisdictions, the following table shows which requirements are additive beyond the EU GDPR / ISO 27001 / SOC 2 baseline:

| Requirement | EU GDPR | UK GDPR | LGPD | PDPA (SG) | Privacy Act (AU) | DPDP (IN) |
|---|---|---|---|---|---|---|
| Breach notification timeline | 72h to DPA | 72h to ICO | ~48h to ANPD | 3 days to PDPC | ASAP to OAIC | As prescribed by rules (DPBI) |
| DPO/Privacy Officer required | Yes (certain cases) | Yes (certain cases) | Yes (Encarregado) | No | No | Yes (SDFs only) |
| Data localization | No general requirement | No general requirement | No general requirement | No general requirement | No general requirement | Specified categories (SDF rules) |
| Transfer mechanisms | Adequacy / SCC / BCR | Adequacy / IDTA | Adequacy / equivalent protection | Adequacy / contractual | Adequacy / APP 8 | Allowlist-based (no SCCs required) |
| Right to erasure | Yes | Yes | Yes | No (in general) | No (in general) | Yes (Right to erasure exists) |

**Practical approach for multi-jurisdiction organizations:**

1. Implement EU GDPR as the global baseline — it is the most stringent and comprehensive requirement
2. Layer jurisdiction-specific additive requirements on top:
   - Australia: Add ASD Essential Eight controls; configure NDB assessment in IR playbook
   - Canada: Add Quebec Law 25 PIA process; configure OPC notification in IR playbook
   - Singapore: Add PDPC notification workflow; assess CII designation
   - Brazil: Add ANPD notification workflow; designate Encarregado; publish contact
   - **India**: Add DPBI notification workflow; assess SDF designation; configure data localization controls for Indian user data; monitor DPBI rulemaking
3. Automate jurisdiction routing in incident response: when a breach is detected, the IR workflow determines which DPAs must be notified based on data subject geography

---

## Compliance Automation Approach

Jurisdiction-specific requirements should be implemented as policy layers in your compliance automation framework:

```yaml
# Example: OPA policy layer for GDPR breach notification threshold
package gdpr.breach_notification

import future.keywords.if

# A breach is reportable if it affects personal data of EU subjects
# and meets the risk threshold
reportable_breach if {
    input.affected_data_subjects_region == "EU"
    input.data_categories[_] == "personal_data"
    input.estimated_harm_likelihood != "low"
}

# Notification required within 72 hours
notification_deadline_hours := 72 if reportable_breach
```

Store jurisdiction policies as separate OPA bundles, loaded conditionally based on the organization's regulatory scope configuration. This avoids applying stricter requirements to organizations not subject to them.

---

## Related Documentation

- [Regulatory Controls Matrix](regulatory-controls-matrix.md) — the foundational control mapping (NIST, SOC 2, ISO 27001, CIS, PCI DSS)
- [Compliance Automation Framework](framework.md) — how to operationalize these requirements as continuous controls
- [Supply Chain Incident Response Playbook](../../software-supply-chain-security-framework/docs/incident-response-playbook.md) — includes regulatory notification requirements for supply chain incidents
- [Investment Framework](../../techstream-docs/docs/investment-framework.md) — compliance-driven investment justification by jurisdiction

---

*Part of the Techstream Compliance Automation Framework. Licensed under Apache 2.0.*
