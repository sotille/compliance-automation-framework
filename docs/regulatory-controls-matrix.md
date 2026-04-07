# Regulatory Controls Cross-Reference Matrix

This document provides a detailed mapping between the Techstream Compliance Automation Framework's technical controls and the specific requirements of five major compliance frameworks: SOC 2 Type II, ISO 27001:2022, NIST SP 800-53 Rev 5, PCI-DSS v4.0, and CIS Controls v8.

Use this matrix to:
- Identify which technical controls satisfy overlapping requirements across frameworks
- Scope your compliance program to the minimum control set for your applicable frameworks
- Demonstrate coverage to auditors with evidence pointers
- Identify gaps when adding a new compliance framework to an existing program

---

## How to Read This Matrix

Each row represents a Techstream control category. Columns indicate the specific control identifiers from each compliance framework that the Techstream control satisfies. An empty cell means the framework either does not address that area or coverage requires additional controls not included in this framework.

**Coverage levels:**
- **Full** — the Techstream control directly satisfies the requirement with automated evidence
- **Partial** — the Techstream control addresses part of the requirement; supplemental controls or manual evidence may be needed
- **Supporting** — the Techstream control provides supporting evidence but is not the primary control

---

## Section 1: Identity and Access Management

| Techstream Control | SOC 2 (CC6) | ISO 27001:2022 | NIST 800-53 Rev 5 | PCI-DSS v4.0 | CIS Controls v8 |
|-------------------|-------------|-----------------|--------------------|--------------|--------------------|
| **IAM policy enforcement (least privilege)** | CC6.1, CC6.2 | A.5.15, A.5.18 | AC-2, AC-3, AC-6 | Req 7.2, 7.3 | CIS 5.3, 5.4 |
| **MFA enforcement for all privileged accounts** | CC6.1 | A.8.5 | IA-2(1), IA-2(2) | Req 8.4 | CIS 6.3, 6.4 |
| **Service account / non-human identity controls** | CC6.1, CC6.6 | A.5.16, A.8.2 | IA-5(4), AC-2(9) | Req 8.6 | CIS 5.6 |
| **OIDC token federation (no long-lived credentials)** | CC6.1 | A.8.2, A.8.9 | IA-5, SC-28 | Req 8.3, 8.6 | CIS 5.4 |
| **Quarterly access reviews** | CC6.2, CC6.3 | A.5.18 | AC-2(2), AC-2(7) | Req 7.2.4 | CIS 5.1 |
| **Role-based access control (RBAC)** | CC6.2 | A.5.15 | AC-3, AC-5 | Req 7.2 | CIS 5.3 |

---

## Section 2: Vulnerability and Patch Management

| Techstream Control | SOC 2 (CC7, CC8) | ISO 27001:2022 | NIST 800-53 Rev 5 | PCI-DSS v4.0 | CIS Controls v8 |
|-------------------|------------------|-----------------|--------------------|--------------|--------------------|
| **SAST in CI pipeline** | CC7.1 | A.8.29 | SA-11(1), SI-2 | Req 6.2.4 | CIS 16.12 |
| **SCA / dependency vulnerability scanning** | CC7.1 | A.8.8, A.8.29 | SI-2, SA-15(7) | Req 6.2.4, 6.3.3 | CIS 7.4, 16.13 |
| **Container image scanning** | CC7.1 | A.8.8, A.8.29 | SI-2(2), CM-7 | Req 6.2.4 | CIS 7.4 |
| **IaC misconfiguration scanning** | CC7.1 | A.8.9, A.8.20 | CM-6, CM-7, SI-2 | Req 6.2.4, 6.3 | CIS 4.1, 7.1 |
| **DAST against deployed applications** | CC7.1 | A.8.29 | SA-11(2) | Req 6.2.4, 11.3 | CIS 18.3 |
| **Vulnerability SLA enforcement (CRITICAL: 7 days, HIGH: 30 days)** | CC7.1, CC7.4 | A.8.8 | SI-2(2) | Req 6.3.3 | CIS 7.7 |
| **CSPM continuous cloud misconfiguration scanning** | CC7.1 | A.8.9 | CM-6, CA-7 | Req 11.3 | CIS 4.1 |

---

## Section 3: Change Management and Pipeline Security

| Techstream Control | SOC 2 (CC8) | ISO 27001:2022 | NIST 800-53 Rev 5 | PCI-DSS v4.0 | CIS Controls v8 |
|-------------------|-------------|-----------------|--------------------|--------------|--------------------|
| **Protected branches with mandatory code review** | CC8.1 | A.8.4, A.8.32 | CM-3, SA-10 | Req 6.2.2 | CIS 16.1 |
| **Separate deployment approvals for production** | CC8.1 | A.5.20, A.8.32 | CM-3(2), SA-10 | Req 6.5.6 | CIS 16.1 |
| **Immutable artifact promotion (no rebuild)** | CC8.1 | A.8.32 | CM-14, SA-10(1) | Req 6.3.2 | CIS 16.7 |
| **Artifact signing and signature verification** | CC8.1 | A.8.32 | CM-14, SI-7(6) | Req 6.3.2 | CIS 16.7 |
| **Pipeline audit log (immutable, tamper-evident)** | CC8.1 | A.8.15, A.8.32 | AU-10, CM-3 | Req 10.2, 10.3 | CIS 8.5, 8.12 |
| **Emergency change process with required approvals** | CC8.1 | A.5.20 | CM-3(2) | Req 6.5.6 | — |

---

## Section 4: Secrets and Cryptography

| Techstream Control | SOC 2 (CC6, CC9) | ISO 27001:2022 | NIST 800-53 Rev 5 | PCI-DSS v4.0 | CIS Controls v8 |
|-------------------|------------------|-----------------|--------------------|--------------|--------------------|
| **Centralized secrets management (Vault / cloud KMS)** | CC6.1, CC6.7 | A.8.24, A.8.25 | SC-12, SC-28 | Req 3.5, 8.3 | CIS 13.9 |
| **Secrets scanning in commits and pipelines** | CC6.7 | A.8.12 | SI-12, SA-3 | Req 3.2.1 | CIS 13.9 |
| **Secret rotation automation** | CC6.1 | A.8.25 | IA-5(1), SC-12(1) | Req 8.3.9 | CIS 5.4 |
| **Encryption in transit (TLS 1.2+ enforced)** | CC6.7, CC9.1 | A.8.24 | SC-8, SC-8(1) | Req 4.2.1 | CIS 3.10 |
| **Encryption at rest for sensitive data stores** | CC6.7 | A.8.24 | SC-28 | Req 3.5 | CIS 3.11 |
| **Key management policy and lifecycle** | CC6.7 | A.8.24 | SC-12 | Req 3.7 | CIS 3.9 |

---

## Section 5: Logging, Monitoring, and Incident Response

| Techstream Control | SOC 2 (CC7, CC4) | ISO 27001:2022 | NIST 800-53 Rev 5 | PCI-DSS v4.0 | CIS Controls v8 |
|-------------------|------------------|-----------------|--------------------|--------------|--------------------|
| **Centralized audit logging (all systems)** | CC7.2, CC4.1 | A.8.15 | AU-2, AU-12 | Req 10.2, 10.3 | CIS 8.1, 8.5 |
| **Log integrity protection (immutable storage, signed)** | CC7.2 | A.8.15 | AU-9 | Req 10.3.2, 10.3.3 | CIS 8.3 |
| **Log retention (minimum 12 months, 3 months hot)** | CC4.1 | A.8.15 | AU-11 | Req 10.7 | CIS 8.10 |
| **SIEM alerting for security events** | CC7.2 | A.8.16 | IR-5, SI-4 | Req 10.4, 10.6 | CIS 8.11 |
| **Incident response plan (defined and tested)** | CC7.3, CC7.4, CC7.5 | A.5.24, A.5.26 | IR-3, IR-4, IR-8 | Req 12.10 | CIS 17.4, 17.8 |
| **Mean time to detect (MTTD) metric tracked** | CC7.2 | A.8.16 | SI-4 | Req 10.7 | CIS 8.11 |

---

## Section 6: Network Security

| Techstream Control | SOC 2 (CC6) | ISO 27001:2022 | NIST 800-53 Rev 5 | PCI-DSS v4.0 | CIS Controls v8 |
|-------------------|-------------|-----------------|--------------------|--------------|--------------------|
| **Network segmentation by workload sensitivity** | CC6.6 | A.8.20, A.8.22 | SC-7, CA-9 | Req 1.3 | CIS 12.2 |
| **Private endpoints for all managed services** | CC6.6 | A.8.20 | SC-7(3) | Req 1.3.2 | CIS 12.3 |
| **Egress allowlisting on CI runners** | CC6.6 | A.8.22 | SC-7(5) | Req 1.3 | CIS 12.4 |
| **No public internet access to management planes** | CC6.6 | A.8.20 | SC-7(3) | Req 1.3.2 | CIS 12.3 |
| **VPC flow logs and network traffic analysis** | CC7.2 | A.8.16 | AU-2, SI-4 | Req 10.2 | CIS 13.6 |
| **Kubernetes NetworkPolicy enforcement** | CC6.6 | A.8.20, A.8.22 | SC-7, CA-9 | Req 1.3 | CIS 12.2 |

---

## Section 7: Software Supply Chain

| Techstream Control | SOC 2 (CC9) | ISO 27001:2022 | NIST 800-53 Rev 5 | PCI-DSS v4.0 | CIS Controls v8 |
|-------------------|-------------|-----------------|--------------------|--------------|--------------------|
| **SBOM generation for all builds** | CC9.2 | A.5.19, A.8.8 | SA-12, SR-3 | Req 6.3.2 | CIS 2.5, 16.8 |
| **SLSA provenance attestations** | CC9.2 | A.8.32 | SA-12, SR-3, SR-4 | Req 6.3.2 | CIS 16.7 |
| **Third-party component risk assessment** | CC9.2 | A.5.19, A.5.20 | SA-4, SR-3 | Req 6.3.3 | CIS 7.6 |
| **Dependency pinning to exact versions/digests** | CC9.2 | A.8.8 | SA-12, SR-3 | Req 6.3.2 | CIS 16.8 |
| **Private artifact registry (no direct public pulls)** | CC9.2 | A.5.19 | SR-3, CM-7 | Req 6.3.2 | CIS 16.9 |
| **Hermetic / reproducible builds** | CC9.2 | A.8.32 | SA-12(1), SR-4 | Req 6.3.2 | CIS 16.7 |

---

## Section 8: Governance and Risk Management

| Techstream Control | SOC 2 (CC3, CC9) | ISO 27001:2022 | NIST 800-53 Rev 5 | PCI-DSS v4.0 | CIS Controls v8 |
|-------------------|------------------|-----------------|--------------------|--------------|--------------------|
| **Information security policy (documented, reviewed annually)** | CC3.1 | A.5.1 | PL-2, PM-1 | Req 12.1 | CIS 17.1 |
| **Risk register and treatment plan** | CC3.2 | A.5.3, A.6.1 | RA-3, PM-9 | Req 12.3 | CIS 18.1 |
| **Documented risk exceptions with owner and expiry** | CC3.2 | A.6.1.3 | RA-3 | Req 12.3.4 | — |
| **Vendor / third-party security assessments** | CC9.2 | A.5.19, A.5.20 | SA-9, SR-6 | Req 12.8 | CIS 15.1 |
| **Policy-as-code enforcement (OPA, Kyverno)** | CC3.1, CC8.1 | A.5.1, A.8.9 | CM-6, CM-7 | Req 6.3, 7.2 | CIS 4.1 |
| **Continuous compliance dashboards** | CC4.1 | A.5.35 | CA-2, CA-7 | Req 12.4 | CIS 18.5 |

---

## Section 9: HIPAA Technical and Administrative Safeguards

Healthcare SaaS organizations, health IT vendors, and any organization acting as a HIPAA Business Associate must implement the HIPAA Security Rule (45 CFR Part 164). This section maps Techstream controls to the three HIPAA safeguard categories: Administrative, Physical, and Technical. HIPAA requirements are listed using the CFR section reference.

**Scope note:** HIPAA does not specify implementation standards with the same prescriptive detail as NIST 800-53 or PCI-DSS. Controls that are "Required" (R) must be implemented; controls that are "Addressable" (A) must be implemented if reasonable and appropriate, with documented rationale if not implemented. The Techstream controls below satisfy both Required and common Addressable specifications.

### HIPAA Administrative Safeguards (§164.308)

| Techstream Control | HIPAA Section | Spec Type | Coverage |
|-------------------|--------------|-----------|----------|
| **Information security risk analysis and risk management program** | §164.308(a)(1) | R | Partial — Techstream automates technical control evidence; formal risk analysis requires organizational process |
| **Workforce security (background checks, access authorization)** | §164.308(a)(3) | R | Supporting — IAM provisioning workflows provide access authorization evidence |
| **RBAC and access provisioning process** | §164.308(a)(4) | R | Full — RBAC enforced via IAM policies; provisioning and de-provisioning audit trail from IDP |
| **Security awareness training program** | §164.308(a)(5) | R | Supporting — training completion tracking if LMS is integrated; curriculum guidance in devsecops-framework |
| **Security incident procedures and response** | §164.308(a)(6) | R | Full — incident response playbooks in place; SIEM alerting; MTTD tracking |
| **Contingency plan (backup, disaster recovery)** | §164.308(a)(7) | R | Supporting — IaC enables reproducible infrastructure; backup enforcement requires supplemental controls |
| **Annual evaluation of security program** | §164.308(a)(8) | R | Supporting — maturity model assessments provide annual evaluation evidence |
| **Business Associate Agreements (BAAs)** | §164.308(b) | R | Supporting — third-party vendor assessment framework provides risk evidence for BAA decisions |

### HIPAA Physical Safeguards (§164.310)

Physical safeguards apply to cloud-hosted PHI primarily through the shared responsibility model — cloud providers cover the physical layer.

| Techstream Control | HIPAA Section | Spec Type | Coverage |
|-------------------|--------------|-----------|----------|
| **Facility access controls (cloud provider physical controls)** | §164.310(a) | R | Supporting — use of ISO 27001-certified cloud providers satisfies physical facility requirements; document CSP compliance attestations |
| **Workstation security policy** | §164.310(b-c) | R | Supporting — endpoint management policy and MDM configuration required as supplemental control |
| **Device and media controls (cloud storage encryption)** | §164.310(d) | R | Full — encryption at rest enforced via IaC policy (Checkov); cloud storage encryption compliance validated continuously |

### HIPAA Technical Safeguards (§164.312)

| Techstream Control | HIPAA Section | Spec Type | Coverage |
|-------------------|--------------|-----------|----------|
| **Unique user identification (no shared accounts)** | §164.312(a)(2)(i) | R | Full — IAM policy enforcement prohibits shared accounts; individual identity required for all human access |
| **Emergency access procedure** | §164.312(a)(2)(ii) | R | Partial — break-glass access process documented; JIT access provides emergency path with audit trail |
| **Automatic logoff** | §164.312(a)(2)(iii) | A | Supporting — enforced via identity provider session policy configuration |
| **Encryption and decryption** | §164.312(a)(2)(iv) | A | Full — encryption at rest and in transit; key management lifecycle enforced; Checkov validates IaC compliance |
| **Audit controls (system activity reviews)** | §164.312(b) | R | Full — centralized audit logging with immutable storage; log integrity verification; SIEM alerting; 12-month retention minimum |
| **Integrity controls (PHI not improperly altered)** | §164.312(c) | A | Full — artifact signing (Cosign) ensures integrity of data pipelines; S3 Object Lock / immutable storage prevents alteration |
| **Authentication (verify person/entity identity)** | §164.312(d) | R | Full — MFA enforced; phishing-resistant MFA for administrative access; OIDC federation for workload identity |
| **Transmission security (PHI in transit)** | §164.312(e) | A | Full — TLS 1.2+ enforced on all endpoints; TLS policy validated via IaC scanning; mTLS in service mesh |

### HIPAA Breach Notification Rule Alignment (§164.400–414)

| Control | HIPAA Requirement | Techstream Evidence |
|---------|-----------------|---------------------|
| Breach detection capability | Identify unauthorized access to PHI | SIEM alerting on anomalous data access; VPC flow log analysis; secrets access audit |
| 60-day notification trigger tracking | Track discovery date and notification deadline | Incident management integration (Jira/ServiceNow) with SLA tracking |
| Risk assessment for breach impact | Determine probability of PHI compromise | Documented IR playbook with breach impact assessment step |
| Breach documentation | Record all breaches including those below notification threshold | Immutable incident record with post-incident review |

### HIPAA Evidence Automation

| Evidence Type | Automated Source | Collection Method |
|--------------|-----------------|-------------------|
| PHI access audit log | Cloud storage access logs (S3/Azure/GCS) | Prowler + CloudTrail → immutable S3 evidence bucket |
| Encryption compliance | Checkov/tfsec IaC scan results | CI pipeline output → evidence catalog API |
| Authentication logs (MFA enforcement) | Identity provider audit log | Automated export + evidence tagging |
| Vulnerability scan results | Trivy, Grype scan outputs | Pipeline artifact → evidence storage |
| Network security configuration | VPC/NSG/firewall IaC compliance report | Prowler + cloud config scanner |
| Access reviews | IAM policy exports + access review workflow | Quarterly automated report generation |
| Incident records | Ticket system integration | SIEM → ticketing webhook → closed-loop evidence |

---

## Compliance Framework Quick-Reference

### Applicable to SaaS / Cloud-Native Companies

| Company Profile | Primary Frameworks | Key Control Areas |
|-----------------|-------------------|-------------------|
| B2B SaaS (no financial data) | SOC 2 Type II | CC6, CC7, CC8 — access, monitoring, change |
| B2B SaaS (handles payment data) | SOC 2 Type II + PCI-DSS | Add Req 3, 4, 6, 10, 12 |
| Healthcare SaaS (US) | SOC 2 Type II + HIPAA | §164.308 admin safeguards, §164.312 technical safeguards, PHI encryption, audit logging |
| EU data processing | SOC 2 + GDPR | Add data subject rights, DPA agreements, breach notification |
| Government / US Federal | FedRAMP (NIST 800-53 moderate/high) | Full AC, AU, CA, CM, IA, SI control families |

### Framework Overlap Map

The following control families have near-complete overlap across frameworks — implementing them well addresses requirements in all applicable frameworks simultaneously.

| Control Family | SOC 2 | ISO 27001 | NIST 800-53 | PCI-DSS | HIPAA |
|----------------|-------|-----------|-------------|---------|-------|
| Access control and least privilege | CC6.1-3 | A.5.15, A.5.18 | AC-2, AC-3 | Req 7 | §164.308(a)(4), §164.312(d) |
| Vulnerability management | CC7.1 | A.8.8 | SI-2 | Req 6 | §164.308(a)(1) |
| Audit logging | CC4.1, CC7.2 | A.8.15 | AU-2, AU-12 | Req 10 | §164.312(b) |
| Change management | CC8.1 | A.8.32 | CM-3 | Req 6.5 | §164.308(a)(1) |
| Cryptography | CC6.7 | A.8.24 | SC-8, SC-28 | Req 3, 4 | §164.312(a)(2)(iv), §164.312(e) |
| Incident response | CC7.3-5 | A.5.24 | IR-4, IR-8 | Req 12.10 | §164.308(a)(6) |

---

## Evidence Automation Coverage

The Techstream Compliance Automation Framework provides automated evidence collection for the following control categories. Manual evidence is still required for the areas indicated.

| Control Category | Automated Evidence | Manual Evidence Still Required |
|------------------|-------------------|--------------------------------|
| Vulnerability scans | Trivy, Grype, Prowler JSON reports | Penetration test findings and remediation |
| Access reviews | IAM policy exports | Evidence that a human reviewed and approved |
| Pipeline audit logs | Immutable pipeline execution records | Evidence that logs are monitored by a person |
| Policy enforcement | OPA / Kyverno decision logs | Policy exception justifications |
| Change approvals | PR merge audit trail | CAB meeting minutes for significant changes |
| Encryption configuration | IaC scan + cloud config reports | Certificate management lifecycle records |
| Training completion | LMS integration (if configured) | Manager attestation of role-specific training |

---

## Section 10: NIST SSDF (SP 800-218) Controls Mapping

The NIST Secure Software Development Framework (SSDF) — NIST Special Publication 800-218 — defines software development security practices for federal agencies and their software suppliers. It is directly referenced by Executive Order 14028 and the OMB M-22-18 memorandum requiring SSDF compliance from all federal software vendors. It is organized into four practice groups (PG, PS, PW, RV) with specific tasks under each.

This section maps Techstream technical controls to SSDF tasks. Unlike prescriptive standards (PCI-DSS, NIST 800-53), SSDF is outcomes-based — it specifies what must be achieved, not how. The Techstream implementations represent one validated approach.

**Notation:** SSDF tasks are referenced as `Practice.Task` (e.g., `PW.4.1` = Prepare the Software practice, Task 4, Sub-task 1).

### PG: Prepare the Organization

| SSDF Task | Description | Techstream Control | Coverage |
|-----------|-------------|-------------------|----------|
| **PG.1.1** | Define security requirements for software development | Security requirements defined in DevSecOps Framework | Full |
| **PG.1.2** | Communicate security requirements to all staff | Security training program; security champions curriculum | Partial |
| **PG.2.1** | Identify roles and responsibilities for software security | RACI matrices in DevSecOps Methodology; security champion role definitions | Full |
| **PG.2.2** | Ensure personnel have skills to fulfill their security roles | Training tiers (L1 fundamentals, L2 secure dev, L3 champions) | Partial |
| **PG.3.1** | Create a software security working group | Governance model: DevSecOps Steering Committee, Security Review Board | Full |
| **PG.3.2** | Gather and use vulnerability data to improve practices | MTTD/MTTR tracking; SAST tuning from false positive data; post-incident reviews | Full |
| **PG.4.1** | Use tools that support security practices | Toolchain reference (Semgrep, Trivy, Cosign, Gitleaks, OPA, Vault) | Full |
| **PG.4.2** | Ensure tool integrity and authenticity | Third-party action pinning to immutable SHAs; tool supply chain verification | Full |

### PS: Protect the Software

| SSDF Task | Description | Techstream Control | Coverage |
|-----------|-------------|-------------------|----------|
| **PS.1.1** | Store all forms of code based on their risk | Repository access controls; CODEOWNERS; branch protection | Full |
| **PS.2.1** | Provide a mechanism for verifying software integrity | Cosign artifact signing; SLSA provenance attestations | Full |
| **PS.2.2** | Verify software prior to deployment | Signature verification at deployment; Kyverno admission control | Full |
| **PS.3.1** | Archive and protect each software release | Immutable artifact registry with tag immutability; S3 Object Lock | Full |
| **PS.3.2** | Collect, safeguard, and share vulnerability disclosures | Responsible disclosure policy; CVE triage and SLA enforcement | Partial |

### PW: Produce Well-Secured Software

| SSDF Task | Description | Techstream Control | Coverage |
|-----------|-------------|-------------------|----------|
| **PW.1.1** | Design software to meet security requirements and mitigate risks | Threat modeling integration in planning phase; STRIDE analysis | Full |
| **PW.1.2** | Design software to be secure by default | Secure coding standards; least privilege defaults in frameworks | Full |
| **PW.2.1** | Review the design to verify compliance with security requirements | Security design review process; architecture review board | Partial |
| **PW.4.1** | Reuse existing, well-secured software when feasible | OSS component assessment framework; approved dependency registry | Full |
| **PW.4.4** | Verify third-party software complies with security requirements | SCA scanning (Trivy, Grype); license compliance; SBOM generation | Full |
| **PW.5.1** | Build software to meet security standards | Secure pipeline templates with mandatory SAST, SCA, secrets, container scanning | Full |
| **PW.6.1** | Configure the build and test environment to include security | Pipeline security controls; ephemeral runners; least-privilege tokens | Full |
| **PW.6.2** | Identify and address security vulnerabilities in the build pipeline | CI/CD threat model; pipeline security hardening checklist | Full |
| **PW.7.1** | Perform targeted security testing on software | DAST integration; API security testing; penetration testing guidance | Full |
| **PW.7.2** | Conduct code reviews that focus on security | Security-focused code review checklist; automated SAST findings in PRs | Full |
| **PW.8.1** | Receive and address vulnerability reports | Vulnerability triage SLA (CRITICAL: 7d, HIGH: 30d); responsible disclosure | Full |
| **PW.8.2** | Monitor all components for vulnerabilities** | Continuous SCA scanning; SBOM-based vulnerability monitoring via Dependency-Track | Full |

### RV: Respond to Vulnerabilities

| SSDF Task | Description | Techstream Control | Coverage |
|-----------|-------------|-------------------|----------|
| **RV.1.1** | Gather information from all sources about potential vulnerabilities | SIEM integration; public CVE feeds; security advisories; SBOM-based alerts | Full |
| **RV.1.2** | Maintain an inventory of potential vulnerabilities | SBOM-based vulnerability inventory in Dependency-Track; VEX lifecycle management | Full |
| **RV.2.1** | Investigate each vulnerability report | Vulnerability triage process with severity assessment | Full |
| **RV.2.2** | Determine the risk each vulnerability poses | CVSS scoring; exploitability assessment (VEX); context-aware severity adjustment | Full |
| **RV.3.1** | Remediate all exploitable vulnerabilities | Vulnerability SLA enforcement; remediation runbooks | Full |
| **RV.3.2** | Monitor the status of all remediation activities | Vulnerability aging metrics; SLA breach alerting; dashboards | Full |
| **RV.3.3** | Analyze each vulnerability to determine root cause | Post-incident review process; blameless postmortem framework | Partial |

### SSDF Evidence Automation

| SSDF Practice | Evidence Type | Automated Collection |
|--------------|--------------|---------------------|
| PG.4 — Tool integrity | Tool version pinning records; SHA verification logs | Pipeline artifact outputs |
| PS.2 — Software integrity | Cosign signature records; SLSA attestations in Rekor | Registry attestation metadata |
| PW.4.4 — Third-party verification | Trivy/Grype SCA scan results; SBOM | CI pipeline SARIF/JSON artifacts |
| PW.5/PW.6 — Secure build | Pipeline audit log; runner configuration; gate pass/fail records | Pipeline execution records |
| PW.7 — Security testing | SAST results (SARIF), DAST results, penetration test reports | CI artifact storage |
| PW.8 — Vulnerability management | Vulnerability tracking records; SLA compliance reports | Dependency-Track API exports |
| RV.1/RV.2 — Vulnerability inventory | SBOM + CVE correlation; VEX statements | Dependency-Track + VEX workflow |

### SSDF Relationship to Other Frameworks

The SSDF complements rather than replaces other compliance frameworks. Use this mapping to avoid duplicated assessment effort:

| SSDF Practice | NIST 800-53 Mapping | ISO 27001:2022 | SOC 2 |
|--------------|--------------------|-----------------|----|
| PG — Prepare Organization | SA-15, AT-2, PM-3 | A.5.2, A.6.3 | CC1.1 |
| PS — Protect Software | CM-14, SI-7, SA-10 | A.8.32 | CC8.1 |
| PW — Produce Well-Secured Software | SA-11, SA-15, CM-6 | A.8.29, A.8.28 | CC7.1, CC8.1 |
| RV — Respond to Vulnerabilities | SI-2, IR-4, RA-5 | A.8.8, A.5.24 | CC7.1, CC7.3 |

---

## Related Documents

- [Compliance Automation Architecture](architecture.md) — Four-layer compliance system design
- [Framework Documentation](framework.md) — Policy-as-Code patterns and tool configurations
- [Implementation Guide](implementation.md) — Phased compliance automation rollout
- [FedRAMP Implementation Guide](fedramp-implementation-guide.md) — FedRAMP-specific controls aligned with NIST SSDF requirements
- [NIST SSDF](https://csrc.nist.gov/Projects/ssdf) — NIST Secure Software Development Framework official specification
- [SLSA Framework](https://slsa.dev/) — Supply chain levels for software artifacts
- [Software Supply Chain Security: SLSA Level Advancement](../../software-supply-chain-security-framework/docs/slsa-level-advancement.md) — Step-by-step SLSA implementation supporting SSDF PS.2 requirements
