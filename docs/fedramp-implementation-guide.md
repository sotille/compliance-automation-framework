# FedRAMP Implementation Guide

The Federal Risk and Authorization Management Program (FedRAMP) is the mandatory compliance framework for cloud service providers (CSPs) offering services to US Federal agencies. FedRAMP authorization demonstrates that a cloud service meets NIST SP 800-53 security controls at the Tailored Low, Low, Moderate, or High impact level as validated by a Third Party Assessment Organization (3PAO).

This guide covers what FedRAMP requires from a DevSecOps and continuous compliance perspective, how to integrate FedRAMP control implementation into CI/CD pipelines, and how the Techstream Compliance Automation Framework maps to FedRAMP authorization requirements.

---

## FedRAMP Authorization Paths

FedRAMP provides three authorization paths. Understanding which path applies determines your documentation and authorization timeline.

| Path | How It Works | Typical Use Case |
|------|-------------|-----------------|
| **Agency Authorization** | A sponsoring federal agency grants an Authority to Operate (ATO) after reviewing your System Security Plan (SSP) and 3PAO assessment | CSPs targeting a specific agency customer |
| **JAB Provisional Authorization (P-ATO)** | The Joint Authorization Board (JAB) — CISA, GSA, DoD — grants a government-wide P-ATO | CSPs targeting broad federal market; highly competitive selection process |
| **FedRAMP Tailored** | Simplified path for low-impact Software as a Service (LI-SaaS) with limited federal data | SaaS with no PII, no federal data storage, minimal data processing |

Most commercial cloud services targeting federal agencies pursue **Agency Authorization** at the **Moderate** impact level, which covers the majority of federal workloads containing Controlled Unclassified Information (CUI).

---

## Impact Level Selection

Impact level determines the control baseline required. Select the highest impact level applicable to the data you will process or store.

| Impact Level | Data Sensitivity | Control Count | Examples |
|-------------|-----------------|---------------|----------|
| **Low** | Information whose unauthorized disclosure would have limited adverse effects | ~125 controls | Public-facing information systems with no PII |
| **Moderate** | Information whose unauthorized disclosure would have serious adverse effects | ~325 controls | CUI, personally identifiable information (PII), law enforcement data |
| **High** | Information whose unauthorized disclosure would have severe or catastrophic effects | ~421 controls | Emergency services, financial systems, law enforcement, healthcare |

**Selecting Moderate as baseline:** Most SaaS products targeting federal agencies select Moderate. The Techstream framework controls described in this guide target FedRAMP Moderate.

---

## FedRAMP Moderate Control Families and DevSecOps Mapping

FedRAMP Moderate requires implementation of 325 controls across 20 control families. The following table maps the control families most directly addressed by DevSecOps practices to specific Techstream capabilities.

### Access Control (AC)

FedRAMP AC controls govern who can access systems, what they can do, and how access is provisioned and revoked.

| FedRAMP Control | Requirement Summary | Techstream DevSecOps Implementation |
|----------------|--------------------|------------------------------------|
| **AC-2** | Account management — provisioning, review, and termination | OIDC workload identity federation; automated access review pipeline triggers |
| **AC-3** | Access enforcement — least-privilege for all accounts | RBAC enforcement via OPA/Kyverno policy; pipeline service accounts use minimum required permissions |
| **AC-6** | Least privilege | Pipeline runners provisioned with job-scoped credentials; no persistent service account keys |
| **AC-17** | Remote access | Bastion host controls enforced via IaC; SSH access audit logging |
| **AC-22** | Publicly accessible content | IaC scan policies block public S3 buckets and unintended public exposure (Checkov CKV_AWS_20) |

**Automation opportunity:** AC-2 access reviews can be triggered by CI/CD pipeline events — new service account creation triggers an automated access review task in your GRC tool.

```yaml
# Example OPA/Rego policy enforcing AC-6 least privilege for AWS IAM roles
package fedramp.ac6

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_iam_role_policy"
  contains(resource.change.after.policy, '"Action": "*"')
  msg := sprintf(
    "AC-6 violation: IAM role '%v' grants wildcard Action — least privilege required under FedRAMP AC-6",
    [resource.address]
  )
}
```

---

### Audit and Accountability (AU)

FedRAMP AU controls require comprehensive, tamper-evident audit logging with defined retention and monitoring requirements.

| FedRAMP Control | Requirement Summary | Techstream DevSecOps Implementation |
|----------------|--------------------|------------------------------------|
| **AU-2** | Audit events — define what events must be logged | Pipeline audit log covers: deployments, approvals, policy overrides, access grants, secrets access |
| **AU-3** | Content of audit records — who, what, when, where, outcome | Structured JSON logging with timestamp, actor, resource, action, outcome |
| **AU-6** | Audit record review | SIEM alerting on anomalous pipeline behavior; automated log analysis |
| **AU-9** | Protection of audit information | Immutable log storage (WORM S3, Azure Immutable Blob, GCS Object Lock) |
| **AU-11** | Audit record retention | Minimum 90 days online; 1 year total retention enforced by IaC policy |
| **AU-12** | Audit record generation | All pipeline stages emit structured audit events; coverage is measured |

**Evidence automation for AU-11 (retention):**

```yaml
# Terraform — enforce S3 bucket retention policy for audit logs
resource "aws_s3_bucket_lifecycle_configuration" "audit_log_retention" {
  bucket = aws_s3_bucket.audit_logs.id

  rule {
    id     = "fedramp-au11-retention"
    status = "Enabled"

    # Keep logs for 1 year (FedRAMP AU-11 minimum)
    expiration {
      days = 365
    }

    # Transition to cheaper storage after 90 days (hot → warm)
    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }
  }
}

resource "aws_s3_bucket_object_lock_configuration" "audit_log_lock" {
  bucket = aws_s3_bucket.audit_logs.id

  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = 365
    }
  }
}
```

---

### Configuration Management (CM)

FedRAMP CM controls require that system configuration is defined, enforced, change-controlled, and auditable.

| FedRAMP Control | Requirement Summary | Techstream DevSecOps Implementation |
|----------------|--------------------|------------------------------------|
| **CM-2** | Baseline configuration | IaC as source of truth; all infrastructure defined in version-controlled Terraform/Bicep/CDK |
| **CM-3** | Configuration change control | PR-based change management; deployment gates require approval |
| **CM-6** | Configuration settings | CIS Benchmark enforcement via Checkov, OPA policies, and Kyverno admission controllers |
| **CM-7** | Least functionality | Container images built from minimal base images (distroless/scratch); unused ports/services removed |
| **CM-8** | Component inventory | SBOM generation on every build provides accurate component inventory |
| **CM-14** | Signed components | All artifacts signed with Cosign before deployment; signatures verified at admission |

**CM-8 SBOM as inventory evidence:**

The FedRAMP SSP requires a System Component Inventory (CM-8). Automated SBOM generation satisfies this requirement with audit-grade precision. Configure your SBOM pipeline to:
1. Generate a CycloneDX SBOM on every successful build
2. Store SBOMs in your artifact registry alongside the image digest
3. Export SBOMs to your GRC platform for SSP attachment
4. Alert when new components appear that are not in the approved component list

---

### Identification and Authentication (IA)

| FedRAMP Control | Requirement Summary | Techstream DevSecOps Implementation |
|----------------|--------------------|------------------------------------|
| **IA-2** | Identification and authentication (users) | MFA enforced for all console access; OIDC SSO for CI/CD platform |
| **IA-4** | Identifier management | Service account lifecycle managed via IaC; accounts deprovisioned on PR merge when removed from config |
| **IA-5** | Authenticator management | No long-lived credentials; workload identity federation (OIDC) for all pipeline-to-cloud auth |
| **IA-8** | Non-organizational users | External CI/CD service connections use short-lived tokens; scope limited to deployment operations |

**IA-5 implementation — workload identity (no secrets):**

```yaml
# GitHub Actions — OIDC to AWS (no AWS credentials stored)
- name: Configure AWS credentials via OIDC
  uses: aws-actions/configure-aws-credentials@v4
  with:
    role-to-assume: arn:aws:iam::ACCOUNT_ID:role/fedramp-deploy-role
    role-session-name: GitHubActions-${{ github.run_id }}
    aws-region: us-gov-west-1  # Use GovCloud regions for FedRAMP systems

# The IAM role trust policy restricts to your specific repository
# and branch — not all GitHub Actions workflows in your org
```

```json
// IAM Role trust policy (FedRAMP-scoped)
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::ACCOUNT_ID:oidc-provider/token.actions.githubusercontent.com"
    },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
        "token.actions.githubusercontent.com:sub": "repo:your-org/your-repo:ref:refs/heads/main"
      }
    }
  }]
}
```

---

### System and Information Integrity (SI)

| FedRAMP Control | Requirement Summary | Techstream DevSecOps Implementation |
|----------------|--------------------|------------------------------------|
| **SI-2** | Flaw remediation — patch within defined timeframes | Vulnerability SLA enforcement: Critical 7 days, High 30 days; tracked via Dependency-Track |
| **SI-3** | Malicious code protection | Container image scanning on every build; runtime malware detection (Falco) |
| **SI-4** | Information system monitoring | SIEM integration; alerting on anomalous pipeline events |
| **SI-7** | Software, firmware, and information integrity | Artifact signing (Cosign); signature verification at deployment; SLSA provenance |
| **SI-12** | Information management and retention | Artifact retention policies enforced via registry lifecycle rules |

**SI-2 flaw remediation evidence pipeline:**

FedRAMP assessors require evidence that vulnerabilities are remediated within defined SLAs. Automate this evidence chain:

1. Vulnerability scanner (Trivy/Grype) exports findings to Dependency-Track
2. Dependency-Track assigns severity and calculates SLA deadlines
3. Failed SLA deadlines trigger a JIRA/GitHub Issues ticket automatically
4. Remediation commit triggers re-scan; closure is logged with timestamps
5. Export the finding lifecycle (open → remediated) as evidence for AU-2/SI-2

---

## FedRAMP-Specific Pipeline Requirements

Beyond standard DevSecOps controls, FedRAMP introduces additional requirements on the pipeline infrastructure itself.

### Continuous Monitoring (ConMon)

FedRAMP authorization is not a point-in-time certification — it requires Continuous Monitoring (ConMon) with monthly deliverables to the authorizing official.

**Monthly ConMon deliverables:**

| Deliverable | Content | Automation Approach |
|------------|---------|---------------------|
| **Vulnerability scan report** | All vulnerabilities by severity with remediation status | Trivy/Qualys scan exports; Dependency-Track monthly report |
| **POA&M (Plan of Action and Milestones)** | Open vulnerabilities and weaknesses with remediation timelines | Auto-generated from DefectDojo/Dependency-Track open findings |
| **Inventory update** | Updated SBOM and component inventory | Automated SBOM generation on every release; delta report |
| **Incident log** | Security incidents detected and resolved | SIEM incident report; pipeline anomaly log |

**Automating the POA&M:**

```python
# Generate FedRAMP POA&M from Dependency-Track findings
import requests
from datetime import datetime, timedelta

DT_API_URL = "https://dependency-track.internal/api/v1"
DT_API_KEY = os.environ["DT_API_KEY"]

def generate_poam():
    response = requests.get(
        f"{DT_API_URL}/finding/project/{PROJECT_UUID}",
        headers={"X-Api-Key": DT_API_KEY},
        params={"suppressed": False}
    )
    findings = response.json()

    poam_entries = []
    for f in findings:
        severity = f["vulnerability"]["severity"]
        sla_days = {"CRITICAL": 30, "HIGH": 90, "MEDIUM": 180}.get(severity, 365)
        identified_date = datetime.fromisoformat(f["attribution"]["referenceUrl"])

        poam_entries.append({
            "weakness": f["vulnerability"]["vulnId"],
            "severity": severity,
            "asset": f["component"]["name"],
            "date_identified": identified_date.strftime("%Y-%m-%d"),
            "scheduled_completion": (identified_date + timedelta(days=sla_days)).strftime("%Y-%m-%d"),
            "milestones": f"Remediate {f['component']['name']} {f['component']['version']}",
            "status": "Ongoing"
        })

    return poam_entries
```

### FedRAMP Boundary Controls

FedRAMP requires a clearly defined authorization boundary. In cloud-native architectures, this manifests as:

1. **Data plane isolation:** Production workloads handling federal data must be isolated in a dedicated account/subscription/project with no shared infrastructure with commercial tenants.
2. **Management plane controls:** Console access, API access, and CI/CD pipeline access to the FedRAMP boundary must use PIV/CAC or FIPS 140-2 validated authentication where applicable.
3. **Data residency:** For most FedRAMP Moderate systems, data must remain in US regions. Use AWS GovCloud, Azure Government, or GCP FedRAMP-authorized regions.

**IaC enforcement — prevent deployment outside approved regions:**

```python
# OPA/Conftest — block deployment to non-FedRAMP regions
package fedramp.boundary

fedramp_approved_aws_regions := {
  "us-gov-west-1",
  "us-gov-east-1",
  "us-east-1",
  "us-east-2",
  "us-west-1",
  "us-west-2"
}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_instance"
  region := resource.change.after.availability_zone
  not any_match(region, fedramp_approved_aws_regions)
  msg := sprintf(
    "FedRAMP boundary violation: resource '%v' deployed to non-approved region '%v'",
    [resource.address, region]
  )
}
```

### FIPS 140-2 Cryptography

FedRAMP Moderate requires FIPS 140-2 validated cryptographic modules for protecting federal data. This affects:

- TLS libraries (use FIPS-validated OpenSSL or BoringCrypto builds)
- Container images (use FIPS-enabled base images; Red Hat UBI FIPS or AWS AL2 FIPS)
- Key management (use FIPS-validated HSMs or cloud KMS with FIPS endpoints)
- Secrets storage (AWS KMS in GovCloud uses FIPS 140-2 Level 3 HSMs)

**Pipeline check for FIPS base image:**

```yaml
# OPA policy — enforce FIPS-approved base images for FedRAMP workloads
package fedramp.fips

approved_base_images := {
  "registry.access.redhat.com/ubi8/ubi-minimal",
  "public.ecr.aws/amazonlinux/amazonlinux:2-with-sources",
  "mcr.microsoft.com/cbl-mariner/base/core"
}

deny[msg] {
  input.stage == "from"
  not approved_base_images[input.value]
  msg := sprintf(
    "FedRAMP FIPS requirement: base image '%v' is not an approved FIPS-compatible base. Use UBI8-minimal or Amazon Linux 2 FIPS.",
    [input.value]
  )
}
```

---

## FedRAMP System Security Plan (SSP) Integration

The SSP is the primary authorization artifact. It documents every control implementation with:
- **Control description** — what the control requires
- **Implementation status** — Implemented, Partially Implemented, Planned, or Not Applicable
- **Implementation details** — how the control is satisfied (with specific tool names, configuration references, and evidence pointers)
- **Evidence pointers** — links to artifacts that prove implementation (scan reports, configuration screenshots, policy documents)

**Mapping Techstream controls to SSP format:**

| Techstream Control | SSP Control Reference | Implementation Status | Evidence Pointer |
|-------------------|-----------------------|----------------------|-----------------|
| SAST on every PR (Semgrep) | SA-11(1) — Developer Testing | Implemented | CI/CD pipeline log; Semgrep scan reports in artifact registry |
| SCA + SBOM generation (Trivy) | SA-12, SR-3, CM-8 | Implemented | SBOM archive in artifact registry; Dependency-Track project export |
| Artifact signing (Cosign) | SI-7(6), CM-14 | Implemented | Sigstore Rekor transparency log entries; cosign verify output |
| Immutable audit logs (WORM S3) | AU-9 | Implemented | S3 Object Lock configuration; AWS Config compliance evidence |
| IaC policy enforcement (OPA) | CM-6, CM-7 | Implemented | OPA policy files in version control; CI/CD policy gate results |
| MFA for all console access | IA-2(1) | Implemented | AWS IAM Identity Center MFA enforcement policy |
| Secrets management (Vault/KMS) | SC-12, SC-28, IA-5 | Implemented | Vault audit log; no long-lived credentials in pipeline |

---

## FedRAMP Readiness Assessment Checklist

Use this checklist before engaging a 3PAO for a formal Readiness Assessment Report (RAR).

### Authorization Boundary
- [ ] System authorization boundary is documented and approved by ISSO
- [ ] All system components (in scope and out of scope) are inventoried
- [ ] Data flows across the boundary are mapped and approved
- [ ] Non-federal tenants are isolated from federal tenants at the infrastructure layer

### Documentation
- [ ] System Security Plan (SSP) is complete and covers all Moderate baseline controls
- [ ] Privacy Threshold Analysis (PTA) / Privacy Impact Assessment (PIA) is complete
- [ ] Incident Response Plan references FedRAMP IR reporting requirements
- [ ] Configuration Management Plan documents the IaC-as-source-of-truth approach
- [ ] Contingency Plan includes RTO/RPO commitments with backup/restore test evidence

### Technical Controls
- [ ] FIPS 140-2 validated cryptography is used for all federal data at rest and in transit
- [ ] MFA is enforced for all privileged accounts accessing the authorization boundary
- [ ] Audit logging covers all AU-2 event types with tamper-evident storage
- [ ] Vulnerability scanning runs on all components (OS, containers, application dependencies)
- [ ] SBOM generation is automated and covers all deployed artifacts
- [ ] Artifact signing and verification is enforced at deployment admission

### Continuous Monitoring
- [ ] Automated monthly vulnerability scan reports are configured
- [ ] POA&M generation from vulnerability findings is automated
- [ ] Inventory updates (SBOM delta) are generated on every release
- [ ] SIEM alerting is configured for FedRAMP-relevant security events
- [ ] Annual penetration test is scheduled with a FedRAMP-recognized 3PAO

---

## Cross-References

| Topic | Related Techstream Document |
|-------|----------------------------|
| NIST 800-53 control implementation | [Regulatory Controls Matrix](regulatory-controls-matrix.md) |
| Evidence collection automation | [Evidence Collection Automation](evidence-collection-automation.md) |
| Continuous compliance monitoring | [Framework Architecture](architecture.md) |
| Exception management | [Exception Management](exception-management.md) |
| Geographic and data residency requirements | [Geographic Compliance Guide](geographic-compliance.md) |
| Supply chain controls (SBOM, SLSA, signing) | [Software Supply Chain Security Framework](../../software-supply-chain-security-framework/docs/framework.md) |
| Pipeline security controls | [Secure CI/CD Reference Architecture](../../secure-ci-cd-reference-architecture/docs/framework.md) |
