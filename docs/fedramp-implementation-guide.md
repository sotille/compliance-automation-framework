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

The POA&M generator below fetches open findings from Dependency-Track, calculates FedRAMP SLA deadlines by severity, creates or updates corresponding tickets in Jira, and exports the full POA&M as a CSV for submission to the authorizing official.

```python
#!/usr/bin/env python3
# conmon-poam-generator.py
# Generates FedRAMP POA&M from Dependency-Track and syncs to Jira
# Required env vars: DT_API_KEY, DT_API_URL, DT_PROJECT_UUID,
#                    JIRA_URL, JIRA_TOKEN, JIRA_PROJECT_KEY, JIRA_REPORTER_ID

import csv
import json
import os
import sys
import requests
from datetime import datetime, timedelta, date

DT_API_URL = os.environ["DT_API_URL"]
DT_API_KEY = os.environ["DT_API_KEY"]
PROJECT_UUID = os.environ["DT_PROJECT_UUID"]
JIRA_URL = os.environ["JIRA_URL"]
JIRA_TOKEN = os.environ["JIRA_TOKEN"]
JIRA_PROJECT_KEY = os.environ["JIRA_PROJECT_KEY"]
JIRA_REPORTER_ID = os.environ["JIRA_REPORTER_ID"]
OUTPUT_CSV = "poam-report.csv"

FEDRAMP_SLA_DAYS = {
    "CRITICAL": 30,
    "HIGH": 90,
    "MEDIUM": 180,
    "LOW": 365,
}

def get_open_findings():
    """Fetch all non-suppressed findings from Dependency-Track."""
    response = requests.get(
        f"{DT_API_URL}/finding/project/{PROJECT_UUID}",
        headers={"X-Api-Key": DT_API_KEY},
        params={"suppressed": False},
        timeout=30,
    )
    response.raise_for_status()
    return response.json()

def parse_identified_date(finding):
    """Extract the earliest known date the vulnerability was attributed."""
    # Prefer attribution date; fall back to today (conservative: never back-dates SLA)
    try:
        return datetime.fromisoformat(
            finding.get("attribution", {}).get("attributedOn", "")
        ).date()
    except (ValueError, TypeError):
        return date.today()

def get_or_create_jira_ticket(cve_id, component, severity, scheduled_completion):
    """Create a Jira ticket for the POA&M item if one does not already exist."""
    jira_headers = {
        "Authorization": f"Bearer {JIRA_TOKEN}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    # Search for existing open ticket for this CVE + component combination
    jql = (
        f'project = "{JIRA_PROJECT_KEY}" '
        f'AND summary ~ "{cve_id}" '
        f'AND summary ~ "{component}" '
        f'AND statusCategory != Done'
    )
    search_response = requests.get(
        f"{JIRA_URL}/rest/api/3/search",
        headers=jira_headers,
        params={"jql": jql, "maxResults": 1},
        timeout=15,
    )
    search_response.raise_for_status()
    issues = search_response.json().get("issues", [])

    if issues:
        ticket_key = issues[0]["key"]
        ticket_status = issues[0]["fields"]["status"]["name"]
        return ticket_key, "existing", ticket_status

    # Create new ticket
    create_payload = {
        "fields": {
            "project": {"key": JIRA_PROJECT_KEY},
            "summary": f"[FedRAMP POA&M] {cve_id} in {component}",
            "description": {
                "type": "doc",
                "version": 1,
                "content": [
                    {
                        "type": "paragraph",
                        "content": [
                            {
                                "type": "text",
                                "text": (
                                    f"FedRAMP POA&M remediation required.\n"
                                    f"CVE: {cve_id}\n"
                                    f"Severity: {severity}\n"
                                    f"Scheduled completion: {scheduled_completion}\n"
                                    f"SLA basis: FedRAMP Moderate vulnerability management SLA."
                                ),
                            }
                        ],
                    }
                ],
            },
            "issuetype": {"name": "Security Vulnerability"},
            "priority": {"name": "Critical" if severity == "CRITICAL" else "High"},
            "reporter": {"id": JIRA_REPORTER_ID},
            "duedate": str(scheduled_completion),
            "labels": ["fedramp", "poam", "conmon"],
        }
    }
    create_response = requests.post(
        f"{JIRA_URL}/rest/api/3/issue",
        headers=jira_headers,
        json=create_payload,
        timeout=15,
    )
    create_response.raise_for_status()
    ticket_key = create_response.json()["key"]
    return ticket_key, "created", "Open"

def check_jira_closure(ticket_key):
    """Return True if the Jira ticket is closed (Done status category)."""
    jira_headers = {"Authorization": f"Bearer {JIRA_TOKEN}", "Accept": "application/json"}
    response = requests.get(
        f"{JIRA_URL}/rest/api/3/issue/{ticket_key}",
        headers=jira_headers,
        params={"fields": "status"},
        timeout=10,
    )
    if response.status_code != 200:
        return False
    category = response.json()["fields"]["status"]["statusCategory"]["key"]
    return category == "done"

def generate_poam():
    findings = get_open_findings()
    poam_entries = []
    sla_breaches = []
    today = date.today()

    for f in findings:
        severity = f["vulnerability"]["severity"].upper()
        cve_id = f["vulnerability"].get("vulnId", "UNKNOWN")
        component = f"{f['component']['name']}@{f['component'].get('version', 'unknown')}"
        identified_date = parse_identified_date(f)
        sla_days = FEDRAMP_SLA_DAYS.get(severity, 365)
        scheduled_completion = identified_date + timedelta(days=sla_days)
        days_overdue = (today - scheduled_completion).days

        # Sync to Jira
        ticket_key, ticket_action, ticket_status = get_or_create_jira_ticket(
            cve_id, component, severity, scheduled_completion
        )

        # Check if Jira ticket is closed (indicates remediation complete)
        if check_jira_closure(ticket_key):
            poam_status = "Completed"
        elif days_overdue > 0:
            poam_status = "Delayed"
            sla_breaches.append((cve_id, component, severity, days_overdue, ticket_key))
        else:
            poam_status = "Ongoing"

        poam_entries.append({
            "POA&M ID": f"POAM-{len(poam_entries) + 1:04d}",
            "Weakness/CVE": cve_id,
            "Weakness Description": f["vulnerability"].get("title", ""),
            "Severity": severity,
            "Affected Asset": component,
            "Date Identified": str(identified_date),
            "Scheduled Completion": str(scheduled_completion),
            "Milestones": f"Upgrade {f['component']['name']} to patched version; verify via re-scan",
            "Status": poam_status,
            "Jira Ticket": ticket_key,
        })

    # Export CSV for submission
    with open(OUTPUT_CSV, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=poam_entries[0].keys())
        writer.writeheader()
        writer.writerows(poam_entries)

    print(f"POA&M generated: {len(poam_entries)} entries written to {OUTPUT_CSV}")

    # Alert on SLA breaches
    if sla_breaches:
        print(f"\nALERT: {len(sla_breaches)} FedRAMP SLA breaches detected:")
        for cve, comp, sev, days, ticket in sla_breaches:
            print(f"  {cve} | {comp} | {sev} | {days} days overdue | Jira: {ticket}")
        sys.exit(1)  # Fail CI to force escalation

if __name__ == "__main__":
    generate_poam()
```

**ConMon deliverable pipeline (GitHub Actions — scheduled monthly):**

```yaml
# .github/workflows/fedramp-conmon.yml
name: FedRAMP Continuous Monitoring — Monthly Deliverables

on:
  schedule:
    - cron: '0 6 1 * *'   # First day of each month at 06:00 UTC
  workflow_dispatch:        # Allow manual trigger for ad-hoc reporting

jobs:
  generate-conmon-package:
    runs-on: ubuntu-latest
    permissions:
      id-token: write   # For OIDC authentication to AWS (artifact upload)
      contents: read

    steps:
      - uses: actions/checkout@v4

      - name: Configure AWS credentials (OIDC)
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::<ACCOUNT>:role/fedramp-conmon-role
          aws-region: us-gov-west-1  # GovCloud for FedRAMP systems

      - name: Run vulnerability scans across all production artifacts
        run: |
          # Pull current production SBOM inventory from Dependency-Track
          python scripts/export-sbom-inventory.py > sbom-inventory.json
          # Run Trivy against all production images listed in inventory
          python scripts/scan-production-images.py --input sbom-inventory.json \
            --output trivy-results.json

      - name: Generate POA&M and sync to Jira
        env:
          DT_API_URL: ${{ secrets.DT_API_URL }}
          DT_API_KEY: ${{ secrets.DT_API_KEY }}
          DT_PROJECT_UUID: ${{ secrets.DT_PROJECT_UUID }}
          JIRA_URL: ${{ secrets.JIRA_URL }}
          JIRA_TOKEN: ${{ secrets.JIRA_TOKEN }}
          JIRA_PROJECT_KEY: ${{ secrets.JIRA_PROJECT_KEY }}
          JIRA_REPORTER_ID: ${{ secrets.JIRA_REPORTER_ID }}
        run: python scripts/conmon-poam-generator.py

      - name: Generate inventory delta (SBOM diff vs. prior month)
        run: |
          python scripts/sbom-delta.py \
            --prior s3://fedramp-evidence/conmon/$(date -d 'last month' +%Y-%m)/sbom-inventory.json \
            --current sbom-inventory.json \
            --output inventory-delta.csv

      - name: Compile ConMon evidence package
        run: |
          MONTH=$(date +%Y-%m)
          mkdir -p conmon-package-${MONTH}
          cp poam-report.csv conmon-package-${MONTH}/
          cp trivy-results.json conmon-package-${MONTH}/
          cp inventory-delta.csv conmon-package-${MONTH}/
          cp scripts/incident-log-export.json conmon-package-${MONTH}/  # Pulled from SIEM
          tar -czf conmon-package-${MONTH}.tar.gz conmon-package-${MONTH}/

      - name: Archive ConMon package to FedRAMP evidence bucket (Object Lock)
        run: |
          MONTH=$(date +%Y-%m)
          aws s3api put-object \
            --bucket fedramp-compliance-evidence \
            --key "conmon/${MONTH}/conmon-package-${MONTH}.tar.gz" \
            --body conmon-package-${MONTH}.tar.gz \
            --object-lock-mode COMPLIANCE \
            --object-lock-retain-until-date "$(date -d '+3 years' --iso-8601=seconds)"

      - name: Notify ISSO of ConMon package availability
        if: always()
        run: |
          # Post to the ISSO notification channel
          python scripts/notify-isso.py \
            --month "$(date +%Y-%m)" \
            --s3-uri "s3://fedramp-compliance-evidence/conmon/$(date +%Y-%m)/" \
            --sla-breaches "${{ steps.poam.outcome == 'failure' && 'YES' || 'NO' }}"
```

**ConMon closure verification loop:**

FedRAMP requires evidence that POA&M items are remediated, not just tracked. Close the loop by verifying that resolved Jira tickets correspond to passing re-scans:

```bash
# Run after deploying a patched artifact — verify the CVE no longer appears
cve_id="CVE-2021-44228"
image_digest="myregistry.io/payment-service@sha256:b4g9..."

# Re-scan with Grype
grype "$image_digest" --output json | \
  jq --arg cve "$cve_id" '.matches[] | select(.vulnerability.id == $cve)' \
  && echo "FAIL: $cve_id still present in $image_digest" && exit 1 \
  || echo "PASS: $cve_id not found in $image_digest — POA&M item ready to close"
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
