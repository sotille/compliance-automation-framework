# Automated Evidence Collection and Audit Reporting

Manual evidence collection for compliance audits is a significant operational burden and a source of audit risk. Evidence collected manually is often inconsistent, incomplete, or collected near the audit date rather than continuously. Automated evidence collection eliminates these failure modes by treating compliance evidence as a continuous data stream rather than a point-in-time collection exercise.

This guide covers the architecture, implementation patterns, and operational practices for automated evidence collection across the compliance frameworks mapped in the [Regulatory Controls Matrix](regulatory-controls-matrix.md).

---

## Table of Contents

- [Evidence Collection Architecture](#evidence-collection-architecture)
- [Evidence Types and Collection Methods](#evidence-types-and-collection-methods)
- [Automated Evidence Pipeline](#automated-evidence-pipeline)
- [Evidence Immutability and Tamper-Evidence](#evidence-immutability-and-tamper-evidence)
- [Audit Artifact Packaging](#audit-artifact-packaging)
- [Continuous Compliance Reporting](#continuous-compliance-reporting)
- [Auditor Portal and Evidence Access](#auditor-portal-and-evidence-access)
- [Evidence Gap Detection](#evidence-gap-detection)
- [Framework-Specific Evidence Templates](#framework-specific-evidence-templates)

---

## Evidence Collection Architecture

### Design Principles

1. **Continuous over periodic** — evidence is collected at the time of the event, not retroactively before an audit. A pull request merge creates an access control review record at merge time, not when an auditor requests it six months later.

2. **Machine-readable first** — evidence stored in structured formats (JSON, YAML, CSV) can be queried, filtered, and reformatted for any auditor's reporting requirements. Evidence stored as PDFs or screenshots cannot.

3. **Source of truth traceability** — every evidence record includes a link to its authoritative source (CloudTrail event ID, GitHub commit SHA, pipeline run ID). Auditors can independently verify the evidence against the source system.

4. **Segregation of duty over the evidence store** — the system that generates evidence must be separate from the system that stores it. Personnel who can modify production systems must not be able to modify the evidence store for those systems.

5. **Defense-in-depth for evidence integrity** — cryptographic hashing, write-once storage, and audit log monitoring of the evidence store itself.

### Evidence Collection Reference Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                    Evidence Source Systems                           │
│  CI/CD Platforms  │  Cloud Providers  │  IAM Systems  │  SIEM/CSPM  │
└──────────┬────────┴─────────┬─────────┴───────┬───────┴──────┬──────┘
           │                  │                  │              │
           └──────────────────▼──────────────────▼──────────────┘
                              │
                   ┌──────────▼────────────┐
                   │  Evidence Collection  │
                   │      Pipeline         │
                   │  (Lambda/Cloud Run/   │
                   │   Argo Events)        │
                   └──────────┬────────────┘
                              │
              ┌───────────────▼───────────────────┐
              │      Evidence Store               │
              │  (S3 Object Lock / GCS WORM /     │
              │   Azure Blob immutable storage)   │
              └───────────────┬───────────────────┘
                              │
         ┌────────────────────▼─────────────────────────┐
         │          Compliance Database                 │
         │  (PostgreSQL / BigQuery)                     │
         │  - Evidence index and metadata               │
         │  - Control coverage tracking                 │
         │  - Gap detection                             │
         │  - Audit report generation                   │
         └──────────────────────────────────────────────┘
```

---

## Evidence Types and Collection Methods

### Category 1: Access Control Evidence

Access control is the most frequently tested area in SOC 2, ISO 27001, and PCI-DSS audits. Automate collection of:

| Evidence Item | Source System | Collection Frequency | Retention |
|---|---|---|---|
| IAM user and role inventory | AWS IAM / Azure AD / GCP IAM | Daily snapshot | 3 years |
| MFA enrollment status | IdP (Okta, Azure AD) | Daily | 3 years |
| Privileged access grants | IAM, PAM system | Event-driven (on change) | 7 years |
| Access review completion records | IGA system (Saviynt, SailPoint) | Quarterly | 7 years |
| Terminated user deprovisioning records | HRIS → IAM | Event-driven | 7 years |
| SSH key and API key inventory | GitHub, AWS, Azure, GCP | Daily | 3 years |

**Automated IAM evidence collection (AWS):**

```python
import boto3
import json
import hashlib
from datetime import datetime, timezone

def collect_iam_evidence(output_bucket: str) -> dict:
    iam = boto3.client("iam")
    s3 = boto3.client("s3")

    timestamp = datetime.now(timezone.utc).isoformat()

    # Collect users with MFA status
    paginator = iam.get_paginator("list_users")
    users = []
    for page in paginator.paginate():
        for user in page["Users"]:
            mfa_devices = iam.list_mfa_devices(UserName=user["UserName"])
            users.append({
                "username": user["UserName"],
                "arn": user["Arn"],
                "created": user["CreateDate"].isoformat(),
                "mfa_enabled": len(mfa_devices["MFADevices"]) > 0,
                "mfa_devices": len(mfa_devices["MFADevices"]),
                "password_last_used": user.get("PasswordLastUsed", "never"),
            })

    evidence = {
        "evidence_type": "iam_user_inventory",
        "collected_at": timestamp,
        "collector": "techstream-compliance-automation",
        "framework_controls": ["SOC2-CC6.1", "ISO27001-A.8.2", "PCI-DSS-8.2"],
        "data": users,
    }

    # Compute content hash for integrity verification
    content = json.dumps(evidence, sort_keys=True).encode()
    evidence["content_hash"] = hashlib.sha256(content).hexdigest()

    # Store to S3 with Object Lock
    key = f"access-control/iam-users/{datetime.now(timezone.utc).strftime('%Y/%m/%d')}/iam-user-inventory.json"
    s3.put_object(
        Bucket=output_bucket,
        Key=key,
        Body=json.dumps(evidence, indent=2),
        ContentType="application/json",
        ObjectLockMode="COMPLIANCE",
        ObjectLockRetainUntilDate=datetime(
            datetime.now().year + 7, 1, 1, tzinfo=timezone.utc
        ),
    )

    return {"key": key, "user_count": len(users)}
```

### Category 2: Change Management Evidence

Change management evidence demonstrates that production changes were authorized, tested, and reviewed before deployment. This maps to SOC 2 CC8.1, ISO 27001 A.8.32, and PCI-DSS 6.4.

**Automated change evidence from CI/CD:**

```yaml
# GitHub Actions job: generate change management evidence record on deployment
- name: Generate deployment evidence record
  if: github.ref == 'refs/heads/main'
  run: |
    EVIDENCE=$(cat << EOF
    {
      "evidence_type": "deployment_change_record",
      "service": "${{ env.SERVICE_NAME }}",
      "version": "${{ env.VERSION }}",
      "environment": "${{ env.TARGET_ENV }}",
      "deployed_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
      "deployed_by": "${{ github.actor }}",
      "commit_sha": "${{ github.sha }}",
      "commit_message": "${{ github.event.head_commit.message }}",
      "pr_number": "${{ github.event.pull_request.number }}",
      "pr_approvers": ${{ toJSON(github.event.pull_request.requested_reviewers) }},
      "pipeline_run_id": "${{ github.run_id }}",
      "pipeline_run_url": "${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}",
      "security_gates_passed": [
        "sast-semgrep",
        "sca-trivy",
        "secrets-gitleaks",
        "container-scan-trivy",
        "iac-checkov"
      ],
      "artifact_signed": true,
      "sbom_attached": true,
      "framework_controls": ["SOC2-CC8.1", "ISO27001-A.8.32", "PCI-DSS-6.4"]
    }
    EOF
    )

    # Upload to evidence store
    aws s3 cp - \
      "s3://${{ env.EVIDENCE_BUCKET }}/change-management/${{ env.SERVICE_NAME }}/$(date -u +%Y/%m/%d)/${{ github.run_id }}.json" \
      --content-type application/json \
      << EOF
    $EVIDENCE
    EOF
```

### Category 3: Vulnerability Management Evidence

Vulnerability management evidence demonstrates ongoing identification and remediation of security findings.

| Evidence Item | Collection Tool | Frequency |
|---|---|---|
| SAST scan results per release | Semgrep, CodeQL API | Per PR and release |
| SCA findings with severity and status | Trivy, Snyk, Dependency-Track | Per release |
| Container image scan results | Trivy, Grype | Per build |
| Vulnerability SLA compliance report | Dependency-Track, DefectDojo | Weekly |
| Patch compliance report | CSPM (Prowler, Security Hub) | Daily |
| Penetration test reports | Manual upload | Annually |

### Category 4: Incident Management Evidence

| Evidence Item | Source | Frequency |
|---|---|---|
| Incident records with timeline | PagerDuty, OpsGenie, JIRA | Event-driven |
| Post-mortem documents | Incident management platform | Per incident |
| Alert notification logs | SIEM | Continuous |
| Incident response SLA compliance | Incident platform API | Monthly report |

### Category 5: Configuration and Hardening Evidence

| Evidence Item | Source | Frequency |
|---|---|---|
| CIS Benchmark compliance results | Prowler, Scout Suite | Weekly |
| Cloud security posture findings | CSPM platform | Daily |
| Network access control configurations | Terraform state, CloudFormation | On change |
| Encryption configuration verification | Cloud provider APIs | Daily |
| Audit logging verification (CloudTrail/etc.) | Cloud provider APIs | Daily |

---

## Automated Evidence Pipeline

### Event-Driven Evidence Collection

Not all evidence should be collected on a schedule — some evidence is best collected at the time of the event:

```python
# AWS Lambda: event-driven IAM change evidence collector
import json
import boto3
import hashlib
from datetime import datetime, timezone

def handler(event, context):
    """
    Triggered by CloudTrail events via EventBridge.
    Captures IAM changes as immutable compliance evidence.
    """
    s3 = boto3.client("s3")
    detail = event["detail"]

    # Filter to high-compliance-relevance IAM events
    relevant_events = {
        "CreateUser", "DeleteUser", "AttachUserPolicy", "DetachUserPolicy",
        "CreateRole", "DeleteRole", "AttachRolePolicy", "DetachRolePolicy",
        "CreateAccessKey", "DeleteAccessKey", "EnableMFADevice", "DeactivateMFADevice",
        "AddUserToGroup", "RemoveUserFromGroup",
    }

    event_name = detail.get("eventName", "")
    if event_name not in relevant_events:
        return {"skipped": True, "reason": "non-compliance-relevant event"}

    evidence = {
        "evidence_type": "iam_change_event",
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "event_name": event_name,
        "event_time": detail.get("eventTime"),
        "event_id": detail.get("eventID"),
        "actor": detail.get("userIdentity", {}).get("arn"),
        "source_ip": detail.get("sourceIPAddress"),
        "request_parameters": detail.get("requestParameters", {}),
        "response_elements": detail.get("responseElements", {}),
        "cloudtrail_event_id": detail.get("eventID"),
        "framework_controls": [
            "SOC2-CC6.2", "SOC2-CC6.3", "ISO27001-A.8.2", "PCI-DSS-7.1"
        ],
    }

    content = json.dumps(evidence, sort_keys=True, default=str).encode()
    evidence["content_hash"] = hashlib.sha256(content).hexdigest()

    key = (
        f"access-control/iam-events/"
        f"{datetime.now(timezone.utc).strftime('%Y/%m/%d')}/"
        f"{detail.get('eventID')}.json"
    )

    s3.put_object(
        Bucket=os.environ["EVIDENCE_BUCKET"],
        Key=key,
        Body=json.dumps(evidence, indent=2, default=str),
        ContentType="application/json",
    )

    return {"collected": True, "key": key}
```

### Scheduled Evidence Collection

For evidence that requires periodic snapshots (configuration states, inventory), use scheduled collection:

```yaml
# Kubernetes CronJob: daily compliance evidence collection
apiVersion: batch/v1
kind: CronJob
metadata:
  name: compliance-evidence-collector
  namespace: compliance
spec:
  schedule: "0 2 * * *"   # Daily at 02:00 UTC
  jobTemplate:
    spec:
      template:
        spec:
          serviceAccountName: compliance-collector
          containers:
          - name: collector
            image: registry.example.com/compliance-collector:latest
            env:
            - name: EVIDENCE_BUCKET
              valueFrom:
                secretKeyRef:
                  name: evidence-store-config
                  key: bucket-name
            - name: FRAMEWORKS
              value: "soc2,iso27001,pci-dss"
            command:
            - /bin/collect-evidence
            - --frameworks=$(FRAMEWORKS)
            - --output-bucket=$(EVIDENCE_BUCKET)
            - --date=$(date -u +%Y-%m-%d)
          restartPolicy: OnFailure
```

---

## Evidence Immutability and Tamper-Evidence

### Object Lock Configuration (AWS S3)

```bash
# Create evidence bucket with Object Lock enabled
aws s3api create-bucket \
  --bucket compliance-evidence-prod \
  --region us-east-1 \
  --object-lock-enabled-for-bucket

# Configure default retention: 7-year compliance hold
aws s3api put-object-lock-configuration \
  --bucket compliance-evidence-prod \
  --object-lock-configuration '{
    "ObjectLockEnabled": "Enabled",
    "Rule": {
      "DefaultRetention": {
        "Mode": "COMPLIANCE",
        "Years": 7
      }
    }
  }'

# Deny all delete and retention modification actions
aws s3api put-bucket-policy \
  --bucket compliance-evidence-prod \
  --policy '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "DenyDeleteAndRetentionModification",
        "Effect": "Deny",
        "Principal": "*",
        "Action": [
          "s3:DeleteObject",
          "s3:DeleteObjectVersion",
          "s3:PutObjectRetention",
          "s3:BypassGovernanceRetention"
        ],
        "Resource": "arn:aws:s3:::compliance-evidence-prod/*"
      }
    ]
  }'
```

### Integrity Verification

Every evidence record must include a SHA-256 hash of its content. Periodically verify stored evidence has not been modified (even write-once storage can have integrity issues from corruption):

```python
# Evidence integrity verification job
import boto3
import json
import hashlib

def verify_evidence_integrity(bucket: str, prefix: str) -> list[dict]:
    s3 = boto3.client("s3")
    violations = []

    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            response = s3.get_object(Bucket=bucket, Key=obj["Key"])
            content = response["Body"].read()
            data = json.loads(content)

            stored_hash = data.pop("content_hash", None)
            computed_hash = hashlib.sha256(
                json.dumps(data, sort_keys=True).encode()
            ).hexdigest()

            if stored_hash != computed_hash:
                violations.append({
                    "key": obj["Key"],
                    "stored_hash": stored_hash,
                    "computed_hash": computed_hash,
                    "last_modified": obj["LastModified"].isoformat(),
                })

    return violations
```

---

## Audit Artifact Packaging

When an audit begins, auditors need specific evidence for specific control periods. Automated packaging reduces the preparation time from weeks to hours.

### Audit Package Structure

```
audit-package-SOC2-2025-Q4/
├── manifest.json                    # Package metadata, control mapping, file index
├── access-control/
│   ├── iam-user-inventory/          # Daily snapshots for audit period
│   ├── mfa-enrollment-reports/
│   ├── access-review-records/
│   └── privileged-access-logs/
├── change-management/
│   ├── deployment-records/          # All production deployments in period
│   ├── pr-approval-evidence/
│   └── change-advisory-board-records/
├── vulnerability-management/
│   ├── sast-scan-results/
│   ├── sca-reports/
│   ├── container-scan-results/
│   └── sla-compliance-reports/
├── incident-management/
│   ├── incident-records/
│   ├── post-mortems/
│   └── response-sla-reports/
└── configuration/
    ├── cis-benchmark-results/
    ├── encryption-verification/
    └── audit-logging-verification/
```

### Automated Audit Package Generator

```python
# audit_packager.py — Generate audit evidence package for a date range
import boto3
import json
import zipfile
import io
from datetime import date, timedelta
from pathlib import Path

def generate_audit_package(
    evidence_bucket: str,
    output_bucket: str,
    framework: str,           # "soc2", "iso27001", "pci-dss"
    period_start: date,
    period_end: date,
    audit_id: str,
) -> str:
    s3 = boto3.client("s3")

    # Define which evidence prefixes map to this framework
    framework_prefixes = {
        "soc2": [
            "access-control/",
            "change-management/",
            "vulnerability-management/",
            "incident-management/",
            "configuration/",
        ],
        "pci-dss": [
            "access-control/",
            "change-management/",
            "vulnerability-management/",
            "network-controls/",
            "encryption/",
            "logging/",
        ],
    }

    prefixes = framework_prefixes.get(framework, [])
    package_buffer = io.BytesIO()
    manifest = {
        "audit_id": audit_id,
        "framework": framework,
        "period_start": period_start.isoformat(),
        "period_end": period_end.isoformat(),
        "generated_at": date.today().isoformat(),
        "files": [],
    }

    with zipfile.ZipFile(package_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for prefix in prefixes:
            paginator = s3.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=evidence_bucket, Prefix=prefix):
                for obj in page.get("Contents", []):
                    # Filter to audit period by key date component
                    key = obj["Key"]
                    # Keys follow: prefix/YYYY/MM/DD/filename.json
                    try:
                        parts = key.split("/")
                        obj_date = date(int(parts[-4]), int(parts[-3]), int(parts[-2]))
                        if period_start <= obj_date <= period_end:
                            response = s3.get_object(Bucket=evidence_bucket, Key=key)
                            content = response["Body"].read()
                            zf.writestr(key, content)
                            manifest["files"].append({
                                "key": key,
                                "size": len(content),
                                "date": obj_date.isoformat(),
                            })
                    except (ValueError, IndexError):
                        pass  # Skip files that don't follow date-based key convention

        zf.writestr("manifest.json", json.dumps(manifest, indent=2))

    package_key = f"audit-packages/{framework}/{audit_id}/{audit_id}.zip"
    package_buffer.seek(0)
    s3.put_object(
        Bucket=output_bucket,
        Key=package_key,
        Body=package_buffer.read(),
        ContentType="application/zip",
    )

    return package_key
```

---

## Continuous Compliance Reporting

### Daily Control Status Dashboard Data

```sql
-- Daily control coverage report query (PostgreSQL)
WITH latest_evidence AS (
  SELECT DISTINCT ON (control_id, source_system)
    control_id,
    source_system,
    evidence_type,
    collected_at,
    status,
    evidence_key
  FROM compliance_evidence
  WHERE collected_at >= NOW() - INTERVAL '24 hours'
  ORDER BY control_id, source_system, collected_at DESC
),
control_coverage AS (
  SELECT
    c.control_id,
    c.framework,
    c.description,
    c.automation_status,
    COALESCE(le.status, 'NO_EVIDENCE') AS current_status,
    le.collected_at AS last_evidence_at,
    CASE
      WHEN le.collected_at IS NULL THEN 'MISSING'
      WHEN le.status = 'PASS' THEN 'COMPLIANT'
      WHEN le.status = 'FAIL' THEN 'NON_COMPLIANT'
      ELSE 'UNKNOWN'
    END AS compliance_status
  FROM controls c
  LEFT JOIN latest_evidence le ON c.control_id = le.control_id
)
SELECT
  framework,
  COUNT(*) AS total_controls,
  COUNT(*) FILTER (WHERE compliance_status = 'COMPLIANT') AS compliant,
  COUNT(*) FILTER (WHERE compliance_status = 'NON_COMPLIANT') AS non_compliant,
  COUNT(*) FILTER (WHERE compliance_status = 'MISSING') AS missing_evidence,
  ROUND(
    COUNT(*) FILTER (WHERE compliance_status = 'COMPLIANT') * 100.0 / COUNT(*), 1
  ) AS compliance_rate_pct
FROM control_coverage
GROUP BY framework
ORDER BY framework;
```

### Weekly Compliance Trend Report

```python
# Weekly compliance summary email/Slack report
def generate_weekly_report(db_conn, report_date: date) -> str:
    week_start = report_date - timedelta(days=7)

    # Query compliance trend
    cursor = db_conn.cursor()
    cursor.execute("""
        SELECT
            framework,
            DATE(measured_at) AS report_date,
            compliance_rate_pct,
            non_compliant_count,
            missing_evidence_count
        FROM daily_compliance_snapshots
        WHERE measured_at >= %s AND measured_at <= %s
        ORDER BY framework, report_date
    """, (week_start, report_date))

    rows = cursor.fetchall()
    frameworks = {}
    for row in rows:
        fw = row[0]
        frameworks.setdefault(fw, []).append({
            "date": row[1].isoformat(),
            "rate": float(row[2]),
            "non_compliant": row[3],
            "missing": row[4],
        })

    lines = [f"## Weekly Compliance Report — {report_date.isoformat()}\n"]
    for fw, data in sorted(frameworks.items()):
        latest = data[-1]
        prev = data[0] if len(data) > 1 else latest
        trend = "▲" if latest["rate"] > prev["rate"] else ("▼" if latest["rate"] < prev["rate"] else "→")
        lines.append(
            f"**{fw.upper()}**: {latest['rate']}% compliant {trend} "
            f"({latest['non_compliant']} findings, {latest['missing']} missing evidence)"
        )

    return "\n".join(lines)
```

---

## Auditor Portal and Evidence Access

### Access Model for Auditors

Auditors require read-only access to evidence with clear attribution and source traceability. Implement a dedicated audit access role:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AuditorReadOnlyEvidence",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket",
        "s3:GetObjectAttributes"
      ],
      "Resource": [
        "arn:aws:s3:::compliance-evidence-prod",
        "arn:aws:s3:::compliance-evidence-prod/*"
      ],
      "Condition": {
        "StringEquals": {
          "s3:prefix": ["audit-packages/"]
        }
      }
    },
    {
      "Sid": "DenyNonEvidenceAccess",
      "Effect": "Deny",
      "NotAction": [
        "s3:GetObject",
        "s3:ListBucket",
        "s3:GetObjectAttributes"
      ],
      "Resource": "*"
    }
  ]
}
```

### Evidence Request Workflow

When auditors request specific evidence not included in the pre-packaged audit bundle:

1. Auditor submits evidence request via audit management platform (Vanta, Drata, AuditBoard)
2. Automated workflow queries evidence store for matching records within the requested date range and control mapping
3. Evidence package is generated and a pre-signed URL is issued with 72-hour expiry
4. Access event is logged in the audit trail (who accessed which evidence, when)
5. Auditor reviews evidence through the pre-signed URL

---

## Evidence Gap Detection

Proactive gap detection ensures evidence collection failures are caught before an audit, not during.

```python
# Evidence gap detector: find controls with missing or stale evidence
from datetime import datetime, timezone, timedelta

EVIDENCE_FRESHNESS_REQUIREMENTS = {
    "iam_user_inventory": timedelta(hours=25),           # Daily with buffer
    "mfa_enrollment_report": timedelta(hours=25),
    "cis_benchmark_results": timedelta(days=8),          # Weekly with buffer
    "vulnerability_sla_report": timedelta(days=8),
    "access_review_completion": timedelta(days=95),      # Quarterly with buffer
}

def detect_evidence_gaps(db_conn) -> list[dict]:
    now = datetime.now(timezone.utc)
    gaps = []

    cursor = db_conn.cursor()
    for evidence_type, max_age in EVIDENCE_FRESHNESS_REQUIREMENTS.items():
        cursor.execute("""
            SELECT MAX(collected_at) FROM compliance_evidence
            WHERE evidence_type = %s
        """, (evidence_type,))
        last_collected = cursor.fetchone()[0]

        if last_collected is None:
            gaps.append({
                "evidence_type": evidence_type,
                "gap_type": "NEVER_COLLECTED",
                "last_collected": None,
                "age": None,
                "severity": "CRITICAL",
            })
        elif now - last_collected > max_age:
            age = now - last_collected
            gaps.append({
                "evidence_type": evidence_type,
                "gap_type": "STALE",
                "last_collected": last_collected.isoformat(),
                "age_hours": age.total_seconds() / 3600,
                "max_age_hours": max_age.total_seconds() / 3600,
                "severity": "HIGH" if age > max_age * 2 else "MEDIUM",
            })

    return gaps
```

---

## Framework-Specific Evidence Templates

### SOC 2 Type II Evidence Summary

For SOC 2 Type II audits (typically covering a 6–12 month period), auditors require evidence that controls operated **continuously** throughout the period, not just at the point of the audit. Automated continuous collection is the only practical way to satisfy this requirement at scale.

| Trust Service Criterion | Automated Evidence Required | Collection Frequency |
|---|---|---|
| CC6.1 — Logical access controls | IAM policy snapshots, MFA reports, network ACL configs | Daily |
| CC6.2 — User registration and authorization | SCIM provisioning logs, access request records | Event-driven |
| CC6.3 — Role-based access | Access review completion records, IAM role exports | Quarterly (reviews) + Daily (snapshots) |
| CC7.1 — Vulnerability management | Scan results, remediation tracking, SLA compliance | Per build + Weekly report |
| CC7.2 — Anomaly detection | SIEM alert configuration, coverage reports | Weekly |
| CC8.1 — Change management | Deployment records, PR approvals, pipeline gate results | Per deployment |
| CC9.1 — Risk management | Risk register snapshots, exception records | Monthly |
| A1.1 — Availability commitments | SLO compliance reports, uptime records | Daily |

### PCI-DSS v4.0 Evidence Summary

| Requirement | Automated Evidence | Frequency |
|---|---|---|
| 2.2 — System hardening | CIS benchmark results, configuration snapshots | Weekly |
| 6.3 — Security vulnerabilities identified and addressed | SAST/SCA scan results, patch records | Per build |
| 6.4 — Web-facing applications protected | WAF configuration, DAST results | Monthly |
| 7.2 — Access control systems | IAM inventory, RBAC configuration | Daily |
| 8.2 — User identification | User account inventory, MFA enforcement | Daily |
| 10.3 — Audit log protection | Log integrity configuration, access logs | Daily |
| 11.3 — External and internal vulnerability scanning | Scan results with required frequency evidence | Quarterly external; Monthly internal |

---

## Related Techstream Resources

- [Compliance Automation Framework — Regulatory Controls Matrix](regulatory-controls-matrix.md)
- [Compliance Automation Framework — Exception Management](exception-management.md)
- [Software Supply Chain Security — SBOM at Scale](../../software-supply-chain-security-framework/docs/sbom-at-scale.md)
- [Secure CI/CD Reference Architecture — Pipeline Forensics](../../secure-ci-cd-reference-architecture/docs/pipeline-forensics-playbook.md)
- [DevSecOps Maturity Model — Compliance and Audit Posture Metrics](../../devsecops-maturity-model/docs/metrics-kpis.md)
