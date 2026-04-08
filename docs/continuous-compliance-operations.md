# Continuous Compliance Operations

## Overview

Compliance automation solves the evidence collection problem. Continuous compliance operations solves the harder problem: maintaining and demonstrating an improving compliance posture over time, across multiple frameworks, as infrastructure and software change continuously.

This document covers the operational model, metrics, reporting cadence, and tooling patterns for a compliance function that operates continuously rather than episodically.

---

## The Episode-to-Continuous Shift

Traditional compliance operates in episodes: a burst of activity before an annual audit, a period of remediation after findings, and a return to normal operations until the next audit cycle. This model has three structural deficiencies:

1. **Compliance debt accumulates invisibly.** Control drift is not detected until an auditor finds it. By then, the evidence gap may span months.
2. **Audit preparation consumes disproportionate resources.** The pre-audit sprint to collect evidence and remediate findings represents the failure of a continuous process.
3. **Compliance posture is unknown between audits.** Leadership cannot answer "are we compliant today?" with any accuracy.

Continuous compliance operations replaces the episode model with:
- Automated evidence collection on the schedule required by each control's evidence frequency requirement
- Continuous control scanning with drift detection and alerting
- Rolling compliance posture measurement updated on a defined cadence (daily for technical controls, weekly for procedural controls)
- Evergreen audit readiness: the evidence package for any audit should be assembling itself continuously, not produced in a pre-audit sprint

---

## Compliance Posture Metrics

### Primary Metrics

**Control Coverage Rate**
```
Control Coverage Rate = (Controls with automated evidence / Total in-scope controls) × 100
```
Target: ≥ 85% automated coverage for technical controls. Manual controls requiring human attestation are excluded from the denominator when calculating automated coverage, but included in the total control count for workload planning.

**Control Pass Rate**
```
Control Pass Rate = (Passing controls / Total in-scope controls) × 100
```
Track by framework (SOC 2, ISO 27001, PCI-DSS, etc.) and by domain (access control, cryptography, logging, etc.). A drop in pass rate for a specific domain signals a localized regression that automated scanning can pinpoint.

**Mean Time to Remediate (MTTR) by Severity**
```
MTTR = Average time from finding creation to finding closure, by severity tier
```
Target baselines (calibrate to your organization):
- Critical (CVSS ≥ 9.0, directly exploitable): ≤ 24 hours
- High: ≤ 7 days
- Medium: ≤ 30 days
- Low: ≤ 90 days

**Evidence Freshness Rate**
```
Evidence Freshness Rate = (Evidence items within required collection window / Total evidence items) × 100
```
Each control has an evidence frequency requirement (continuous, daily, weekly, monthly, quarterly, annual). Evidence is "fresh" if it was collected within the required window. Stale evidence is a compliance finding in itself.

**Finding Recurrence Rate**
```
Finding Recurrence Rate = (Findings reopened within 90 days of closure / Total findings closed) × 100
```
A high recurrence rate indicates that remediation addressed symptoms (the specific finding) rather than root causes (the underlying control weakness). Track recurrence by control domain and by team.

### Derived Metrics

**Compliance Risk Score**
A weighted aggregate combining: Control Pass Rate (40%), Evidence Freshness Rate (30%), Finding Recurrence Rate (20%), MTTR adherence (10%). Normalize to 0–100, where 100 is full compliance. Use as the primary executive KPI.

**Time-to-Audit-Ready**
Simulated audit: how long would it take to produce a complete evidence package for a surprise audit of a specific framework? Measure quarterly. Target: ≤ 2 business days for any in-scope framework.

---

## Continuous Scanning Architecture

### Scanning Tiers

Compliance scanning operates across three tiers with different tooling and evidence cadences:

**Tier 1 — Cloud Infrastructure (Continuous)**
Tool: Prowler, AWS Config, Azure Policy, GCP SCC
Cadence: Every 15–60 minutes (cloud-provider rule evaluation); Prowler full assessment daily
Evidence: JSON output per scan, stored in tamper-evident evidence bucket with Object Lock
Frameworks: SOC 2 CC6-7 (logical access), ISO 27001 A.8 (technology controls), PCI-DSS Req 2, 6, 7

**Tier 2 — Container and IaC (Per Commit + Daily)**
Tool: Checkov (IaC), Trivy (containers), Kyverno (runtime admission)
Cadence: Every pull request (IaC/container scanning); daily full-cluster scan
Evidence: SARIF output per scan, Kyverno admission controller logs
Frameworks: SOC 2 CC8 (change management), ISO 27001 A.8.8 (vulnerability management)

**Tier 3 — Application and Secrets (Per Commit + Weekly)**
Tool: Semgrep/SAST (application), Gitleaks/Trufflehog (secrets), DAST (weekly)
Cadence: Every pull request (SAST, secrets); weekly scheduled DAST
Evidence: SARIF output, secrets detection logs, DAST HTML/JSON report
Frameworks: SOC 2 CC7 (vulnerability management), PCI-DSS Req 6 (secure development)

### Evidence Storage Architecture

```
compliance-evidence/
├── {framework}/
│   ├── {control-id}/
│   │   ├── {YYYY-MM}/
│   │   │   ├── {YYYY-MM-DD}_{tool}_{scan-id}.json
│   │   │   └── metadata.json  # evidence metadata: collection date, tool version, collector identity
│   │   └── latest -> {YYYY-MM-DD}_{tool}_{scan-id}.json  # symlink to most recent
│   └── index.json  # control → evidence file mapping for auditor access
└── attestations/
    └── {YYYY-MM-DD}_{control-id}_{attestor}.json  # signed manual attestations
```

**Storage requirements:**
- AWS S3 with Object Lock (COMPLIANCE mode): evidence files are write-once, read-many
- Minimum retention: 7 years for SOC 2 and ISO 27001; 10 years for FedRAMP; 5 years for GDPR processing records
- Encryption: SSE-KMS with customer-managed key; key rotation annual minimum
- Access: compliance team read/write; auditors read-only via pre-signed URLs or dedicated IAM role; no delete permissions except via legal hold release process

### Compliance Event Pipeline

```
Cloud APIs / CI/CD Tools
         │
         ▼
  Scanning Tools (Prowler, Checkov, Trivy, etc.)
         │
         ▼
  Evidence Normalization Layer
  (convert tool output to common finding schema)
         │
    ┌────┴─────────────────────────────┐
    ▼                                  ▼
Evidence Bucket (S3 Object Lock)  Finding Database (DynamoDB/PostgreSQL)
                                       │
                                  ┌────┴──────────────────────┐
                                  ▼                            ▼
                         Compliance Dashboard           Alert Engine
                         (Grafana / AWS QuickSight)     (PagerDuty / OpsGenie)
```

**Finding Schema (normalized across all tools):**
```json
{
  "finding_id": "prowler-aws-iam-001-2026-04-08T14:30:00Z",
  "source_tool": "prowler",
  "source_version": "3.x",
  "scan_id": "scan-2026-04-08-daily",
  "framework": "SOC2",
  "control_id": "CC6.1",
  "resource_id": "arn:aws:iam::123456789012:user/example",
  "resource_type": "aws_iam_user",
  "severity": "HIGH",
  "status": "FAIL",
  "title": "IAM user has console access without MFA",
  "description": "...",
  "remediation": "...",
  "first_seen": "2026-04-08T14:30:00Z",
  "last_seen": "2026-04-08T14:30:00Z",
  "account_id": "123456789012",
  "region": "us-east-1",
  "tags": {"owner": "platform-team", "environment": "production"}
}
```

---

## Alerting and Escalation Model

### Alert Thresholds

Not every finding warrants a PagerDuty alert. Define alert thresholds by the severity and compliance risk of the finding:

| Condition | Severity | Response Time | Notification Channel |
|-----------|----------|---------------|---------------------|
| Critical finding in production | P1 | 15 min | PagerDuty (on-call) |
| High finding, production, frameworks in scope for upcoming audit | P2 | 4 hours | Slack #compliance-alerts |
| Control Pass Rate drops >5% vs. prior day | P2 | 4 hours | Slack #compliance-alerts |
| Evidence freshness failure (stale evidence for in-scope control) | P2 | 4 hours | Email to control owner |
| Medium finding in production | P3 | 7 days | JIRA ticket, weekly summary |
| Low finding or non-production | P4 | 30 days | Weekly digest |
| Finding recurrence (previously closed, reopened) | P2 bump | Previous SLA −50% | Slack to control owner + manager |

### Drift Detection Alerts

Infrastructure drift — where deployed resources diverge from IaC-defined state — requires specific alerting beyond generic finding alerts:

```yaml
# AWS Config rule: detect resources not managed by Terraform
# Implemented as a Lambda-backed custom Config rule
alert_conditions:
  - condition: "resource_created_outside_iac"
    severity: HIGH
    frameworks: [SOC2_CC6, ISO27001_A8]
    message: "Resource created without IaC state — potential unauthorized change"
    auto_remediate: false  # alert only; do not auto-delete
    escalate_to: security-team
  
  - condition: "config_drift_from_iac_state"
    severity: MEDIUM
    frameworks: [SOC2_CC8, PCI_DSS_Req12]
    message: "Resource configuration differs from IaC definition"
    auto_remediate: false
    escalate_to: platform-team
```

---

## Compliance Review Cadence

### Daily (Automated)
- Continuous scanning results ingested; new findings auto-triaged to JIRA
- Evidence collection jobs execute and write to evidence bucket
- Compliance dashboard updated
- P1/P2 alerts auto-routed to on-call and compliance team
- Evidence freshness check: flag any control with stale evidence

### Weekly (Engineering)
- Compliance operations meeting (30 min): review new High/Critical findings, confirm remediation timelines, unblock stuck findings
- Control Pass Rate trend review: identify domains regressing vs. prior week
- Finding age review: findings approaching SLA expiry escalated
- MTTR metric update

### Monthly (CISO-Level)
- Compliance Risk Score reported to CISO and engineering leadership
- Trend analysis: 3-month view of Control Pass Rate, MTTR, Evidence Freshness Rate, Finding Recurrence Rate
- Framework-by-framework posture summary
- Exception inventory review: all open exceptions revalidated for continued business justification
- Audit readiness simulation: measure Time-to-Audit-Ready for each in-scope framework

### Quarterly (Executive)
- Board-level compliance report: Compliance Risk Score trend, open High/Critical finding count, exception count, regulatory changes horizon
- Framework scope review: assess whether any new frameworks apply (new geographies, new product lines, new data types)
- Evidence retention audit: confirm retention policies are enforced, no evidence gap for any in-scope control
- External assessor relationship management: status of continuous monitoring agreements with auditors

### Annual
- Internal compliance audit: independent review of continuous compliance program by internal audit function
- Framework reassessment: re-scope each applicable framework against current business operations
- Tooling evaluation: assess whether current scanning tooling covers all in-scope controls; identify coverage gaps
- Evidence retention housekeeping: confirm records eligible for deletion are deleted per retention schedule

---

## Evidence Aging and Refresh Requirements

Evidence has a defined usable life for each control category. Evidence outside this window is stale and constitutes a compliance gap:

| Control Category | Evidence Frequency | Evidence Usable Life | Auto-collect? |
|---|---|---|---|
| Access reviews | Quarterly | 120 days | Partial (access list auto, review human) |
| MFA enforcement | Continuous | 24 hours | Yes (AWS Config/Prowler) |
| Encryption at rest | Continuous | 24 hours | Yes |
| Patch currency | Weekly | 7 days | Yes (Trivy, Grype) |
| Secrets rotation | Monthly | 35 days | Yes (AWS Secrets Manager) |
| Security training | Annual | 400 days | No (HR system attestation) |
| Penetration test | Annual | 400 days | No (external report) |
| Vendor risk assessment | Annual | 400 days | No (manual questionnaire) |
| Change approval records | Per change | N/A (immutable) | Yes (PR merge records) |
| Incident response testing | Annual | 400 days | No (tabletop documentation) |

**Freshness monitoring implementation (AWS Lambda + EventBridge):**
```python
import boto3
import json
from datetime import datetime, timedelta

def check_evidence_freshness(control_id: str, required_frequency_days: int) -> dict:
    """
    Check whether evidence for a control is within its required freshness window.
    Returns: {'control_id': str, 'status': 'FRESH'|'STALE', 'last_collected': datetime, 'age_days': int}
    """
    s3 = boto3.client('s3')
    evidence_prefix = f"compliance-evidence/{control_id}/"
    
    response = s3.list_objects_v2(
        Bucket='compliance-evidence-bucket',
        Prefix=evidence_prefix
    )
    
    if not response.get('Contents'):
        return {
            'control_id': control_id,
            'status': 'STALE',
            'last_collected': None,
            'age_days': None,
            'reason': 'No evidence found'
        }
    
    # Find most recent evidence object
    latest = max(response['Contents'], key=lambda x: x['LastModified'])
    last_collected = latest['LastModified'].replace(tzinfo=None)
    age_days = (datetime.utcnow() - last_collected).days
    
    return {
        'control_id': control_id,
        'status': 'FRESH' if age_days <= required_frequency_days else 'STALE',
        'last_collected': last_collected.isoformat(),
        'age_days': age_days,
        'required_frequency_days': required_frequency_days
    }
```

---

## Executive Compliance Reporting

### Compliance Risk Score Dashboard

The Compliance Risk Score (0–100) is the primary executive metric. Visualize as a gauge with traffic-light coloring:
- 90–100: Green (audit-ready)
- 75–89: Yellow (active remediation required)
- 60–74: Orange (significant gaps, escalate to CISO)
- Below 60: Red (material compliance risk, escalate to board)

### Monthly Executive Report Template

```
Compliance Posture Report — [Month YYYY]
Generated: [date]
Frameworks in scope: SOC 2 Type II, ISO 27001, PCI-DSS v4

COMPLIANCE RISK SCORE: [score]/100 ([change vs. prior month] vs. [prior month score])

CONTROL PASS RATE
  SOC 2:       [N]% ([N] controls passing / [N] total)
  ISO 27001:   [N]% ([N] controls passing / [N] total)
  PCI-DSS v4:  [N]% ([N] controls passing / [N] total)

OPEN FINDINGS (production, in-scope frameworks only)
  Critical:    [N] (target: 0; all require same-day action)
  High:        [N] (SLA: 7 days; [N] approaching SLA, [N] overdue)
  Medium:      [N] (SLA: 30 days; [N] approaching, [N] overdue)
  Low:         [N] (SLA: 90 days)

MTTR (30-DAY AVERAGE)
  Critical:    [N] hours (target: ≤ 24h)
  High:        [N] days (target: ≤ 7d)

OPEN EXCEPTIONS
  Total open:  [N] (all exceptions require revalidation by end of month)
  Expired:     [N] (immediate action required)

NEXT AUDIT: [Framework] — [date] — [N] days away
AUDIT READINESS: Time-to-Audit-Ready = [N] business days (target: ≤ 2)

KEY CHANGES THIS MONTH
  - [material control change 1]
  - [new finding category or trend]
  - [exception opened/closed]
```

---

## Integration with GRC Platforms

For organizations using a GRC platform (Vanta, Drata, Secureframe, Tugboat Logic, OneTrust), the evidence pipeline described above should feed the GRC platform rather than replace it. The GRC platform provides auditor access, evidence review workflows, and control testing scheduling. The scanning tools provide the automated evidence.

**Integration pattern:**
1. Scanning tools write evidence to S3 evidence bucket (tamper-evident storage)
2. A Lambda function processes new evidence files and calls the GRC platform API to create evidence records
3. The GRC platform stores the evidence link (S3 URL with pre-signed access) and marks the control's last evidence collection timestamp
4. Auditors access evidence through the GRC platform interface; actual evidence files remain in S3

**GRC platform API integration (Vanta example):**
```python
import requests
import boto3

def sync_evidence_to_grc(
    evidence_s3_key: str,
    control_id: str,
    framework: str,
    collected_at: str,
    vanta_api_key: str
) -> None:
    """
    Creates a pre-signed URL for the evidence file and registers it with Vanta.
    Pre-signed URL expires in 7 days — GRC platform should download and store internally.
    """
    s3 = boto3.client('s3')
    presigned_url = s3.generate_presigned_url(
        'get_object',
        Params={'Bucket': 'compliance-evidence-bucket', 'Key': evidence_s3_key},
        ExpiresIn=604800  # 7 days
    )
    
    # Vanta evidence upload API (illustrative — check current Vanta API docs)
    response = requests.post(
        'https://api.vanta.com/v1/evidence',
        headers={'Authorization': f'Bearer {vanta_api_key}'},
        json={
            'controlId': control_id,
            'framework': framework,
            'collectedAt': collected_at,
            'evidenceUrl': presigned_url,
            'evidenceType': 'automated_scan'
        }
    )
    response.raise_for_status()
```

---

## Common Failure Modes

**Evidence collection automation breaks silently.** A Lambda that collects Prowler output fails due to a permissions change, and evidence gaps accumulate for weeks without detection. Mitigation: monitor the freshness check Lambda independently; alert on evidence collection job failures via CloudWatch alarms, not only on finding severity.

**Control coverage rate conflated with compliance posture.** A team measures that 90% of controls have automated evidence collection and reports this as "90% compliant." Automated evidence collection measures process health, not control effectiveness — a Prowler scan that shows a control failing still generates evidence. Track Control Pass Rate and Control Coverage Rate as distinct metrics.

**Findings closed without verifying root cause.** A finding is marked resolved when the specific resource is remediated, but the process that created the misconfiguration (a Terraform module default, a misconfigured CI/CD template) is not fixed. Finding Recurrence Rate catches this when measured. Include root cause analysis as a closure requirement for High and Critical findings.

**Evidence retention policy not enforced technically.** The retention policy document specifies 7-year retention, but the S3 bucket lacks Object Lock, and evidence files are deleted accidentally or by cost-reduction scripts. Enforce retention technically, not only by policy: S3 Object Lock in COMPLIANCE mode prevents deletion regardless of permissions.

**Exception sprawl.** Exceptions accumulate over time and are never reviewed. Each exception represents a control weakness that has been accepted rather than remediated. Enforce a maximum exception lifetime (90–180 days for High-risk exceptions), require revalidation at expiry, and report exception count as an executive KPI.
