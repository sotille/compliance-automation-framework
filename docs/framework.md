# Compliance Automation Framework — Controls Framework

## Table of Contents

1. [SOC 2 Trust Service Criteria — Automated Controls Mapping](#soc-2-trust-service-criteria--automated-controls-mapping)
2. [ISO 27001:2022 Annex A Control Automation](#iso-270012022-annex-a-control-automation)
3. [NIST 800-53 Automation Coverage](#nist-800-53-automation-coverage)
4. [CIS Benchmark Automation](#cis-benchmark-automation)
5. [Automated Evidence Collection Catalog](#automated-evidence-collection-catalog)
6. [Policy as Code Patterns](#policy-as-code-patterns)
7. [Risk Management Automation](#risk-management-automation)
8. [Compliance Exception Management Workflow](#compliance-exception-management-workflow)
9. [Continuous Compliance Monitoring Rules](#continuous-compliance-monitoring-rules)

---

## SOC 2 Trust Service Criteria — Automated Controls Mapping

SOC 2 Trust Service Criteria (TSC) define the controls a service organization must demonstrate for a SOC 2 report. The table below maps each automatable TSC to its automated control implementation and evidence collection method.

### CC6 — Logical and Physical Access Controls

| Control | Description | Automation Method | Evidence Type |
|---------|-------------|------------------|--------------|
| CC6.1 | Logical access security measures to protect against threats from outside system boundaries | IAM policy scanning; MFA enforcement verification; network access control auditing | AWS Config rules: MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS; Prowler output |
| CC6.2 | Registration and authorization of new users before issuing credentials | IAM user creation audit log; provisioning workflow evidence | CloudTrail events: CreateUser, AttachUserPolicy; SCIM provisioning logs |
| CC6.3 | Role-based access control implementation | IAM role and policy configuration snapshots; quarterly access reviews | IAM policy exports; access review automation output |
| CC6.6 | Logical access measures against threats from outside system boundaries | Security group and firewall rule compliance; VPN verification | Security group scan results; network flow logs analysis |
| CC6.7 | Data transmission encryption | TLS configuration verification; encryption-in-transit policy compliance | Certificate scan results; SSL/TLS assessment reports |
| CC6.8 | Controls to prevent or detect introduction of unauthorized or malicious software | SAST/DAST results; dependency scanning; container image scanning | CI/CD scan outputs; vulnerability management reports |

### CC7 — System Operations

| Control | Description | Automation Method | Evidence Type |
|---------|-------------|------------------|--------------|
| CC7.1 | Vulnerability management procedures | Automated vulnerability scanning; patch compliance monitoring | SAST reports; dependency CVE scan results; CSPM findings |
| CC7.2 | Detection of anomalies and security events | SIEM alert configuration; anomaly detection rules; monitoring coverage | SIEM rule inventory; alert configuration snapshots; coverage reports |
| CC7.3 | Security event response procedures | IR playbook documentation; tabletop exercise records; SOAR configuration | Incident response records; post-mortem database; SOAR playbook configs |
| CC7.4 | Security incident communication procedures | Incident escalation automation; notification configuration | Incident notification logs; communication chain tests |
| CC7.5 | Post-incident review procedures | Post-mortem database; lessons-learned tracking | Post-mortem records; finding remediation tracking |

### CC8 — Change Management

| Control | Description | Automation Method | Evidence Type |
|---------|-------------|------------------|--------------|
| CC8.1 | Infrastructure and software changes are authorized and tested | CI/CD pipeline change gate records; approval workflow evidence | GitHub/GitLab merge records with approval evidence; pipeline run logs |

---

## ISO 27001:2022 Annex A Control Automation

ISO 27001:2022 Annex A contains 93 controls across four categories. The Technological controls (Section 8) have the highest automation potential.

| Control ID | Control Name | Automation Coverage | Implementation |
|-----------|-------------|---------------------|----------------|
| A.8.2 | Privileged access rights | Full | IAM privileged role inventory; JIT access logs; PAM session records |
| A.8.3 | Information access restriction | Full | IAM policy review automation; data access control verification |
| A.8.5 | Secure authentication | Full | MFA enforcement verification; password policy compliance; SSO coverage |
| A.8.7 | Protection against malware | Full | AV/EDR deployment verification; container image scanning; SAST results |
| A.8.8 | Management of technical vulnerabilities | Full | Vulnerability scan results; patch compliance; CVE remediation tracking |
| A.8.9 | Configuration management | Full | IaC scanning; configuration baseline drift detection; CSPM compliance |
| A.8.15 | Logging | Full | Logging coverage verification; log retention compliance; SIEM ingestion |
| A.8.16 | Monitoring activities | Full | SIEM configuration; alert coverage; monitoring dashboard |
| A.8.20 | Networks security | Full | Security group/NSG compliance; network segmentation verification |
| A.8.22 | Segregation of networks | Full | VPC/VNET segmentation verification; network policy compliance |
| A.8.24 | Use of cryptography | Full | Encryption-at-rest compliance; key management; TLS standards |
| A.8.25 | Secure development life cycle | Full | SAST/DAST pipeline integration evidence; security gate configuration |
| A.8.28 | Secure coding | Full | SAST findings; secure coding standard enforcement; code review coverage |
| A.8.29 | Security testing in development and acceptance | Full | DAST results; penetration test reports; security acceptance testing records |
| A.8.31 | Separation of development, test and production environments | Full | Environment access control verification; configuration difference analysis |
| A.8.32 | Change management | Full | Change approval records; CI/CD pipeline gate evidence |

---

## NIST 800-53 Automation Coverage

| Control Family | Abbrev | Controls | Automated | Partially | Manual Only |
|----------------|--------|----------|-----------|-----------|-------------|
| Access Control | AC | 25 | 18 | 5 | 2 |
| Audit and Accountability | AU | 16 | 15 | 1 | 0 |
| Configuration Management | CM | 14 | 12 | 2 | 0 |
| Contingency Planning | CP | 13 | 5 | 5 | 3 |
| Identification and Authentication | IA | 12 | 11 | 1 | 0 |
| Incident Response | IR | 10 | 7 | 2 | 1 |
| Risk Assessment | RA | 10 | 8 | 2 | 0 |
| System Acquisition | SA | 23 | 10 | 8 | 5 |
| System and Communications Protection | SC | 51 | 38 | 9 | 4 |
| System and Information Integrity | SI | 23 | 18 | 4 | 1 |
| Supply Chain Risk Management | SR | 12 | 8 | 3 | 1 |

**Key automated NIST 800-53 controls**:

- **AC-2 (Account Management)**: Automated IAM account inventory, orphaned account detection, privileged account review
- **AU-2 (Event Logging)**: Logging coverage matrix automated verification across all services
- **AU-9 (Protection of Audit Information)**: Log storage immutability verification, log access control compliance
- **CM-6 (Configuration Settings)**: CIS Benchmark compliance, baseline configuration drift detection
- **CM-7 (Least Functionality)**: Unnecessary service detection, open port scanning, default account review
- **IA-2 (Multi-Factor Authentication)**: MFA enforcement verification across all identity providers and access methods
- **RA-5 (Vulnerability Monitoring and Scanning)**: Vulnerability scan coverage, scan frequency compliance, finding age distribution
- **SC-8 (Transmission Confidentiality and Integrity)**: TLS configuration compliance, encryption-in-transit verification
- **SC-28 (Protection of Information at Rest)**: Encryption-at-rest compliance for all storage services
- **SI-2 (Flaw Remediation)**: Vulnerability remediation SLA compliance, patch status tracking

---

## CIS Benchmark Automation

### CIS AWS Foundations Benchmark

```bash
# Check 1.1: MFA for root account
aws iam get-account-summary | jq '.SummaryMap.AccountMFAEnabled'

# Check 1.4: No root access keys
aws iam get-account-summary | jq '.SummaryMap.AccountAccessKeysPresent'

# Check 2.1.1: S3 blocks public access per bucket
for bucket in $(aws s3api list-buckets --query 'Buckets[].Name' --output text); do
  aws s3api get-public-access-block --bucket "$bucket" 2>/dev/null \
    || echo "WARNING: $bucket has no public access block"
done

# Check 3.1: CloudTrail enabled in all regions
aws cloudtrail describe-trails --include-shadow-trails true \
  | jq '.trailList[] | select(.IsMultiRegionTrail == true)'
```

Prowler provides a unified wrapper for CIS checks across AWS, Azure, and GCP:

```bash
# Run full CIS AWS benchmark
prowler aws --compliance cis_1.5_aws \
  --output-formats json \
  --output-directory /evidence/cis/aws/$(date +%Y%m%d)

# Run CIS Azure benchmark
prowler azure --compliance cis_2.0_azure \
  --output-formats json \
  --output-directory /evidence/cis/azure/$(date +%Y%m%d)
```

### CIS Kubernetes Benchmark via kube-bench

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: kube-bench-compliance
  namespace: security
spec:
  template:
    spec:
      hostPID: true
      containers:
      - name: kube-bench
        image: aquasec/kube-bench:latest
        command: ["kube-bench", "--json", "--outputfile", "/output/results.json"]
        volumeMounts:
        - name: output
          mountPath: /output
      restartPolicy: Never
      volumes:
      - name: output
        emptyDir: {}
```

---

## Automated Evidence Collection Catalog

| Category | Evidence Item | Collection Frequency | Method | Retention |
|----------|--------------|---------------------|--------|-----------|
| **Access Control** | IAM user inventory | Daily | Cloud IAM API | 3 years |
| | MFA compliance status | Daily | IAM credential report | 3 years |
| | Access key age report | Daily | IAM credential report | 3 years |
| | Role/permission assignments | Weekly | IAM policy snapshot | 3 years |
| **Vulnerability Mgmt** | SAST scan results | Per CI/CD run | SAST tool output | 2 years |
| | Dependency vulnerability report | Per CI/CD run | SCA tool output | 2 years |
| | DAST scan results | Per release / Weekly | DAST tool output | 2 years |
| | Container image vulnerabilities | Per CI/CD run | Trivy / Grype output | 2 years |
| | Cloud misconfiguration report | Daily | Prowler / CSPM output | 3 years |
| **Change Management** | Deployment records | Per deployment | CI/CD pipeline logs | 3 years |
| | Approval records | Per change | SCM merge records | 3 years |
| | Infrastructure change log | Continuous | CloudTrail / Activity Log | 7 years |
| **Configuration** | CIS Benchmark results | Weekly | kube-bench / Prowler | 3 years |
| | IaC scan results | Per CI/CD run | Checkov output | 2 years |
| | Baseline configuration snapshot | Weekly | Cloud Config APIs | 3 years |
| **Logging & Monitoring** | Log coverage matrix | Weekly | Custom automation | 3 years |
| | SIEM rule inventory | Monthly | SIEM API export | 3 years |
| | Alert statistics | Monthly | SIEM reporting | 3 years |
| **Training** | Completion records | Monthly | LMS API export | 5 years |
| **Incidents** | Incident records | Per incident | SIEM / ticket system | 7 years |
| | Post-mortem records | Per incident | Document management | 7 years |
| **Encryption** | TLS certificate inventory | Daily | Certificate manager API | 3 years |
| | KMS key rotation compliance | Daily | KMS API | 3 years |

---

## Policy as Code Patterns

### Pattern 1: OPA Rego Policy for S3 Public Access

```rego
package compliance.aws.s3

import future.keywords.in

# Frameworks: SOC2-CC6.1, ISO27001-A.8.3, NIST-SC-28
deny[msg] {
    resource := input.resource.aws_s3_bucket[name]
    acl := resource.config.acl
    public_acls := {"public-read", "public-read-write", "authenticated-read"}
    acl in public_acls
    msg := sprintf(
        "S3 bucket '%v' has public ACL '%v'. SOC2:CC6.1 / ISO27001:A.8.3",
        [name, acl]
    )
}

deny[msg] {
    resource := input.resource.aws_s3_bucket_public_access_block[name]
    not resource.config.block_public_acls == true
    msg := sprintf(
        "S3 bucket '%v' does not block public ACLs. SOC2:CC6.1 / NIST:SC-28",
        [name]
    )
}
```

### Pattern 2: Kyverno Policy for Pod Security Context

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-security-context
  annotations:
    policies.kyverno.io/title: Require Security Context
    policies.kyverno.io/category: "CIS-5.2, SOC2-CC6.6, NIST-SC-28"
spec:
  validationFailureAction: enforce
  background: true
  rules:
    - name: require-run-as-non-root
      match:
        any:
        - resources:
            kinds: [Pod]
      validate:
        message: "Containers must run as non-root. CIS Benchmark 5.2.6."
        pattern:
          spec:
            containers:
              - securityContext:
                  runAsNonRoot: true
    - name: disallow-privileged-containers
      match:
        any:
        - resources:
            kinds: [Pod]
      validate:
        message: "Privileged containers are not allowed. CIS Benchmark 5.2.1."
        pattern:
          spec:
            containers:
              - =(securityContext):
                  =(privileged): "false"
    - name: require-read-only-root-filesystem
      match:
        any:
        - resources:
            kinds: [Pod]
      validate:
        message: "Root filesystem must be read-only. CIS Benchmark 5.2.4."
        pattern:
          spec:
            containers:
              - securityContext:
                  readOnlyRootFilesystem: true
```

### Pattern 3: CI/CD Compliance Gate (GitHub Actions)

```yaml
name: Compliance Gate
on: [push, pull_request]

jobs:
  compliance-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: IaC Compliance Scan
        run: |
          pip install checkov
          checkov -d ./infrastructure \
            --framework terraform \
            --compliance soc2 \
            --output sarif \
            --output-file-path ./compliance-results/checkov.sarif \
            --soft-fail false

      - name: OPA Policy Check
        run: |
          conftest test \
            --policy ./policies/ \
            --namespace compliance \
            ./infrastructure/terraform/

      - name: Container Compliance Scan
        run: |
          trivy image \
            --exit-code 1 \
            --severity CRITICAL,HIGH \
            --compliance soc2 \
            myregistry/myimage:${{ github.sha }}

      - name: Upload Evidence to S3
        if: always()
        run: |
          aws s3 cp ./compliance-results/ \
            s3://compliance-evidence/ci-cd/$(date +%Y/%m/%d)/${{ github.sha }}/ \
            --recursive
```

### Pattern 4: Checkov Custom Policy for RDS Encryption

```python
from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

class RDSEncryptionAtRestCheck(BaseResourceCheck):
    """Verify RDS instances have encryption at rest enabled.
    Frameworks: SOC2-CC6.1, ISO27001-A.8.24, NIST-SC-28
    """
    def __init__(self):
        name = "Ensure RDS database instance has encryption at rest enabled"
        id = "CKV_CUSTOM_RDS_1"
        supported_resources = ["aws_db_instance"]
        categories = [CheckCategories.ENCRYPTION]
        super().__init__(name=name, id=id,
                         categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        encrypted = conf.get("storage_encrypted", [False])
        if isinstance(encrypted, list):
            encrypted = encrypted[0]
        return CheckResult.PASSED if encrypted is True else CheckResult.FAILED

scanner = RDSEncryptionAtRestCheck()
```

---

## Risk Management Automation

### Automated Risk Scoring

Risk Score combines four factors:

```
Risk Score = Severity Weight × Framework Weight × Asset Criticality × Exploit Likelihood
```

| Component | Scale | Source |
|-----------|-------|--------|
| Severity Weight | CRITICAL=1.0, HIGH=0.8, MEDIUM=0.5, LOW=0.2 | Finding metadata |
| Framework Weight | PCI-DSS=1.2, SOC2=1.1, ISO27001=1.0, NIST=1.0, CIS=0.9 | Configured |
| Asset Criticality | 0.0–1.0 | CMDB |
| Exploit Likelihood | 0.0–1.0 | Threat intelligence feeds (CVE exploitability) |

### Risk Heat Map SQL Query

```sql
SELECT
    b.business_unit,
    c.framework,
    SUM(CASE
        WHEN c.severity = 'CRITICAL' THEN 10
        WHEN c.severity = 'HIGH'     THEN 5
        WHEN c.severity = 'MEDIUM'   THEN 2
        WHEN c.severity = 'LOW'      THEN 1
        ELSE 0
    END)                                             AS risk_score,
    COUNT(*)                                         AS finding_count,
    COUNT(CASE WHEN c.status = 'FAIL' THEN 1 END)   AS failing_controls
FROM compliance_events c
JOIN asset_registry a ON c.resource_id = a.resource_id
JOIN business_units  b ON a.owner_team  = b.team_id
WHERE c.timestamp > NOW() - INTERVAL '7 days'
GROUP BY b.business_unit, c.framework
ORDER BY risk_score DESC;
```

---

## Compliance Exception Management Workflow

When a compliant configuration cannot be achieved immediately, a formal exception process ensures the gap is tracked, risk-accepted, and time-bounded.

**Workflow Stages**:

1. **Submission** — Engineer submits exception request via JIRA/ServiceNow template, providing: Control ID, Resource ID, Business Justification, Compensating Controls, Requested Expiry Date
2. **Automated Triage** — System checks: Is the control exemptable? What is the asset risk score? Are there existing exceptions for this control?
3. **Risk-Based Routing** — CRITICAL findings route to CISO; HIGH to Security Architect; MEDIUM to Security Engineer; LOW to Team Lead
4. **Review and Decision** — Approver evaluates and decides: Approve / Deny / Request More Information
5. **Recording** — Approved exceptions recorded in compliance database with expiry date and compensating controls
6. **Reminders** — Automated notifications at 30 / 14 / 7 days before expiry to owner and manager
7. **Expiry Handling** — Expired exceptions auto-flag as compliance failures until renewed or remediated

### Exception Record Schema

```sql
CREATE TABLE compliance_exceptions (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    control_id            VARCHAR(100) NOT NULL,
    framework             VARCHAR(50)  NOT NULL,
    resource_id           VARCHAR(500),
    business_reason       TEXT         NOT NULL,
    compensating_controls TEXT,
    risk_acknowledged     BOOLEAN      NOT NULL DEFAULT false,
    requested_by          VARCHAR(255) NOT NULL,
    approved_by           VARCHAR(255),
    status                VARCHAR(20)  NOT NULL DEFAULT 'PENDING',
    created_at            TIMESTAMPTZ  DEFAULT NOW(),
    approved_at           TIMESTAMPTZ,
    expires_at            TIMESTAMPTZ  NOT NULL,
    review_ticket         VARCHAR(100)
);
```

---

## Continuous Compliance Monitoring Rules

### AWS EventBridge Rule: Security Group Changes

```json
{
  "source": ["aws.ec2"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventName": [
      "AuthorizeSecurityGroupIngress",
      "AuthorizeSecurityGroupEgress",
      "RevokeSecurityGroupIngress",
      "CreateSecurityGroup",
      "DeleteSecurityGroup"
    ]
  }
}
```

### Prometheus Compliance Alerting Rules

```yaml
groups:
  - name: compliance_alerts
    interval: 5m
    rules:
      - alert: ComplianceCriticalFailure
        expr: compliance_control_status{severity="CRITICAL",status="FAIL"} > 0
        for: 5m
        labels:
          severity: critical
          team: security
        annotations:
          summary: "Critical compliance control failing: {{ $labels.control_id }}"
          runbook: "https://wiki.internal/runbooks/compliance/{{ $labels.control_id }}"

      - alert: ComplianceDriftDetected
        expr: changes(compliance_control_status{status="FAIL"}[15m]) > 0
        for: 0m
        labels:
          severity: warning
        annotations:
          summary: "Compliance drift detected: {{ $labels.control_id }}"

      - alert: ComplianceScoreLow
        expr: compliance_framework_score < 80
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "{{ $labels.framework }} compliance score below 80%: {{ $value }}"
```

### Monitoring Thresholds Reference

| Metric | Warning | Critical | Automated Action |
|--------|---------|---------|-----------------|
| Framework compliance score | < 90% | < 80% | Alert + create JIRA ticket |
| Critical control failures | Any | Any | Immediate page to on-call |
| High control failures | > 10 | > 25 | Alert to security team |
| Exception expiry days remaining | 30 days | 7 days | Notification to owner + manager |
| Evidence age | 48 hours stale | 7 days stale | Alert + escalation |
| Compliance drift events per hour | > 5 | > 20 | Alert + auto-remediation attempt |
| Unapproved configuration changes | Any | Any | Alert + change rollback where safe |
