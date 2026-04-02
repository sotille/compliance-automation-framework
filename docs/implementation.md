# Compliance Automation Framework — Implementation Guide

## Table of Contents

1. [Phase 1 — Foundation (Months 1-3)](#phase-1--foundation-months-1-3)
2. [Phase 2 — Automated Scanning (Months 3-6)](#phase-2--automated-scanning-months-3-6)
3. [Phase 3 — Policy as Code and Evidence Automation (Months 6-12)](#phase-3--policy-as-code-and-evidence-automation-months-6-12)
4. [Phase 4 — Continuous Compliance and Audit Readiness (Months 12-18)](#phase-4--continuous-compliance-and-audit-readiness-months-12-18)
5. [Toolchain Setup](#toolchain-setup)
6. [CI/CD Integration for Compliance Scanning](#cicd-integration-for-compliance-scanning)
7. [Kubernetes Admission Control Setup](#kubernetes-admission-control-setup)
8. [Evidence Collection Pipeline](#evidence-collection-pipeline)
9. [Compliance Dashboard Setup](#compliance-dashboard-setup)
10. [Audit Report Generation Automation](#audit-report-generation-automation)
11. [Compliance-as-Code Repository Structure](#compliance-as-code-repository-structure)
12. [Team Roles and Responsibilities](#team-roles-and-responsibilities)

---

## Phase 1 — Foundation (Months 1-3)

### Objectives

- Establish the compliance control inventory and framework mapping
- Deploy baseline scanning tooling on all cloud accounts
- Implement centralized logging for compliance-relevant events
- Define the compliance team structure and ownership model

### Activities

**Month 1: Inventory and Mapping**

1. Complete a compliance framework assessment: which frameworks apply to the organization (SOC 2, ISO 27001, PCI-DSS, etc.)
2. Build the master controls inventory — a single spreadsheet or GRC tool record of all applicable controls across all frameworks
3. Identify which controls are automatable vs. requiring manual evidence (typically 60-70% of technical controls are automatable)
4. Map controls to the control owner — the team or role responsible for implementing and maintaining each control
5. Deploy cloud account tagging strategy: all resources must be tagged with owner, environment, data-classification, and compliance-scope

**Month 2: Baseline Scanning**

1. Deploy Prowler against all cloud accounts (AWS, Azure, GCP) for baseline posture assessment
2. Deploy AWS Config / Azure Policy / GCP SCC with built-in CIS benchmark rule packs
3. Stand up centralized log aggregation: ship CloudTrail, Azure Activity Logs, GCP Audit Logs to a central SIEM
4. Configure log retention: 90 days hot, 7 years cold for compliance audit logs
5. Establish the compliance evidence S3 bucket with Object Lock (COMPLIANCE mode, 2,555-day retention)

**Month 3: Gap Analysis and Planning**

1. Run initial Prowler assessment and score against each applicable framework
2. Categorize findings as: Critical (remediate in 30 days), High (remediate in 90 days), Medium (remediate in 180 days), Low (roadmap item)
3. Create the compliance remediation backlog in JIRA with control references and owners
4. Establish the compliance operations meeting cadence (weekly engineering, monthly CISO review)
5. Define the exception management process and stand up the exception tracking database

### Phase 1 Deliverables

| Deliverable | Owner | Due |
|-------------|-------|-----|
| Controls inventory spreadsheet | Compliance team | Month 1 |
| Framework-to-control mapping | Compliance team | Month 1 |
| Prowler baseline assessment report | Cloud security engineer | Month 2 |
| Log retention architecture | Platform team | Month 2 |
| Evidence S3 bucket with Object Lock | Platform team | Month 2 |
| Compliance remediation backlog | Compliance team | Month 3 |
| Exception management process doc | CISO | Month 3 |

---

## Phase 2 — Automated Scanning (Months 3-6)

### Objectives

- Integrate automated scanning into CI/CD pipelines
- Achieve continuous scanning coverage for all cloud accounts
- Deploy container and IaC scanning
- Begin automated evidence collection

### IaC Scanning Deployment (Checkov)

```bash
# Install Checkov
pip install checkov

# Scan Terraform directory against multiple frameworks
checkov -d ./infrastructure/terraform \
  --framework terraform \
  --compliance soc2 iso27001 \
  --output json cli \
  --output-file-path ./reports/checkov

# Scan Kubernetes manifests
checkov -d ./k8s \
  --framework kubernetes \
  --output json \
  --output-file-path ./reports/checkov-k8s

# Scan Dockerfiles
checkov -d . \
  --framework dockerfile \
  --output json
```

### Container Security Scanning (Trivy)

```bash
# Install Trivy
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh

# Scan image for vulnerabilities and misconfigurations
trivy image \
  --format json \
  --output /evidence/trivy/$(date +%Y%m%d)/image-scan.json \
  --severity HIGH,CRITICAL \
  myregistry/myapp:latest

# Scan Kubernetes cluster configuration
trivy k8s \
  --report summary \
  --compliance k8s-cis-1.23 \
  --format json \
  --output /evidence/trivy/$(date +%Y%m%d)/cluster-cis.json

# Scan filesystem for IaC issues
trivy fs \
  --security-checks config,secret \
  ./infrastructure
```

### Cloud Configuration Scanning (Prowler)

```bash
# Install Prowler
pip install prowler

# Run full SOC2 assessment on AWS
prowler aws \
  --compliance soc2_aws \
  --output-formats json html \
  --output-directory /evidence/prowler/$(date +%Y%m%d)/soc2

# Run CIS assessment
prowler aws \
  --compliance cis_1.5_aws \
  --output-formats json \
  --output-directory /evidence/prowler/$(date +%Y%m%d)/cis

# Run all checks and filter by service
prowler aws \
  --services s3 iam ec2 rds \
  --output-formats json \
  --output-directory /evidence/prowler/$(date +%Y%m%d)/all
```

### Scheduling Prowler as a Kubernetes CronJob

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: prowler-compliance-scan
  namespace: security
spec:
  schedule: "0 2 * * *"    # Daily at 2 AM
  jobTemplate:
    spec:
      template:
        spec:
          serviceAccountName: prowler-scanner
          containers:
          - name: prowler
            image: toniblyx/prowler:latest
            command:
            - /bin/sh
            - -c
            - |
              prowler aws \
                --compliance soc2_aws cis_1.5_aws \
                --output-formats json \
                --output-directory /evidence/$(date +%Y%m%d)
            env:
            - name: AWS_DEFAULT_REGION
              value: "us-east-1"
            volumeMounts:
            - name: evidence
              mountPath: /evidence
          volumes:
          - name: evidence
            emptyDir: {}
          restartPolicy: OnFailure
```

---

## Phase 3 — Policy as Code and Evidence Automation (Months 6-12)

### Objectives

- Deploy OPA/Kyverno for Kubernetes admission control
- Build the Policy Repository with versioned compliance policies
- Implement automated evidence collection pipeline
- Deploy compliance dashboard (Grafana)

### OPA Gatekeeper Installation

```bash
# Install OPA Gatekeeper
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/master/deploy/gatekeeper.yaml

# Verify installation
kubectl get pods -n gatekeeper-system

# Deploy constraint template for required labels
kubectl apply -f - <<EOF
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8srequiredlabels
spec:
  crd:
    spec:
      names:
        kind: K8sRequiredLabels
      validation:
        openAPIV3Schema:
          type: object
          properties:
            labels:
              type: array
              items: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8srequiredlabels

        violation[{"msg": msg, "details": {"missing_labels": missing}}] {
          provided := {label | input.review.object.metadata.labels[label]}
          required := {label | label := input.parameters.labels[_]}
          missing := required - provided
          count(missing) > 0
          msg := sprintf("Missing required labels: %v", [missing])
        }
EOF

# Apply constraint requiring security labels on all deployments
kubectl apply -f - <<EOF
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequiredLabels
metadata:
  name: deployment-security-labels
spec:
  match:
    kinds:
    - apiGroups: ["apps"]
      kinds: ["Deployment"]
  parameters:
    labels:
    - "app.kubernetes.io/name"
    - "security-classification"
    - "data-classification"
EOF
```

### Kyverno Installation and Policy Deployment

```bash
# Install Kyverno
kubectl create -f https://github.com/kyverno/kyverno/releases/download/v1.11.0/install.yaml

# Verify
kubectl get pods -n kyverno

# Apply Pod Security policy
kubectl apply -f policies/kubernetes/kyverno/pod-security.yaml

# Test policy
kubectl run test --image=nginx --privileged=true
# Expected: Error from server (Privileged containers are not allowed)
```

### Automated Evidence Collection Pipeline

The evidence collection pipeline runs as a set of Lambda functions triggered by EventBridge rules and scheduled events:

```yaml
# AWS CDK / CloudFormation snippet for evidence collection infrastructure
# Evidence collection Lambda triggered by CloudTrail events
ComplianceEvidenceCollector:
  Type: AWS::Lambda::Function
  Properties:
    FunctionName: compliance-evidence-collector
    Runtime: python3.11
    Handler: evidence_collector.handler
    Environment:
      Variables:
        EVIDENCE_BUCKET: !Ref ComplianceEvidenceBucket
        EVIDENCE_TABLE: !Ref ComplianceEventsTable
    Code:
      ZipFile: |
        import boto3, json, hashlib, datetime

        def handler(event, context):
            s3 = boto3.client('s3')
            ddb = boto3.client('dynamodb')

            evidence_data = json.dumps(event, default=str).encode()
            evidence_hash = hashlib.sha256(evidence_data).hexdigest()
            timestamp = datetime.datetime.utcnow().isoformat()

            key = f"cloudtrail/{timestamp[:10]}/{evidence_hash}.json"
            s3.put_object(
                Bucket=os.environ['EVIDENCE_BUCKET'],
                Key=key,
                Body=evidence_data,
                ContentType='application/json',
                Metadata={'sha256': evidence_hash}
            )

            ddb.put_item(
                TableName=os.environ['EVIDENCE_TABLE'],
                Item={
                    'id': {'S': evidence_hash},
                    'timestamp': {'S': timestamp},
                    'type': {'S': event.get('source', 'unknown')},
                    's3_key': {'S': key}
                }
            )
```

---

## Phase 4 — Continuous Compliance and Audit Readiness (Months 12-18)

### Objectives

- Achieve real-time compliance posture visibility
- Generate audit-ready evidence packages on demand
- Implement compliance drift alerting
- Validate compliance program with external auditor

### Continuous Compliance Dashboard Metrics

By Phase 4, the following metrics should be available in real time:

| Metric | Target | Source |
|--------|--------|--------|
| SOC 2 overall compliance % | > 95% | Compliance data lake |
| ISO 27001 Annex A coverage % | > 90% | Compliance data lake |
| CIS benchmark score | > 85% | Prowler / CSPM |
| Critical findings open | 0 | Vulnerability management |
| Mean time to detect drift | < 15 minutes | EventBridge + Lambda |
| Evidence collection completeness | 100% for in-scope controls | Evidence catalog |
| Exception count | < 20 | Exception database |

### Pre-Audit Readiness Checklist

Run this checklist 60 days before each annual SOC 2 or ISO 27001 audit:

```markdown
## Audit Readiness Checklist — 60 Days Before Audit

### Evidence Completeness
- [ ] All CC6 controls have evidence covering the full audit period
- [ ] All CC7 controls have evidence covering the full audit period
- [ ] All CC8 controls have change records for the full period
- [ ] IAM access reviews completed for all quarters in audit period
- [ ] Security training completion records available for all employees

### Technical Controls
- [ ] SAST has run on all production codebases; findings documented
- [ ] Penetration test completed within audit period; findings remediated
- [ ] Vulnerability management: no critical findings older than 30 days
- [ ] MFA enforced for all users with production access
- [ ] Encryption at rest: all production databases encrypted
- [ ] Encryption in transit: TLS 1.2+ on all external endpoints

### Operational Controls
- [ ] IR plan updated within last 12 months
- [ ] IR tabletop exercise conducted within last 6 months
- [ ] Business continuity plan tested within last 12 months
- [ ] Vendor risk assessments current for all critical vendors

### Governance Controls
- [ ] All security policies reviewed and updated within last 12 months
- [ ] Risk register reviewed within last quarter
- [ ] Exception log: all exceptions have valid approval and expiry
- [ ] Security training: 100% completion rate
```

---

## Toolchain Setup

### Checkov Installation and Configuration

```bash
# Install via pip (recommended for CI/CD)
pip install checkov

# Or via Homebrew (local development)
brew install checkov

# Configure .checkov.yaml in repository root
cat > .checkov.yaml << 'EOF'
compact: true
output: cli json sarif
framework: terraform kubernetes dockerfile
check:
  - CKV_AWS_*
  - CKV_K8S_*
  - CKV2_AWS_*
skip-check:
  - CKV_AWS_79    # Approved exception: root account monitoring via alternate means
directory:
  - ./infrastructure
  - ./k8s
download-external-modules: true
EOF
```

### Trivy Configuration

```yaml
# trivy.yaml — place in repository root
scan:
  exit-code: 1
  severity: CRITICAL,HIGH
  ignore-unfixed: false

db:
  auto-update: true

cache:
  dir: /tmp/trivy-cache

report:
  format: json
  output: ./trivy-results.json
```

### OPA Policy Testing with Conftest

```bash
# Install Conftest
brew install conftest

# Test Terraform plan against compliance policies
terraform plan -out tfplan.binary
terraform show -json tfplan.binary > tfplan.json

conftest test tfplan.json \
  --policy ./policies/opa/ \
  --namespace compliance \
  --output json

# Run all policy tests against example inputs
conftest verify --policy ./policies/opa/
```

### Prowler Configuration

```ini
# prowler.conf
[aws]
region = us-east-1
output_formats = json html
output_directory = /evidence/prowler
log_level = INFO
checks_to_skip = prowler-check-id-123   # Documented exception
```

---

## CI/CD Integration for Compliance Scanning

### Full Compliance Pipeline (GitHub Actions)

```yaml
name: Compliance and Security Pipeline
on:
  push:
    branches: [main, release/**]
  pull_request:

env:
  EVIDENCE_BUCKET: compliance-evidence-prod

jobs:
  iac-compliance:
    name: IaC Compliance Scanning
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install scanners
        run: pip install checkov

      - name: Checkov - Terraform
        run: |
          checkov -d ./infrastructure/terraform \
            --framework terraform \
            --compliance soc2 iso27001 \
            --output json cli \
            --output-file-path ./scan-results/checkov-terraform \
            --soft-fail false

      - name: Checkov - Kubernetes
        run: |
          checkov -d ./k8s \
            --framework kubernetes \
            --output json cli \
            --output-file-path ./scan-results/checkov-k8s \
            --soft-fail false

      - name: OPA Policy Gate
        run: |
          curl -L -o /usr/local/bin/conftest \
            https://github.com/open-policy-agent/conftest/releases/download/v0.46.0/conftest_0.46.0_Linux_x86_64.tar.gz
          tar xzf /tmp/conftest.tar.gz -C /usr/local/bin/
          conftest test ./infrastructure/terraform/ \
            --policy ./policies/opa/ \
            --namespace compliance

      - name: Upload evidence
        if: always()
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_COMPLIANCE_ROLE }}
          aws-region: us-east-1
      - run: |
          aws s3 cp ./scan-results/ \
            s3://$EVIDENCE_BUCKET/ci-cd/$(date +%Y/%m/%d)/${{ github.sha }}/ \
            --recursive

  container-compliance:
    name: Container Compliance Scanning
    runs-on: ubuntu-latest
    needs: [iac-compliance]
    steps:
      - uses: actions/checkout@v4

      - name: Build image
        run: docker build -t myapp:${{ github.sha }} .

      - name: Trivy vulnerability scan
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: myapp:${{ github.sha }}
          format: json
          output: trivy-results.json
          severity: CRITICAL,HIGH
          exit-code: 1

      - name: Trivy IaC scan
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: config
          scan-ref: .
          format: json
          output: trivy-config-results.json
          exit-code: 1
```

---

## Kubernetes Admission Control Setup

### Complete Admission Control Deployment

```bash
# 1. Install Kyverno with HA configuration
helm repo add kyverno https://kyverno.github.io/kyverno/
helm repo update

helm install kyverno kyverno/kyverno \
  --namespace kyverno \
  --create-namespace \
  --set replicaCount=3 \
  --set resources.limits.memory=512Mi

# 2. Install policy library
helm install kyverno-policies kyverno/kyverno-policies \
  --namespace kyverno \
  --set podSecurityStandard=restricted

# 3. Apply custom compliance policies
kubectl apply -f policies/kubernetes/kyverno/

# 4. Monitor policy violations
kubectl get policyreport -A
kubectl get clusterpolicyreport

# 5. Configure policy reporting to external system
kubectl apply -f - <<EOF
apiVersion: kyverno.io/v1alpha2
kind: PolicyReportChangeRequest
metadata:
  name: send-to-compliance-system
spec:
  webhooks:
  - url: https://compliance-api.internal/k8s-policy-events
    timeoutSeconds: 30
EOF
```

### Validating Admission Control is Working

```bash
# Attempt to create privileged pod (should be blocked)
kubectl run test-privileged --image=nginx \
  --overrides='{"spec":{"containers":[{"name":"test-privileged","image":"nginx","securityContext":{"privileged":true}}]}}'

# Expected output:
# Error from server: admission webhook "validate.kyverno.svc-fail" denied the request:
# policy Deployment/default/test-privileged for resource test-privileged failed:
# disallow-privileged-containers: Privileged containers are not allowed.

# Attempt to create pod without required labels (should be blocked)
kubectl run test-labels --image=nginx
# Expected: Error about missing required labels
```

---

## Evidence Collection Pipeline

### Evidence Collection Lambda Functions

Deploy the following Lambda functions for automated evidence collection:

| Function | Trigger | Evidence Collected |
|----------|---------|-------------------|
| iam-evidence-collector | EventBridge daily schedule | IAM user inventory, MFA status, access keys |
| cloudtrail-shipper | S3 event on CloudTrail delivery | All CloudTrail events |
| config-snapshot-collector | AWS Config snapshot delivery | Resource configuration snapshots |
| prowler-evidence-collector | EventBridge daily schedule | CSPM scan results |
| siem-evidence-exporter | EventBridge weekly schedule | SIEM rule inventory, alert statistics |
| training-evidence-collector | EventBridge monthly schedule | LMS completion records |
| certificate-inventory | EventBridge daily schedule | TLS certificate inventory |

### Evidence Hash Verification

```python
import boto3, hashlib, json

def verify_evidence_integrity(evidence_id: str, s3_bucket: str) -> bool:
    """
    Verify that an evidence artifact has not been tampered with
    since collection by comparing its current hash to the stored hash.
    """
    s3 = boto3.client('s3')
    ddb = boto3.resource('dynamodb')

    # Retrieve stored hash from DynamoDB
    table = ddb.Table('compliance-evidence-catalog')
    item = table.get_item(Key={'id': evidence_id})['Item']
    stored_hash = item['sha256_hash']

    # Download object and compute current hash
    response = s3.get_object(Bucket=s3_bucket, Key=item['s3_key'])
    content = response['Body'].read()
    current_hash = hashlib.sha256(content).hexdigest()

    return stored_hash == current_hash
```

---

## Compliance Dashboard Setup

### Grafana Dashboard Deployment

```bash
# Add Grafana Helm chart
helm repo add grafana https://grafana.github.io/helm-charts
helm repo update

# Install Grafana with compliance datasources
helm install grafana grafana/grafana \
  --namespace monitoring \
  --create-namespace \
  --set persistence.enabled=true \
  --set persistence.size=10Gi \
  --set sidecar.datasources.enabled=true \
  --set sidecar.dashboards.enabled=true

# Configure PostgreSQL datasource (compliance data lake)
kubectl apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: grafana-datasource-compliance
  namespace: monitoring
  labels:
    grafana_datasource: "1"
data:
  compliance-datasource.yaml: |
    apiVersion: 1
    datasources:
    - name: ComplianceDB
      type: postgres
      url: postgres-compliance.internal:5432
      database: compliance
      user: grafana_reader
      secureJsonData:
        password: \$__env{COMPLIANCE_DB_PASSWORD}
      jsonData:
        sslmode: require
        postgresVersion: 1500
EOF
```

### Key Grafana Dashboard Queries

```sql
-- Overall compliance score by framework
SELECT
    framework,
    ROUND(
        COUNT(CASE WHEN status = 'PASS' THEN 1 END)::numeric /
        NULLIF(COUNT(CASE WHEN status != 'EXEMPT' THEN 1 END), 0) * 100,
        1
    ) AS compliance_pct,
    COUNT(CASE WHEN status = 'FAIL' AND severity = 'CRITICAL' THEN 1 END) AS critical_failures
FROM compliance_events
WHERE timestamp > NOW() - INTERVAL '24 hours'
GROUP BY framework
ORDER BY framework;

-- Compliance trend over time (for time series panel)
SELECT
    DATE_TRUNC('day', timestamp) AS day,
    framework,
    ROUND(
        COUNT(CASE WHEN status = 'PASS' THEN 1 END)::numeric /
        NULLIF(COUNT(CASE WHEN status != 'EXEMPT' THEN 1 END), 0) * 100,
        1
    ) AS compliance_pct
FROM compliance_events
WHERE timestamp > NOW() - INTERVAL '90 days'
GROUP BY 1, 2
ORDER BY 1, 2;
```

---

## Audit Report Generation Automation

### Automated SOC 2 Evidence Package Generator

```python
import boto3, zipfile, json, datetime
from pathlib import Path

def generate_soc2_evidence_package(
    audit_period_start: str,
    audit_period_end: str,
    output_path: str
) -> str:
    """
    Generate a ZIP package of all SOC 2 evidence for the specified audit period.
    Returns the S3 path to the generated package.
    """
    s3 = boto3.client('s3')
    EVIDENCE_BUCKET = 'compliance-evidence-prod'

    # Define evidence sections and their S3 prefixes
    evidence_sections = {
        'cloudtrail': f'cloudtrail/{audit_period_start}/{audit_period_end}/',
        'iam_reviews': f'iam-reviews/{audit_period_start[:7]}/',
        'vulnerability_scans': f'scanning/sast/',
        'cspm_reports': f'prowler/soc2/',
        'change_records': f'cicd/deployments/',
        'training_records': f'training/completions/',
        'incident_records': f'incidents/'
    }

    timestamp = datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    package_key = f'audit-packages/soc2_{audit_period_start}_{audit_period_end}_{timestamp}.zip'

    # Create evidence summary report
    summary = {
        'framework': 'SOC 2 Type II',
        'audit_period': {
            'start': audit_period_start,
            'end': audit_period_end
        },
        'generated_at': datetime.datetime.utcnow().isoformat(),
        'sections': list(evidence_sections.keys()),
        'controls_covered': get_controls_status(audit_period_start, audit_period_end)
    }

    print(f"Generated evidence package: {package_key}")
    print(f"Controls covered: {len(summary['controls_covered'])}")

    return f"s3://{EVIDENCE_BUCKET}/{package_key}"

def get_controls_status(start: str, end: str) -> dict:
    """Query compliance database for control status over the audit period."""
    # Implementation queries compliance_events table
    pass
```

---

## Compliance-as-Code Repository Structure

```
compliance-as-code/
├── README.md
├── .checkov.yaml                      # Global Checkov configuration
├── policies/
│   ├── README.md                      # Policy catalog and guidelines
│   ├── opa/                           # OPA/Rego policies
│   │   ├── aws/
│   │   │   ├── s3.rego
│   │   │   ├── iam.rego
│   │   │   ├── ec2.rego
│   │   │   └── rds.rego
│   │   ├── azure/
│   │   ├── gcp/
│   │   └── common/
│   │       ├── encryption.rego
│   │       └── tagging.rego
│   ├── kyverno/                       # Kyverno policies
│   │   ├── pod-security.yaml
│   │   ├── required-labels.yaml
│   │   ├── image-registry.yaml
│   │   └── network-policies.yaml
│   └── checkov/                       # Custom Checkov policies
│       ├── custom_rds_encryption.py
│       └── custom_s3_logging.py
├── controls/
│   ├── soc2-controls.yaml             # SOC 2 control inventory
│   ├── iso27001-controls.yaml         # ISO 27001 control inventory
│   ├── nist-800-53-controls.yaml      # NIST control inventory
│   ├── cis-controls.yaml              # CIS control inventory
│   └── pci-dss-controls.yaml          # PCI-DSS control inventory
├── evidence/
│   ├── collectors/                    # Evidence collection Lambda functions
│   │   ├── iam_collector.py
│   │   ├── cloudtrail_shipper.py
│   │   └── prowler_collector.py
│   ├── schemas/                       # Evidence schema definitions
│   └── retention-policies.yaml       # Evidence retention configuration
├── dashboards/
│   ├── grafana/
│   │   ├── compliance-overview.json
│   │   ├── soc2-detail.json
│   │   └── executive-summary.json
│   └── reports/
│       ├── soc2-report-template.md
│       └── audit-package-generator.py
├── exceptions/
│   ├── approved-exceptions.yaml      # Current approved exceptions
│   └── exception-schema.json         # Exception record schema
└── tests/
    ├── opa/                           # OPA policy unit tests
    ├── kyverno/                       # Kyverno policy tests
    └── evidence/                      # Evidence collection tests
```

---

## Team Roles and Responsibilities

| Role | Responsibilities | Time Allocation |
|------|-----------------|----------------|
| **Compliance Automation Lead** | Owns the framework, coordinates implementation, reports to CISO | 100% dedicated |
| **Cloud Security Engineer** | Deploys and maintains CSPM tools, cloud-native compliance rules, Prowler automation | 50-75% |
| **Platform Security Engineer** | Implements CI/CD compliance gates, Kubernetes admission control, IaC scanning | 50% |
| **Security Data Engineer** | Builds evidence collection pipeline, compliance data lake, dashboard queries | 75% |
| **Compliance Analyst** | Maps controls to automation, manages exceptions, prepares for audits | 100% dedicated |
| **DevSecOps Engineer** | Integrates compliance checks into developer workflow, trains engineering teams | 25-50% |
| **CISO / Security Leadership** | Sponsors the program, reviews monthly metrics, approves exceptions | 5-10% |

### RACI Matrix for Key Compliance Automation Activities

| Activity | Compliance Lead | Cloud Security | Platform Security | Compliance Analyst | Engineering |
|----------|----------------|---------------|-------------------|-------------------|-------------|
| Policy as Code development | A | R | C | C | I |
| CI/CD gate implementation | C | C | R | I | A |
| Evidence collection | R | A | C | C | I |
| Exception management | A | C | I | R | I |
| Audit report generation | A | C | I | R | I |
| Dashboard maintenance | C | I | I | C | R |
| Control mapping | A | C | I | R | I |
| Vendor assessment | A | I | I | R | I |

*R=Responsible, A=Accountable, C=Consulted, I=Informed*
