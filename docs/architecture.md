# Compliance Automation Framework — Architecture

## Table of Contents

1. [High-Level Architecture Overview](#high-level-architecture-overview)
2. [Policy as Code Architecture](#policy-as-code-architecture)
3. [Infrastructure Compliance Scanning Architecture](#infrastructure-compliance-scanning-architecture)
4. [Continuous Compliance Monitoring Pipeline](#continuous-compliance-monitoring-pipeline)
5. [Audit Evidence Collection System Design](#audit-evidence-collection-system-design)
6. [Compliance Data Lake Architecture](#compliance-data-lake-architecture)
7. [Dashboard and Reporting Architecture](#dashboard-and-reporting-architecture)

---

## High-Level Architecture Overview

The Techstream Compliance Automation Framework is organized as a four-layer architecture: Policy Engine, Scan Engine, Evidence Collector, and Audit Dashboard. Each layer has distinct responsibilities and interfaces, enabling independent scaling and replacement of components.

```
+------------------------------------------------------------------+
|                    AUDIT DASHBOARD LAYER                          |
|  Grafana Dashboards  |  Compliance Reports  |  Executive Views   |
+------------------------------------------------------------------+
           |                    |                    |
+------------------------------------------------------------------+
|                  EVIDENCE COLLECTOR LAYER                         |
|  Cloud Audit Logs  |  Scan Results  |  Change Records  |  SBOMs  |
|           Immutable Evidence Store (S3/Blob + Hash)               |
+------------------------------------------------------------------+
           |                    |                    |
+------------------------------------------------------------------+
|                    SCAN ENGINE LAYER                              |
|  CSPM Scanners   |  IaC Scanners  |  Container Scanners          |
|  (Prowler, Checkov, Trivy, AWS Config, Azure Policy, GCP SCC)    |
+------------------------------------------------------------------+
           |                    |                    |
+------------------------------------------------------------------+
|                    POLICY ENGINE LAYER                            |
|  OPA/Rego Policies  |  Kyverno Policies  |  Pipeline Gates       |
|           Policy Repository (Git-backed, versioned)               |
+------------------------------------------------------------------+
           |                    |
+------------------------------------------------------------------+
|                  INFRASTRUCTURE & APPLICATIONS                    |
|  Cloud Resources  |  Kubernetes  |  CI/CD Pipelines  |  Code     |
+------------------------------------------------------------------+
```

### Layer Responsibilities

**Policy Engine Layer**: Defines what "compliant" means in executable form. Policies are stored in a Git repository (the Policy Repository) and versioned alongside infrastructure code. Changes to policies go through pull request review and automated testing before deployment. The policy engine enforces these definitions at multiple points: Kubernetes admission (preventing non-compliant resources from being created), CI/CD pipeline gates (preventing non-compliant code or infrastructure from being deployed), and continuous assessment (evaluating existing resources against current policy).

**Scan Engine Layer**: Evaluates the current state of infrastructure, code, and configurations against the policies defined in the Policy Engine layer. Scanners run continuously (for cloud resources) and on each change (for code and infrastructure-as-code). Scan results feed into the Evidence Collector and the Dashboard.

**Evidence Collector Layer**: Captures and preserves all compliance-relevant events, configurations, and scan results in an immutable, tamper-evident store. Evidence is hashed on ingestion and verified on retrieval to detect tampering. Retention policies ensure evidence is available for the full audit period plus legally required retention periods.

**Audit Dashboard Layer**: Presents compliance posture in real time to security teams, compliance officers, and executive leadership. Generates audit-ready reports on demand. Provides drill-down capability from high-level compliance scores to specific failing controls and their remediation status.

---

## Policy as Code Architecture

### OPA and Rego

Open Policy Agent (OPA) is a general-purpose policy engine that evaluates queries against a set of policies written in the Rego policy language. In the compliance automation context, OPA serves multiple enforcement roles:

**Kubernetes Admission Control (via OPA Gatekeeper)**:
```
Request (kubectl apply) → API Server → OPA Gatekeeper Webhook
                                              |
                            Policy Evaluation (Rego policies)
                                              |
                        Allow / Deny + Audit Log
```

OPA Gatekeeper implements the Kubernetes admission webhook interface. When a resource is created or updated, the API server sends a webhook request to Gatekeeper, which evaluates the resource manifest against all registered policies and returns an admission decision (allow or deny) with a reason.

**Example Rego policy for container security context**:
```rego
package k8s.security.containers

deny[msg] {
    container := input.review.object.spec.containers[_]
    not container.securityContext.runAsNonRoot
    msg := sprintf("Container '%v' must run as non-root", [container.name])
}

deny[msg] {
    container := input.review.object.spec.containers[_]
    container.securityContext.privileged == true
    msg := sprintf("Container '%v' must not run as privileged", [container.name])
}

deny[msg] {
    container := input.review.object.spec.containers[_]
    not container.resources.limits.memory
    msg := sprintf("Container '%v' must have memory limits set", [container.name])
}
```

**CI/CD Pipeline Policy Gates (via Conftest)**:
```yaml
# .github/workflows/compliance-check.yml
- name: OPA Policy Check
  run: |
    conftest test \
      --policy ./policies/ci-cd/ \
      --namespace compliance \
      ./infrastructure/terraform/
```

**Cloud Configuration Assessment (via OPA + cloud resource data)**:
OPA can evaluate cloud resource configurations expressed as JSON against compliance policies. AWS Config and similar services can pipe resource configuration data to OPA for policy evaluation.

### Kyverno

Kyverno is a Kubernetes-native policy engine that uses YAML-based policies, making it more accessible to platform teams than OPA/Rego. Kyverno supports three policy types:

- **Validate**: Check resources against rules; deny or audit violations
- **Mutate**: Automatically modify resources to add required security configurations
- **Generate**: Automatically create additional resources when specified resources are created

```yaml
# Kyverno policy: require pod security labels
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-pod-security-labels
  annotations:
    policies.kyverno.io/title: Require Pod Security Labels
    policies.kyverno.io/category: SOC2-CC6, ISO27001-A.8.9
    policies.kyverno.io/description: >-
      Pods must have required security labels for compliance tracking.
spec:
  validationFailureAction: enforce
  background: true
  rules:
    - name: require-security-labels
      match:
        any:
        - resources:
            kinds:
            - Pod
      validate:
        message: "Pod must have 'app.kubernetes.io/name' and 'security-classification' labels."
        pattern:
          metadata:
            labels:
              app.kubernetes.io/name: "?*"
              security-classification: "?*"
```

### Policy Repository Structure

```
policies/
├── README.md                    # Policy catalog and maintenance guide
├── soc2/                        # SOC 2 Trust Service Criteria policies
│   ├── cc6-logical-access/      # CC6 controls
│   ├── cc7-system-operations/   # CC7 controls
│   ├── cc8-change-management/   # CC8 controls
│   └── cc9-risk-mitigation/     # CC9 controls
├── iso27001/                    # ISO 27001 Annex A policies
│   ├── a8-technological/        # A.8 Technological controls
│   └── a7-people/               # A.7 People controls (partially automatable)
├── nist-800-53/                 # NIST 800-53 control families
│   ├── ac-access-control/
│   ├── au-audit-accountability/
│   ├── cm-configuration-management/
│   └── ...
├── cis/                         # CIS Benchmark policies
│   ├── aws/                     # CIS AWS Foundations
│   ├── azure/                   # CIS Azure Foundations
│   ├── gcp/                     # CIS GCP Foundations
│   └── kubernetes/              # CIS Kubernetes Benchmark
├── pci-dss/                     # PCI-DSS v4.0 policies
├── kubernetes/                  # K8s admission control policies
│   ├── kyverno/                 # Kyverno policies
│   └── opa-gatekeeper/          # OPA Gatekeeper constraint templates
└── ci-cd/                       # CI/CD pipeline compliance gates
    ├── sast-gates.rego
    ├── dependency-gates.rego
    └── iac-gates.rego
```

---

## Infrastructure Compliance Scanning Architecture

### Cloud-Native Scanners

**AWS: AWS Config + Security Hub**

AWS Config provides continuous recording of AWS resource configurations. Security Hub aggregates findings from Config, GuardDuty, Inspector, and third-party tools into a unified compliance view with standards-based scoring.

```
AWS Resources → AWS Config Recorder → Config Rules (managed + custom)
                                             |
                                    AWS Security Hub
                                             |
                              Findings API → Evidence Collector
```

Key AWS Config integration patterns:
- Managed Config Rules for CIS AWS Benchmark checks
- Custom Config Rules using Lambda for organization-specific policies
- Conformance Packs for packaging multiple rules as compliance standards
- Continuous recording with delivery to S3 (evidence collection)

**Azure: Azure Policy + Microsoft Defender for Cloud**

Azure Policy enables definition and enforcement of organizational standards across Azure resources. Defender for Cloud provides continuous security posture assessment and compliance scoring.

```
Azure Resources → Azure Policy Engine → Policy Assignments (built-in + custom)
                                               |
                              Defender for Cloud Secure Score
                                               |
                                  Compliance Dashboard → Evidence Export
```

**GCP: Security Command Center (SCC)**

GCP Security Command Center provides continuous security and risk assessment for GCP resources.

```
GCP Resources → Cloud Asset Inventory → SCC Security Health Analytics
                                                |
                                      Security Findings API
                                                |
                                      Evidence Collector
```

### Open Source Scanners

**Prowler**

Prowler is an open-source security tool for AWS, Azure, and GCP assessments. It provides hundreds of checks across multiple compliance frameworks and can export findings in JSON, CSV, and HTML formats.

```bash
# Run Prowler for SOC2 compliance
prowler aws \
  --compliance soc2_aws \
  --output-formats json html \
  --output-directory /evidence/prowler/$(date +%Y%m%d)

# Run Prowler for CIS AWS Benchmark
prowler aws \
  --compliance cis_1.5_aws \
  --output-formats json \
  --output-directory /evidence/prowler/cis/$(date +%Y%m%d)
```

Prowler can be deployed as:
- A scheduled Lambda function for periodic cloud assessments
- A Kubernetes CronJob for containerized environments
- A GitHub Actions step for CI/CD integration

**Checkov**

Checkov is a static analysis tool for Infrastructure as Code security and compliance scanning. It supports Terraform, CloudFormation, Kubernetes YAML, Helm charts, Dockerfiles, and Secrets.

```bash
# Scan Terraform for compliance violations
checkov -d ./infrastructure/terraform \
  --framework terraform \
  --compliance soc2 \
  --output json \
  --output-file-path /evidence/checkov/$(date +%Y%m%d)

# Scan Kubernetes manifests
checkov -d ./k8s \
  --framework kubernetes \
  --check CKV_K8S_30,CKV_K8S_35,CKV_K8S_36 \
  --output json
```

**Trivy**

Trivy is a comprehensive vulnerability and misconfiguration scanner for containers, IaC, and Kubernetes clusters.

```bash
# Scan container image
trivy image \
  --format json \
  --output /evidence/trivy/image-$(date +%Y%m%d).json \
  your-registry/your-image:latest

# Scan Kubernetes cluster
trivy k8s \
  --report summary \
  --compliance k8s-cis-1.23 \
  --format json \
  --output /evidence/trivy/cluster-$(date +%Y%m%d).json
```

---

## Continuous Compliance Monitoring Pipeline

```
Source of Truth (Git)
        |
        v
+-------------------+     Push/PR     +-------------------+
| IaC + App Code    | --------------> | CI/CD Pipeline     |
+-------------------+                 +-------------------+
                                               |
                            +------------------+------------------+
                            |                  |                  |
                     Checkov Scan        OPA/Conftest        Trivy Scan
                     (IaC rules)         (Policy gates)      (Container)
                            |                  |                  |
                     Pass/Fail           Pass/Fail           Pass/Fail
                            |                  |                  |
                            +------------------+------------------+
                                               |
                                    Fail = Block deployment
                                    Pass = Continue + Evidence log
                                               |
                                        Deploy to Staging
                                               |
                                    Kyverno admission check
                                    OPA Gatekeeper validation
                                               |
                                        Deploy to Production
                                               |
                               +---------------+---------------+
                               |               |               |
                        AWS Config       Azure Policy    GCP SCC
                       continuous       continuous      continuous
                       assessment       assessment      assessment
                               |               |               |
                               +---------------+---------------+
                                               |
                                    Compliance Findings
                                               |
                                    Evidence Collector
                                               |
                               +---------------+---------------+
                               |                               |
                        Immutable Evidence Store          Dashboard
                        (S3 + hash verification)          (Grafana)
```

### Event-Driven Compliance Assessment

Rather than only periodic scheduled scans, TCAF implements event-driven compliance assessment that responds to configuration changes in near-real time:

**Trigger**: CloudTrail event indicating a security group rule change
**Response**:
1. CloudWatch Events / EventBridge rule matches the CloudTrail event pattern
2. Lambda function invoked with the event payload
3. Lambda calls Prowler check for the affected security group
4. Finding compared against compliance policy
5. If non-compliant: alert generated, finding recorded to evidence store, JIRA ticket created
6. If compliant: compliance event logged to evidence store

This approach achieves compliance drift detection latency measured in minutes rather than days.

---

## Audit Evidence Collection System Design

### Evidence Types and Sources

| Evidence Type | Source | Collection Method | Retention |
|--------------|--------|------------------|-----------|
| Cloud API calls | CloudTrail / Activity Logs / Audit Logs | Continuous streaming to S3 | 7 years |
| Cloud configuration snapshots | AWS Config / Azure Resource Graph / GCP Asset Inventory | Daily snapshot + change capture | 3 years |
| Compliance scan results | Prowler, Checkov, Trivy, CSPM | Scheduled + event-triggered | 3 years |
| IAM access reviews | Custom automation against cloud IAM APIs | Quarterly automated + on-demand | 3 years |
| Vulnerability scan reports | SAST, DAST, dependency scanning | Every CI/CD run | 2 years |
| Change management records | CI/CD pipeline logs, Git commit history | Continuous | 3 years |
| Training completion records | LMS integration | Monthly export | 5 years |
| Incident records | SIEM, ticketing system | Event-triggered | 7 years |
| SBOM records | CI/CD pipeline | Per-deployment | Product lifetime |
| Certificate lifecycle | Certificate manager, ACME logs | Continuous | 3 years |

### Evidence Immutability Architecture

```
Evidence Generation
        |
        v
Evidence Collector Service
        |
   Hash Generation (SHA-256)
        |
        +---> Immutable Object Store (S3 with Object Lock / Azure Immutable Blob)
        |                |
        |         Hash Stored in
        |         Audit Log Table (DynamoDB / CosmosDB)
        |
        +---> Evidence Metadata Index (search and retrieval)
```

Object Lock configuration (AWS S3 example):
```json
{
  "ObjectLockEnabled": "Enabled",
  "Rule": {
    "DefaultRetention": {
      "Mode": "COMPLIANCE",
      "Days": 2555
    }
  }
}
```

### Evidence Catalog API

The Evidence Collector exposes a REST API for the Audit Dashboard and external audit tooling:

```
GET /evidence?framework=soc2&control=CC6.1&period=2024-01-01/2024-12-31
GET /evidence/{id}
GET /evidence/{id}/verify     # Returns hash verification result
GET /evidence/summary?framework=soc2&period=2024-01-01/2024-12-31
POST /evidence/export?format=zip&framework=soc2&period=2024-01-01/2024-12-31
```

---

## Compliance Data Lake Architecture

The Compliance Data Lake aggregates all compliance-related data from multiple sources to enable cross-framework analysis, trend reporting, and advanced analytics.

```
+------------------+   +------------------+   +------------------+
| Cloud Audit Logs |   |  Scan Results    |   | Change Records   |
+------------------+   +------------------+   +------------------+
         |                     |                       |
         +---------------------+-----------------------+
                               |
                    +----------+----------+
                    | Data Ingestion Layer |
                    | (Kinesis / Event Hub)|
                    +---------------------+
                               |
                    +----------+----------+
                    |   Data Lake Storage  |
                    | (S3 / ADLS Gen2)     |
                    | Partitioned by:      |
                    |  - Framework         |
                    |  - Control family    |
                    |  - Date              |
                    |  - Resource type     |
                    +---------------------+
                               |
              +----------------+----------------+
              |                |                |
    +----------+-----+ +-------+------+ +-------+------+
    | Compliance DB   | | Analytics    | | ML Models    |
    | (PostgreSQL /   | | (Athena /    | | (SageMaker / |
    | Azure SQL)      | | Synapse)     | | Azure ML)    |
    +----------------+ +--------------+ +--------------+
              |                |
              +-------+--------+
                      |
              Evidence Catalog API
```

### Data Schema

The central compliance events table captures all compliance assessment results:

```sql
CREATE TABLE compliance_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp       TIMESTAMPTZ NOT NULL,
    framework       VARCHAR(50) NOT NULL,     -- 'soc2', 'iso27001', 'nist', 'cis', 'pci-dss'
    control_id      VARCHAR(100) NOT NULL,    -- 'CC6.1', 'A.8.9', 'AC-2'
    control_name    VARCHAR(255),
    resource_id     VARCHAR(500) NOT NULL,    -- ARN, resource path
    resource_type   VARCHAR(100),
    environment     VARCHAR(50),             -- 'production', 'staging'
    status          VARCHAR(20) NOT NULL,    -- 'PASS', 'FAIL', 'WARN', 'EXEMPT'
    severity        VARCHAR(20),            -- 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
    finding_detail  JSONB,
    scanner         VARCHAR(50),           -- 'prowler', 'checkov', 'aws-config'
    evidence_ref    VARCHAR(500),          -- reference to evidence store
    remediation_id  VARCHAR(100),          -- linked remediation ticket
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_compliance_events_framework ON compliance_events(framework);
CREATE INDEX idx_compliance_events_timestamp ON compliance_events(timestamp);
CREATE INDEX idx_compliance_events_status ON compliance_events(status);
```

---

## Dashboard and Reporting Architecture

### Grafana Dashboard Stack

```
Compliance Data Lake (PostgreSQL)
            |
   Grafana Data Source Plugin
            |
   Grafana Dashboard Layer
   +---------+-----------+----------+
   |         |           |          |
Framework  Control    Resource  Trend
Overview   Detail     Explorer  Analysis
   |         |           |          |
Executive  Technical   DevOps    CISO
Audience   Audience    Teams     Leadership
```

### Key Dashboard Views

**Executive Compliance Overview**:
- Overall compliance score by framework (gauge charts)
- Critical failing controls count
- Compliance trend over rolling 90 days
- Top 5 highest-risk compliance gaps by business impact

**Framework Detail View** (one per compliance framework):
- Control-by-control compliance status heat map
- Control family compliance percentage bar charts
- Recent compliance events timeline
- Evidence collection status by control

**Resource Compliance View**:
- Compliance status by resource type (EC2, S3, RDS, etc.)
- Highest-risk non-compliant resources
- Compliance score by team/account/project

**Audit Evidence View**:
- Evidence collection completeness by control
- Evidence age and staleness indicators
- Evidence download for auditor packages

### Automated Audit Report Generation

TCAF includes a report generation service that produces auditor-ready compliance packages:

```python
# Example: Generate SOC 2 audit evidence package
compliance_reporter.generate_audit_package(
    framework="soc2",
    audit_period_start="2024-01-01",
    audit_period_end="2024-12-31",
    output_format="zip",
    include=[
        "control_assessment_summary",
        "evidence_inventory",
        "exception_log",
        "remediation_records",
        "scanning_tool_configurations",
        "change_management_records"
    ]
)
```

The generated package includes:
1. **Executive compliance summary**: Overall scores, key findings, exceptions
2. **Control-by-control assessment**: Pass/fail/exempt status with evidence references
3. **Evidence inventory**: Catalog of all evidence collected with timestamps and hash values
4. **Exception and waiver log**: All approved exceptions with rationale and expiry
5. **Remediation tracking**: Evidence of finding remediation within SLA
6. **Tool configuration snapshots**: Configuration of all scanning tools at start of period
