# Compliance Exception Management

A compliance exception is a formally documented, time-bounded acceptance of a specific deviation from a required control. Exception management is not a weakness in a compliance program — it is a mandatory capability. Every real-world compliance environment has configurations that require exceptions due to technical constraints, vendor limitations, migration timelines, or risk-accepted architectural decisions. The danger is not the exception; it is the exception that is not tracked, reviewed, or closed.

This document defines the complete exception lifecycle, request and approval procedures, risk assessment standards, compensating control requirements, audit trail obligations, and annual review processes.

---

## Exception Lifecycle Overview

```
              ┌──────────────┐
              │   IDENTIFIED │  Control cannot be met; exception required
              └──────┬───────┘
                     │
                     ▼
              ┌──────────────┐
              │   SUBMITTED  │  Exception request filed with required fields
              └──────┬───────┘
                     │
              ┌──────▼───────┐
              │   TRIAGED    │  Automated check: exemptable? duplicates? risk score
              └──────┬───────┘
                     │
              ┌──────▼───────┐
              │   IN REVIEW  │  Risk-based routing to appropriate approver
              └──┬───────┬───┘
                 │       │
          ┌──────▼──┐ ┌──▼──────┐
          │ APPROVED│ │ DENIED  │  → Control must be remediated; no further exception
          └──────┬──┘ └─────────┘
                 │
          ┌──────▼──────────────────┐
          │ ACTIVE (time-bounded)   │  Exception in force; compensating controls active
          └──────┬──────────────────┘
                 │  ┌──── 30-day renewal reminder
                 │  ├──── 14-day final notice
                 │  └──── 7-day escalation to manager
                 ▼
     ┌────────────────────┐
     │  EXPIRED / RENEWED │  Expired: flagged as compliance failure
     └──┬─────────────────┘  Renewed: re-enter review workflow
        │
   ┌────▼────────────┐
   │  REMEDIATED     │  Control now met; exception closed with remediation evidence
   └─────────────────┘
```

---

## Exception Request Form

All exception requests must be submitted via the configured ticketing system (JIRA, ServiceNow, or equivalent). The following fields are required. Incomplete submissions are automatically rejected during triage.

### Required Fields

**Section 1: Control Identification**

| Field | Required | Description |
|-------|----------|-------------|
| Control ID | Yes | The specific control identifier (e.g., `SOC2-CC6.1`, `CIS-2.1.1`, `NIST-AC-6`) |
| Compliance Framework | Yes | The framework(s) requiring this control: SOC 2, ISO 27001, PCI-DSS, CIS, NIST |
| Control Description | Yes | Brief description of what the control requires |
| Resource/System ID | Yes | The specific system, service, or infrastructure resource that cannot meet the control |
| Environment | Yes | Production / Staging / Development |

**Section 2: Exception Justification**

| Field | Required | Description |
|-------|----------|-------------|
| Exception Category | Yes | See Exception Categories below |
| Business Justification | Yes | Why the control cannot be met at this time. Must be specific — "technical constraint" is not sufficient |
| Technical Reason | Yes | Specific technical reason the control cannot be implemented |
| Vendor/Third-Party Limitation | If applicable | Vendor ticket or documentation confirming the limitation |
| Remediation Timeline | Yes | Specific target date for full control implementation |
| Remediation Plan | Yes | Step-by-step plan to achieve compliance by the target date |

**Section 3: Risk Assessment**

| Field | Required | Description |
|-------|----------|-------------|
| Inherent Risk Rating | Yes | Requester's assessment: Critical / High / Medium / Low |
| Risk Description | Yes | What specific risk is created by not meeting this control? |
| Compensating Controls | Yes | What additional controls reduce the risk during the exception period? |
| Compensating Control Validation | Yes | How are the compensating controls being verified? |
| Residual Risk Rating | Yes | Risk level after compensating controls are applied |

**Section 4: Governance**

| Field | Required | Description |
|-------|----------|-------------|
| Requested By | Yes | Name and email of the person requesting the exception |
| Business Owner | Yes | The product/service owner who accepts organizational risk |
| Exception Duration | Yes | Requested expiry date (maximum durations apply — see below) |
| Data Classification | Yes | The data classification of the affected system (Public / Internal / Confidential / Restricted) |
| Regulatory Scope | Yes | Is this system in scope for any regulated data (PHI, PCI, PII, FedRAMP)? |

---

### Exception Categories

| Category | Description | Example |
|----------|-------------|---------|
| `TECHNICAL_CONSTRAINT` | Technical limitation prevents control implementation | TLS 1.2 minimum not achievable on legacy IoT device firmware |
| `VENDOR_LIMITATION` | Third-party vendor does not support the required control | SaaS vendor does not support SCIM provisioning |
| `MIGRATION_IN_PROGRESS` | Control will be met after a documented migration | Moving from self-managed secrets to Secrets Manager; takes 45 days |
| `COST_CONSTRAINT` | Control implementation has disproportionate cost vs. risk | CloudHSM cost for non-regulated, low-sensitivity internal tool |
| `REGULATORY_CONFLICT` | Control conflicts with another regulatory requirement | GDPR data residency requires local storage conflicting with centralized logging control |
| `OPERATIONAL_IMPACT` | Control implementation creates unacceptable operational risk | Enforcing TLS mutual auth on internal API breaks critical monitoring |

---

## Exception Request Template (JIRA/ServiceNow)

```
EXCEPTION REQUEST — SECURITY COMPLIANCE

=== SECTION 1: CONTROL IDENTIFICATION ===
Control ID:         [e.g., SOC2-CC6.1 / CIS-4.1 / NIST-AC-6]
Framework(s):       [SOC 2 / ISO 27001 / PCI-DSS / CIS / NIST]
Control Summary:    [What the control requires in one sentence]
Affected Resource:  [service name / AWS ARN / GCP resource ID / specific hostname]
Environment:        [Production / Staging]

=== SECTION 2: JUSTIFICATION ===
Category:           [TECHNICAL_CONSTRAINT / VENDOR_LIMITATION / MIGRATION_IN_PROGRESS / ...]

Business Justification:
[Why is this control not met? Be specific. Include references to vendor tickets,
architecture constraints, or business decisions.]

Technical Reason:
[What technical mechanism prevents implementation?]

Vendor Limitation (if applicable):
[Vendor name, support ticket number, and quoted limitation]

Remediation Target Date: [YYYY-MM-DD]

Remediation Plan:
Step 1: [Action, owner, target date]
Step 2: [Action, owner, target date]
Step 3: [Final implementation and verification]

=== SECTION 3: RISK ASSESSMENT ===
Inherent Risk:      [Critical / High / Medium / Low]

Risk Description:
[What attack or compliance failure is enabled by this control gap?
Be specific: which threat actors, which attack paths, which data at risk?]

Compensating Controls:
1. [Control name and description]
   Validation method: [How is this control verified to be effective?]
2. [Control name and description]
   Validation method: [How is this control verified to be effective?]

Residual Risk After Compensating Controls: [High / Medium / Low]
Risk Acceptance Statement: I, [Business Owner Name], accept organizational responsibility
for this risk and attest that the compensating controls are implemented and effective.

=== SECTION 4: GOVERNANCE ===
Requested By:        [name, email, team]
Business Owner:      [name, email, title]
Exception Duration:  [Requested: YYYY-MM-DD] [Maximum allowed: per policy below]
Data Classification: [Public / Internal / Confidential / Restricted]
Regulated Data:      [Yes — specify: PCI / PHI / PII / FedRAMP] [No]
```

---

## Maximum Exception Durations

Exception duration is limited based on the control severity and data classification. These are organizational maximums — approvers may set shorter durations.

| Control Severity | Non-Regulated System | Regulated System (PCI/PHI/PII) |
|-----------------|---------------------|-------------------------------|
| Critical | 30 days | Not approvable — must remediate |
| High | 90 days | 30 days |
| Medium | 180 days | 90 days |
| Low | 365 days | 180 days |

**Prohibited exceptions:** The following controls may never have exceptions granted for systems in scope for PCI-DSS, HIPAA, or FedRAMP:
- Encryption in transit (TLS 1.2+ enforcement)
- Multi-factor authentication for privileged access
- Audit logging for regulated data access
- Data retention and destruction controls

---

## Risk-Based Approval Routing

| Residual Risk | Regulated Data in Scope | Required Approver |
|--------------|------------------------|------------------|
| Critical | Any | Exception not approvable — escalate to CISO for remediation timeline enforcement |
| High | Yes | CISO sign-off |
| High | No | Security Architect sign-off |
| Medium | Yes | Security Architect + CISO notification |
| Medium | No | Senior Security Engineer |
| Low | Any | Security Engineer |

**Quorum requirements:**
- CISO-level exceptions require CISO + Legal approval for regulated data systems.
- All approvals must be recorded in the exception ticket with the approver's identity, timestamp, and justification for the approval decision.

---

## Approver Decision Criteria

Approvers evaluate exception requests against these criteria:

**Approve when:**
- Business justification is credible and specific
- Remediation plan is realistic and time-bound
- Compensating controls demonstrably reduce the residual risk to an acceptable level
- Residual risk is commensurate with the business value of the affected system
- The exception category is genuine (not a workaround for resource constraints)

**Deny when:**
- Control gap creates Critical residual risk with no effective compensating control
- The affected system processes regulated data and the control is required by regulation
- The remediation plan has no credible delivery mechanism
- A prior exception for the same control and system was granted and expired without remediation
- The compensating controls cannot be verified

**Request More Information when:**
- Compensating controls are described but no verification method is specified
- The remediation timeline appears unrealistic without explanation
- The technical constraint is not specific enough to verify

**Approver must document the reasoning for their decision in the exception ticket — a one-line approval ("looks fine") is not sufficient evidence.**

---

## Compensating Controls Standards

A compensating control must:

1. **Actually reduce the specific risk** created by the control gap — not just add generic security measures. A compensating control for "no MFA on service account" is not "we have a strong password policy."
2. **Be independently verifiable** — it must be possible to confirm the compensating control is functioning through automated scanning, log review, or equivalent.
3. **Be maintained actively** — compensating controls that require manual intervention must have a named owner and documented maintenance schedule.
4. **Be proportional to the risk** — compensating controls for Critical control gaps must reduce residual risk to Medium or lower before approval is possible.

### Compensating Control Examples

| Control Gap | Acceptable Compensating Control | Unacceptable Compensating Control |
|-------------|-------------------------------|----------------------------------|
| No TLS on internal API | Network isolation (private VPC, no external access); mTLS for consuming services | "The data is not sensitive" |
| No MFA on service account | Short-lived OIDC tokens with IP allowlisting; no console access; access limited to specific pipeline | "The service account password is strong" |
| Secrets in environment variables | Secret rotation every 7 days; no log output of env vars; instance profile with no IAM listing permissions | "The application is internal only" |
| No patch within SLA | Service isolated from network; WAF rules blocking known exploit paths; active monitoring for exploitation | "We are planning to patch next quarter" |

---

## Exception Audit Trail Requirements

Every exception record must maintain an immutable audit trail containing:

| Event | Required Information |
|-------|---------------------|
| Submission | Requester identity, timestamp, all field values at submission |
| Automated triage result | Check results, risk score, routing decision |
| Approver actions | Approver identity, timestamp, decision (Approve/Deny/RFI), full justification text |
| Compensating control verification | Evidence records (scan results, access logs), verification timestamp |
| Renewal actions | Same as approval — full records for each renewal cycle |
| Reminder delivery | Record of each notification with recipient, timestamp, channel |
| Expiry event | Whether exception was renewed, remediated, or allowed to lapse |
| Remediation closure | Evidence of control implementation, verification method and result, closure timestamp |

**Retention:** Exception audit trail records must be retained for a minimum of 7 years (SOC 2 Type II / ISO 27001 evidence retention standard). Records must be stored in tamper-evident storage.

---

## Annual Exception Review

All active exceptions must be reviewed annually, regardless of their expiry date. The annual review is not a renewal — it is an independent assessment of whether the exception is still warranted.

**Annual Review Checklist:**

```
For each active exception:

[ ] Has the underlying business or technical constraint changed?
    → If yes, can the exception now be closed and the control implemented?

[ ] Are the compensating controls still in place and effective?
    → Verify via automated scanning or manual check; document the result

[ ] Is the remediation plan still on track?
    → Review progress against the plan milestones; document current status

[ ] Has the risk profile of the affected system changed?
    → New regulated data in scope? Critical system designation changed?

[ ] Has this exception been renewed more than twice?
    → Escalate to CISO — an exception renewed three times indicates a structural issue

[ ] Approver decision: Maintain / Require remediation within 30 days / Close

Annual review must be completed by the same approval tier that granted the exception.
Annual review records must be stored in the exception audit trail.
```

---

## Exception Dashboard and Reporting

The compliance dashboard must provide real-time visibility into the exception portfolio:

| Metric | Description | Alert Threshold |
|--------|-------------|----------------|
| Total active exceptions | Count by severity | CRITICAL active > 0 alerts immediately |
| Exceptions expiring in 30 days | Count requiring renewal action | Any pending renewal |
| Exceptions past expiry | Count of expired exceptions not yet remediated | Any expired > 0 |
| Average exception age | Mean age of all active exceptions | > 90 days average |
| Exceptions by category | Distribution across exception categories | Migration exceptions > 50% suggests systemic planning failures |
| Repeat exceptions | Exceptions on same control renewed 2+ times | Any repeat > 2 escalates to CISO |
| Compensating control verification rate | % of active exceptions with verified compensating controls | < 100% triggers alert |

**Regulatory reporting:** SOC 2, ISO 27001, and PCI-DSS auditors routinely request the exception inventory, approval records, and compensating control evidence. Maintaining the audit trail as specified in this document satisfies most auditor requests without additional preparation.

---

## Integration with Policy-as-Code

For automated compliance systems (Prowler, Checkov, AWS Config, Kyverno), exceptions must be reflected in the scanning suppression configuration while preserving the audit trail.

**Suppression management:**

```yaml
# Checkov suppression block (in IaC file)
# IMPORTANT: Suppression must reference the exception ticket ID
resource "aws_s3_bucket" "legacy-data" {
  # checkov:skip=CKV_AWS_18:EXCEPTION-2024-0031
  # Exception: CloudTrail logging not yet enabled on legacy bucket during migration
  # Expiry: 2024-06-30 | Approved by: security-architect@example.com
  bucket = "legacy-data-bucket"
}
```

```yaml
# Kyverno policy exception (audit mode for excepted resource)
apiVersion: kyverno.io/v2
kind: PolicyException
metadata:
  name: exception-2024-0031-legacy-bucket
  namespace: compliance
  annotations:
    techstream/exception-id: "EXCEPTION-2024-0031"
    techstream/exception-expiry: "2024-06-30"
    techstream/approved-by: "security-architect@example.com"
spec:
  exceptions:
  - policyName: require-s3-access-logging
    ruleNames:
    - check-s3-access-logging
  match:
    any:
    - resources:
        kinds: [S3Bucket]
        names: [legacy-data-bucket]
```

**Exception-scanner synchronization:** A nightly job must verify that:
- All active exceptions in the exception database have a corresponding suppression in the scanner configuration.
- All suppressions in the scanner configuration have a corresponding active exception record.
- Expired exceptions automatically have their scanner suppressions removed.

---

*See also:*
- *[framework.md](framework.md) — Compliance controls framework and Policy-as-Code patterns*
- *[architecture.md](architecture.md) — Compliance evidence storage architecture*
- *[regulatory-controls-matrix.md](regulatory-controls-matrix.md) — Control-to-framework mapping for determining exception impact*
- *[devsecops-maturity-model: remediation-playbooks.md](../../devsecops-maturity-model/docs/remediation-playbooks.md) — Governance & Compliance domain remediation guidance*
