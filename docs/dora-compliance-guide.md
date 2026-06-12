# DORA Compliance Guide — Software Delivery Under Regulation (EU) 2022/2554

The Digital Operational Resilience Act (DORA) — Regulation (EU) 2022/2554 of 14 December 2022 — is the European Union's binding operational-resilience regime for the financial sector. It has applied directly in all EU member states since **17 January 2025**. Unlike a directive, DORA required no national transposition: its obligations are enforceable as written.

DORA matters to engineering teams because it converts software-delivery discipline into a supervisory matter. Where SOC 2 is a voluntary attestation demanded by customers, DORA is law enforced by financial supervisors (EBA, ESMA, EIOPA and national competent authorities), with the supervisory posture in 2026 shifting from reviewing policy documents to **demanding evidence** that controls operate continuously.

This guide covers what DORA requires from a DevSecOps and continuous-compliance perspective, where the software delivery pipeline meets the regulation, and how the Techstream Compliance Automation Framework maps to DORA's evidence obligations.

> **Terminology note — two DORAs.** In this framework ecosystem, "DORA metrics" refers to the DevOps Research & Assessment delivery metrics (deployment frequency, lead time, change failure rate, MTTR) used throughout the release-orchestration-framework. **In this document, DORA means Regulation (EU) 2022/2554.** The two are unrelated; always qualify which one you mean.

---

## Table of Contents

- [Who Is in Scope](#who-is-in-scope)
- [The Five Pillars](#the-five-pillars)
- [Where the Delivery Pipeline Meets DORA](#where-the-delivery-pipeline-meets-dora)
- [Article 9(4)(e): The Change-Management Provision](#article-94e-the-change-management-provision)
- [Delivery-Pipeline Control Mapping](#delivery-pipeline-control-mapping)
- [Evidence Automation for DORA](#evidence-automation-for-dora)
- [Incident Management and Reporting (Articles 17–19)](#incident-management-and-reporting-articles-1719)
- [Resilience Testing (Articles 24–26)](#resilience-testing-articles-2426)
- [Crosswalk: DORA ↔ SOC 2 ↔ ISO 27001](#crosswalk-dora--soc-2--iso-27001)
- [What Supervisors Ask For in 2026](#what-supervisors-ask-for-in-2026)

---

## Who Is in Scope

DORA applies to more than twenty categories of **financial entities** (Article 2), including:

- Credit institutions, payment institutions, electronic money institutions (EMIs)
- Investment firms, trading venues, central counterparties, central securities depositories
- Management companies (UCITS/AIFM), insurance and reinsurance undertakings
- Crypto-asset service providers authorised under MiCA
- Crowdfunding service providers, credit rating agencies, and others

It also reaches **ICT third-party service providers**. Critical ICT third-party providers (CTPPs) can be designated for direct oversight by the European Supervisory Authorities. Every other ICT provider serving an EU financial entity is reached **contractually**: Article 30 prescribes mandatory contractual provisions (audit and access rights, security requirements, termination rights, exit strategies) that financial entities must flow down to their providers.

**Practical consequence for SaaS and platform vendors:** if your customers include EU financial entities, DORA obligations arrive in your contracts and security questionnaires even though the regulation does not name you directly.

**Proportionality (Article 4):** obligations scale with the entity's size, risk profile, and the nature of its services. Article 16 provides a simplified ICT risk-management framework for specific small entities. Proportionality changes the depth of implementation — it does not remove the obligation to evidence change control.

---

## The Five Pillars

| Pillar | DORA Chapter | Articles | Delivery-pipeline relevance |
|---|---|---|---|
| ICT risk management | Chapter II | 5–16 | **High** — change management (Art. 9(4)(e)), protection and prevention (Art. 9), identification of vulnerabilities (Art. 8), detection (Art. 10), response and recovery (Art. 11–12) |
| ICT incident management, classification and reporting | Chapter III | 17–23 | **Medium** — release records feed root-cause analysis and incident reports; deployment timeline evidence supports classification |
| Digital operational resilience testing | Chapter IV | 24–27 | **Medium** — vulnerability assessments, scans and source-code reviews per Article 25(1) are pipeline-native activities |
| ICT third-party risk management | Chapter V | 28–44 | **Medium** — Register of Information; Article 30 contractual flow-down to ICT providers |
| Information sharing | Chapter VI | 45 | Low |

The **ICT risk-management RTS** — Commission Delegated Regulation (EU) 2024/1774 — supplements Chapter II with detailed technical requirements, including documented ICT change-management procedures with fallback (rollback) provisions and post-implementation verification, and handling of emergency changes with retrospective approval.

---

## Where the Delivery Pipeline Meets DORA

Most DORA commentary focuses on governance, incident reporting, and third-party registers. For engineering organizations, the densest concentration of obligations sits in **Chapter II**, and specifically in how production change is controlled and evidenced:

1. **Article 8 (Identification)** — continuously identify sources of ICT risk and assess cyber threats and **ICT vulnerabilities** relevant to ICT-supported business functions. Per-release SAST/SCA/container scanning is the pipeline-native implementation.
2. **Article 9 (Protection and prevention)** — maintain high standards of **availability, authenticity, integrity and confidentiality** of data and ICT systems (Art. 9(2)); implement documented **ICT change-management controls** (Art. 9(4)(e)).
3. **Article 10 (Detection)** — promptly detect anomalous activities; post-deployment verification and health checks contribute.
4. **Articles 11–12 (Response and recovery; backup and restoration)** — response and recovery plans, restoration capabilities; tested rollback procedures are the delivery-side expression.
5. **Articles 24–26 (Testing)** — an ongoing resilience-testing programme including vulnerability assessments and scans, source-code review where feasible, and end-to-end testing.

---

## Article 9(4)(e): The Change-Management Provision

The single most pipeline-relevant sentence in DORA:

> Financial entities shall *"implement documented policies, procedures and controls for ICT change management, including changes to software, hardware, firmware components, systems or security parameters, that are based on a risk assessment approach and are an integral part of the financial entity's overall change management process, in order to ensure that **all changes to ICT systems are recorded, tested, assessed, approved, implemented and verified in a controlled manner**."* — Article 9(4)(e)

Six verbs, each demanding evidence:

| Verb | What supervisors expect | Pipeline-native evidence |
|---|---|---|
| **Recorded** | Every production change traceable, with an immutable record | PR metadata, commit SHA, deployment events, immutable audit log |
| **Tested** | Changes tested before production, results retained | CI test results bound to the released SHA |
| **Assessed** | Risk assessment proportional to the change | Risk labels/tiering on changes; security scan results; review notes |
| **Approved** | Authorised approval before implementation, segregation of duties | Non-author PR approval; protected-environment deployment approval |
| **Implemented** | Controlled deployment by authorised actor/mechanism | Deployment event with actor, timestamp, target environment, artifact digest |
| **Verified** | Post-implementation verification that the change behaves as intended | Post-deploy checks, health verification, monitoring window record |

Manual screenshot-and-spreadsheet evidence can satisfy these verbs; it does so at a cost of dozens to hundreds of engineering hours per audit cycle and with material risk of gaps. The automated pattern in [Evidence Collection Automation](evidence-collection-automation.md) satisfies them as a by-product of delivery.

---

## Delivery-Pipeline Control Mapping

| Techstream Control | DORA Reference | Coverage |
|---|---|---|
| Protected branches with mandatory non-author code review | Art. 9(4)(e) — assessed, approved | Full |
| Separate deployment approvals for production (segregation of duties) | Art. 9(4)(e) — approved; Art. 9(4)(c) — logical access restriction | Full |
| CI test execution bound to released SHA, results retained | Art. 9(4)(e) — tested; Art. 25(1) — testing programme | Full |
| SAST / SCA / container scanning per release with triage records | Art. 8(2) — vulnerability identification; Art. 25(1) — vulnerability assessments and scans; Art. 9(2) | Full |
| Immutable artifact promotion, digest pinning, signature verification | Art. 9(2) — integrity and authenticity; Art. 9(4)(e) — implemented in a controlled manner | Full |
| Pipeline audit log (immutable, tamper-evident, hash-chained) | Art. 9(4)(e) — recorded | Full |
| Post-deployment verification job with retained results | Art. 9(4)(e) — verified; Art. 10 — detection | Full |
| Tested rollback / fallback procedure with execution history | Art. 11 — response and recovery; Art. 12 — restoration; RTS (EU) 2024/1774 fallback provisions | Full |
| Emergency change path with retrospective approval record | Art. 9(4)(e); RTS (EU) 2024/1774 emergency-change provisions | Full |
| Evidence store segregated from production access (WORM/Object Lock) | Art. 9(2) — integrity; supervisory evidentiary expectations | Full |
| Release evidence package per production change (machine-readable + auditor rendering) | Art. 9(4)(e) — all six verbs, packaged for supervisory review | Full |

---

## Evidence Automation for DORA

Following the same architecture as the [Evidence Collection Automation](evidence-collection-automation.md) guide (continuous collection → immutable store → compliance database → audit packaging):

| Evidence Item | Source System | Collection Trigger | DORA Reference | Retention |
|---|---|---|---|---|
| Change record (PR, approvals, linked issue) | GitHub / GitLab API + webhooks | On merge to protected branch | Art. 9(4)(e) recorded/assessed/approved | 5+ years |
| Test results on released SHA | CI platform (workflow run artifacts) | Per pipeline run on release SHA | Art. 9(4)(e) tested; Art. 25(1) | 5+ years |
| Vulnerability scan results (SAST/SCA/container) with disposition | Scanner output normalized to findings schema | Per release + scheduled | Art. 8(2); Art. 25(1) | 5+ years |
| Deployment event (actor, environment, artifact digest, timestamp) | Deployment system / GitHub deployments API | Event-driven | Art. 9(4)(e) implemented | 5+ years |
| Post-deployment verification result | CI verification job / synthetic checks | Post-deploy | Art. 9(4)(e) verified; Art. 10 | 5+ years |
| Rollback execution + periodic rollback test record | Orchestration system | Event-driven + scheduled test | Art. 11; Art. 12 | 5+ years |
| Emergency change record with retrospective approval | Change workflow | Event-driven | Art. 9(4)(e); RTS | 5+ years |
| Evidence-store integrity proof (hash chain, WORM configuration) | Evidence store | Continuous | Art. 9(2) | Life of store |

**Retention note:** DORA does not prescribe a single universal retention figure for change evidence; supervisory expectations and related EU financial-sector record-keeping rules make 5 years a defensible floor — confirm with compliance counsel per entity type.

---

## Incident Management and Reporting (Articles 17–19)

Articles 17–19 require an ICT incident-management process, harmonised classification, and reporting of **major ICT-related incidents** to competent authorities using staged reports (initial, intermediate, final) on short regulatory timelines defined in the incident-reporting technical standards.

Delivery evidence directly supports this pillar:

- **Was the incident change-induced?** The release timeline answers in minutes what log archaeology answers in days.
- **Root-cause and remediation reporting** draws on deployment records, approvals, scan results, and rollback execution evidence.
- **Recurrence prevention** (Art. 13 — learning and evolving) is evidenced by post-incident changes traced through the same pipeline records.

---

## Resilience Testing (Articles 24–26)

Article 24 requires a proportionate, risk-based **digital operational resilience testing programme**; Article 25(1) explicitly lists vulnerability assessments and scans, open-source analyses, network assessments, **source code reviews where feasible**, scenario-based tests, compatibility, performance and end-to-end testing. Significant entities face **threat-led penetration testing (TLPT)** at regulatory intervals (Article 26, TIBER-EU aligned).

Pipeline-native security testing — SAST, SCA, container and IaC scanning executed per release with retained, triaged results — constitutes standing evidence of the Article 25 programme's operation. Annual test-programme documentation should reference the pipeline's continuous testing record rather than duplicate it.

---

## Crosswalk: DORA ↔ SOC 2 ↔ ISO 27001

For organizations already operating SOC 2 or ISO 27001 programmes (see the [Regulatory Controls Matrix](regulatory-controls-matrix.md)):

| Control area | DORA | SOC 2 | ISO 27001:2022 |
|---|---|---|---|
| Change management | Art. 9(4)(e) | CC8.1 | A.8.32 |
| Vulnerability identification | Art. 8(2); Art. 25(1) | CC7.1 | A.8.8 |
| Logging and audit trail | Art. 9(4)(e) recorded; Art. 10 | CC7.2 | A.8.15 |
| Integrity of artifacts/data | Art. 9(2) | CC8.1 | A.8.24, A.8.32 |
| Response, recovery, rollback | Art. 11; Art. 12 | A1.2, A1.3 | A.5.29, A.8.13 |
| Incident management | Art. 17–19 | CC7.3–CC7.5 | A.5.24–A.5.28 |
| Third-party/ICT supplier control | Art. 28–30 | CC9.2 | A.5.19–A.5.22 |

An organization with mature SOC 2 CC8.1 change-management evidence is approximately 70% of the way to Article 9(4)(e) — the deltas are typically the **risk-assessment verb**, the **verified verb** (post-implementation verification evidence), formal **fallback procedures**, and supervisory-grade **record immutability**.

---

## What Supervisors Ask For in 2026

The supervisory posture since the regulation began applying has moved from documentation review toward operational evidence. Recurring requests observed across the sector:

1. **"Show us your last N production changes"** — with approval chain, test results, and verification for each. (Minutes with automated evidence packs; weeks with screenshots.)
2. **"Demonstrate your change-management procedure operating"** — not the policy PDF, but records proving the six verbs of Art. 9(4)(e) executed in order.
3. **"Show the testing programme operating"** — continuous scan results with triage decisions, not a one-time pentest report.
4. **"Prove your records cannot be silently altered"** — evidence-store integrity (WORM, hash chains, segregation of duties over the store).
5. **Register of Information** completeness for ICT third-party arrangements (Chapter V).

Teams that generate evidence at deployment time (see release-orchestration-framework, Best Practice #24: *"Generate compliance evidence at deployment time, not audit time"*) answer these requests as a query, not a project.

---

## Related Documents

- [Regulatory Controls Matrix — Section 13: DORA](regulatory-controls-matrix.md) — control-by-control mapping table
- [Evidence Collection Automation](evidence-collection-automation.md) — the collection architecture these mappings assume
- [Continuous Compliance Operations](continuous-compliance-operations.md) — operating model for evidence freshness and drift detection
- [Exception Management](exception-management.md) — risk-acceptance records (relevant to Art. 9(4)(e) "assessed")
- release-orchestration-framework — governance model, approval workflows, rollback decision tree, Best Practice #24
