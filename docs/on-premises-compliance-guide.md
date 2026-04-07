# On-Premises and Hybrid Compliance Automation

The Compliance Automation Framework's core guidance is primarily designed for cloud-native environments, where native APIs, serverless functions, and managed storage make automated evidence collection straightforward. On-premises and hybrid environments present distinct challenges: diverse infrastructure APIs, network segmentation that limits central collection, and tooling that lacks the cloud-native integration hooks that make automation easy.

This guide addresses those gaps — providing evidence collection patterns, tooling recommendations, and hybrid architectures that work across data centers, private clouds, and hybrid environments where cloud and on-premises systems coexist.

---

## On-Premises Compliance Challenges

| Challenge | Cloud Equivalent | On-Premises Reality |
|-----------|-----------------|-------------------|
| IAM inventory | Single API call to cloud provider IAM | Multiple directory systems (Active Directory, LDAP), local accounts, application-specific users |
| Configuration scanning | CSPM APIs with continuous drift detection | Manual CIS benchmarks, periodic scans, no continuous monitoring |
| Audit log centralization | Cloud provider native log aggregation | Multiple disparate log sources, syslog, Windows Event Log, application logs |
| Evidence storage | S3 Object Lock / Azure Blob immutable | On-premises object storage or file systems without native immutability |
| Change management evidence | CI/CD pipeline API events | Manual change management systems, ITSM tools (ServiceNow, BMC Remedy) |

---

## Evidence Collection Architecture for On-Premises

### Agent-Based Collection

In environments where central API access is unavailable or impractical, deploy lightweight agents on each system to collect evidence locally and forward to a central store:

```
┌─────────────────────────────────────────────────────────┐
│                  On-Premises Infrastructure              │
│                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐              │
│  │ Server A │  │ Server B │  │ Server C │              │
│  │ (Agent)  │  │ (Agent)  │  │ (Agent)  │              │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘              │
│       └─────────────┴─────────────┘                     │
│                      │                                   │
│              ┌────────▼────────┐                         │
│              │  Evidence       │                         │
│              │  Aggregator     │                         │
│              │  (on-prem)      │                         │
│              └────────┬────────┘                         │
└───────────────────────┼─────────────────────────────────┘
                         │  Forwarding (HTTPS/TLS)
                         ▼
              ┌──────────────────────┐
              │   Central Evidence   │
              │   Store              │
              │   (on-prem or cloud) │
              └──────────────────────┘
```

**Agent options:**

| Agent | Best For | Protocol |
|-------|---------|---------|
| **Fluentd / Fluent Bit** | Log-based evidence (auth events, configuration changes) | TCP/TLS, HTTP |
| **Wazuh** | System integrity monitoring, CIS benchmarks, compliance evidence | TLS |
| **Osquery** | SQL-based system state queries (user accounts, installed software, network connections) | TLS to Fleet/osctrl |
| **Chef InSpec** | Configuration compliance checks across diverse OS types | Push or pull |
| **Custom Python agent** | Proprietary system APIs, ITSM integration | HTTPS |

### Osquery for Cross-Platform Evidence Collection

Osquery provides a SQL interface to system state, making it practical for collecting evidence from diverse Linux, Windows, and macOS systems using a unified query language:

```sql
-- Osquery: Collect user account evidence for access control
SELECT
    u.username,
    u.uid,
    u.gid,
    u.description,
    u.directory,
    u.shell,
    g.groupname AS primary_group,
    datetime(u.created, 'unixepoch') AS created_at
FROM users u
LEFT JOIN groups g ON u.gid = g.gid
WHERE u.uid >= 1000  -- Exclude system accounts (adjust threshold for Windows)
ORDER BY u.username;

-- Osquery: Collect open network connections for network segmentation evidence
SELECT
    p.name AS process,
    p.pid,
    s.local_address,
    s.local_port,
    s.remote_address,
    s.remote_port,
    s.state,
    s.protocol
FROM process_open_sockets s
JOIN processes p ON s.pid = p.pid
WHERE s.state = 'ESTABLISHED'
ORDER BY p.name;

-- Osquery: Software inventory for vulnerability management
SELECT
    name,
    version,
    install_date,
    install_location
FROM programs  -- Windows
-- For Linux, use: FROM deb_packages or rpm_packages
ORDER BY name;
```

**Scheduled evidence collection with osquery:**

```json
{
  "schedule": {
    "compliance_users_daily": {
      "query": "SELECT username, uid, gid, shell FROM users WHERE uid >= 1000;",
      "interval": 86400,
      "snapshot": true,
      "description": "Daily user account inventory for access control evidence"
    },
    "compliance_listening_ports_daily": {
      "query": "SELECT pid, port, protocol, address FROM listening_ports;",
      "interval": 86400,
      "snapshot": true,
      "description": "Daily listening port inventory for network security evidence"
    },
    "compliance_sudoers_weekly": {
      "query": "SELECT source, header, spec FROM sudoers;",
      "interval": 604800,
      "snapshot": true,
      "description": "Weekly sudoers configuration for privileged access evidence"
    }
  }
}
```

---

## Active Directory / LDAP Evidence Collection

Active Directory is the primary identity store in most on-premises environments. Automated collection of AD state provides access control evidence for SOC 2 CC6.1-CC6.3 and ISO 27001 A.8.2.

```python
# ad_evidence_collector.py — Collect AD user inventory for compliance
import ldap3
import json
import hashlib
from datetime import datetime, timezone

def collect_ad_users(
    ldap_server: str,
    bind_dn: str,
    bind_password: str,
    search_base: str,
    output_path: str,
) -> dict:
    server = ldap3.Server(ldap_server, use_ssl=True)
    conn = ldap3.Connection(server, user=bind_dn, password=bind_password, auto_bind=True)

    conn.search(
        search_base=search_base,
        search_filter="(&(objectClass=user)(objectCategory=person))",
        attributes=[
            "sAMAccountName",
            "displayName",
            "mail",
            "memberOf",
            "accountExpires",
            "userAccountControl",
            "pwdLastSet",
            "lastLogonTimestamp",
            "whenCreated",
            "whenChanged",
        ],
    )

    users = []
    for entry in conn.entries:
        uac = int(entry.userAccountControl.value) if entry.userAccountControl else 0
        users.append({
            "username": str(entry.sAMAccountName),
            "display_name": str(entry.displayName) if entry.displayName else None,
            "email": str(entry.mail) if entry.mail else None,
            "account_disabled": bool(uac & 0x0002),
            "password_never_expires": bool(uac & 0x10000),
            "groups": [str(g) for g in entry.memberOf] if entry.memberOf else [],
            "created": str(entry.whenCreated.value) if entry.whenCreated else None,
            "last_modified": str(entry.whenChanged.value) if entry.whenChanged else None,
            "last_logon": str(entry.lastLogonTimestamp.value) if entry.lastLogonTimestamp else None,
        })

    evidence = {
        "evidence_type": "active_directory_user_inventory",
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "server": ldap_server,
        "search_base": search_base,
        "total_users": len(users),
        "disabled_users": sum(1 for u in users if u["account_disabled"]),
        "framework_controls": ["SOC2-CC6.1", "SOC2-CC6.3", "ISO27001-A.8.2", "PCI-DSS-8.2"],
        "data": users,
    }

    content = json.dumps(evidence, sort_keys=True, default=str).encode()
    evidence["content_hash"] = hashlib.sha256(content).hexdigest()

    with open(output_path, "w") as f:
        json.dump(evidence, f, indent=2, default=str)

    return {"user_count": len(users), "output": output_path}
```

---

## On-Premises CIS Benchmark Compliance

Cloud environments have CSPM tools (Prowler, Scout Suite) that automate CIS benchmark checks. For on-premises, Chef InSpec is the most portable solution for CIS-certified compliance profiles.

### Chef InSpec for CIS Benchmarks

```bash
# Install InSpec
curl https://omnitruck.chef.io/install.sh | bash -s -- -P inspec

# Run CIS Benchmark for RHEL 8 (InSpec CIS profile from Chef Marketplace)
inspec exec https://github.com/dev-sec/cis-dil-benchmark \
  --target ssh://user@server-hostname \
  --key-files /etc/inspec/scan-key \
  --reporter json:/tmp/cis-report-$(hostname).json \
  --controls /CIS-1 /CIS-2 /CIS-3  # Run specific CIS sections

# Run CIS Windows Server 2022 benchmark
inspec exec https://github.com/mitre/microsoft-windows-server-2022-stig-baseline \
  --target winrm://administrator@windows-server \
  --password "${WINRM_PASSWORD}" \
  --reporter json:/tmp/cis-windows-$(hostname).json
```

**Aggregating results from multiple servers:**

```python
# aggregate_inspec_results.py — Combine InSpec results across fleet
import json
import os
import glob
from datetime import datetime, timezone

def aggregate_inspec_results(results_dir: str, framework_controls: list[str]) -> dict:
    results = []
    for report_file in glob.glob(f"{results_dir}/cis-report-*.json"):
        with open(report_file) as f:
            report = json.load(f)
            hostname = os.path.basename(report_file).replace("cis-report-", "").replace(".json", "")
            controls_summary = {
                "hostname": hostname,
                "passed": sum(1 for c in report.get("controls", []) if c.get("status") == "passed"),
                "failed": sum(1 for c in report.get("controls", []) if c.get("status") == "failed"),
                "skipped": sum(1 for c in report.get("controls", []) if c.get("status") == "skipped"),
                "failed_controls": [
                    {"id": c["id"], "title": c["title"]}
                    for c in report.get("controls", [])
                    if c.get("status") == "failed"
                ],
            }
            results.append(controls_summary)

    evidence = {
        "evidence_type": "cis_benchmark_compliance",
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "total_servers": len(results),
        "servers_fully_compliant": sum(1 for r in results if r["failed"] == 0),
        "framework_controls": framework_controls,
        "server_results": results,
    }

    return evidence
```

---

## On-Premises Immutable Evidence Storage

S3 Object Lock provides the reference implementation for tamper-evident evidence storage. On-premises equivalents:

### MinIO with Object Lock

```bash
# Deploy MinIO with Object Lock enabled (on-premises S3-compatible storage)
docker run -d \
  -p 9000:9000 \
  -p 9001:9001 \
  -v /data/minio:/data \
  -e MINIO_ROOT_USER=compliance-admin \
  -e MINIO_ROOT_PASSWORD="${MINIO_ADMIN_PASSWORD}" \
  --name minio \
  quay.io/minio/minio server /data --console-address ":9001"

# Create evidence bucket with Object Lock
mc alias set onprem http://minio:9000 compliance-admin "${MINIO_ADMIN_PASSWORD}"
mc mb --with-lock onprem/compliance-evidence

# Set default retention policy (COMPLIANCE mode, 7 years)
mc retention set --default COMPLIANCE "7y" onprem/compliance-evidence

# Upload evidence with object lock
mc cp --retention-mode COMPLIANCE --retention-duration "7y" \
  evidence.json \
  onprem/compliance-evidence/access-control/2026/01/15/iam-inventory.json
```

### Immutability with Hash Chains (Alternative)

For environments where object storage with object lock is unavailable, use a cryptographic hash chain to provide tamper evidence:

```python
# hash_chain_evidence.py — Build a verifiable hash chain for evidence files
import hashlib
import json
from pathlib import Path

def compute_file_hash(file_path: str) -> str:
    with open(file_path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

def build_evidence_chain(evidence_dir: str, chain_file: str):
    """
    Build a hash chain linking all evidence files in a directory.
    The chain provides tamper evidence: modifying any file breaks the chain.
    """
    chain = []
    prev_hash = "genesis"

    for evidence_file in sorted(Path(evidence_dir).glob("**/*.json")):
        file_hash = compute_file_hash(str(evidence_file))
        chain_entry = {
            "file": str(evidence_file.relative(evidence_dir)),
            "file_hash": file_hash,
            "prev_chain_hash": prev_hash,
            "chain_hash": hashlib.sha256(
                f"{prev_hash}:{file_hash}".encode()
            ).hexdigest(),
        }
        prev_hash = chain_entry["chain_hash"]
        chain.append(chain_entry)

    with open(chain_file, "w") as f:
        json.dump({"chain": chain, "head_hash": prev_hash}, f, indent=2)

    return prev_hash
```

---

## ITSM Integration for Change Management Evidence

In on-premises environments, change management is often managed in ITSM platforms (ServiceNow, BMC Remedy, Jira Service Management). Automated extraction of change records provides the change management evidence required for SOC 2 CC8.1 and ISO 27001 A.8.32.

```python
# servicenow_evidence_collector.py — Extract change records from ServiceNow
import requests
import json
from datetime import datetime, timezone, timedelta
import hashlib

def collect_change_records(
    instance_url: str,
    username: str,
    password: str,
    period_start: datetime,
    period_end: datetime,
    output_path: str,
) -> dict:
    """Collect approved change records from ServiceNow for the specified period."""

    query_params = {
        "sysparm_query": (
            f"state=3"  # 3 = Closed/Implemented
            f"^opened_at>={period_start.strftime('%Y-%m-%d %H:%M:%S')}"
            f"^opened_at<={period_end.strftime('%Y-%m-%d %H:%M:%S')}"
        ),
        "sysparm_fields": (
            "number,short_description,state,priority,risk,change_model,"
            "opened_at,closed_at,opened_by,assigned_to,approval,"
            "cab_date,cab_recommendation"
        ),
        "sysparm_limit": 1000,
    }

    response = requests.get(
        f"{instance_url}/api/now/table/change_request",
        auth=(username, password),
        params=query_params,
        headers={"Accept": "application/json"},
    )
    response.raise_for_status()
    records = response.json().get("result", [])

    evidence = {
        "evidence_type": "itsm_change_records",
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "period_start": period_start.isoformat(),
        "period_end": period_end.isoformat(),
        "source": instance_url,
        "total_records": len(records),
        "framework_controls": ["SOC2-CC8.1", "ISO27001-A.8.32", "PCI-DSS-6.4"],
        "data": records,
    }

    content = json.dumps(evidence, sort_keys=True, default=str).encode()
    evidence["content_hash"] = hashlib.sha256(content).hexdigest()

    with open(output_path, "w") as f:
        json.dump(evidence, f, indent=2)

    return {"record_count": len(records), "output": output_path}
```

---

## Hybrid Architecture: On-Premises + Cloud

Many organizations run a hybrid estate where some systems are in the cloud and others remain on-premises. A unified evidence collection architecture spans both:

```
┌─────────────────────────────┐    ┌─────────────────────────────┐
│   On-Premises Infrastructure │    │   Cloud Infrastructure      │
│                              │    │                              │
│  [InSpec agents]            │    │  [CloudTrail / Activity Logs]│
│  [osquery fleet]            │    │  [IAM Access Analyzer]       │
│  [AD/LDAP collectors]       │    │  [CSPM (Prowler/ScoutSuite)] │
│  [ITSM API collectors]      │    │  [CI/CD pipeline events]     │
│                              │    │                              │
│  ┌──────────────────┐       │    │  ┌──────────────────┐       │
│  │ On-Prem Evidence │       │    │  │  Cloud Evidence  │       │
│  │ Aggregator       │       │    │  │  Collector       │       │
│  │ (Wazuh / custom) │       │    │  │  (Lambda/Cloud   │       │
│  └────────┬─────────┘       │    │  │   Run)           │       │
│            │ HTTPS forward  │    │  └────────┬─────────┘       │
└────────────┼─────────────────┘    └──────────┼─────────────────┘
             │                                  │
             └────────────┬─────────────────────┘
                           │
                  ┌─────────▼──────────┐
                  │  Central Evidence  │
                  │  Store             │
                  │  (MinIO Object     │
                  │  Lock or S3)       │
                  └─────────┬──────────┘
                             │
                  ┌─────────▼──────────┐
                  │  Compliance DB     │
                  │  (PostgreSQL)      │
                  │  + Dashboard       │
                  └────────────────────┘
```

### Unified Control Coverage Tracking

The compliance database tracks evidence from both cloud and on-premises sources against the same control inventory:

```sql
-- Map controls to evidence sources spanning on-prem and cloud
INSERT INTO control_evidence_sources (control_id, source_type, source_name, collection_method, cadence) VALUES
  ('SOC2-CC6.1', 'on_premises', 'active_directory_users', 'LDAP query', 'daily'),
  ('SOC2-CC6.1', 'cloud',       'aws_iam_users',          'AWS IAM API',  'daily'),
  ('SOC2-CC6.1', 'cloud',       'azure_ad_users',         'MS Graph API', 'daily'),
  ('SOC2-CC8.1', 'on_premises', 'servicenow_changes',     'ServiceNow API','daily'),
  ('SOC2-CC8.1', 'cloud',       'github_deployments',     'GitHub API',   'event-driven'),
  ('CIS-2.1',    'on_premises', 'inspec_cis_rhel',        'InSpec agent', 'weekly'),
  ('CIS-2.1',    'cloud',       'prowler_cis_aws',        'Prowler scan', 'weekly');
```

---

## Related Techstream Resources

| Topic | Document |
|-------|---------|
| Core evidence collection architecture | [Evidence Collection Automation](evidence-collection-automation.md) |
| Exception management | [Exception Management](exception-management.md) |
| FedRAMP guidance | [FedRAMP Implementation Guide](fedramp-implementation-guide.md) |
| Geographic compliance | [Geographic Compliance](geographic-compliance.md) |
| Framework-wide compliance matrix | [Regulatory Controls Matrix](regulatory-controls-matrix.md) |

*Part of the Techstream Compliance Automation Framework. Licensed under Apache 2.0.*
