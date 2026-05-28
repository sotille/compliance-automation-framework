# Control-to-Policy Mapping Examples

This document provides concrete examples of how compliance controls map to Policy-as-Code expressions.

## Example mappings

### SOC2 CC8.1 (Change Management) → OPA / Kyverno

**Control intent:** All changes to production are reviewed, approved, and tracked.

**Policy implementation (OPA / Rego):**
```rego
package deploy.approval

default allow = false

allow {
  input.pull_request.approvals_count >= 2
  input.pull_request.required_reviewers_satisfied == true
  input.pull_request.ci_passed == true
}
```

### NIST SP 800-53 AC-3 (Access Enforcement) → Kyverno

**Control intent:** Enforce least-privilege access to Kubernetes resources.

**Policy implementation (Kyverno):**
```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: deny-cluster-admin-binding
spec:
  validationFailureAction: enforce
  rules:
    - name: no-cluster-admin
      match:
        resources:
          kinds:
            - ClusterRoleBinding
      validate:
        message: "ClusterRoleBinding to cluster-admin is prohibited."
        pattern:
          roleRef:
            name: "!cluster-admin"
```

### PCI-DSS 6.4 (Secure Development) → CI Gate Policy

**Control intent:** All code is scanned before deployment.

**Policy implementation (Conftest / OPA):**
```rego
package ci.gate

deny[msg] {
  input.scan.sast.critical_findings > 0
  msg := sprintf("SAST critical findings present (%v); deployment blocked.", [input.scan.sast.critical_findings])
}

deny[msg] {
  input.scan.sca.high_findings_unverified > 0
  msg := sprintf("SCA high findings without VEX exception (%v); deployment blocked.", [input.scan.sca.high_findings_unverified])
}
```

### NIST SP 800-53 SI-3 (Malicious Code Protection) → Container Scan Gate

**Control intent:** Container images are scanned for malware/malicious code before deployment.

**Policy implementation (Kyverno + Trivy):**
```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: deny-vulnerable-images
spec:
  validationFailureAction: enforce
  rules:
    - name: require-trivy-scan-clean
      match:
        resources:
          kinds: [Pod]
      verifyImages:
        - imageReferences:
            - "*"
          attestations:
            - type: https://trivy.dev/scan/v1
              attestors:
                - entries:
                    - keyless:
                        subject: "ci-runner@yourorg.example"
                        issuer: "https://token.actions.githubusercontent.com"
              conditions:
                - all:
                    - key: "{{ vulnerabilities.critical }}"
                      operator: Equals
                      value: 0
```

## How to extend this guide

For each new control you want to automate:
1. Identify the control intent (one sentence)
2. Identify the enforcement point (CI gate, admission controller, runtime monitor)
3. Choose the policy engine (OPA, Kyverno, Cedar, etc.)
4. Write the policy with explicit deny conditions
5. Test against known good and known bad inputs
6. Add to your policy library with documentation
