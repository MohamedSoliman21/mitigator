# Security Policy

## Supported Versions

Security updates are applied to the **latest minor release** of each major version.

| Version | Supported         |
| ------- | ----------------- |
| 1.x.x   | ✅ Active support |

---

## Reporting a Vulnerability

**Please do NOT open a public GitHub issue for security vulnerabilities.**

Disclosing vulnerabilities publicly before a patch is available puts all users at risk.

### How to Report

1. **Email**: Send a detailed report to the maintainers privately. Include:
   - A clear description of the vulnerability and its potential impact.
   - Steps to reproduce (proof-of-concept code is strongly encouraged).
   - The affected version(s) and module(s) (e.g., `node-mitigator/auth`, `node-mitigator/crypto`).
   - Any suggested mitigations or patches you may have.

2. **GitHub Private Advisory** _(preferred)_: Use the
   [GitHub Security Advisories](https://github.com/features/security/advisories) feature
   on this repository:
   - Navigate to **Security → Advisories → Report a vulnerability**.

### Response Timeline

| Stage                         | Target                                                    |
| ----------------------------- | --------------------------------------------------------- |
| Acknowledgement               | Within **48 hours** of report receipt                     |
| Triage & severity assessment  | Within **5 business days**                                |
| Patch release (Critical/High) | Within **14 days** of confirmation                        |
| Patch release (Medium/Low)    | Next scheduled minor release                              |
| Public disclosure             | Coordinated with reporter — typically 90 days after patch |

---

## Scope

The following are **in scope** for this policy:

- All modules under `src/` in this repository.
- The `mitigator-audit` CLI binary.
- Published npm package versions listed in **Supported Versions** above.

The following are **out of scope**:

- Vulnerabilities in third-party dependencies (report to the respective upstream project).
- Issues requiring physical access to the host machine.
- Denial-of-service via resource exhaustion that requires authentication credentials.

---

## Severity Classification

We use the [CVSS v3.1](https://www.first.org/cvss/v3.1/specification-document) scoring
system and map scores to the following severities:

| CVSS Score | Severity |
| ---------- | -------- |
| 9.0 – 10.0 | Critical |
| 7.0 – 8.9  | High     |
| 4.0 – 6.9  | Medium   |
| 0.1 – 3.9  | Low      |

---

## Safe Harbor

We consider good-faith security research conducted in accordance with this policy to be
authorized. We will not initiate legal action against researchers who:

- Report vulnerabilities through the channels described above.
- Do not exploit vulnerabilities beyond demonstrating the proof-of-concept.
- Do not access, modify, or exfiltrate user data.
- Do not perform denial-of-service attacks against production systems.

---

## Acknowledgements

We are grateful to all security researchers who responsibly disclose vulnerabilities.
Contributors who report valid confirmed vulnerabilities will be acknowledged in the
relevant release notes unless they prefer to remain anonymous.
