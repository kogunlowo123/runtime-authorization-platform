# Compliance control mapping

Evidence names the artifact an auditor can inspect. Mappings show where the
platform contributes to a control; the deploying organization remains
responsible for the control as a whole.

| Control objective | HIPAA Security Rule | SOC 2 (TSC 2017) | ISO/IEC 27001:2022 | NIST SP 800-53 r5 | NIST AI RMF 1.0 | 21 CFR Part 11 / GxP | Evidence |
|---|---|---|---|---|---|---|---|
| Least privilege per action | 164.308(a)(4) | CC6.1, CC6.3 | 5.15, 8.2 | AC-3, AC-6 | MANAGE 2.4 | 11.10(g) | Action catalog, policy, `/v1/decisions` records |
| Attribute-based access decisions | 164.312(a)(1) | CC6.1 | 8.3 | AC-3(13), AC-16 | MAP 3.5 | 11.10(d) | Policy facts, PIP sources in decision log |
| Human oversight of high-risk agent actions | — | CC6.2 | 5.18 | AC-3(2) (dual authorization) | GOVERN 1.4, MANAGE 2.3 | 11.10(g), 11.200 | Intent approvals (approver id, time) |
| Separation of duties | 164.308(a)(3) | CC6.3 | 5.3 | AC-5 | GOVERN 2.1 | 11.10(g) | Author cannot activate; declarer cannot approve |
| Authentication of callers | 164.312(d) | CC6.1 | 5.17, 8.5 | IA-2, IA-8, IA-9 | — | 11.300 | Entra ID validation, fabric introspection |
| Change control of authorization policy | 164.308(a)(8) | CC8.1 | 8.32 | CM-3, CM-4 | GOVERN 1.4 | 11.10(k) | Policy versions with test reports, digests, activation audit events, CODEOWNERS |
| Testing of security controls | 164.308(a)(8) | CC7.1 | 8.29 | CA-2, SA-11 | MEASURE 2.7 | CSV/CSA OQ | Policy unit tests in CI, security test suite |
| Audit trail integrity | 164.312(b) | CC7.2 | 8.15 | AU-9, AU-10 | MEASURE 2.8 | 11.10(e) | Signed per-replica chains in immutable storage; `verify_chain` |
| Decision traceability | 164.312(b) | CC7.2 | 8.15 | AU-3, AU-12 | MEASURE 2.9 | 11.10(e) | Decision log: policy digest, rules, intent, sources |
| Emergency access restriction | 164.308(a)(6) | CC7.4 | 5.26 | IR-4, AC-2(13) | MANAGE 4.1 | — | Action blocks (audited) |
| Data classification enforcement | 164.312(a)(1) | C1.1 | 5.12, 5.13 | AC-16, AC-21 | MAP 2.3 | — | Clearance ceiling; purpose-of-use rule |
| Monitoring and response | 164.308(a)(6) | CC7.3 | 5.24, 8.16 | SI-4, IR-5 | MANAGE 4.1 | — | Alert rules, incident runbook |
| Availability and recovery | 164.308(a)(7) | A1.2, A1.3 | 8.13, 8.14 | CP-9, CP-10 | — | — | HA database, PDB, DR runbook |
| Supply-chain integrity | — | CC8.1 | 5.21 | SR-3, SR-11 | GOVERN 6.1 | — | SBOM, Grype, Trivy, provenance attestation |

HITRUST CSF: the rows above map through its harmonized NIST 800-53 and ISO
27001 references (access control 01.c/01.v, audit logging 09.aa/09.ab,
change control 10.k).

GxP: in GxP contexts, the decision log and signed audit chain provide
attributable, time-stamped, tamper-evident records of which agent was
authorized to act on which record, under which approved policy version, with
whose approval. Validation (IQ/OQ/PQ, or FDA CSA risk-based assurance) can
use the CI run of the deployed tag as OQ evidence for the acceptance
criteria in `docs/architecture/overview.md`.
