# Standing Crypto Watch Baseline & Audit Rhythm

This document establishes the concrete baseline and review rhythm for the Standing Crypto Watch. Rather than a static checklist, this is a real, recurring, logged review integrated into our audit cadence. 

## 1. Concrete Baseline (As of August 2026)

To accurately detect drift, vulnerabilities, or required migrations, the Crypto Watch must compare current threat intelligence against the following concrete implementation baseline:

* Digital Signatures (Root, Epoch, Tokens): 
  * Algorithm: `ML-DSA-87` (Post-Quantum Lattice Signature, NIST Level 5)
  * Implementation: `dilithium_py` (Pure Python reference implementation)
  * Status: Marked as dev-grade. Not constant-time, not fault-resistant.
* History Chain Hashing & Event Logs: 
  * Algorithm: `SHA-256` (Agile, runtime dispatch active)
* At-Rest Twin Snapshot Encryption: 
  * Algorithm: `AES-256-GCM`
* Ceremony & Key Derivation:
  * Algorithm: `HMAC-SHA256` and Shamir Secret Sharing

## 2. Sources to Monitor

The watch tracks these sources for the triggers below. Whoever runs a review checks each of them against the baseline in Section 1:

* NIST PQC project and CSRC pages, for FIPS revisions and transition guidance (including NIST IR 8547).
* The pqc-forum mailing list, for early signal on parameter and standard changes.
* The release notes and CVE feed for each library we depend on (`dilithium_py`, `pycryptodome`).
* IACR ePrint, for lattice cryptanalysis touching Module-LWE security estimates relevant to ML-DSA.

## 3. Action Promotion Triggers

A watch item is promoted to a mandatory action item (Action/Migration) if any of the following triggers are met:

1. Implementation Vulnerability (CVE): A published CVE affecting our underlying cryptography library (e.g., `dilithium_py` or `pycryptodome`).
2. NIST Standard Updates: A formal NIST parameter modification, category change, or deprecation of an algorithm we currently employ.
3. Cryptanalytic Advances: A credible, published margin-reduction result against the lattice problem (impacting ML-DSA).
4. Deadline Approaches: The approach of the 2030 and 2035 NIST deprecation deadlines for quantum-vulnerable cryptography (though MeshKor currently holds no asymmetric vulnerable primitives).

## 4. Audit Rhythm & Logging

The Crypto Watch is not a passive document. 
* Review Schedule: The watch runs on a quarterly floor plus event-triggered checks. It is executed during scheduled audit rounds, and additionally at least once per quarter regardless of whether any code has shipped, so a quiet stretch with no pushes cannot leave the watch un-run. Any of the Section 3 triggers also forces an immediate review outside the schedule.
* Logging Requirement: Each review execution MUST be formally logged and recorded in the exact same manner as a standard audit round (e.g., as a dated markdown report in the `the_findings_and_audits` directory). If no triggers are met, the audit log must explicitly state "All baselines verified secure; no promotion triggers hit."
