# Kormic Agent Pedigree System

Welcome to the Kormic Agent Pedigree and Trust Architecture. This repository houses the core modules ensuring agent authenticity, structured identity, tamper-evident history, and correctness monitoring at scale.

## Currently Implemented Features (Phase 1 Core)

This system currently implements the Phase 1 specification of the trust architecture. It operates via infrastructure-agnostic protocols and manages agent pedigrees separately from behavioral correctness.

### 1. Agent Pedigree & History Chain
- **Structured Identity:** Implements the `KMC.<type>.<entity_ref>.<instance>.<realid_hash>` format to ensure safe, immutable identities bound to real-world entities.
- **Birth Records:** Every agent receives a sealed birth record upon creation containing its identity, guardrails, and creation timestamp, serialized canonically and cryptographically signed.
- **Tamper-Evident History:** Operational events are appended as history links, each containing the SHA-256 hash of the previous link.
- **Constant-Size Summary:** Avoids O(N) linear growth limits by tracking a fixed 64-byte `running_head` that updates with every new event, mathematically summarizing the entire history up to that point.

### 2. Verification Engine
- **FAST Verification (O(1)):** Rapidly confirms an agent's authenticity by verifying the origin signature and matching the current running head without traversing the entire history chain.
- **FULL Verification (O(N)):** Reconstructs the entire hash chain from the birth record, validating every link for dispute resolution and deep audits.
- **Trust Cache:** Supports short-lived trusted tickets to bypass expensive signature verifications on repeated checks, dramatically improving speed while preserving security.

### 3. Behavioral Monitoring (The Watchdog)
- **Decoupled Evaluator:** Operates entirely independently of the pedigree (cryptographic) system.
- **Metric Thresholds:** Evaluates rolling metrics including accuracy, overconfidence, guardrail hits, and latency drift.
- **Tiered Verdicts:** Automatically outputs `OK`, `FLAG`, or `HALT` verdicts based on tunable thresholds, isolating genuine agents that misbehave.

### 4. Cryptographic Key Custody (Dev/Software Mode)
- **Epoch Keys:** Uses a root-and-epoch hierarchy for key rotation and revocation.
- **Post-Quantum Signatures:** Implements real ML-DSA-44 post-quantum signature logic for birth record signing.
- **Threshold Key (Shamir Secret Sharing):** Implements a k-of-n polynomial split (e.g., 3-of-5) for threshold key reconstruction using PyCryptodome. 
- *Note: All keys currently use software-based implementations and are strictly marked with `# DEV_KEY_NOT_PRODUCTION` for safe testing prior to Phase 3 hardware isolation.*

### 5. Agent Manager
- **Unified Wrapper:** Simplifies agent integration by providing a single interface to generate identities, sign birth records, initialize pedigrees, and commit data to the RecordStore.

---