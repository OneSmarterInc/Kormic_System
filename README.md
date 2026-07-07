# Kormic Agent Pedigree System

Welcome to the Kormic Agent Pedigree and Trust Architecture. This repository houses the core modules ensuring agent authenticity, structured identity, tamper-evident history, correctness monitoring, and catastrophic recovery at a global scale.

## Architecture Status

This system currently implements the **Phase 1 (Core Pedigree)** and **Phase 2 (Global Scale & Recovery)** specifications of the trust architecture. It operates via infrastructure-agnostic protocols and manages agent pedigrees separately from behavioral correctness. All cryptography relies on software-emulated HSMs prior to Phase 3 hardware hand-over.

---

## Phase 1 Features (Core Cryptography)

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
- *Note: All keys currently use software-based implementations and are strictly marked with `# DEV_KEY_NOT_PRODUCTION` for safe testing prior to Phase 3 hardware isolation.*

---

## Phase 2 Features (Global Scale & Recovery)

### 5. Encrypted Recovery Twins
- **High-Churn Snapshot Optimization:** Replaces per-event backup syncing with a bounded `K-event` snapshot model, saving massive amounts of network bandwidth at the cost of a strictly bounded data-loss window (e.g., losing a maximum of `K-1` events).
- **AES-256-GCM Vaults:** Each Twin Snapshot is locked with military-grade AES-256 encryption. The system verifies the cryptographic MAC to ensure the backup has never been tampered with.
- **Shamir Key Shattering:** The AES Master Key is generated, immediately split into a polynomial 5-part Shamir quorum (e.g., given to 5 executives), and then permanently destroyed from memory. 
- **Catastrophic Key Ceremonies:** To wake a Twin during a server fire, 3 of the 5 hardware shares must be mathematically reassembled.

### 6. Distributed Registry Fan-Out
- **Central Authority:** A single root authority packages all globally revoked agents into a version-controlled, ML-DSA-44 signed `RegistrySnapshot`.
- **Regional Replicas:** Edge servers (e.g., US-East, EU-West, India-South) act as decentralized read-nodes, pulling Snapshots to maintain local authority. 
- **Latency Realism:** System accurately models "Residual Risk Windows" where an agent might temporarily pass verification in a distant region due to the physics of network propagation delay.

### 7. Scalable Revocation (Bloom Filter)
- **Zero-Memory Checks:** Replicas load the revoked agent IDs into highly compressed `ScalableBloomFilters`. 
- **Instant Verdicts:** Allows O(1) checks for revocation status. If the Bloom Filter flags an agent as "Maybe Revoked," the system falls back to a Tier-2 authoritative dictionary lookup.

---

## Getting Started & Demos

You can run the full, interactive system demonstration for Phase 1 and 2 by running:

```bash
# Phase 1: Core Pedigree & Tamper-Evident History
python main.py

# Phase 1: Cryptographic Attack Simulation (Fails verification safely)
python demo_attack.py

# Phase 2: Global Scale, Network Lag, and Catastrophic Twin Recovery Demo
python demo_phase2.py
```

### Running Tests
The codebase is heavily tested. A massive unified end-to-end simulation covering all edge cases (Birth -> High Churn -> Behavior Halts -> Global Revocation Fan-out -> Bloom Filter Rejection -> Server Crash -> Shamir Key Ceremony Twin Recovery -> Verification) can be run via:

```bash
pytest tests/test_integration_unified.py -v
```
