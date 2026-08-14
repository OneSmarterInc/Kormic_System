# Kormic Agent Pedigree System

Welcome to the Kormic Agent Pedigree and Trust Architecture. This repository houses the core modules ensuring agent authenticity, structured identity, tamper-evident history, correctness monitoring, and catastrophic recovery at a global scale.

## Architecture Status

This system currently implements the **Phase 1 (Core Pedigree)** and **Phase 2 (Global Scale & Recovery)** specifications of the trust architecture. It operates via infrastructure-agnostic protocols and manages agent pedigrees separately from behavioral correctness. All cryptography relies on software-emulated HSMs prior to Phase 3 hardware hand-over.

---

## Phase 1 Features (Core Cryptography)

### 1. Agent Pedigree & History Chain
- **Structured Identity:** Implements the `KMC.<type>.<entity_ref>.<instance>.<realid_hash>` format to ensure safe, immutable identities bound to real-world entities.
- **Birth Records (Self-Describing):** Every agent receives a sealed birth record containing its identity, guardrails, and creation timestamp. For crypto-agility, records are strictly self-describing, structurally sealing the cryptographic algorithm (`sig_alg`) and format version (`fmt_ver`) directly into the payload.
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

### 4. Cryptographic Key Custody & Crypto-Agility (Dev/Software Mode)
- **Epoch Keys:** Uses a root-and-epoch hierarchy for key rotation and revocation.
- **Crypto-Agility:** The system is fully algorithm-parametric for both signatures and hashing. Signatures explicitly declare their algorithm (`sig_alg`), and the history chain hash algorithm is declared at birth (`hash_alg`). The `MLDSASigner` and hash serializers dispatch validation dynamically, structurally preventing downgrade attacks while enabling safe migration to new standards.
- **Post-Quantum Signatures:** Upgraded to NIST Level 5 (`ML-DSA-87`) as the default for all root, epoch, and birth record signatures.
- **Agile Hash Strategy:** The system defaults to `SHA-256` for constant-size history chain link hashing and running head calculations, but is fully agile and allows allowlisted standards like `SHA3-256`.
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

## Phase 2.5 Features (Rogue-Agent Countermeasures)
This module hardens the runtime environment to mitigate shared-runtime bleed (like the 2026 Varonis Dialogflow incident) and unauthorized destructive actions (like the Replit incident).

### 8. Capability Manifest & Sandbox (C1)
- **Manifest Isolation:** The loose `guardrails` dict is upgraded to a strict capability manifest defining exactly what tools and network endpoints an agent can reach.
- **Runtime Enforcer:** The `Sandbox` wraps the agent at boot. It blocks any tools or endpoints not explicitly allowed in the manifest, ensuring shared infrastructure does not equate to shared authority.

### 9. Credential Root & FAST Challenge (C2 & Gap 1)
- **Fail-Closed Verification:** The FAST engine is mathematically forced to fail-closed, entirely rejecting "keyless" birth records and instantly blocking tokens missing signatures.
- **Anti-Replay Nonce Engine:** Agents must mathematically sign a random, server-issued challenge to prove possession of their birth keys. A strict 5-minute freshness window and memory-safe spent-nonce cache completely close the token-theft replay gap.
- **No Ambient Authority:** Agents do not receive standing API keys. They request 5-minute scoped credentials from the `CredentialRoot`. 
- **Irreversible Scopes:** Destructive actions (like refunds or deletes) are explicitly flagged and must be declared at birth to be issued.

### 10. Drift HALT Wiring
- **Automatic Revocation:** If the Sandbox blocks an out-of-manifest action, it registers a `MANIFEST_BREACH` in the Tamper-Evident History.
- **Behavioral Loop:** The breach is fed to the `BehaviorMonitor` which issues a `HALT`, automatically triggering global revocation via the `CentralRegistryAuthority`.

---

## Phase 3 Features (Hardware Readiness & Human Quorum)
This module secures the existential actions (Create, Destroy, Restore) and removes single points of failure at the human/admin layer.

### 11. Threshold Ceremony (Shamir Quorum)
- **Existential Quorums:** Generating an agent, restoring a Twin, or destroying a single agent mathematically requires `3-of-5` physical keys.
- **Catastrophic Quorum:** A total wipe of the registry requires the absolute largest quorum (`5-of-5`). No single "God Key" exists.
- **Cryptographic Key Validation:** Reconstructed keys are verified via constant-time HMAC validation against expected secure hashes, physically preventing fake or "math garbage" shares from passing the quorum.

### 12. Self-Defense
- **Self-Isolation:** Agents can voluntarily pull their own plug if they detect prompt-injection manipulation.
- **No Self-Destruct:** Reversible isolation is automated; irreversible destruction is strictly kept behind the human Threshold Quorum.

---

## Phase 4 Features (MeshKor SDK & Concurrency Safety)
This phase productizes the mathematical models into a usable, high-performance Python SDK.

### 13. Drop-in Abstractions
- **MeshKorAgent / ReceiverClient:** Hides the complexity of Pedigrees, ProofTokens, and Bloom Filters behind simple abstractions. `ReceiverClient.validate()` seamlessly validates incoming actions, while agents interact with `CredentialRoot.issue_scoped_credential()` for secure 5-minute scoped execution tokens.

### 14. High-Performance Concurrency
- **Sub-Millisecond SQLite:** Migrated from individual filesystem JSON blobs to a shared, persistent SQLite connection using Write-Ahead Logging (WAL) and memory pragmas, dropping write latency to <0.9ms.
- **Double-Lock Serialization:** Implemented strict per-agent threading locks and connection locks. This mathematically ensures that hundreds of multi-threaded AI events occurring simultaneously are never dropped or overwritten, maintaining absolute chain integrity.
- **Strict Default Security:** Cross-region Replay Protection is explicitly enforced by default via `central_sync` wiring.

---

## Phase 5 Features (Two-Tier Identity & Containment)
This phase solves the commercial "multi-tenant" problem, ensuring that a software vendor's build identity and a hospital's deployment identity are strictly separated, without creating a single point of failure.

### 15. The BAIN & DAIN Split
- **Build AIN (BAIN):** Issued to the software vendor for an immutable software release. It seals the *capability envelope* (the maximum allowed permissions).
- **Deployment AIN (DAIN):** Issued to the customer for a specific running instance. It seals the *operating manifest*, owner, and storage locus. It cryptographically links back to the BAIN.

### 16. Containment Envelopes
- **Mathematical Ceiling:** During DAIN enrollment, the requested operating manifest is strictly verified to be a subset of the parent BAIN's capability envelope. A customer cannot grant more power than the vendor allowed, and a vendor cannot silently expand a running deployment's permissions.

### 17. The Revocation Kill Switch
- **Two-Tier FAST Verification:** The `Verifier` Engine simultaneously authenticates both the DAIN signature and the parent BAIN signature.
- **Cascading Revocation:** If a vendor discovers a zero-day vulnerability in their software and revokes the `BAIN`, every single `DAIN` derived from that build is instantly and mathematically rejected by the system worldwide.

### 18. Cryptographic Storage Isolation
- **Per-Deployment Salt:** To ensure cross-deployment privacy, each DAIN is issued a unique cryptographic salt that is stored *only* in the local SQLite database. It is never transmitted to the global registry, ensuring that event hashes cannot be correlated by observers or the vendor.

### 19. Vendor Enrollment & Anti-Squatting
- **Bind-Once Namespaces:** Vendors must cryptographically enroll their identities to mint BAINs. The registry uses a strict `Bind-Once` invariant, guaranteeing an enterprise namespace (like "Acme") can never be silently overwritten or squatted by an attacker.
- **Proof of Possession (Replay-Protected):** Enrollment enforces strict Challenge-Response cryptography. The vendor must mathematically prove ownership of the private key by signing a payload binding a fresh ML-DSA challenge nonce issued by the central authority to their exact entity name (`f"{nonce}:{name}"`). The Central Authority enforces strict single-use memory on all challenges, making token-theft replays or namespace hijacking mathematically impossible.
- **Root-Signed Replication:** The vendor identity list is packaged into the global `RegistrySnapshot`. Replicas do not rely on local databases for vendor truth; they mathematically verify the root signature of the global snapshot to establish identity consistency worldwide.

## Phase 6 Features (Reconnaissance Gap Defenses & Identity-Bound Approval)
This phase strictly seals the "Reconnaissance Gap," where compromised agents could steal data without triggering an active log entry, protecting systems from scenarios like the Hugging Face RCE breach and Reddit scraping incident.

### 20. Read-Scope Manifests
- **Cryptographic Read Boundaries:** The `BirthRecord` securely seals `read_scopes` and `allowed_egress` manifests. A child deployment (DAIN) is mathematically constrained; it can only declare read scopes that are a strict subset of its parent vendor's authorized limits. 

### 21. Session-Scoped Environment Evaporation
- **Standing Credential Defense:** When an agent sandbox is initialized, the `Evaporator` securely scopes its execution context. Rather than altering the host machine's global environment, it identifies standing credentials (matching keys like `AWS`, `SECRET`, `PASSWORD`) and locks them in a session-only memory vault, yielding a mathematically scrubbed environment dictionary for sidecar or subprocess injection. 

### 22. Verified Reader Handshake
- **Platform-Side Verification:** The MeshKor SDK's `ReceiverClient.validate()` enforces a `"read"` action type. When an agent attempts to scrape or query data, the resource platform explicitly validates the agent's ProofToken against its `read_scopes`. If the token is valid but the scope is unauthorized, the read is denied. Replay attacks on the read token are structurally blocked.

### 23. Attested Egress Firewall
- **Session-Boundary Containment:** The Sandbox explicitly declares and attests the agent's `allowed_egress` target scope. True enforcement is paired with out-of-process network controls (like an infrastructure sidecar or proxy), ensuring multiple concurrent agents cannot clobber each other's network policies in a shared interpreter.

### 24. Identity-Bound Approval & Principal Anti-Impersonation
- **Principal Enrollment & Anti-Squatting:** Humans and organizational principals enroll insert-only using cryptographic proof of possession, mirroring vendor enrollment to prevent spoofed identities.
- **Consequential Approval Gates:** The system refuses to mint a Build AIN unless authorized by an enrolled principal. The approval must be a time-bounded, single-use `DelegationAssertion` signed by the principal.
- **Sealed Approval Chain:** The attested approval is cryptographically sealed inside the Build AIN's birth record, guaranteeing that receivers can verify the human approval directly from the cryptographic chain without trusting standard display names or checkboxes.
- **High-Fidelity Detection Signals:** Any attempt to use a counterfeit, expired, or non-enrolled identity at the approval gate fires a structured, high-fidelity detection event.

---

## Getting Started & Demos

You can run the full, interactive system demonstration for Phase 1, 2, 2.5, and 3 by running:

```bash
# Phase 1: Core Pedigree & Tamper-Evident History
python main.py

# Phase 1: Cryptographic Attack Simulation (Fails verification safely)
python demo_attack.py

# Phase 2: Global Scale, Network Lag, and Catastrophic Twin Recovery Demo
python demo_phase2.py

# Runtime Countermeasures: Dialogflow/Replit attacks and Drift wiring
python demos/demo_attacks.py
```

### Running Tests
The codebase is heavily tested. A massive unified end-to-end simulation covering all edge cases (Birth -> High Churn -> Behavior Halts -> Global Revocation Fan-out -> Bloom Filter Rejection -> Server Crash -> Shamir Key Ceremony Twin Recovery -> Verification) can be run via:

```bash
pytest tests/test_integration_unified.py -v
```
