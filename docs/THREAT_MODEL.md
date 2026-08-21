# Kormic Threat Model

Kormic employs a Zero-Trust, Pedigree-based security model.

## What We Defend Against
- **The Reconnaissance Gap:** (e.g., RCE data exfiltration, scraping). Mitigated by `read_scopes` manifests, the network egress firewall, and the `Evaporator` which strips standing credentials from memory into a session-scoped vault.
- **Ambient Authority & Cross-Agent Bleed:** (e.g., Replit or Dialogflow incidents). Prevented by the `Sandbox` which enforces strict capability manifests and blocks unauthorized tools and endpoints. Agents get no ambient API keys.
- **Token Replay & Squatting:** Thwarted by Challenge-Response nonces with a 5-minute freshness window, and strict Bind-Once identity enrollment.

## Trust Anchors
- **Mathematical Immutability:** Agents have an immutable identity and a tamper-evident history chain signed by Post-Quantum ML-DSA-87 cryptography.
- **Identity-Bound Approvals:** Existential actions require cryptographic proof of possession from human principals (no spoofing via display names).
- **Threshold Quorums:** Existential root operations require Shamir Secret Sharing (k-of-n) signatures from enrolled holders. No single "God Key" exists.

## Deferred Hardware Custody Items
- **Software Key Custody:** Currently, all cryptographic keys rely on software-based implementations and are strictly marked with `# DEV_KEY_NOT_PRODUCTION`. 
- **Phase 3 Migration:** Hardware isolation (e.g., YubiKeys or AWS KMS integration) is deferred to Phase 3 hardware hand-over to physicalize the Shamir Quorums.
