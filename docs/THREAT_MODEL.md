# Kormic Threat Model

Kormic employs a Zero-Trust, Pedigree-based security model.

## What We Defend Against
- **The Reconnaissance Gap:** (e.g., RCE data exfiltration, scraping). Mitigated by `read_scopes` manifests, the network egress firewall, and the `Evaporator` which strips standing credentials from memory into a session-scoped vault.
- **Ambient Authority & Cross-Agent Bleed:** (e.g., Replit or Dialogflow incidents). Prevented by the `Sandbox` which enforces strict capability manifests and blocks unauthorized tools and endpoints. Agents get no ambient API keys.
- **Token Replay & Squatting:** Thwarted by Challenge-Response nonces with a 5-minute freshness window, and strict Bind-Once identity enrollment.

## Trust Anchors
- **Mathematical Immutability:** Agents have an immutable identity and a tamper-evident history chain signed by Post-Quantum ML-DSA-87 cryptography.
- **Identity-Bound Approvals:** Existential actions require cryptographic proof of possession from human principals (no spoofing via display names).
- **Threshold Quorums:** The quorum is an opt-in seam enforced only when a threshold policy is configured. By default, software custody is single-party, explicitly dev-grade (marked `DEV_KEY_NOT_PRODUCTION`), meaning a single master key effectively exists today. The fully enforced k-of-n Shamir Secret Sharing quorum is a Phase 3 capability.

## Honest Boundaries
- **Detection Sinks:** The webhook detection sink makes outbound network connections from the enforcement process to an operator-configured URL. The operator is responsible for securely hosting and owning this endpoint.

## Deferred Hardware Custody Items
- **Software Key Custody:** Currently, all cryptographic keys rely on software-based implementations and are strictly marked with `DEV_KEY_NOT_PRODUCTION`. 
- **Phase 3 Migration:** Hardware isolation (e.g., YubiKeys or AWS KMS integration) is deferred to Phase 3 hardware hand-over to physicalize the Shamir Quorums.
