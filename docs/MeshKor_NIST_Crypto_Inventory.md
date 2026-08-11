# Cryptographic Primitive Inventory

This document enumerates every cryptographic primitive utilized within the MeshKor system, plotted against the NIST transition clock for quantum vulnerability. 

Finding: The MeshKor system contains no quantum-vulnerable asymmetric cryptography to migrate. There is no RSA, no elliptic-curve, and no classical key exchange present in the system, meaning there is nothing on the 2030 or 2035 deprecation deadlines.

| Primitive | Where Used | Quantum Status | Action / Margin |
| :--- | :--- | :--- | :--- |
| ML-DSA-87 | All digital signatures (Birth Records, Tokens, Root, Epoch) | Post-Quantum Safe | None required. NIST Level 5 standard. |
| AES-256-GCM | At-rest encryption for Twin snapshots | Post-Quantum Safe | None required. 256-bit symmetric keys provide adequate margin against Grover's algorithm. |
| SHA-256 | Chain hashing (`running_head`), event hashing | Post-Quantum Safe | None required. Fully agile implementation capable of swapping to SHA3-256. |
| HMAC-SHA256 | Threshold ceremony validation (constant-time compare) | Post-Quantum Safe | None required. |
| Shamir Secret Sharing | Splitting the Twin master key | Information-Theoretic| None required. Mathematically perfectly secure regardless of compute power. |

### Future Agility Candidates

While the core history chain is now fully algorithm-agile (supporting runtime dispatch of `SHA-256`, `SHA3-256`, etc.), there are two hash surfaces remaining that currently hardcode `SHA-256` logic:
1. The salted real-world-ID hash (used during enrollment in `AgentManager`)
2. The sandbox helper hash

These instances use standard cryptographic hashing for privacy, not signatures, and are completely safe under Grover's algorithm today. They are noted here purely as future agility candidates rather than current vulnerabilities or risks.
