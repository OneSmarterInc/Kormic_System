# MeshKor Pilot Service Notes (Advisory Mode)

## Important Security Disclaimers for Phase 4 (Pilot)

As noted in Audit Round 21, the current integration is running in **Advisory Mode (Fail-Open)** to ensure zero disruption to Kormic students during the pilot. 

Please be aware of the following design shortcuts taken strictly for the pilot phase:

1. **AINs are Bearer Identifiers (No Proof-of-Possession):**
   In this pilot, the agent does *not* possess a local cryptographic keypair (it sends \"advisory_mode_no_local_key"\). Therefore, it cannot sign a session challenge. The AIN is currently a bearer identifier�anyone who learns the AIN string could theoretically present it. **This means that in the pilot, having an AIN does not mean the agent is cryptographically authenticated.** 
   *Enforced Mode Fix:* The agent will generate a local keypair and execute FAST proof-of-possession.

2. **Flat, Non-Standard Tiering:**
   Currently, the \agent_type\ (e.g., \"Student_agent"\) is passed directly as the tier prefix, producing AINs like \KMC.Student_agent.agent_x...\ instead of the formal two-tier \KMC.BLD\ / \KMC.DPL\ model. 
   *Enforced Mode Fix:* Enforced mode will strictly require two-tier enrollment, where each agent class is a BAIN and each instance is a DAIN deriving from it.

These shortcuts are acceptable for the pilot (since nothing is enforced yet), but **must be resolved** before transitioning to Phase 5 (Enforced Mode/Fail-Closed).
