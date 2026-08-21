# Integration Guide

Deploying Kormic to real resources requires wiring into your SIEM and choosing your enforcement posture.

## Advisory vs. Enforced Mode
Kormic supports two operational modes:
- **Advisory Mode** (`enforcement_mode="advisory"`): Violations (like out-of-scope tool use or unauthorized reads) generate `DetectionEvent`s but do *not* block the action. Use this during initial deployment to observe agent behavior and tune manifests without breaking workflows.
- **Enforced Mode** (`enforcement_mode="enforced"`): Violations immediately block the action (e.g., raising a `PermissionError` in the Sandbox or returning `ok=False` in the ReceiverClient).

## SIEM Wiring and Detection Plane
Kormic emits structured signals via the `DetectionSink` interface. It routes rule violations to pluggable sinks (e.g., JSONL files, Webhooks) on a fire-and-forget basis. 
- **Enriched Threat Signals:** Events include a standard `severity` (info, warning, critical) and map to a `session_id`.
- **Reconnaissance Digests:** To prevent alert fatigue, repeated unauthorized probing triggers a critical "Ongoing Reconnaissance" digest instead of individual alerts.

## Receiver Verification
Integrate the `ReceiverClient` into your API gateway or resource server. 
- Ensure that you use `action_type="read"` when an agent tries to scrape or query data.
- **Artifact Verification:** When checking deployments, ensure you verify the `BAIN` (Build AIN) and its exact `artifact_digest` bound to an enrolled vendor.
