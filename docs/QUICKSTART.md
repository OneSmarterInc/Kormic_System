# Kormic Quickstart

Welcome to Kormic! This guide will take you from cloning the repository to running a verified agent in **Advisory Mode**.

## 1. Clone & Setup
```bash
git clone <repo-url> kormic
cd kormic
pip install -r requirements.txt
```

## 2. Initialize an Agent in Advisory Mode
Advisory mode logs unauthorized actions without blocking them, making it perfect for initial integration.

```python
from kormic.verify.engine import Verifier
from kormic.runtime.sandbox import Sandbox
from kormic.runtime.detection import DetectionSink

# Setup detection and verifier
sink = DetectionSink(...) # Define your sink
verifier = Verifier(...)

# Initialize the Sandbox in advisory mode
sandbox = Sandbox(
    verifier=verifier,
    token=agent_token,
    detection_sink=sink,
    enforcement_mode="advisory"
)

# In advisory mode, this will log a warning but proceed
sandbox.use_tool("unauthorized_tool")
```

## 3. Verify Agent Actions (Receiver)
Use the `ReceiverClient` to validate agents connecting to your APIs.

```python
from meshkor.receiver import ReceiverClient

receiver = ReceiverClient(
    authority=authority,
    detection_sink=sink,
    enforcement_mode="advisory"
)

verdict = receiver.validate(token, action_type="read", resource="data")
# verdict.ok will be True in advisory mode, even if unauthorized
```
Next, see [INTEGRATION.md](./INTEGRATION.md) for deploying to real resources.
