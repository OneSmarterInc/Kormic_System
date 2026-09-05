from dataclasses import dataclass
from typing import Optional, List
import time
import json
import urllib.request

@dataclass
class DetectionEvent:
    event_kind: str
    identity: str
    action_target: str
    reason: str
    mode: str
    timestamp: float
    severity: str = "info"
    schema_ver: int = 1
    session_id: str = ""
    
    def to_dict(self):
        return {
            "event_kind": self.event_kind,
            "identity": self.identity,
            "action_target": self.action_target,
            "reason": self.reason,
            "mode": self.mode,
            "timestamp": self.timestamp,
            "severity": self.severity,
            "schema_ver": self.schema_ver,
            "session_id": self.session_id
        }

class DetectionSink:
    def emit(self, event: DetectionEvent):
        pass

class DevDetectionSink(DetectionSink):
    def __init__(self):
        self.events = []
        
    def emit(self, event: DetectionEvent):
        self.events.append(event)
        
    def get_events(self) -> List[DetectionEvent]:
        return self.events

class SlackDetectionSink(DetectionSink):
    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url
        import requests
        self.requests = requests

    def emit(self, event: DetectionEvent):
        color = "#ff0000" if event.severity == "critical" else "#ffa500" if event.severity == "high" else "#00ff00"
        payload = {
            "attachments": [
                {
                    "fallback": f"MeshKor Alert: {event.event_kind}",
                    "color": color,
                    "title": f"MeshKor Alert: {event.event_kind}",
                    "text": f"*AIN:* {event.agent_code}\n*Reason:* {event.reason}\n*Severity:* {event.severity}",
                }
            ]
        }
        try:
            self.requests.post(self.webhook_url, json=payload, timeout=2.0)
        except Exception:
            pass # Fire and forget

class JsonlDetectionSink(DetectionSink):
    def __init__(self, path: str):
        self.path = path
        
    def emit(self, event: DetectionEvent):
        try:
            with open(self.path, "a") as f:
                f.write(json.dumps(event.to_dict()) + "\n")
        except Exception:
            pass

class WebhookDetectionSink(DetectionSink):
    def __init__(self, url: str):
        self.url = url
        
    def emit(self, event: DetectionEvent):
        try:
            req = urllib.request.Request(
                self.url, 
                data=json.dumps(event.to_dict()).encode('utf-8'), 
                headers={'Content-Type': 'application/json'}, 
                method='POST'
            )
            urllib.request.urlopen(req, timeout=1.0)
        except Exception:
            pass
