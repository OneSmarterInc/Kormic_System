from dataclasses import dataclass
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
