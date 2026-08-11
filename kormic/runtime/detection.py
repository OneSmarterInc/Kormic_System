from dataclasses import dataclass
import time

@dataclass
class DetectionEvent:
    event_kind: str
    identity: str
    action_target: str
    reason: str
    mode: str
    timestamp: float

class DetectionSink:
    def emit(self, event: DetectionEvent):
        pass

class DevDetectionSink(DetectionSink):
    def __init__(self):
        self.events = []
        
    def emit(self, event: DetectionEvent):
        self.events.append(event)
