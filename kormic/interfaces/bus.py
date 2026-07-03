from typing import Protocol, Callable, Any

class MessageBus(Protocol):
    """
    Capability interface for pub/sub messaging.
    Satisfies Section 4.2. Maps to managed event brokers / queues asynchronously.
    """
    def post(self, topic: str, message: dict) -> None:
        """Posts a message to a specific topic."""
        ...

    def subscribe(self, topic: str, handler: Callable[[dict], Any]) -> None:
        """Subscribes a callable handler to receive events on a topic."""
        ...
