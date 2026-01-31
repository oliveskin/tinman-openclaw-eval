"""OpenClaw Gateway adapter for Tinman monitoring.

This adapter connects to the OpenClaw Gateway WebSocket and converts
events to Tinman's canonical GatewayEvent format.

OpenClaw Gateway default: ws://127.0.0.1:18789

Event types from OpenClaw:
- message.received: User message received
- message.sent: Assistant message sent
- tool.call: Tool invocation started
- tool.result: Tool invocation completed
- tool.blocked: Tool blocked by sandbox policy
- session.start: New session started
- session.end: Session ended
- llm.request: LLM API call started
- llm.response: LLM API call completed
- llm.error: LLM API error
- approval.requested: Human approval requested
- approval.resolved: Human approval granted/denied
"""

import asyncio
import json
from datetime import datetime
from typing import Any, AsyncIterator

try:
    import websockets
    from websockets import ClientConnection

    WEBSOCKETS_AVAILABLE = True
except ImportError:
    WEBSOCKETS_AVAILABLE = False
    websockets = None  # type: ignore
    ClientConnection = Any  # type: ignore

from tinman.integrations.gateway_plugin import (
    ConnectionState,
    EventSeverity,
    EventType,
    GatewayAdapter,
    GatewayEvent,
)
from tinman.utils import generate_id, get_logger

logger = get_logger("openclaw_adapter")

# Map OpenClaw event types to canonical EventType
OPENCLAW_EVENT_MAP: dict[str, EventType] = {
    "message.received": EventType.MESSAGE_RECEIVED,
    "message.sent": EventType.MESSAGE_SENT,
    "tool.call": EventType.TOOL_CALL_START,
    "tool.result": EventType.TOOL_CALL_END,
    "tool.blocked": EventType.TOOL_BLOCKED,
    "session.start": EventType.SESSION_START,
    "session.end": EventType.SESSION_END,
    "llm.request": EventType.LLM_REQUEST,
    "llm.response": EventType.LLM_RESPONSE,
    "llm.error": EventType.LLM_ERROR,
    "approval.requested": EventType.APPROVAL_REQUESTED,
    "approval.granted": EventType.APPROVAL_GRANTED,
    "approval.denied": EventType.APPROVAL_DENIED,
}


class OpenClawAdapter(GatewayAdapter):
    """Adapter for OpenClaw Gateway WebSocket.

    Usage:
        from tinman_openclaw_eval.adapters.openclaw import OpenClawAdapter
        from tinman.integrations.gateway_plugin import GatewayMonitor

        adapter = OpenClawAdapter("ws://127.0.0.1:18789")
        monitor = GatewayMonitor(adapter)
        await monitor.start()
    """

    DEFAULT_URL = "ws://127.0.0.1:18789"

    def __init__(
        self,
        url: str = DEFAULT_URL,
        reconnect_delay: float = 5.0,
        ping_interval: float = 30.0,
        ping_timeout: float = 10.0,
        **config: Any,
    ):
        """Initialize OpenClaw adapter.

        Args:
            url: WebSocket URL for OpenClaw Gateway
            reconnect_delay: Seconds to wait before reconnecting
            ping_interval: WebSocket ping interval in seconds
            ping_timeout: WebSocket ping timeout in seconds
            **config: Additional configuration
        """
        if not WEBSOCKETS_AVAILABLE:
            raise ImportError(
                "websockets package required: pip install websockets"
            )

        super().__init__(url, **config)
        self.reconnect_delay = reconnect_delay
        self.ping_interval = ping_interval
        self.ping_timeout = ping_timeout

        self._ws: ClientConnection | None = None
        self._state = ConnectionState()

    @property
    def name(self) -> str:
        return "openclaw"

    async def connect(self) -> None:
        """Connect to OpenClaw Gateway WebSocket."""
        try:
            self._ws = await websockets.connect(
                self.url,
                ping_interval=self.ping_interval,
                ping_timeout=self.ping_timeout,
            )
            self._state.connected = True
            self._state.last_error = None
            logger.info(f"Connected to OpenClaw Gateway at {self.url}")

        except Exception as e:
            self._state.connected = False
            self._state.error_count += 1
            self._state.last_error = str(e)
            raise ConnectionError(f"Failed to connect to {self.url}: {e}") from e

    async def disconnect(self) -> None:
        """Disconnect from OpenClaw Gateway."""
        if self._ws:
            try:
                await self._ws.close()
            except Exception as e:
                logger.warning(f"Error closing WebSocket: {e}")
            finally:
                self._ws = None
                self._state.connected = False

    async def stream(self) -> AsyncIterator[GatewayEvent]:
        """Stream events from OpenClaw Gateway.

        Yields:
            GatewayEvent objects as they arrive
        """
        if not self._ws:
            raise ConnectionError("Not connected. Call connect() first.")

        try:
            async for message in self._ws:
                try:
                    raw_event = json.loads(message)
                    event = self.parse_event(raw_event)
                    self._state.last_event_at = event.timestamp
                    yield event

                except json.JSONDecodeError as e:
                    logger.warning(f"Invalid JSON from gateway: {e}")
                    continue
                except Exception as e:
                    logger.warning(f"Error parsing event: {e}")
                    continue

        except websockets.ConnectionClosed:
            self._state.connected = False
            self._state.reconnect_count += 1
            raise ConnectionError("WebSocket connection closed")

        except Exception as e:
            self._state.connected = False
            self._state.error_count += 1
            self._state.last_error = str(e)
            raise ConnectionError(f"Stream error: {e}") from e

    def parse_event(self, raw_event: dict[str, Any]) -> GatewayEvent:
        """Parse OpenClaw event to canonical format.

        OpenClaw event format:
        {
            "type": "tool.call",
            "timestamp": "2024-01-15T10:30:00Z",
            "session_id": "sess_123",
            "channel": "telegram",
            "user_id": "user_456",
            "data": {
                "tool": "bash",
                "args": {"cmd": "ls -la"},
                ...
            }
        }
        """
        event_type_str = raw_event.get("type", "unknown")
        event_type = OPENCLAW_EVENT_MAP.get(event_type_str, EventType.UNKNOWN)

        # Parse timestamp
        timestamp_str = raw_event.get("timestamp")
        if timestamp_str:
            try:
                timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
            except ValueError:
                timestamp = datetime.utcnow()
        else:
            timestamp = datetime.utcnow()

        # Extract data payload
        data = raw_event.get("data", {})

        # Determine severity
        severity = self._get_severity(event_type, data)

        # Build canonical event
        event = GatewayEvent(
            event_id=raw_event.get("id") or generate_id(),
            event_type=event_type,
            timestamp=timestamp,
            severity=severity,
            session_id=raw_event.get("session_id"),
            channel=raw_event.get("channel"),
            user_id=raw_event.get("user_id"),
            payload=data,
        )

        # Populate type-specific fields
        self._populate_tool_fields(event, event_type, data)
        self._populate_message_fields(event, event_type, data)
        self._populate_error_fields(event, event_type, data)

        return event

    def _get_severity(self, event_type: EventType, data: dict[str, Any]) -> EventSeverity:
        """Determine event severity."""
        # Error events
        if event_type in (EventType.LLM_ERROR, EventType.TOOL_BLOCKED):
            return EventSeverity.ERROR

        # Approval events are warnings
        if event_type in (
            EventType.APPROVAL_REQUESTED,
            EventType.APPROVAL_DENIED,
        ):
            return EventSeverity.WARNING

        # Check for error in data
        if data.get("error") or data.get("error_type"):
            return EventSeverity.ERROR

        # Normal events
        return EventSeverity.INFO

    def _populate_tool_fields(
        self,
        event: GatewayEvent,
        event_type: EventType,
        data: dict[str, Any],
    ) -> None:
        """Populate tool-related fields."""
        if event_type in (
            EventType.TOOL_CALL_START,
            EventType.TOOL_CALL_END,
            EventType.TOOL_BLOCKED,
        ):
            event.tool_name = data.get("tool") or data.get("name")
            event.tool_args = data.get("args") or data.get("arguments")
            event.tool_result = data.get("result") or data.get("output")

    def _populate_message_fields(
        self,
        event: GatewayEvent,
        event_type: EventType,
        data: dict[str, Any],
    ) -> None:
        """Populate message-related fields."""
        if event_type in (EventType.MESSAGE_RECEIVED, EventType.MESSAGE_SENT):
            event.message_role = data.get("role")
            if event_type == EventType.MESSAGE_RECEIVED:
                event.message_role = event.message_role or "user"
            else:
                event.message_role = event.message_role or "assistant"

            event.message_content = (
                data.get("content")
                or data.get("text")
                or data.get("message")
            )

    def _populate_error_fields(
        self,
        event: GatewayEvent,
        event_type: EventType,
        data: dict[str, Any],
    ) -> None:
        """Populate error-related fields."""
        if event_type == EventType.LLM_ERROR or data.get("error"):
            event.error_type = data.get("error_type") or data.get("type")
            event.error_message = (
                data.get("error_message")
                or data.get("error")
                or data.get("message")
            )

        if event_type == EventType.TOOL_BLOCKED:
            event.error_type = "ToolBlocked"
            event.error_message = data.get("reason") or "Blocked by sandbox policy"

    async def subscribe(self, event_types: list[str] | None = None) -> None:
        """Subscribe to specific event types.

        Args:
            event_types: List of OpenClaw event types to subscribe to.
                        If None, subscribes to all events.

        Note:
            This sends a subscription message to the gateway.
            Implementation depends on OpenClaw's subscription protocol.
        """
        if not self._ws:
            raise ConnectionError("Not connected")

        subscription = {
            "action": "subscribe",
            "events": event_types or ["*"],
        }
        await self._ws.send(json.dumps(subscription))
        logger.debug(f"Subscribed to events: {event_types or 'all'}")

    async def health_check(self) -> bool:
        """Check if connected to OpenClaw Gateway."""
        if not self._ws:
            return False

        try:
            # WebSocket ping/pong is handled by websockets library
            return self._ws.open
        except Exception:
            return False
