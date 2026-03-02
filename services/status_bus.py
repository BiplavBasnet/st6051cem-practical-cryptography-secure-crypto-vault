# -*- coding: utf-8 -*-
"""
StatusBus - Universal Real-Time Status Terminal Backend
=========================================================

Thread-safe event bus for emitting status updates across all modules.
Designed for real-time UI display without leaking sensitive information.

Usage:
    from services.status_bus import get_bus, StatusContext

    # Simple emission
    get_bus().emit("INFO", "Vault Add", "Validating entry...")

    # Context manager for multi-step operations
    with StatusContext("Document Sign") as ctx:
        ctx.step("Hashing document")
        # ... do work ...
        ctx.step("Signing")
        # ... do work ...
        ctx.ok("Document signed successfully")
"""

import queue
import uuid
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Callable


# ═══════════════════════════════════════════════════════════════════════════════
# STATUS EVENT
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class StatusEvent:
    """Represents a single status update event."""
    timestamp: str          # HH:MM:SS format
    level: str              # INFO | OK | WARN | ERROR
    operation: str          # Short operation name (e.g., "Document Sign")
    message: str            # Safe human-readable message (NO SECRETS)
    step: Optional[str] = None      # Optional step label (e.g., "Hashing")
    op_id: Optional[str] = None     # Correlation ID for multi-step ops

    def format_line(self) -> str:
        """Format event as a single terminal line."""
        level_padded = f"[{self.level}]".ljust(7)
        if self.step:
            return f"[{self.timestamp}] {level_padded} {self.operation} ({self.step}): {self.message}"
        else:
            return f"[{self.timestamp}] {level_padded} {self.operation}: {self.message}"


# ═══════════════════════════════════════════════════════════════════════════════
# STATUS BUS SINGLETON
# ═══════════════════════════════════════════════════════════════════════════════

class StatusBus:
    """
    Thread-safe singleton for status event emission and consumption.
    
    Events are queued and consumed by the UI poller via drain().
    Sessions are kept in memory only (no disk persistence).
    """
    
    _instance: Optional["StatusBus"] = None
    _lock = threading.Lock()
    
    # Configuration
    MAX_SESSION_EVENTS = 500
    MAX_SESSIONS = 10
    
    def __new__(cls) -> "StatusBus":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._init_instance()
        return cls._instance
    
    def _init_instance(self):
        """Initialize instance state (called once)."""
        self._queue: queue.Queue = queue.Queue()
        self._current_session: List[StatusEvent] = []
        self._sessions: List[List[StatusEvent]] = []
        self._session_lock = threading.Lock()
    
    # ───────────────────────────────────────────────────────────────────────────
    # EMISSION API
    # ───────────────────────────────────────────────────────────────────────────
    
    def emit(
        self,
        level: str,
        operation: str,
        message: str,
        step: Optional[str] = None,
        op_id: Optional[str] = None,
    ) -> None:
        """
        Emit a status event (thread-safe).
        
        Args:
            level: INFO | OK | WARN | ERROR
            operation: Short operation name (e.g., "Document Sign")
            message: Safe human-readable message (NO SECRETS!)
            step: Optional step label (e.g., "Hashing")
            op_id: Optional correlation ID for multi-step operations
        """
        event = StatusEvent(
            timestamp=datetime.now().strftime("%H:%M:%S"),
            level=level.upper(),
            operation=operation,
            message=message,
            step=step,
            op_id=op_id,
        )
        
        # Add to queue for UI consumption
        self._queue.put(event)
        
        # Add to current session
        with self._session_lock:
            self._current_session.append(event)
            # Trim if too long
            if len(self._current_session) > self.MAX_SESSION_EVENTS:
                self._current_session = self._current_session[-self.MAX_SESSION_EVENTS:]
    
    def info(self, operation: str, message: str, step: Optional[str] = None, op_id: Optional[str] = None) -> None:
        """Emit INFO level event."""
        self.emit("INFO", operation, message, step, op_id)
    
    def ok(self, operation: str, message: str, step: Optional[str] = None, op_id: Optional[str] = None) -> None:
        """Emit OK level event."""
        self.emit("OK", operation, message, step, op_id)
    
    def warn(self, operation: str, message: str, step: Optional[str] = None, op_id: Optional[str] = None) -> None:
        """Emit WARN level event."""
        self.emit("WARN", operation, message, step, op_id)
    
    def error(self, operation: str, message: str, step: Optional[str] = None, op_id: Optional[str] = None) -> None:
        """Emit ERROR level event."""
        self.emit("ERROR", operation, message, step, op_id)
    
    # ───────────────────────────────────────────────────────────────────────────
    # CONSUMPTION API (called by UI poller)
    # ───────────────────────────────────────────────────────────────────────────
    
    def drain(self) -> List[StatusEvent]:
        """
        Drain all queued events (called by UI poller).
        Returns list of events and clears the queue.
        """
        events = []
        while True:
            try:
                event = self._queue.get_nowait()
                events.append(event)
            except queue.Empty:
                break
        return events
    
    # ───────────────────────────────────────────────────────────────────────────
    # SESSION MANAGEMENT
    # ───────────────────────────────────────────────────────────────────────────
    
    def get_current_session(self) -> List[StatusEvent]:
        """Get copy of current session events."""
        with self._session_lock:
            return list(self._current_session)
    
    def clear_session(self) -> None:
        """Clear current session (user action)."""
        with self._session_lock:
            self._current_session.clear()
    
    def archive_session(self) -> None:
        """Archive current session and start a new one."""
        with self._session_lock:
            if self._current_session:
                self._sessions.append(list(self._current_session))
                # Trim old sessions
                if len(self._sessions) > self.MAX_SESSIONS:
                    self._sessions = self._sessions[-self.MAX_SESSIONS:]
                self._current_session.clear()
    
    def get_archived_sessions(self) -> List[List[StatusEvent]]:
        """Get all archived sessions."""
        with self._session_lock:
            return [list(s) for s in self._sessions]
    
    # ───────────────────────────────────────────────────────────────────────────
    # UTILITY
    # ───────────────────────────────────────────────────────────────────────────
    
    @staticmethod
    def new_op_id() -> str:
        """Generate a short operation ID for correlating multi-step operations."""
        return uuid.uuid4().hex[:8]


# ═══════════════════════════════════════════════════════════════════════════════
# STATUS CONTEXT (Context Manager)
# ═══════════════════════════════════════════════════════════════════════════════

class StatusContext:
    """
    Context manager for multi-step operations with automatic start/end emission.
    
    Usage:
        with StatusContext("Document Sign") as ctx:
            ctx.step("Hashing document")
            # ... do work ...
            ctx.step("Signing")
            # ... do work ...
            ctx.ok("Document signed successfully")
    
    On exception, automatically emits ERROR with sanitized message.
    """
    
    def __init__(
        self,
        operation: str,
        op_id: Optional[str] = None,
        emit_start: bool = True,
        emit_end: bool = True,
    ):
        """
        Args:
            operation: Operation name (e.g., "Document Sign")
            op_id: Optional correlation ID (auto-generated if None)
            emit_start: Whether to emit "Started" on enter
            emit_end: Whether to emit "Completed" on successful exit
        """
        self.operation = operation
        self.op_id = op_id or StatusBus.new_op_id()
        self.emit_start = emit_start
        self.emit_end = emit_end
        self._bus = get_bus()
        self._completed = False
        self._errored = False
    
    def __enter__(self) -> "StatusContext":
        if self.emit_start:
            self._bus.info(self.operation, "Started", op_id=self.op_id)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        if exc_type is not None:
            # Exception occurred - emit ERROR with sanitized message
            self._errored = True
            safe_msg = self._sanitize_error(exc_val)
            self._bus.error(self.operation, f"Failed: {safe_msg}", op_id=self.op_id)
            return False  # Re-raise the exception
        
        if self.emit_end and not self._completed:
            self._bus.ok(self.operation, "Completed", op_id=self.op_id)
        
        return False
    
    def step(self, step_name: str, message: Optional[str] = None) -> None:
        """Emit a step progress update."""
        msg = message or f"Processing {step_name.lower()}..."
        self._bus.info(self.operation, msg, step=step_name, op_id=self.op_id)
    
    def info(self, message: str, step: Optional[str] = None) -> None:
        """Emit INFO level message."""
        self._bus.info(self.operation, message, step=step, op_id=self.op_id)
    
    def ok(self, message: str, step: Optional[str] = None) -> None:
        """Emit OK level message (marks operation as completed)."""
        self._completed = True
        self._bus.ok(self.operation, message, step=step, op_id=self.op_id)
    
    def warn(self, message: str, step: Optional[str] = None) -> None:
        """Emit WARN level message."""
        self._bus.warn(self.operation, message, step=step, op_id=self.op_id)
    
    def error(self, message: str, step: Optional[str] = None) -> None:
        """Emit ERROR level message."""
        self._errored = True
        self._bus.error(self.operation, message, step=step, op_id=self.op_id)
    
    def _sanitize_error(self, exc: Exception) -> str:
        """
        Sanitize exception message to avoid leaking sensitive info.
        Never include full stack traces or raw exception details.
        """
        exc_type = type(exc).__name__
        
        # Map common exceptions to safe messages
        safe_messages = {
            "FileNotFoundError": "File not found",
            "PermissionError": "Permission denied",
            "ValueError": "Invalid value provided",
            "KeyError": "Missing required data",
            "TypeError": "Invalid data type",
            "ConnectionError": "Connection failed",
            "TimeoutError": "Operation timed out",
            "InvalidSignature": "Signature verification failed",
            "InvalidTag": "Decryption failed (invalid key or corrupted data)",
        }
        
        if exc_type in safe_messages:
            return safe_messages[exc_type]
        
        # For other exceptions, use generic message
        # Never expose the actual exception message as it may contain secrets
        return f"Operation error ({exc_type})"


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE-LEVEL API
# ═══════════════════════════════════════════════════════════════════════════════

def get_bus() -> StatusBus:
    """Get the global StatusBus singleton."""
    return StatusBus()


def emit(
    level: str,
    operation: str,
    message: str,
    step: Optional[str] = None,
    op_id: Optional[str] = None,
) -> None:
    """Convenience function to emit a status event."""
    get_bus().emit(level, operation, message, step, op_id)


def status_context(operation: str, op_id: Optional[str] = None) -> StatusContext:
    """Convenience function to create a StatusContext."""
    return StatusContext(operation, op_id)
