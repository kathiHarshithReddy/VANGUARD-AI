"""
Sandbox — tests the VANGUARD defences against a single attack payload
in a safe, isolated execution context.

Each test runs within a configurable timeout.  The sandbox captures
whether the defence successfully blocked the payload and assigns a
label for the training pipeline.
"""

from __future__ import annotations

import logging
import signal
import time
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from typing import Any

from vanguard.config import config
from vanguard.dojo.fuzzer import AttackPayload, PayloadType
from vanguard.entropy.behavioral import extract_features
from vanguard.entropy.classifier import TrafficClass

logger = logging.getLogger(__name__)

_cfg = config.dojo


class SandboxOutcome(str, Enum):
    BLOCKED = "blocked"
    EVADED = "evaded"
    TIMEOUT = "timeout"
    ERROR = "error"


@dataclass
class SandboxResult:
    payload: AttackPayload
    outcome: SandboxOutcome
    elapsed_seconds: float
    label: TrafficClass        # ground-truth label for training
    features: Any              # np.ndarray of shape (FEATURE_DIM,) or None
    detail: str = ""


# ---------------------------------------------------------------------------
# Timeout helper (UNIX only — uses SIGALRM)
# ---------------------------------------------------------------------------

class _TimeoutError(Exception):
    pass


@contextmanager
def _timeout(seconds: float):
    """Context manager that raises _TimeoutError after ``seconds``."""
    def _handler(signum, frame):
        raise _TimeoutError

    old_handler = signal.signal(signal.SIGALRM, _handler)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    except _TimeoutError:
        raise
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old_handler)


# ---------------------------------------------------------------------------
# Sandbox
# ---------------------------------------------------------------------------

class DefenceSandbox:
    """
    Runs each attack payload against all active defence layers and records
    whether the shield correctly blocked the attack.

    Parameters
    ----------
    detector:   EntropyDetector instance (lazy-imported to avoid circular deps)
    validator:  InjectionValidator instance
    """

    def __init__(self, detector=None, validator=None):
        # Lazy defaults — created on first use
        self._detector = detector
        self._validator = validator

    # ------------------------------------------------------------------
    # Helpers to initialise dependencies lazily
    # ------------------------------------------------------------------

    def _get_detector(self):
        if self._detector is None:
            from vanguard.entropy.detector import EntropyDetector
            self._detector = EntropyDetector()
        return self._detector

    def _get_validator(self):
        if self._validator is None:
            from vanguard.injection_shield.validator import InjectionValidator
            self._validator = InjectionValidator()
        return self._validator

    # ------------------------------------------------------------------
    # Primary test method
    # ------------------------------------------------------------------

    def test_payload(self, payload: AttackPayload) -> SandboxResult:
        """Test a single payload and return the outcome."""
        start = time.perf_counter()

        try:
            with _timeout(_cfg.sandbox_timeout):
                outcome, detail, features = self._run_test(payload)
        except _TimeoutError:
            elapsed = time.perf_counter() - start
            return SandboxResult(
                payload=payload,
                outcome=SandboxOutcome.TIMEOUT,
                elapsed_seconds=elapsed,
                label=TrafficClass.ATTACK,
                features=None,
                detail="Sandbox test timed out",
            )
        except Exception as exc:
            elapsed = time.perf_counter() - start
            logger.warning("Sandbox error for payload %s: %s", payload.payload_type, exc)
            return SandboxResult(
                payload=payload,
                outcome=SandboxOutcome.ERROR,
                elapsed_seconds=elapsed,
                label=TrafficClass.ATTACK,
                features=None,
                detail=str(exc),
            )

        elapsed = time.perf_counter() - start
        # All attacks should be blocked — EVADED means a defence gap
        label = (
            TrafficClass.ATTACK
            if outcome in (SandboxOutcome.BLOCKED, SandboxOutcome.EVADED)
            else TrafficClass.HUMAN
        )
        return SandboxResult(
            payload=payload,
            outcome=outcome,
            elapsed_seconds=elapsed,
            label=label,
            features=features,
            detail=detail,
        )

    def test_batch(self, payloads: list[AttackPayload]) -> list[SandboxResult]:
        """Test a list of payloads sequentially."""
        return [self.test_payload(p) for p in payloads]

    # ------------------------------------------------------------------
    # Internal dispatch
    # ------------------------------------------------------------------

    def _run_test(
        self, payload: AttackPayload
    ) -> tuple[SandboxOutcome, str, Any]:
        if payload.payload_type == PayloadType.DDOS_REQUEST:
            return self._test_ddos(payload)
        return self._test_injection(payload)

    def _test_ddos(self, payload: AttackPayload) -> tuple[SandboxOutcome, str, Any]:
        """Test a DDoS / bot request against the entropy detector."""
        request = payload.metadata.get("request") or {}

        # Fill in any missing required fields
        request.setdefault("method", "GET")
        request.setdefault("path", "/")
        request.setdefault("headers", {})
        request.setdefault("client_ip", "10.0.0.1")
        request.setdefault("timestamp", time.time())

        detector = self._get_detector()
        result = detector.inspect(request)
        features = result.features

        from vanguard.entropy.detector import Decision

        if result.decision in (Decision.BLOCK, Decision.CHALLENGE):
            return SandboxOutcome.BLOCKED, result.reason, features
        return SandboxOutcome.EVADED, "Entropy detector did not block the request", features

    def _test_injection(
        self, payload: AttackPayload
    ) -> tuple[SandboxOutcome, str, Any]:
        """Test an injection payload against the injection shield."""
        # Map payload type to query hint
        hint_map = {
            PayloadType.SQL_INJECTION: "sql",
            PayloadType.NOSQL_INJECTION: "nosql",
            PayloadType.GRAPHQL_INJECTION: "graphql",
        }
        hint = hint_map.get(payload.payload_type)

        validator = self._get_validator()

        from vanguard.injection_shield.validator import ShieldVerdict

        result = validator.validate(payload.raw, hint)

        # Build synthetic request features for non-injection payloads
        request = {
            "method": "GET",
            "path": "/search",
            "query_string": payload.raw,
            "headers": {},
            "body": payload.raw.encode("utf-8", errors="ignore"),
            "client_ip": "10.0.0.1",
            "timestamp": time.time(),
        }
        features = extract_features(request)

        if result.verdict in (ShieldVerdict.BLOCKED, ShieldVerdict.SUSPICIOUS):
            return SandboxOutcome.BLOCKED, result.reason, features
        return SandboxOutcome.EVADED, f"Shield verdict was {result.verdict}", features
