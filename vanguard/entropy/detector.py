"""
Entropy-based DDoS / bot traffic detector.

Pipeline:
  Traffic Ingestion → Entropy Analysis → Intent Classification → Edge-Blocking

The detector maintains a sliding window of per-IP request statistics and
computes a multi-factor entropy score that feeds into the ML classifier.
"""

from __future__ import annotations

import collections
import logging
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any

import numpy as np

from vanguard.config import config
from vanguard.entropy.behavioral import extract_features
from vanguard.entropy.classifier import IntentClassifier, TrafficClass

logger = logging.getLogger(__name__)

_cfg = config.entropy


class Decision(str, Enum):
    PASS = "pass"
    CHALLENGE = "challenge"
    BLOCK = "block"


@dataclass
class DetectionResult:
    decision: Decision
    traffic_class: TrafficClass
    confidence: float
    entropy_score: float
    features: np.ndarray
    reason: str


class EntropyDetector:
    """
    Stateful detector that tracks per-IP request history and applies the
    entropy analysis + ML classification pipeline.

    Thread safety: this class is NOT thread-safe by default.  Wrap in a lock
    or use one instance per worker if running concurrent request handlers.
    """

    def __init__(self, classifier: IntentClassifier | None = None):
        self._classifier = classifier or IntentClassifier()
        # {ip: deque of timestamps}
        self._ts_window: dict[str, collections.deque] = collections.defaultdict(
            lambda: collections.deque(maxlen=_cfg.window_size)
        )
        # {ip: deque of feature vectors}  — kept for Dojo retraining
        self._feature_buffer: dict[str, collections.deque] = (
            collections.defaultdict(lambda: collections.deque(maxlen=50))
        )

    # ------------------------------------------------------------------
    # Primary inspection method
    # ------------------------------------------------------------------

    def inspect(self, request: dict[str, Any]) -> DetectionResult:
        """Inspect a single request and return a routing decision."""
        ip = request.get("client_ip", "0.0.0.0")
        now = float(request.get("timestamp", time.time()))

        # Update timestamp window
        ts_deque = self._ts_window[ip]
        prev_ts = list(ts_deque)
        ts_deque.append(now)

        # Enrich request with temporal context
        enriched = dict(request)
        enriched["prev_timestamps"] = prev_ts

        # Extract 47-dim feature vector
        features = extract_features(enriched)

        # Store for later retraining
        self._feature_buffer[ip].append(features)

        # Compute composite entropy score
        entropy_score = self._compute_entropy_score(features, prev_ts, now)

        # ML classification
        traffic_class, confidence = self._classifier.predict(features)

        # Final routing decision
        decision, reason = self._make_decision(
            entropy_score, traffic_class, confidence
        )

        return DetectionResult(
            decision=decision,
            traffic_class=traffic_class,
            confidence=confidence,
            entropy_score=entropy_score,
            features=features,
            reason=reason,
        )

    # ------------------------------------------------------------------
    # Entropy score computation
    # ------------------------------------------------------------------

    def _compute_entropy_score(
        self,
        features: np.ndarray,
        prev_ts: list[float],
        now: float,
    ) -> float:
        """
        Weighted combination of feature sub-groups to produce a single
        [0, 1] entropy score.  Higher → more likely to be benign.
        """
        # Sub-group means (indices correspond to behavioral.py groups)
        structure = float(features[0:10].mean())
        header = float(features[10:20].mean())
        temporal = float(features[20:30].mean())
        uri_pattern = float(features[30:39].mean())
        payload = float(features[39:47].mean())

        # Higher header/uri anomaly → lower entropy (more suspicious)
        raw = (
            0.10 * (1 - structure)
            + 0.20 * (1 - header)
            + 0.30 * (1 - temporal)
            + 0.25 * (1 - uri_pattern)
            + 0.15 * (1 - payload)
        )
        return float(np.clip(raw, 0.0, 1.0))

    # ------------------------------------------------------------------
    # Decision logic
    # ------------------------------------------------------------------

    def _make_decision(
        self,
        entropy_score: float,
        traffic_class: TrafficClass,
        confidence: float,
    ) -> tuple[Decision, str]:
        if traffic_class == TrafficClass.ATTACK and confidence >= _cfg.block_confidence:
            return Decision.BLOCK, f"ML classified as ATTACK (confidence={confidence:.2f})"

        if entropy_score < _cfg.benign_threshold:
            if confidence >= _cfg.block_confidence:
                return Decision.BLOCK, (
                    f"Low entropy score ({entropy_score:.2f}) + high ML confidence"
                )
            return Decision.CHALLENGE, (
                f"Low entropy score ({entropy_score:.2f}) — issuing challenge"
            )

        if traffic_class == TrafficClass.BOT:
            return Decision.CHALLENGE, f"ML classified as BOT (confidence={confidence:.2f})"

        return Decision.PASS, "Traffic appears legitimate"

    # ------------------------------------------------------------------
    # Feedback / retraining surface
    # ------------------------------------------------------------------

    def drain_labeled_buffer(self) -> tuple[np.ndarray, np.ndarray]:
        """
        Pop all buffered feature vectors with their current ML label.
        Used by the Continuous Dojo trainer to collect new training data.
        """
        rows, labels = [], []
        for ip, deque in list(self._feature_buffer.items()):
            while deque:
                feat = deque.popleft()
                # Placeholder label — in production these are enriched by
                # feedback signals (e.g. confirmed fraud, CAPTCHA result).
                label = int(TrafficClass.HUMAN)
                rows.append(feat)
                labels.append(label)
        if not rows:
            return np.empty((0, 47)), np.empty(0)
        return np.array(rows), np.array(labels)

    def bootstrap_classifier(self, X: np.ndarray) -> None:
        """Warm-start the embedded classifier on a batch of clean samples."""
        self._classifier.fit_unsupervised(X)

    @property
    def classifier(self) -> IntentClassifier:
        return self._classifier
