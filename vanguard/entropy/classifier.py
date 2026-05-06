"""
ML ensemble intent classifier.

Uses a lightweight scikit-learn voting ensemble (IsolationForest +
RandomForest) to classify traffic into:

  0 → HUMAN   (clean, pass through)
  1 → BOT     (automated, but not necessarily malicious — challenge)
  2 → ATTACK  (malicious — block immediately)

The classifier is intentionally kept small so it can be retrained inside
the Continuous Dojo loop in near-real-time.
"""

from __future__ import annotations

import logging
from enum import IntEnum
from typing import Optional

import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler

from vanguard.entropy.behavioral import FEATURE_DIM, extract_features

logger = logging.getLogger(__name__)


class TrafficClass(IntEnum):
    HUMAN = 0
    BOT = 1
    ATTACK = 2


class IntentClassifier:
    """Ensemble intent classifier for HTTP traffic.

    A fresh instance starts with heuristic-only mode (using IsolationForest
    anomaly scores).  Once ``fit()`` is called with labelled samples it
    switches to supervised RandomForest mode.
    """

    def __init__(self, n_estimators: int = 100, contamination: float = 0.01):
        self._scaler = StandardScaler()
        self._isolation = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=42,
        )
        self._rf: Optional[RandomForestClassifier] = None
        self._fitted = False
        self._supervised = False

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------

    def fit_unsupervised(self, X: np.ndarray) -> None:
        """Bootstrap the anomaly detector on a batch of (assumed-clean) samples."""
        X_scaled = self._scaler.fit_transform(X)
        self._isolation.fit(X_scaled)
        self._fitted = True
        self._supervised = False
        logger.info("IntentClassifier bootstrapped on %d samples (unsupervised)", len(X))

    def fit_supervised(self, X: np.ndarray, y: np.ndarray) -> None:
        """Retrain the full supervised ensemble.

        Parameters
        ----------
        X:  (n_samples, FEATURE_DIM) feature matrix
        y:  (n_samples,) integer labels — see TrafficClass
        """
        X_scaled = self._scaler.fit_transform(X)
        self._isolation.fit(X_scaled[y == TrafficClass.HUMAN])
        self._rf = RandomForestClassifier(
            n_estimators=200,
            max_depth=12,
            class_weight="balanced",
            n_jobs=-1,
            random_state=42,
        )
        self._rf.fit(X_scaled, y)
        self._fitted = True
        self._supervised = True
        logger.info(
            "IntentClassifier retrained (supervised) on %d samples", len(X)
        )

    # ------------------------------------------------------------------
    # Inference
    # ------------------------------------------------------------------

    def predict(self, features: np.ndarray) -> tuple[TrafficClass, float]:
        """Classify a single feature vector.

        Returns
        -------
        (traffic_class, confidence)
        """
        if not self._fitted:
            # Cold start: fall through as HUMAN with low confidence
            return TrafficClass.HUMAN, 0.0

        vec = features.reshape(1, -1)
        vec_scaled = self._scaler.transform(vec)

        if self._supervised and self._rf is not None:
            proba = self._rf.predict_proba(vec_scaled)[0]
            best_idx = int(np.argmax(proba))
            confidence = float(proba[best_idx])
            # Map back to the actual class label (classes_ may be [0, 2] not [0, 1, 2])
            cls_label = int(self._rf.classes_[best_idx])
            return TrafficClass(cls_label), confidence

        # Unsupervised fallback: IsolationForest score in [-1, 1]
        score = float(self._isolation.decision_function(vec_scaled)[0])
        # Normalise to [0, 1] — higher = more anomalous
        anomaly_score = 1.0 - (score + 0.5)
        anomaly_score = max(0.0, min(anomaly_score, 1.0))

        if anomaly_score > 0.75:
            return TrafficClass.ATTACK, anomaly_score
        if anomaly_score > 0.50:
            return TrafficClass.BOT, anomaly_score
        return TrafficClass.HUMAN, 1.0 - anomaly_score

    def classify_request(
        self, request: dict
    ) -> tuple[TrafficClass, float]:
        """End-to-end: extract features then classify."""
        features = extract_features(request)
        return self.predict(features)

    # ------------------------------------------------------------------
    # Persistence helpers (used by the Dojo trainer)
    # ------------------------------------------------------------------

    def get_params(self) -> dict:
        return {
            "scaler": self._scaler,
            "isolation": self._isolation,
            "rf": self._rf,
            "fitted": self._fitted,
            "supervised": self._supervised,
        }

    def load_params(self, params: dict) -> None:
        self._scaler = params["scaler"]
        self._isolation = params["isolation"]
        self._rf = params["rf"]
        self._fitted = params["fitted"]
        self._supervised = params["supervised"]
