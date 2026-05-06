"""
Unit tests for the Entropy Detection Engine.

Tests cover:
  - Feature extraction (47-dimensional vector)
  - Entropy score computation
  - IntentClassifier (unsupervised + supervised)
  - EntropyDetector end-to-end decision pipeline
"""

import time

import numpy as np
import pytest

from vanguard.entropy.behavioral import extract_features, FEATURE_DIM, _byte_entropy
from vanguard.entropy.classifier import IntentClassifier, TrafficClass
from vanguard.entropy.detector import EntropyDetector, Decision


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_human_request(ip: str = "1.2.3.4") -> dict:
    """A realistic-looking human browser request."""
    return {
        "method": "GET",
        "path": "/products/shoes",
        "query_string": "color=red&size=10",
        "headers": {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Referer": "https://example.com/products",
            "Cookie": "session=abc123; pref=dark",
        },
        "body": b"",
        "client_ip": ip,
        "timestamp": time.time(),
        "prev_timestamps": [time.time() - i * 3.5 for i in range(10, 0, -1)],
    }


def _make_bot_request(ip: str = "10.0.0.1") -> dict:
    """A request with bot-like characteristics (very high rate, no UA)."""
    now = time.time()
    return {
        "method": "GET",
        "path": "/api/data",
        "query_string": "",
        "headers": {},  # No User-Agent — suspicious
        "body": b"",
        "client_ip": ip,
        "timestamp": now,
        # Very fast and regular — bot-like
        "prev_timestamps": [now - i * 0.002 for i in range(200, 0, -1)],
    }


def _make_attack_request(ip: str = "10.0.0.2") -> dict:
    """A request with SQL injection in the query string."""
    return {
        "method": "GET",
        "path": "/search",
        "query_string": "q=1'+OR+'1'='1",
        "headers": {"User-Agent": "sqlmap/1.7"},
        "body": b"",
        "client_ip": ip,
        "timestamp": time.time(),
    }


# ---------------------------------------------------------------------------
# Feature extraction tests
# ---------------------------------------------------------------------------

class TestFeatureExtraction:
    def test_returns_correct_dimension(self):
        req = _make_human_request()
        features = extract_features(req)
        assert features.shape == (FEATURE_DIM,), (
            f"Expected {FEATURE_DIM} features, got {features.shape[0]}"
        )

    def test_dtype_is_float32(self):
        features = extract_features(_make_human_request())
        assert features.dtype == np.float32

    def test_all_features_in_range(self):
        for req in [_make_human_request(), _make_bot_request(), _make_attack_request()]:
            features = extract_features(req)
            assert np.all(features >= 0.0), "Features must be >= 0"
            assert np.all(features <= 1.0), "Features must be <= 1"

    def test_missing_fields_use_defaults(self):
        """Extracting features from a minimal (empty) request must not crash."""
        features = extract_features({})
        assert features.shape == (FEATURE_DIM,)

    def test_sql_keyword_feature_fires(self):
        req = {
            "method": "GET",
            "path": "/search",
            "query_string": "q=SELECT * FROM users",
            "headers": {},
            "body": b"",
        }
        features = extract_features(req)
        # Feature 30 = _has_sql_keywords
        assert features[30] == 1.0

    def test_traversal_feature_fires(self):
        req = {
            "method": "GET",
            "path": "/../../../etc/passwd",
            "query_string": "",
            "headers": {},
            "body": b"",
        }
        features = extract_features(req)
        # Feature 31 = _has_traversal_pattern
        assert features[31] == 1.0

    def test_script_tag_feature_fires(self):
        req = {
            "method": "GET",
            "path": "/search",
            "query_string": "q=<script>alert(1)</script>",
            "headers": {},
            "body": b"",
        }
        features = extract_features(req)
        # Feature 32 = _has_script_tags
        assert features[32] == 1.0

    def test_byte_entropy_empty(self):
        assert _byte_entropy(b"") == 0.0

    def test_byte_entropy_uniform(self):
        # All unique bytes → maximum entropy ≈ 1.0
        data = bytes(range(256))
        entropy = _byte_entropy(data)
        assert entropy > 0.99, f"Expected high entropy, got {entropy}"

    def test_byte_entropy_constant(self):
        # Single repeated byte → minimum entropy = 0
        data = b"A" * 256
        entropy = _byte_entropy(data)
        assert entropy == 0.0


# ---------------------------------------------------------------------------
# Classifier tests
# ---------------------------------------------------------------------------

class TestIntentClassifier:
    def test_cold_start_returns_human(self):
        clf = IntentClassifier()
        features = np.random.rand(FEATURE_DIM).astype(np.float32)
        cls, conf = clf.predict(features)
        assert cls == TrafficClass.HUMAN
        assert conf == 0.0

    def test_fit_unsupervised_changes_state(self):
        clf = IntentClassifier()
        X = np.random.rand(100, FEATURE_DIM).astype(np.float32)
        clf.fit_unsupervised(X)
        assert clf._fitted is True
        assert clf._supervised is False

    def test_predict_after_unsupervised(self):
        clf = IntentClassifier()
        X = np.random.rand(200, FEATURE_DIM).astype(np.float32)
        clf.fit_unsupervised(X)
        features = np.random.rand(FEATURE_DIM).astype(np.float32)
        cls, conf = clf.predict(features)
        assert cls in list(TrafficClass)
        assert 0.0 <= conf <= 1.0

    def test_fit_supervised(self):
        clf = IntentClassifier()
        rng = np.random.default_rng(0)
        n = 150
        X = rng.random((n, FEATURE_DIM)).astype(np.float32)
        y = np.array(
            [TrafficClass.HUMAN] * 100
            + [TrafficClass.BOT] * 30
            + [TrafficClass.ATTACK] * 20,
            dtype=int,
        )
        clf.fit_supervised(X, y)
        assert clf._fitted is True
        assert clf._supervised is True
        assert clf._rf is not None

    def test_supervised_classifies_correctly(self):
        """Train on clearly separated data and expect correct classification."""
        clf = IntentClassifier(n_estimators=50)
        rng = np.random.default_rng(42)

        # Human: low feature values
        X_human = rng.random((100, FEATURE_DIM)).astype(np.float32) * 0.1
        # Attack: high feature values
        X_attack = (rng.random((100, FEATURE_DIM)).astype(np.float32) * 0.1 + 0.9)

        X = np.vstack([X_human, X_attack])
        y = np.array([TrafficClass.HUMAN] * 100 + [TrafficClass.ATTACK] * 100)
        clf.fit_supervised(X, y)

        # Predict on a clearly-human sample
        human_sample = np.full(FEATURE_DIM, 0.05, dtype=np.float32)
        cls_h, _ = clf.predict(human_sample)
        assert cls_h == TrafficClass.HUMAN, f"Expected HUMAN, got {cls_h}"

        # Predict on a clearly-attack sample
        attack_sample = np.full(FEATURE_DIM, 0.95, dtype=np.float32)
        cls_a, _ = clf.predict(attack_sample)
        assert cls_a == TrafficClass.ATTACK, f"Expected ATTACK, got {cls_a}"

    def test_params_roundtrip(self):
        clf = IntentClassifier()
        X = np.random.rand(50, FEATURE_DIM).astype(np.float32)
        clf.fit_unsupervised(X)
        params = clf.get_params()

        clf2 = IntentClassifier()
        clf2.load_params(params)
        assert clf2._fitted is True

    def test_classify_request_end_to_end(self):
        clf = IntentClassifier()
        X = np.random.rand(100, FEATURE_DIM).astype(np.float32)
        clf.fit_unsupervised(X)
        req = _make_human_request()
        cls, conf = clf.classify_request(req)
        assert cls in list(TrafficClass)


# ---------------------------------------------------------------------------
# EntropyDetector tests
# ---------------------------------------------------------------------------

class TestEntropyDetector:
    def test_human_request_not_blocked(self):
        detector = EntropyDetector()
        # Bootstrap with some clean traffic
        X = np.random.rand(100, FEATURE_DIM).astype(np.float32) * 0.3
        detector.bootstrap_classifier(X)

        result = detector.inspect(_make_human_request())
        assert result.decision in (Decision.PASS, Decision.CHALLENGE), (
            f"Human request was blocked: {result.reason}"
        )

    def test_result_has_features(self):
        detector = EntropyDetector()
        result = detector.inspect(_make_human_request())
        assert result.features is not None
        assert result.features.shape == (FEATURE_DIM,)

    def test_entropy_score_in_range(self):
        detector = EntropyDetector()
        result = detector.inspect(_make_human_request())
        assert 0.0 <= result.entropy_score <= 1.0

    def test_confidence_in_range(self):
        detector = EntropyDetector()
        result = detector.inspect(_make_human_request())
        assert 0.0 <= result.confidence <= 1.0

    def test_traffic_class_is_valid(self):
        detector = EntropyDetector()
        result = detector.inspect(_make_human_request())
        assert result.traffic_class in list(TrafficClass)

    def test_same_ip_accumulates_history(self):
        detector = EntropyDetector()
        ip = "5.5.5.5"
        for _ in range(5):
            detector.inspect({"client_ip": ip, "method": "GET", "path": "/"})
        assert len(detector._ts_window[ip]) == 5

    def test_inspect_attack_url(self):
        """The entropy detector handles volumetric/bot attacks via temporal features.
        A single SQL injection request without bot-like temporal patterns should not
        be blocked here — that is the injection shield's responsibility.
        We just verify the detector doesn't crash and returns a valid result."""
        detector = EntropyDetector()
        result = detector.inspect(_make_attack_request())
        # Must return a valid decision
        assert result.decision in list(Decision)
        # Must return a valid traffic class
        assert result.traffic_class in list(TrafficClass)
        # Confidence and entropy must be in range
        assert 0.0 <= result.confidence <= 1.0
        assert 0.0 <= result.entropy_score <= 1.0
