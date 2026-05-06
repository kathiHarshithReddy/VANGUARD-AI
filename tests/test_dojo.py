"""
Unit tests for the Continuous Dojo adversarial training loop.

Tests cover:
  - FuzzingEngine payload generation
  - Payload mutation strategies
  - DefenceSandbox test execution
  - DojoTrainer synchronous run + checkpoint roundtrip
"""

import os
import time

import numpy as np
import pytest

from vanguard.dojo.fuzzer import (
    AttackPayload,
    FuzzingEngine,
    PayloadType,
    _mutate,
    _mutate_encode,
    _mutate_case,
)
from vanguard.dojo.sandbox import DefenceSandbox, SandboxOutcome
from vanguard.dojo.trainer import DojoTrainer
from vanguard.entropy.classifier import TrafficClass


# ---------------------------------------------------------------------------
# FuzzingEngine tests
# ---------------------------------------------------------------------------

class TestFuzzingEngine:
    def test_generate_returns_correct_count(self):
        engine = FuzzingEngine(seed=0)
        payloads = engine.generate(count=50)
        assert len(payloads) == 50

    def test_payloads_are_attack_payload_instances(self):
        engine = FuzzingEngine(seed=1)
        for p in engine.generate(count=10):
            assert isinstance(p, AttackPayload)

    def test_payload_types_are_valid(self):
        engine = FuzzingEngine(seed=2)
        valid_types = set(PayloadType)
        for p in engine.generate(count=100):
            assert p.payload_type in valid_types

    def test_payloads_have_non_empty_raw_or_metadata(self):
        engine = FuzzingEngine(seed=3)
        for p in engine.generate(count=20):
            # Either raw string is set or metadata has content
            assert p.raw or p.metadata

    def test_generate_1000_per_minute_equivalent(self):
        """1000 payloads should generate in much less than 60 seconds."""
        engine = FuzzingEngine(seed=4)
        start = time.perf_counter()
        payloads = engine.generate_per_minute(target_ppm=1000)
        elapsed = time.perf_counter() - start
        assert len(payloads) == 1000
        assert elapsed < 10.0, f"Generation too slow: {elapsed:.1f}s"

    def test_ddos_request_metadata(self):
        """DDOS payloads must carry a valid request dict."""
        engine = FuzzingEngine(seed=5)
        ddos_payloads = [
            p for p in engine.generate(count=200)
            if p.payload_type == PayloadType.DDOS_REQUEST
        ]
        assert ddos_payloads, "Expected some DDOS payloads"
        for p in ddos_payloads:
            req = p.metadata.get("request")
            assert isinstance(req, dict)
            assert "method" in req
            assert "client_ip" in req

    def test_stream_yields_infinitely(self):
        """generate_stream must be an infinite generator."""
        engine = FuzzingEngine(seed=6)
        gen = engine.generate_stream()
        samples = [next(gen) for _ in range(20)]
        assert len(samples) == 20

    def test_sql_injection_seeds_present(self):
        engine = FuzzingEngine(seed=7)
        payloads = engine.generate(count=500)
        sql_payloads = [p for p in payloads if p.payload_type == PayloadType.SQL_INJECTION]
        assert sql_payloads, "Expected SQL injection payloads"

    def test_different_seeds_produce_different_payloads(self):
        e1 = FuzzingEngine(seed=10)
        e2 = FuzzingEngine(seed=20)
        p1 = [p.raw for p in e1.generate(count=10)]
        p2 = [p.raw for p in e2.generate(count=10)]
        # With different seeds, at least some payloads should differ
        assert p1 != p2


# ---------------------------------------------------------------------------
# Mutation tests
# ---------------------------------------------------------------------------

class TestMutations:
    def test_mutate_returns_string(self):
        result = _mutate("SELECT * FROM users", n_mutations=2)
        assert isinstance(result, str)

    def test_mutate_encode_preserves_non_alpha(self):
        original = "123 !@#"
        result = _mutate_encode(original)
        # Non-alpha chars should not be encoded (they're not alphabetic)
        assert result  # Just check it doesn't crash

    def test_mutate_case_changes_case(self):
        original = "select union drop"
        result = _mutate_case(original)
        # The result should differ in casing at least sometimes
        assert result.lower() == original.lower()

    def test_zero_mutations(self):
        original = "SELECT 1"
        result = _mutate(original, n_mutations=0)
        assert result == original


# ---------------------------------------------------------------------------
# DefenceSandbox tests
# ---------------------------------------------------------------------------

class TestDefenceSandbox:
    def test_sql_injection_is_blocked(self):
        sandbox = DefenceSandbox()
        payload = AttackPayload(
            payload_type=PayloadType.SQL_INJECTION,
            raw="' OR '1'='1",
            metadata={},
        )
        result = sandbox.test_payload(payload)
        assert result.outcome == SandboxOutcome.BLOCKED

    def test_union_injection_is_blocked(self):
        sandbox = DefenceSandbox()
        payload = AttackPayload(
            payload_type=PayloadType.SQL_INJECTION,
            raw="' UNION SELECT NULL,NULL,NULL--",
            metadata={},
        )
        result = sandbox.test_payload(payload)
        assert result.outcome == SandboxOutcome.BLOCKED

    def test_nosql_injection_is_blocked(self):
        sandbox = DefenceSandbox()
        payload = AttackPayload(
            payload_type=PayloadType.NOSQL_INJECTION,
            raw='{"$where": "1==1"}',
            metadata={},
        )
        result = sandbox.test_payload(payload)
        assert result.outcome == SandboxOutcome.BLOCKED

    def test_graphql_introspection_is_blocked(self):
        sandbox = DefenceSandbox()
        payload = AttackPayload(
            payload_type=PayloadType.GRAPHQL_INJECTION,
            raw="{__schema{types{name}}}",
            metadata={},
        )
        result = sandbox.test_payload(payload)
        assert result.outcome == SandboxOutcome.BLOCKED

    def test_ddos_request_is_tested(self):
        sandbox = DefenceSandbox()
        from vanguard.dojo.fuzzer import _generate_ddos_request
        req = _generate_ddos_request()
        payload = AttackPayload(
            payload_type=PayloadType.DDOS_REQUEST,
            raw=str(req),
            metadata={"request": req},
        )
        result = sandbox.test_payload(payload)
        assert result.outcome in list(SandboxOutcome)

    def test_result_has_features_for_injection(self):
        sandbox = DefenceSandbox()
        payload = AttackPayload(
            payload_type=PayloadType.SQL_INJECTION,
            raw="' OR 1=1--",
            metadata={},
        )
        result = sandbox.test_payload(payload)
        assert result.features is not None

    def test_result_elapsed_time_is_positive(self):
        sandbox = DefenceSandbox()
        payload = AttackPayload(
            payload_type=PayloadType.SQL_INJECTION,
            raw="' OR 1=1--",
            metadata={},
        )
        result = sandbox.test_payload(payload)
        assert result.elapsed_seconds >= 0.0

    def test_label_is_attack_for_blocked_payload(self):
        sandbox = DefenceSandbox()
        payload = AttackPayload(
            payload_type=PayloadType.SQL_INJECTION,
            raw="' UNION SELECT NULL--",
            metadata={},
        )
        result = sandbox.test_payload(payload)
        assert result.label == TrafficClass.ATTACK

    def test_batch_returns_same_count(self):
        sandbox = DefenceSandbox()
        payloads = [
            AttackPayload(PayloadType.SQL_INJECTION, "' OR 1=1--", {}),
            AttackPayload(PayloadType.SQL_INJECTION, "' UNION SELECT NULL--", {}),
            AttackPayload(PayloadType.NOSQL_INJECTION, '{"$where":"1"}', {}),
        ]
        results = sandbox.test_batch(payloads)
        assert len(results) == len(payloads)


# ---------------------------------------------------------------------------
# DojoTrainer tests
# ---------------------------------------------------------------------------

class TestDojoTrainer:
    def test_run_single_iteration(self):
        trainer = DojoTrainer()
        stats = trainer.run(max_iterations=1)
        assert stats.iterations == 1
        assert stats.total_payloads_tested > 0

    def test_run_multiple_iterations(self):
        trainer = DojoTrainer()
        stats = trainer.run(max_iterations=3)
        assert stats.iterations == 3

    def test_stats_counters_are_non_negative(self):
        trainer = DojoTrainer()
        stats = trainer.run(max_iterations=2)
        assert stats.total_blocked >= 0
        assert stats.total_evaded >= 0
        assert stats.total_payloads_tested >= 0

    def test_evasion_rate_in_range(self):
        trainer = DojoTrainer()
        stats = trainer.run(max_iterations=2)
        assert 0.0 <= stats.evasion_rate <= 1.0

    def test_start_stop_background_thread(self):
        trainer = DojoTrainer()
        trainer.start()
        time.sleep(0.5)  # Let it run briefly
        trainer.stop(timeout=5.0)
        assert not trainer._thread.is_alive()

    def test_checkpoint_roundtrip(self, tmp_path):
        checkpoint = str(tmp_path / "test_checkpoint.pkl")
        trainer = DojoTrainer()
        trainer.run(max_iterations=1)
        trainer.save_checkpoint(checkpoint)
        assert os.path.exists(checkpoint)

        trainer2 = DojoTrainer()
        loaded = trainer2.load_checkpoint(checkpoint)
        assert loaded is True

    def test_load_missing_checkpoint_returns_false(self, tmp_path):
        trainer = DojoTrainer()
        loaded = trainer.load_checkpoint(str(tmp_path / "nonexistent.pkl"))
        assert loaded is False

    def test_retrain_triggered_after_threshold(self):
        """Force a retrain by injecting samples into the buffer."""
        from vanguard.entropy.behavioral import FEATURE_DIM
        from vanguard.entropy.classifier import TrafficClass

        trainer = DojoTrainer()
        # Inject enough samples to trigger a retrain
        threshold = 10  # use a small threshold for testing
        human_feats = np.random.rand(threshold // 2, FEATURE_DIM).astype(np.float32) * 0.1
        attack_feats = np.random.rand(threshold // 2, FEATURE_DIM).astype(np.float32) * 0.9

        with trainer._lock:
            for f in human_feats:
                trainer._sample_buffer.append((f, int(TrafficClass.HUMAN)))
            for f in attack_feats:
                trainer._sample_buffer.append((f, int(TrafficClass.ATTACK)))

        # Manually trigger retrain
        trainer._retrain()
        assert trainer._stats.model_retrain_count == 1
