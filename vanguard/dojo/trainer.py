"""
Continuous Dojo Trainer — adversarial training loop.

Loop iteration:
  1. FuzzingEngine generates N attack payloads
  2. DefenceSandbox tests each payload
  3. Evaded payloads are collected as new training samples
  4. When enough samples accumulate the ML classifier is retrained
  5. New model is hot-swapped into the live detector (zero downtime)
  6. Repeat

The loop runs in a background thread and can be started / stopped
via the DojoTrainer public API.
"""

from __future__ import annotations

import logging
import pickle
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np

from vanguard.config import config
from vanguard.dojo.fuzzer import FuzzingEngine, PayloadType
from vanguard.dojo.sandbox import DefenceSandbox, SandboxOutcome
from vanguard.entropy.classifier import IntentClassifier, TrafficClass

logger = logging.getLogger(__name__)

_cfg = config.dojo


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@dataclass
class DojoStats:
    iterations: int = 0
    total_payloads_tested: int = 0
    total_evaded: int = 0
    total_blocked: int = 0
    model_retrain_count: int = 0
    last_retrain_time: float = 0.0
    evasion_rate: float = 0.0
    sample_buffer_size: int = 0
    running: bool = False


# ---------------------------------------------------------------------------
# Trainer
# ---------------------------------------------------------------------------

class DojoTrainer:
    """
    Runs the adversarial training loop.

    Usage (blocking)::

        trainer = DojoTrainer()
        trainer.run(max_iterations=100)

    Usage (background thread)::

        trainer = DojoTrainer()
        trainer.start()
        ...
        trainer.stop()
        stats = trainer.stats
    """

    def __init__(
        self,
        classifier: IntentClassifier | None = None,
        detector=None,
        validator=None,
    ):
        self._classifier = classifier or IntentClassifier()
        self._fuzzer = FuzzingEngine()
        self._sandbox = DefenceSandbox(detector=detector, validator=validator)

        # Buffer: (features, label) tuples collected between retrains
        self._sample_buffer: list[tuple[np.ndarray, int]] = []
        # Historical buffer kept for incremental retraining
        self._history_X: list[np.ndarray] = []
        self._history_y: list[int] = []

        self._stats = DojoStats()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the training loop in a background thread."""
        if self._thread and self._thread.is_alive():
            logger.warning("Dojo trainer is already running")
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._loop, name="dojo-trainer", daemon=True
        )
        self._thread.start()
        logger.info("Continuous Dojo trainer started")

    def stop(self, timeout: float = 10.0) -> None:
        """Signal the training loop to stop and wait for it."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=timeout)
        logger.info("Continuous Dojo trainer stopped")

    def run(self, max_iterations: int = 10) -> DojoStats:
        """Run the training loop synchronously for ``max_iterations`` cycles."""
        self._stats.running = True
        try:
            for _ in range(max_iterations):
                if self._stop_event.is_set():
                    break
                self._run_one_iteration()
        finally:
            self._stats.running = False
        return self._stats

    @property
    def stats(self) -> DojoStats:
        return self._stats

    def save_checkpoint(self, path: str | None = None) -> None:
        """Persist the current classifier to disk."""
        checkpoint_path = Path(path or _cfg.checkpoint_path)
        params = self._classifier.get_params()
        with open(checkpoint_path, "wb") as f:
            pickle.dump(params, f)
        logger.info("Checkpoint saved to %s", checkpoint_path)

    def load_checkpoint(self, path: str | None = None) -> bool:
        """Load a previously saved classifier from disk."""
        checkpoint_path = Path(path or _cfg.checkpoint_path)
        if not checkpoint_path.exists():
            logger.warning("Checkpoint not found: %s", checkpoint_path)
            return False
        with open(checkpoint_path, "rb") as f:
            params = pickle.load(f)
        self._classifier.load_params(params)
        logger.info("Checkpoint loaded from %s", checkpoint_path)
        return True

    # ------------------------------------------------------------------
    # Internal loop
    # ------------------------------------------------------------------

    def _loop(self) -> None:
        self._stats.running = True
        try:
            while not self._stop_event.is_set():
                self._run_one_iteration()
                # Throttle to ~target_ppm payloads per minute
                time.sleep(60.0 / max(_cfg.payloads_per_minute, 1))
        finally:
            self._stats.running = False

    def _run_one_iteration(self) -> None:
        # 1. Generate a batch of attack payloads
        batch_size = max(_cfg.payloads_per_minute // 60, 10)
        payloads = self._fuzzer.generate(count=batch_size)

        # 2. Test each payload in the sandbox
        results = self._sandbox.test_batch(payloads)

        # 3. Collect stats + new training samples
        evaded = []
        for result in results:
            self._stats.total_payloads_tested += 1
            if result.outcome == SandboxOutcome.BLOCKED:
                self._stats.total_blocked += 1
            elif result.outcome == SandboxOutcome.EVADED:
                self._stats.total_evaded += 1
                evaded.append(result)

            if result.features is not None:
                with self._lock:
                    self._sample_buffer.append(
                        (result.features, int(result.label))
                    )

        self._stats.iterations += 1

        if self._stats.total_payloads_tested > 0:
            self._stats.evasion_rate = (
                self._stats.total_evaded / self._stats.total_payloads_tested
            )

        if evaded:
            logger.warning(
                "Dojo iteration %d: %d/%d payloads evaded detection — "
                "evasion_rate=%.1f%%",
                self._stats.iterations,
                len(evaded),
                len(results),
                self._stats.evasion_rate * 100,
            )

        # 4. Retrain if threshold reached
        with self._lock:
            buffer_size = len(self._sample_buffer)
        self._stats.sample_buffer_size = buffer_size

        if buffer_size >= _cfg.retrain_threshold:
            self._retrain()

    def _retrain(self) -> None:
        """Retrain the classifier on accumulated samples."""
        with self._lock:
            new_samples = list(self._sample_buffer)
            self._sample_buffer.clear()

        if not new_samples:
            return

        new_X = np.array([s[0] for s in new_samples])
        new_y = np.array([s[1] for s in new_samples])

        # Append to history (keep last 50k samples to avoid memory growth)
        self._history_X.append(new_X)
        self._history_y.append(new_y)
        max_history = 50_000
        all_X = np.vstack(self._history_X)
        all_y = np.concatenate(self._history_y)
        if len(all_X) > max_history:
            all_X = all_X[-max_history:]
            all_y = all_y[-max_history:]
            # Reset lists to trimmed arrays
            self._history_X = [all_X]
            self._history_y = [all_y]

        # Need at least two classes to do supervised training
        unique_classes = np.unique(all_y)
        if len(unique_classes) < 2:
            logger.info(
                "Skipping supervised retrain — only one class present (%s). "
                "Using unsupervised bootstrap.",
                unique_classes,
            )
            self._classifier.fit_unsupervised(all_X)
        else:
            logger.info(
                "Retraining classifier on %d samples (%s classes)...",
                len(all_X),
                len(unique_classes),
            )
            self._classifier.fit_supervised(all_X, all_y)

        self._stats.model_retrain_count += 1
        self._stats.last_retrain_time = time.time()

        # Save checkpoint automatically
        try:
            self.save_checkpoint()
        except Exception as exc:
            logger.warning("Could not save checkpoint: %s", exc)

        logger.info(
            "Model retrain #%d complete", self._stats.model_retrain_count
        )
