"""
Autonomous Grammar Learner.

Learns the "normal" query grammar patterns from legitimate traffic and
provides a similarity score for new queries.  Queries that deviate
significantly from the learned corpus are flagged as anomalous.

Technique
─────────
  - Represent each query as a token-type n-gram profile (n=1,2,3)
  - Store the distribution of token types seen in legitimate queries
  - Score a new query as the cosine similarity of its token-type profile
    against the learned distribution

The learner is intentionally lightweight so it can be updated continuously
inside the Continuous Dojo loop.
"""

from __future__ import annotations

import collections
import logging
import math
from typing import Iterable

logger = logging.getLogger(__name__)

# Maximum n for n-gram profiles
MAX_N = 3


class GrammarLearner:
    """
    Incremental grammar learner for SQL / NoSQL / GraphQL token sequences.

    Usage::

        learner = GrammarLearner()
        learner.learn(parsed_query_1)
        learner.learn(parsed_query_2)
        score = learner.similarity(parsed_query_new)  # 0.0 – 1.0
    """

    def __init__(self, max_grammars: int = 10_000):
        self._max_grammars = max_grammars
        # token-type n-gram → count
        self._ngram_counts: dict[str, dict[tuple, int]] = {
            "sql": collections.defaultdict(int),
            "nosql": collections.defaultdict(int),
            "graphql": collections.defaultdict(int),
        }
        self._query_counts: dict[str, int] = {"sql": 0, "nosql": 0, "graphql": 0}
        # Capped grammar store for type-specific norms
        self._type_profiles: dict[str, dict[tuple, float]] = {}

    # ------------------------------------------------------------------
    # Learning
    # ------------------------------------------------------------------

    def learn(self, parsed: dict) -> None:
        """Incorporate a single parsed (legitimate) query into the model."""
        qtype = parsed.get("type", "unknown")
        if qtype not in self._ngram_counts:
            return
        if parsed.get("error"):
            return

        tokens = parsed.get("tokens", [])
        if not tokens:
            return

        type_seq = [t[0] for t in tokens]  # just token types, not values

        for n in range(1, MAX_N + 1):
            for gram in _ngrams(type_seq, n):
                self._ngram_counts[qtype][gram] += 1

        self._query_counts[qtype] += 1

        # Periodically prune low-frequency n-grams to cap memory
        if self._query_counts[qtype] % 1000 == 0:
            self._prune(qtype)

        # Invalidate cached profile
        self._type_profiles.pop(qtype, None)

    def learn_batch(self, parsed_queries: Iterable[dict]) -> None:
        """Incorporate multiple parsed queries at once."""
        for parsed in parsed_queries:
            self.learn(parsed)

    # ------------------------------------------------------------------
    # Similarity scoring
    # ------------------------------------------------------------------

    def similarity(self, parsed: dict) -> float:
        """
        Return a similarity score in [0, 1].

        1.0 = identical to learned grammar patterns
        0.0 = completely novel / suspicious pattern

        Returns 0.5 (neutral) if the learner has no data for this type.
        """
        qtype = parsed.get("type", "unknown")
        if qtype not in self._ngram_counts:
            return 0.5
        if parsed.get("error"):
            # Parse error itself is already suspicious — handled by validator
            return 0.0

        tokens = parsed.get("tokens", [])
        if not tokens:
            return 0.5

        if self._query_counts.get(qtype, 0) < 10:
            # Not enough data to have opinions — neutral
            return 0.5

        type_seq = [t[0] for t in tokens]
        query_profile = _build_profile(type_seq)
        learned_profile = self._get_normalized_profile(qtype)

        return _cosine_similarity(query_profile, learned_profile)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_normalized_profile(self, qtype: str) -> dict[tuple, float]:
        if qtype in self._type_profiles:
            return self._type_profiles[qtype]

        counts = self._ngram_counts[qtype]
        total = sum(counts.values()) or 1
        profile = {gram: count / total for gram, count in counts.items()}
        self._type_profiles[qtype] = profile
        return profile

    def _prune(self, qtype: str) -> None:
        """Remove the least common n-grams to stay within memory bounds."""
        counts = self._ngram_counts[qtype]
        if len(counts) <= self._max_grammars:
            return
        sorted_items = sorted(counts.items(), key=lambda x: x[1], reverse=True)
        self._ngram_counts[qtype] = collections.defaultdict(
            int, dict(sorted_items[: self._max_grammars])
        )
        logger.debug("Pruned grammar for %s to %d n-grams", qtype, self._max_grammars)

    @property
    def stats(self) -> dict:
        return {
            qtype: {
                "query_count": self._query_counts.get(qtype, 0),
                "ngram_count": len(self._ngram_counts.get(qtype, {})),
            }
            for qtype in ("sql", "nosql", "graphql")
        }


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _ngrams(seq: list, n: int) -> Iterable[tuple]:
    """Yield n-grams from a sequence."""
    for i in range(len(seq) - n + 1):
        yield tuple(seq[i : i + n])


def _build_profile(type_seq: list[str]) -> dict[tuple, float]:
    """Build a normalised n-gram frequency profile for a single query."""
    counts: dict[tuple, int] = collections.defaultdict(int)
    for n in range(1, MAX_N + 1):
        for gram in _ngrams(type_seq, n):
            counts[gram] += 1
    total = sum(counts.values()) or 1
    return {gram: count / total for gram, count in counts.items()}


def _cosine_similarity(a: dict, b: dict) -> float:
    """Cosine similarity between two sparse vector dicts."""
    if not a or not b:
        return 0.0
    dot = sum(a.get(k, 0.0) * b.get(k, 0.0) for k in a)
    norm_a = math.sqrt(sum(v ** 2 for v in a.values()))
    norm_b = math.sqrt(sum(v ** 2 for v in b.values()))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)
