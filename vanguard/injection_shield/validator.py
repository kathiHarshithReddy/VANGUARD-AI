"""
Context-Aware Injection Validator.

Combines three layers of defence:
  1. Static signature matching       — fast-path against known attack patterns
  2. AST structural analysis         — detect dangerous query structures
  3. Grammar-based anomaly detection — flag queries deviating from the norm

Each layer can independently block a query.  The first layer to trigger
returns immediately; all three must pass for a query to be considered clean.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from vanguard.config import config
from vanguard.injection_shield.ast_parser import parse_query
from vanguard.injection_shield.grammar_learner import GrammarLearner

logger = logging.getLogger(__name__)

_cfg = config.injection_shield


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

class ShieldVerdict(str, Enum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    BLOCKED = "blocked"


@dataclass
class ValidationResult:
    verdict: ShieldVerdict
    query_type: str
    layer: str          # which layer caught the issue
    score: float        # 0.0 (safe) – 1.0 (dangerous)
    reason: str
    details: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Static attack signatures
# ---------------------------------------------------------------------------

_SQL_SIGNATURES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"(--|#|/\*)", re.I), "SQL comment"),
    (re.compile(r"\bOR\b\s+[\w'\"]+\s*=\s*[\w'\"]+", re.I), "SQL OR-based tautology"),
    (re.compile(r"\bUNION\b.+\bSELECT\b", re.I | re.DOTALL), "UNION SELECT injection"),
    (re.compile(r"\bDROP\b\s+\bTABLE\b", re.I), "DROP TABLE"),
    (re.compile(r"\bEXEC(UTE)?\b\s*\(", re.I), "Stored procedure execution"),
    (re.compile(r"\bINSERT\b\s+\bINTO\b", re.I), "Unexpected INSERT"),
    (re.compile(r"\bUPDATE\b\s+\w+\s+\bSET\b", re.I), "Unexpected UPDATE"),
    (re.compile(r"\bDELETE\b\s+\bFROM\b", re.I), "Unexpected DELETE"),
    (re.compile(r"0x[0-9a-fA-F]{4,}", re.I), "Hex-encoded payload"),
    (re.compile(r"CHAR\s*\(\s*\d+", re.I), "CHAR() obfuscation"),
    (re.compile(r"\bWAITFOR\b\s+\bDELAY\b", re.I), "Time-based blind injection"),
    (re.compile(r"\bSLEEP\s*\(", re.I), "Time-based blind injection"),
    (re.compile(r"\bBENCHMARK\s*\(", re.I), "CPU-based blind injection"),
    (re.compile(r"';\s*--", re.I), "Quote-semicolon escape"),
    (re.compile(r"1\s*=\s*1", re.I), "Always-true tautology"),
]

_NOSQL_SIGNATURES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\$where", re.I), "NoSQL $where operator"),
    (re.compile(r"\$regex", re.I), "NoSQL $regex (potential ReDoS)"),
    (re.compile(r"\$gt|\$lt|\$gte|\$lte|\$ne|\$nin", re.I), "NoSQL comparison operator"),
    (re.compile(r"\$or|\$and|\$nor|\$not", re.I), "NoSQL logical operator"),
    (re.compile(r"function\s*\(", re.I), "JavaScript function in query"),
    (re.compile(r"this\.", re.I), "JavaScript this reference"),
    (re.compile(r"eval\s*\(", re.I), "eval() call"),
]

_GRAPHQL_SIGNATURES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\bintrospection\b|\b__schema\b|\b__type\b", re.I), "Introspection query"),
    (re.compile(r"fragment\s+\w+\s+on\s+\w+\s*\{[^}]{0,500}\.\.\.", re.I), "Fragment spreading"),
    (re.compile(r"(\w+\s*\{){8,}", re.I), "Deeply nested GraphQL query"),
    (re.compile(r"alias\d{3,}", re.I), "Alias-based amplification"),
]

_SIGNATURE_MAP = {
    "sql": _SQL_SIGNATURES,
    "nosql": _NOSQL_SIGNATURES,
    "graphql": _GRAPHQL_SIGNATURES,
}


# ---------------------------------------------------------------------------
# Structural checks
# ---------------------------------------------------------------------------

_DANGEROUS_SQL_TYPES = frozenset([
    "tokens.Keyword.DML",  # Data Manipulation Language keywords
    "tokens.DDL",          # Data Definition Language (DROP, CREATE, ALTER)
])

_MAX_QUERY_DEPTH = 12
_MAX_NOSQL_OPERATORS = 5
_MAX_GRAPHQL_DEPTH = 10


def _check_sql_structure(parsed: dict) -> tuple[bool, str]:
    """Returns (is_dangerous, reason)."""
    if parsed.get("depth", 0) > _MAX_QUERY_DEPTH:
        return True, f"SQL nesting depth {parsed['depth']} exceeds limit"

    tokens = parsed.get("tokens", [])
    dml_count = sum(
        1 for ttype, _ in tokens if "DML" in ttype or "DDL" in ttype
    )
    if dml_count > 1:
        return True, f"Multiple DML/DDL statements ({dml_count}) in single query"

    return False, ""


def _check_nosql_structure(parsed: dict) -> tuple[bool, str]:
    ast = parsed.get("ast")
    if not isinstance(ast, dict):
        return False, ""

    operator_count = sum(
        1 for k in _walk_keys(ast) if k.startswith("$")
    )
    if operator_count > _MAX_NOSQL_OPERATORS:
        return True, f"Excessive NoSQL operators ({operator_count})"

    if parsed.get("depth", 0) > _MAX_QUERY_DEPTH:
        return True, f"NoSQL nesting depth {parsed['depth']} exceeds limit"

    return False, ""


def _check_graphql_structure(parsed: dict) -> tuple[bool, str]:
    if parsed.get("depth", 0) > _MAX_GRAPHQL_DEPTH:
        return True, f"GraphQL nesting depth {parsed['depth']} exceeds limit"
    return False, ""


def _walk_keys(obj: Any):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield k
            yield from _walk_keys(v)
    elif isinstance(obj, list):
        for item in obj:
            yield from _walk_keys(item)


# ---------------------------------------------------------------------------
# Main validator
# ---------------------------------------------------------------------------

class InjectionValidator:
    """
    Three-layer injection shield.

    Usage::

        validator = InjectionValidator()
        # Feed legitimate queries to train the grammar:
        validator.learn_query("SELECT id, name FROM users WHERE id = ?", "sql")
        # Validate a new query:
        result = validator.validate("SELECT * FROM users WHERE 1=1 --", "sql")
        assert result.verdict == ShieldVerdict.BLOCKED
    """

    def __init__(self, learner: GrammarLearner | None = None):
        self._learner = learner or GrammarLearner(
            max_grammars=_cfg.max_grammars
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def validate(
        self, query: str, hint: str | None = None
    ) -> ValidationResult:
        """
        Validate a query string.  Returns a ValidationResult indicating
        whether the query should be BLOCKED, flagged as SUSPICIOUS, or CLEAN.
        """
        if not query or not query.strip():
            return ValidationResult(
                verdict=ShieldVerdict.CLEAN,
                query_type="unknown",
                layer="pre-check",
                score=0.0,
                reason="Empty query",
            )

        # Parse into AST
        parsed = parse_query(query, hint)

        if parsed.get("error") and parsed.get("type") != "unknown":
            # A real parser error on non-empty input is suspicious
            return ValidationResult(
                verdict=ShieldVerdict.SUSPICIOUS,
                query_type=parsed["type"],
                layer="ast-parse",
                score=0.6,
                reason=f"Query failed AST parse: {parsed['error']}",
                details={"parse_error": parsed["error"]},
            )

        qtype = parsed["type"]

        # ── Layer 1: Static signatures ────────────────────────────────────
        sig_result = self._check_signatures(query, qtype)
        if sig_result:
            return sig_result

        # ── Layer 2: AST structure ────────────────────────────────────────
        struct_result = self._check_structure(parsed, qtype)
        if struct_result:
            return struct_result

        # ── Layer 3: Grammar anomaly ──────────────────────────────────────
        return self._check_grammar(parsed, qtype)

    def learn_query(self, query: str, hint: str | None = None) -> None:
        """Incorporate a legitimate query into the grammar model."""
        parsed = parse_query(query, hint)
        if not parsed.get("error"):
            self._learner.learn(parsed)

    def learn_batch(self, queries: list[tuple[str, str | None]]) -> None:
        """Batch-learn from a list of (query, hint) tuples."""
        for query, hint in queries:
            self.learn_query(query, hint)

    @property
    def learner(self) -> GrammarLearner:
        return self._learner

    # ------------------------------------------------------------------
    # Layer implementations
    # ------------------------------------------------------------------

    def _check_signatures(
        self, query: str, qtype: str
    ) -> ValidationResult | None:
        signatures = _SIGNATURE_MAP.get(qtype, [])
        for pattern, description in signatures:
            if pattern.search(query):
                logger.warning(
                    "Injection blocked [signature] type=%s pattern=%s",
                    qtype, description,
                )
                return ValidationResult(
                    verdict=ShieldVerdict.BLOCKED,
                    query_type=qtype,
                    layer="signature",
                    score=1.0,
                    reason=f"Matched injection signature: {description}",
                    details={"signature": description},
                )
        return None

    def _check_structure(
        self, parsed: dict, qtype: str
    ) -> ValidationResult | None:
        if qtype == "sql":
            dangerous, reason = _check_sql_structure(parsed)
        elif qtype == "nosql":
            dangerous, reason = _check_nosql_structure(parsed)
        elif qtype == "graphql":
            dangerous, reason = _check_graphql_structure(parsed)
        else:
            return None

        if dangerous:
            logger.warning("Injection blocked [structure] %s", reason)
            return ValidationResult(
                verdict=ShieldVerdict.BLOCKED,
                query_type=qtype,
                layer="structure",
                score=0.9,
                reason=reason,
            )
        return None

    def _check_grammar(
        self, parsed: dict, qtype: str
    ) -> ValidationResult:
        score = self._learner.similarity(parsed)
        threshold = _cfg.similarity_threshold

        if score < threshold:
            logger.info(
                "Query below grammar threshold (score=%.2f threshold=%.2f)",
                score, threshold,
            )
            return ValidationResult(
                verdict=ShieldVerdict.SUSPICIOUS,
                query_type=qtype,
                layer="grammar",
                score=1.0 - score,
                reason=(
                    f"Query grammar anomaly: similarity={score:.2f} "
                    f"(threshold={threshold:.2f})"
                ),
                details={"grammar_similarity": score},
            )

        return ValidationResult(
            verdict=ShieldVerdict.CLEAN,
            query_type=qtype,
            layer="grammar",
            score=1.0 - score,
            reason="Query passed all injection checks",
            details={"grammar_similarity": score},
        )
