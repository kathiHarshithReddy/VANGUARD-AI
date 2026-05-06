"""
Unit tests for the Context-Aware Injection Shield.

Tests cover:
  - SQL / NoSQL / GraphQL AST parsing
  - Static signature detection
  - AST structural analysis
  - Grammar learner (learn + similarity scoring)
  - InjectionValidator end-to-end
"""

import pytest

from vanguard.injection_shield.ast_parser import (
    parse_sql,
    parse_nosql,
    parse_graphql,
    parse_query,
)
from vanguard.injection_shield.grammar_learner import GrammarLearner
from vanguard.injection_shield.validator import (
    InjectionValidator,
    ShieldVerdict,
)


# ---------------------------------------------------------------------------
# AST Parser tests
# ---------------------------------------------------------------------------

class TestSQLParser:
    def test_simple_select(self):
        result = parse_sql("SELECT id, name FROM users WHERE id = 1")
        assert result["type"] == "sql"
        assert result["error"] is None
        assert len(result["tokens"]) > 0
        assert result["depth"] >= 0

    def test_returns_tokens_list(self):
        result = parse_sql("SELECT * FROM products")
        assert isinstance(result["tokens"], list)
        for token in result["tokens"]:
            assert len(token) == 2  # (type, value)

    def test_empty_query_error(self):
        result = parse_sql("")
        assert result["error"] is not None

    def test_node_count_positive(self):
        result = parse_sql("SELECT a, b, c FROM table1 JOIN table2 ON table1.id = table2.id")
        assert result["node_count"] > 0


class TestNoSQLParser:
    def test_simple_find(self):
        result = parse_nosql('{"username": "alice", "active": true}')
        assert result["type"] == "nosql"
        assert result["error"] is None
        assert result["depth"] >= 1

    def test_nested_object(self):
        result = parse_nosql('{"user": {"profile": {"age": 30}}}')
        assert result["depth"] >= 3

    def test_invalid_json(self):
        result = parse_nosql("{not valid json}")
        assert result["error"] is not None

    def test_array_query(self):
        result = parse_nosql('[{"id": 1}, {"id": 2}]')
        assert result["type"] == "nosql"
        assert result["error"] is None


class TestGraphQLParser:
    def test_simple_query(self):
        result = parse_graphql("{ user(id: 1) { name email } }")
        assert result["type"] == "graphql"
        assert result["error"] is None
        assert result["node_count"] > 0

    def test_mutation(self):
        result = parse_graphql(
            "mutation { createUser(name: \"Alice\", email: \"a@b.com\") { id } }"
        )
        assert result["type"] == "graphql"
        assert result["error"] is None

    def test_invalid_graphql(self):
        result = parse_graphql("{ unclosed {")
        assert result["error"] is not None

    def test_depth_calculation(self):
        nested = "{ a { b { c { d { e { id } } } } } }"
        result = parse_graphql(nested)
        assert result["depth"] >= 4


class TestQueryAutoDetect:
    def test_detect_sql(self):
        result = parse_query("SELECT * FROM users")
        assert result["type"] == "sql"

    def test_detect_nosql(self):
        result = parse_query('{"username": "alice"}')
        assert result["type"] == "nosql"

    def test_detect_graphql(self):
        result = parse_query("{ user { id name } }")
        assert result["type"] == "graphql"

    def test_hint_overrides_detection(self):
        # JSON string but hint says SQL
        result = parse_query("SELECT 1", hint="sql")
        assert result["type"] == "sql"

    def test_empty_query(self):
        result = parse_query("")
        assert result["error"] is not None


# ---------------------------------------------------------------------------
# Grammar Learner tests
# ---------------------------------------------------------------------------

class TestGrammarLearner:
    _BENIGN_SQL = [
        "SELECT id, name FROM users WHERE id = ?",
        "SELECT * FROM products WHERE category = ?",
        "SELECT COUNT(*) FROM orders WHERE status = ?",
        "SELECT u.name, o.total FROM users u JOIN orders o ON u.id = o.user_id",
        "SELECT id FROM items WHERE price BETWEEN ? AND ?",
        "SELECT name FROM categories ORDER BY name ASC",
        "SELECT * FROM logs WHERE created_at > ? LIMIT 100",
        "SELECT id, title FROM articles WHERE published = true",
        "SELECT SUM(amount) FROM payments WHERE user_id = ?",
        "SELECT * FROM sessions WHERE token = ? AND expires > ?",
    ]

    def test_learn_batch_does_not_raise(self):
        learner = GrammarLearner()
        parsed_queries = [parse_sql(q) for q in self._BENIGN_SQL]
        learner.learn_batch(parsed_queries)
        stats = learner.stats
        assert stats["sql"]["query_count"] == len(self._BENIGN_SQL)

    def test_similarity_neutral_before_learning(self):
        learner = GrammarLearner()
        parsed = parse_sql("SELECT id FROM users")
        score = learner.similarity(parsed)
        assert score == 0.5  # neutral

    def test_known_query_has_high_similarity(self):
        learner = GrammarLearner()
        for q in self._BENIGN_SQL:
            learner.learn(parse_sql(q))

        # A structurally similar SELECT should score high
        parsed = parse_sql("SELECT name FROM products WHERE id = ?")
        score = learner.similarity(parsed)
        assert score > 0.5, f"Expected high similarity, got {score}"

    def test_attack_query_has_lower_similarity(self):
        learner = GrammarLearner()
        for q in self._BENIGN_SQL:
            learner.learn(parse_sql(q))

        # A UNION-based injection has very different token structure
        attack = parse_sql("SELECT 1 UNION SELECT NULL,NULL,NULL--")
        benign = parse_sql("SELECT id FROM users WHERE id = ?")

        attack_score = learner.similarity(attack)
        benign_score = learner.similarity(benign)
        assert benign_score >= attack_score, (
            f"Attack scored higher ({attack_score}) than benign ({benign_score})"
        )

    def test_error_query_scores_zero(self):
        learner = GrammarLearner()
        for q in self._BENIGN_SQL:
            learner.learn(parse_sql(q))
        parsed = {"type": "sql", "tokens": [], "error": "parse error", "depth": 0}
        score = learner.similarity(parsed)
        assert score == 0.0

    def test_unknown_type_returns_neutral(self):
        learner = GrammarLearner()
        parsed = {"type": "unknown", "tokens": [("Keyword", "HACK")], "error": None}
        score = learner.similarity(parsed)
        assert score == 0.5

    def test_stats_structure(self):
        learner = GrammarLearner()
        stats = learner.stats
        assert "sql" in stats
        assert "nosql" in stats
        assert "graphql" in stats
        for qtype in ("sql", "nosql", "graphql"):
            assert "query_count" in stats[qtype]
            assert "ngram_count" in stats[qtype]


# ---------------------------------------------------------------------------
# InjectionValidator end-to-end tests
# ---------------------------------------------------------------------------

class TestInjectionValidator:
    _BENIGN_SQL_QUERIES = [
        ("SELECT id, name FROM users WHERE id = ?", "sql"),
        ("SELECT * FROM products WHERE category = ?", "sql"),
        ("SELECT COUNT(*) FROM orders", "sql"),
    ]

    def _trained_validator(self) -> InjectionValidator:
        """Return a validator pre-trained on benign SQL queries."""
        validator = InjectionValidator()
        for q, hint in self._BENIGN_SQL_QUERIES * 5:  # repeat for better coverage
            validator.learn_query(q, hint)
        return validator

    # ── SQL injection attacks ────────────────────────────────────────────

    def test_or_tautology_blocked(self):
        v = InjectionValidator()
        result = v.validate("' OR '1'='1", "sql")
        assert result.verdict == ShieldVerdict.BLOCKED

    def test_union_select_blocked(self):
        v = InjectionValidator()
        result = v.validate("' UNION SELECT NULL,NULL,NULL--", "sql")
        assert result.verdict == ShieldVerdict.BLOCKED

    def test_drop_table_blocked(self):
        v = InjectionValidator()
        result = v.validate("1; DROP TABLE users--", "sql")
        assert result.verdict == ShieldVerdict.BLOCKED

    def test_sleep_injection_blocked(self):
        v = InjectionValidator()
        result = v.validate("' AND SLEEP(5)--", "sql")
        assert result.verdict == ShieldVerdict.BLOCKED

    def test_comment_escape_blocked(self):
        v = InjectionValidator()
        result = v.validate("admin'--", "sql")
        assert result.verdict == ShieldVerdict.BLOCKED

    def test_hex_encoded_blocked(self):
        v = InjectionValidator()
        result = v.validate("0x27204f52203127", "sql")
        assert result.verdict == ShieldVerdict.BLOCKED

    def test_waitfor_delay_blocked(self):
        v = InjectionValidator()
        result = v.validate("'; WAITFOR DELAY '0:0:5'--", "sql")
        assert result.verdict == ShieldVerdict.BLOCKED

    # ── NoSQL injection attacks ──────────────────────────────────────────

    def test_nosql_where_blocked(self):
        v = InjectionValidator()
        result = v.validate('{"$where": "1==1"}', "nosql")
        assert result.verdict == ShieldVerdict.BLOCKED

    def test_nosql_ne_operator_blocked(self):
        v = InjectionValidator()
        result = v.validate('{"username": {"$ne": null}}', "nosql")
        assert result.verdict == ShieldVerdict.BLOCKED

    def test_nosql_regex_blocked(self):
        v = InjectionValidator()
        result = v.validate('{"username": {"$regex": ".*"}}', "nosql")
        assert result.verdict == ShieldVerdict.BLOCKED

    # ── GraphQL attacks ──────────────────────────────────────────────────

    def test_graphql_introspection_blocked(self):
        v = InjectionValidator()
        result = v.validate("{__schema{types{name}}}", "graphql")
        assert result.verdict == ShieldVerdict.BLOCKED

    def test_graphql_deeply_nested_blocked(self):
        v = InjectionValidator()
        deeply_nested = "{" + "a{" * 15 + "id" + "}" * 15 + "}"
        result = v.validate(deeply_nested, "graphql")
        assert result.verdict == ShieldVerdict.BLOCKED

    # ── Clean queries ────────────────────────────────────────────────────

    def test_empty_query_is_clean(self):
        v = InjectionValidator()
        result = v.validate("", "sql")
        assert result.verdict == ShieldVerdict.CLEAN

    def test_learn_then_validate_clean(self):
        v = self._trained_validator()
        result = v.validate("SELECT id FROM users WHERE id = ?", "sql")
        # After training on similar queries this should pass
        assert result.verdict in (ShieldVerdict.CLEAN, ShieldVerdict.SUSPICIOUS)

    def test_result_has_required_fields(self):
        v = InjectionValidator()
        result = v.validate("' OR 1=1--", "sql")
        assert result.verdict is not None
        assert result.query_type is not None
        assert result.layer is not None
        assert 0.0 <= result.score <= 1.0
        assert isinstance(result.reason, str)

    def test_layer_reported_correctly_for_signature(self):
        v = InjectionValidator()
        result = v.validate("' OR 1=1--", "sql")
        assert result.layer == "signature"

    def test_learn_query_nosql(self):
        """Learning NoSQL queries should not raise."""
        v = InjectionValidator()
        v.learn_query('{"active": true, "role": "user"}', "nosql")
        v.learn_query('{"age": {"$gte": 18}}', "nosql")  # this gets blocked by signature, not learned

    def test_learn_query_graphql(self):
        v = InjectionValidator()
        v.learn_query("{ user(id: 1) { name email } }", "graphql")
