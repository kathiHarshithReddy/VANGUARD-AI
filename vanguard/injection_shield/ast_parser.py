"""
Query AST Parser — converts SQL, NoSQL, and GraphQL query strings into
normalised abstract syntax tree representations.

Each parser returns a dict with:
  type        str   "sql" | "nosql" | "graphql"
  ast         any   Language-specific AST object
  tokens      list  Flat list of (token_type, token_value) tuples
  depth       int   Maximum nesting depth
  node_count  int   Total number of AST nodes
  error       str?  Parse error message if parsing failed
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# SQL parser (via sqlparse)
# ---------------------------------------------------------------------------

def parse_sql(query: str) -> dict[str, Any]:
    """Parse a SQL query string and return a normalised AST dict."""
    try:
        import sqlparse
        from sqlparse import tokens as T
    except ImportError:
        logger.warning("sqlparse not installed — SQL parsing degraded")
        return _error_result("sql", "sqlparse not installed")

    try:
        statements = sqlparse.parse(query.strip())
        if not statements:
            return _error_result("sql", "Empty SQL statement")

        stmt = statements[0]
        flat_tokens = list(_flatten_sql_tokens(stmt))
        depth = _sql_nesting_depth(stmt)

        return {
            "type": "sql",
            "ast": stmt,
            "tokens": flat_tokens,
            "depth": depth,
            "node_count": len(flat_tokens),
            "error": None,
            "raw": query,
        }
    except Exception as exc:
        return _error_result("sql", str(exc))


def _flatten_sql_tokens(token_list) -> list[tuple[str, str]]:
    """Recursively flatten a sqlparse TokenList into (type, value) tuples."""
    result = []
    for token in token_list.tokens:
        if hasattr(token, "tokens"):
            result.extend(_flatten_sql_tokens(token))
        else:
            ttype = str(token.ttype) if token.ttype else "Unknown"
            result.append((ttype, token.normalized))
    return result


def _sql_nesting_depth(token_list, depth: int = 0) -> int:
    max_depth = depth
    for token in token_list.tokens:
        if hasattr(token, "tokens"):
            child_depth = _sql_nesting_depth(token, depth + 1)
            max_depth = max(max_depth, child_depth)
    return max_depth


# ---------------------------------------------------------------------------
# NoSQL / JSON parser
# ---------------------------------------------------------------------------

def parse_nosql(query: str) -> dict[str, Any]:
    """Parse a JSON-encoded NoSQL query object."""
    try:
        obj = json.loads(query.strip())
    except json.JSONDecodeError as exc:
        return _error_result("nosql", f"JSON parse error: {exc}")

    tokens = list(_flatten_json(obj))
    depth = _json_depth(obj)

    return {
        "type": "nosql",
        "ast": obj,
        "tokens": tokens,
        "depth": depth,
        "node_count": len(tokens),
        "error": None,
        "raw": query,
    }


def _flatten_json(
    obj: Any, parent_key: str = ""
) -> list[tuple[str, Any]]:
    items = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            full_key = f"{parent_key}.{k}" if parent_key else k
            items.append(("key", full_key))
            items.extend(_flatten_json(v, full_key))
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            items.extend(_flatten_json(item, f"{parent_key}[{i}]"))
    else:
        items.append(("value", obj))
    return items


def _json_depth(obj: Any, depth: int = 0) -> int:
    if isinstance(obj, dict):
        if not obj:
            return depth
        return max(_json_depth(v, depth + 1) for v in obj.values())
    if isinstance(obj, list):
        if not obj:
            return depth
        return max(_json_depth(item, depth + 1) for item in obj)
    return depth


# ---------------------------------------------------------------------------
# GraphQL parser (via graphql-core)
# ---------------------------------------------------------------------------

def parse_graphql(query: str) -> dict[str, Any]:
    """Parse a GraphQL query string into its AST."""
    try:
        from graphql import parse as gql_parse, GraphQLError
    except ImportError:
        logger.warning("graphql-core not installed — GraphQL parsing degraded")
        return _error_result("graphql", "graphql-core not installed")

    try:
        ast = gql_parse(query.strip())
        tokens = list(_flatten_graphql(ast))
        depth = _graphql_depth(ast)

        return {
            "type": "graphql",
            "ast": ast,
            "tokens": tokens,
            "depth": depth,
            "node_count": len(tokens),
            "error": None,
            "raw": query,
        }
    except Exception as exc:
        return _error_result("graphql", str(exc))


def _flatten_graphql(node) -> list[tuple[str, str]]:
    """Walk graphql-core AST and yield (kind, value) tuples."""
    result = []
    kind = getattr(node, "kind", type(node).__name__)
    value = getattr(node, "value", None)
    result.append((kind, str(value) if value is not None else ""))

    # graphql-core 3.x exposes field names via node.keys (a tuple)
    field_names = getattr(node, "keys", ()) or ()
    for field_name in field_names:
        if field_name in ("loc",):
            continue
        child = getattr(node, field_name, None)
        if child is None:
            continue
        if hasattr(child, "kind"):
            result.extend(_flatten_graphql(child))
        elif isinstance(child, (list, tuple)):
            for item in child:
                if hasattr(item, "kind"):
                    result.extend(_flatten_graphql(item))
    return result


def _graphql_depth(node, depth: int = 0) -> int:
    max_d = depth
    field_names = getattr(node, "keys", ()) or ()
    for field_name in field_names:
        if field_name in ("loc",):
            continue
        child = getattr(node, field_name, None)
        if child is None:
            continue
        if hasattr(child, "kind"):
            max_d = max(max_d, _graphql_depth(child, depth + 1))
        elif isinstance(child, (list, tuple)):
            for item in child:
                if hasattr(item, "kind"):
                    max_d = max(max_d, _graphql_depth(item, depth + 1))
    return max_d


# ---------------------------------------------------------------------------
# Auto-detect query type and dispatch
# ---------------------------------------------------------------------------

_GRAPHQL_RE = re.compile(
    r"^\s*(query|mutation|subscription|fragment|\{)", re.MULTILINE
)


def parse_query(query: str, hint: str | None = None) -> dict[str, Any]:
    """
    Auto-detect query type (or use ``hint``) and parse accordingly.

    Parameters
    ----------
    query:  Raw query string
    hint:   Optional type hint: "sql" | "nosql" | "graphql"
    """
    if not query or not query.strip():
        return _error_result("unknown", "Empty query")

    q = query.strip()

    if hint:
        hint = hint.lower()
        if hint == "sql":
            return parse_sql(q)
        if hint == "nosql":
            return parse_nosql(q)
        if hint == "graphql":
            return parse_graphql(q)

    # Auto-detect
    if q.startswith("{") or q.startswith("["):
        try:
            json.loads(q)
            return parse_nosql(q)
        except json.JSONDecodeError:
            if _GRAPHQL_RE.match(q):
                return parse_graphql(q)

    if _GRAPHQL_RE.match(q):
        return parse_graphql(q)

    # Default to SQL
    return parse_sql(q)


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _error_result(qtype: str, msg: str) -> dict[str, Any]:
    return {
        "type": qtype,
        "ast": None,
        "tokens": [],
        "depth": 0,
        "node_count": 0,
        "error": msg,
        "raw": "",
    }
