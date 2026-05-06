"""
VANGUARD Edge Proxy.

Inspection pipeline for every incoming HTTP request:
  1. Entropy detector   — DDoS / bot detection
  2. Injection shield   — SQL / NoSQL / GraphQL injection detection
  3. Forward to origin  — only if all checks pass

Blocked/challenged requests are terminated at the edge with a 403/429.
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any

from flask import Flask, Response, request as flask_request, jsonify

from vanguard.config import config
from vanguard.entropy.detector import Decision, EntropyDetector
from vanguard.injection_shield.validator import InjectionValidator, ShieldVerdict

logger = logging.getLogger(__name__)

_cfg = config.proxy


# ---------------------------------------------------------------------------
# Shared defence instances (module-level singletons)
# ---------------------------------------------------------------------------

_detector = EntropyDetector()
_validator = InjectionValidator()


# ---------------------------------------------------------------------------
# Flask application factory
# ---------------------------------------------------------------------------

def create_app(
    detector: EntropyDetector | None = None,
    validator: InjectionValidator | None = None,
) -> Flask:
    """Create and configure the Flask proxy application."""
    app = Flask(__name__)
    app.config["PROPAGATE_EXCEPTIONS"] = True

    det = detector or _detector
    val = validator or _validator

    @app.before_request
    def _inspect():
        """Run VANGUARD checks on every incoming request."""
        # Build a request dict from the Flask request context
        req_dict = _flask_to_request_dict(flask_request)

        # ── Layer 1: Entropy / DDoS detection ────────────────────────────
        entropy_result = det.inspect(req_dict)

        if entropy_result.decision == Decision.BLOCK:
            logger.warning(
                "BLOCKED [entropy] ip=%s path=%s reason=%s",
                req_dict["client_ip"],
                req_dict["path"],
                entropy_result.reason,
            )
            return _block_response(
                reason=entropy_result.reason,
                score=entropy_result.entropy_score,
            )

        if entropy_result.decision == Decision.CHALLENGE:
            logger.info(
                "CHALLENGE [entropy] ip=%s path=%s reason=%s",
                req_dict["client_ip"],
                req_dict["path"],
                entropy_result.reason,
            )
            return _challenge_response(entropy_result.reason)

        # ── Layer 2: Injection shield ─────────────────────────────────────
        queries_to_check = _extract_queries(flask_request)
        for raw_query, hint in queries_to_check:
            shield_result = val.validate(raw_query, hint)
            if shield_result.verdict == ShieldVerdict.BLOCKED:
                logger.warning(
                    "BLOCKED [injection] ip=%s path=%s reason=%s",
                    req_dict["client_ip"],
                    req_dict["path"],
                    shield_result.reason,
                )
                return _block_response(
                    reason=shield_result.reason,
                    score=shield_result.score,
                )
            if shield_result.verdict == ShieldVerdict.SUSPICIOUS:
                logger.info(
                    "SUSPICIOUS [injection] ip=%s path=%s reason=%s",
                    req_dict["client_ip"],
                    req_dict["path"],
                    shield_result.reason,
                )
                # Suspicious but not definitively blocked — tag and continue
                # In production you'd add a request header for downstream review

    @app.route("/healthz", methods=["GET"])
    def _healthz():
        return jsonify({"status": "ok", "service": "vanguard"}), 200

    @app.route("/metrics", methods=["GET"])
    def _metrics():
        return jsonify({
            "service": "vanguard",
            "timestamp": time.time(),
        }), 200

    # Catch-all proxy route
    @app.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT",
                                                     "PATCH", "DELETE", "HEAD",
                                                     "OPTIONS"])
    @app.route("/<path:path>", methods=["GET", "POST", "PUT", "PATCH",
                                         "DELETE", "HEAD", "OPTIONS"])
    def _proxy(path: str):
        """Forward clean requests to the origin server."""
        import httpx

        origin = config.proxy.origin_url.rstrip("/")
        target = f"{origin}/{path}"
        if flask_request.query_string:
            target += "?" + flask_request.query_string.decode("utf-8", errors="replace")

        try:
            resp = httpx.request(
                method=flask_request.method,
                url=target,
                headers={
                    k: v for k, v in flask_request.headers.items()
                    if k.lower() not in ("host", "transfer-encoding")
                },
                content=flask_request.get_data(),
                timeout=30.0,
                follow_redirects=False,
            )
            return Response(
                resp.content,
                status=resp.status_code,
                headers={
                    k: v for k, v in resp.headers.items()
                    if k.lower() not in ("transfer-encoding", "content-encoding")
                },
            )
        except Exception as exc:
            logger.error("Proxy forward error: %s", exc)
            return Response("Bad Gateway", status=502)

    return app


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _flask_to_request_dict(req) -> dict[str, Any]:
    return {
        "method": req.method,
        "path": req.path,
        "query_string": req.query_string.decode("utf-8", errors="replace"),
        "headers": dict(req.headers),
        "body": req.get_data(),
        "client_ip": req.remote_addr or "0.0.0.0",
        "timestamp": time.time(),
    }


def _extract_queries(req) -> list[tuple[str, str | None]]:
    """
    Extract candidate query strings from the request for injection checking.
    Returns a list of (raw_string, hint) pairs.
    """
    queries = []

    # Query parameters
    qs = req.query_string.decode("utf-8", errors="replace")
    if qs:
        queries.append((qs, None))
        # Also check individual parameter values
        for key, value in req.args.items():
            if len(value) > 5:
                queries.append((value, None))

    # JSON body — check for nested query fields
    content_type = req.content_type or ""
    if "application/json" in content_type:
        try:
            body_json = req.get_json(force=True, silent=True) or {}
            _collect_json_strings(body_json, queries)
        except Exception:
            pass

    # Form data
    for key, value in req.form.items():
        if len(value) > 5:
            queries.append((value, None))

    # Raw body for GraphQL endpoints
    if "graphql" in req.path.lower() or "application/graphql" in content_type:
        body_text = req.get_data(as_text=True)
        if body_text:
            queries.append((body_text, "graphql"))

    return queries


def _collect_json_strings(
    obj: Any, output: list, max_depth: int = 5
) -> None:
    """Recursively collect string values from a JSON object."""
    if max_depth <= 0:
        return
    if isinstance(obj, str) and len(obj) > 5:
        output.append((obj, None))
    elif isinstance(obj, dict):
        for v in obj.values():
            _collect_json_strings(v, output, max_depth - 1)
    elif isinstance(obj, list):
        for item in obj:
            _collect_json_strings(item, output, max_depth - 1)


def _block_response(reason: str, score: float = 1.0) -> Response:
    return Response(
        response=f"Forbidden — {reason}",
        status=403,
        mimetype="text/plain",
        headers={"X-VANGUARD-Block-Reason": reason[:200]},
    )


def _challenge_response(reason: str) -> Response:
    return Response(
        response="Too Many Requests — Please slow down",
        status=429,
        mimetype="text/plain",
        headers={
            "Retry-After": "5",
            "X-VANGUARD-Challenge-Reason": reason[:200],
        },
    )
