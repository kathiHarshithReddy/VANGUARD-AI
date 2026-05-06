"""
Behavioral feature extractor — produces a 47-dimensional feature vector
from a single HTTP request description dict.

Feature groups
──────────────
 0- 9  Request structure features
10-19  Header anomaly features
20-29  Temporal / jitter features
30-38  Path / URI pattern features
39-46  Payload shape features
"""

from __future__ import annotations

import hashlib
import math
import re
import time
from typing import Any

import numpy as np


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

FEATURE_DIM = 47


def extract_features(request: dict[str, Any]) -> np.ndarray:
    """Return a float32 array of length FEATURE_DIM.

    Parameters
    ----------
    request:
        A dict describing one HTTP request.  Expected keys (all optional,
        defaults applied when missing):

        method          str   HTTP method (GET, POST, …)
        path            str   Request URI path
        query_string    str   Raw query string (after '?')
        headers         dict  HTTP headers {name: value}
        body            bytes Raw request body
        client_ip       str   Source IP address
        timestamp       float Unix timestamp of arrival
        prev_timestamps list  List of recent timestamps from same IP
        mouse_path      list  Optional list of (x, y) coordinate tuples
    """
    features = np.zeros(FEATURE_DIM, dtype=np.float32)

    method = request.get("method", "GET").upper()
    path = request.get("path", "/")
    query_string = request.get("query_string", "")
    headers: dict = request.get("headers", {})
    body: bytes = request.get("body", b"")
    timestamp: float = request.get("timestamp", time.time())
    prev_ts: list[float] = request.get("prev_timestamps", [])
    mouse_path: list[tuple] = request.get("mouse_path", [])

    # ── Group 0-9: Request structure ────────────────────────────────────────
    features[0] = _method_score(method)
    features[1] = min(len(path) / 2048.0, 1.0)
    features[2] = min(len(query_string) / 4096.0, 1.0)
    features[3] = min(len(body) / 65536.0, 1.0)
    features[4] = _byte_entropy(path.encode())
    features[5] = _byte_entropy(query_string.encode())
    features[6] = _byte_entropy(body) if body else 0.0
    features[7] = _special_char_ratio(path + "?" + query_string)
    features[8] = _digit_ratio(path)
    features[9] = _path_depth(path)

    # ── Group 10-19: Header anomalies ───────────────────────────────────────
    features[10] = min(len(headers) / 30.0, 1.0)
    features[11] = _has_user_agent(headers)
    features[12] = _user_agent_entropy(headers)
    features[13] = _accept_header_score(headers)
    features[14] = _content_type_score(headers, method)
    features[15] = _has_referer(headers)
    features[16] = _has_accept_encoding(headers)
    features[17] = _has_accept_language(headers)
    features[18] = _cookie_count(headers)
    features[19] = _unknown_header_ratio(headers)

    # ── Group 20-29: Temporal / jitter ──────────────────────────────────────
    features[20] = _arrival_rate(prev_ts, timestamp)
    features[21] = _inter_arrival_jitter(prev_ts)
    features[22] = _burst_score(prev_ts, timestamp)
    features[23] = _time_of_day_score(timestamp)
    features[24] = _regularity_score(prev_ts)
    features[25] = _request_acceleration(prev_ts)
    features[26] = _weekend_flag(timestamp)
    features[27] = _off_hours_flag(timestamp)
    features[28] = _idle_gap_score(prev_ts)
    features[29] = _session_duration_score(prev_ts)

    # ── Group 30-38: Path / URI pattern ─────────────────────────────────────
    features[30] = _has_sql_keywords(path + "?" + query_string)
    features[31] = _has_traversal_pattern(path)
    features[32] = _has_script_tags(query_string)
    features[33] = _encoded_chars_ratio(query_string)
    features[34] = _repeated_param_score(query_string)
    features[35] = _path_extension_score(path)
    features[36] = _double_encoded(query_string)
    features[37] = _null_byte_present(path + query_string)
    features[38] = _unicode_anomaly(path + query_string)

    # ── Group 39-46: Payload shape ──────────────────────────────────────────
    features[39] = _body_entropy_delta(body)
    features[40] = _json_depth_score(body)
    features[41] = _xml_nesting_score(body)
    features[42] = _binary_ratio(body)
    features[43] = _large_value_ratio(body)
    features[44] = _mouse_path_linearity(mouse_path)
    features[45] = _mouse_velocity_entropy(mouse_path)
    features[46] = _request_hash_bit(method, path, headers)

    return features


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _byte_entropy(data: bytes) -> float:
    """Shannon entropy of byte distribution normalised to [0, 1]."""
    if not data:
        return 0.0
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    probs = counts / counts.sum()
    probs = probs[probs > 0]
    entropy = -float(np.sum(probs * np.log2(probs)))
    return entropy / 8.0  # max entropy of a byte is 8 bits


def _method_score(method: str) -> float:
    scores = {"GET": 0.1, "POST": 0.2, "PUT": 0.25, "PATCH": 0.3,
              "DELETE": 0.4, "HEAD": 0.15, "OPTIONS": 0.5, "CONNECT": 0.8,
              "TRACE": 0.9}
    return scores.get(method, 0.95)


def _special_char_ratio(text: str) -> float:
    if not text:
        return 0.0
    specials = sum(1 for c in text if not c.isalnum() and c not in "-_./?=&")
    return min(specials / max(len(text), 1), 1.0)


def _digit_ratio(text: str) -> float:
    if not text:
        return 0.0
    return sum(c.isdigit() for c in text) / max(len(text), 1)


def _path_depth(path: str) -> float:
    depth = path.count("/")
    return min(depth / 10.0, 1.0)


def _has_user_agent(headers: dict) -> float:
    ua_key = next((k for k in headers if k.lower() == "user-agent"), None)
    return 0.0 if ua_key else 1.0  # missing UA is suspicious


def _user_agent_entropy(headers: dict) -> float:
    ua_key = next((k for k in headers if k.lower() == "user-agent"), None)
    if ua_key is None:
        return 1.0
    return _byte_entropy(headers[ua_key].encode())


def _accept_header_score(headers: dict) -> float:
    key = next((k for k in headers if k.lower() == "accept"), None)
    return 0.5 if key is None else 0.0


def _content_type_score(headers: dict, method: str) -> float:
    ct_key = next((k for k in headers if k.lower() == "content-type"), None)
    if method in ("POST", "PUT", "PATCH") and ct_key is None:
        return 0.8
    return 0.0


def _has_referer(headers: dict) -> float:
    key = next((k for k in headers if k.lower() == "referer"), None)
    return 0.0 if key else 0.3


def _has_accept_encoding(headers: dict) -> float:
    key = next((k for k in headers if k.lower() == "accept-encoding"), None)
    return 0.0 if key else 0.4


def _has_accept_language(headers: dict) -> float:
    key = next((k for k in headers if k.lower() == "accept-language"), None)
    return 0.0 if key else 0.4


def _cookie_count(headers: dict) -> float:
    key = next((k for k in headers if k.lower() == "cookie"), None)
    if key is None:
        return 0.0
    return min(headers[key].count(";") / 20.0, 1.0)


_STANDARD_HEADERS = frozenset([
    "host", "user-agent", "accept", "accept-language", "accept-encoding",
    "content-type", "content-length", "authorization", "cookie", "referer",
    "origin", "x-requested-with", "cache-control", "connection",
    "transfer-encoding", "if-none-match", "if-modified-since",
])


def _unknown_header_ratio(headers: dict) -> float:
    if not headers:
        return 0.0
    unknown = sum(
        1 for k in headers if k.lower() not in _STANDARD_HEADERS
    )
    return unknown / max(len(headers), 1)


def _arrival_rate(prev_ts: list[float], current: float) -> float:
    """Requests per second over recent window, normalised to [0,1]."""
    if len(prev_ts) < 2:
        return 0.0
    window = 1.0  # 1-second window
    recent = [t for t in prev_ts if current - t <= window]
    return min(len(recent) / 500.0, 1.0)  # normalise against 500 RPS ceiling


def _inter_arrival_jitter(prev_ts: list[float]) -> float:
    """Coefficient of variation of inter-arrival times (0 = perfectly regular)."""
    if len(prev_ts) < 3:
        return 0.0
    diffs = np.diff(sorted(prev_ts))
    mean = diffs.mean()
    if mean == 0:
        return 1.0
    return min(float(diffs.std() / mean), 1.0)


def _burst_score(prev_ts: list[float], current: float) -> float:
    recent = [t for t in prev_ts if current - t <= 0.1]
    return min(len(recent) / 50.0, 1.0)


def _time_of_day_score(ts: float) -> float:
    hour = time.gmtime(ts).tm_hour
    # Traffic after midnight UTC is slightly more suspicious
    return 0.7 if 0 <= hour < 5 else 0.1


def _regularity_score(prev_ts: list[float]) -> float:
    """1.0 = perfectly regular (bot-like), 0.0 = random (human-like)."""
    if len(prev_ts) < 5:
        return 0.0
    diffs = np.diff(sorted(prev_ts[-20:]))
    if diffs.mean() == 0:
        return 1.0
    cv = diffs.std() / diffs.mean()
    return max(0.0, 1.0 - min(cv, 1.0))


def _request_acceleration(prev_ts: list[float]) -> float:
    if len(prev_ts) < 4:
        return 0.0
    sorted_ts = sorted(prev_ts[-10:])
    diffs = np.diff(sorted_ts)
    if len(diffs) < 2:
        return 0.0
    accel = np.diff(diffs)
    return min(float(np.abs(accel).mean()), 1.0)


def _weekend_flag(ts: float) -> float:
    return 1.0 if time.gmtime(ts).tm_wday >= 5 else 0.0


def _off_hours_flag(ts: float) -> float:
    hour = time.gmtime(ts).tm_hour
    return 1.0 if not (8 <= hour < 20) else 0.0


def _idle_gap_score(prev_ts: list[float]) -> float:
    if len(prev_ts) < 2:
        return 0.0
    gap = max(np.diff(sorted(prev_ts)))
    return min(float(gap) / 3600.0, 1.0)


def _session_duration_score(prev_ts: list[float]) -> float:
    if len(prev_ts) < 2:
        return 0.0
    duration = max(prev_ts) - min(prev_ts)
    return min(duration / 3600.0, 1.0)


_SQL_RE = re.compile(
    r"\b(select|insert|update|delete|drop|union|exec|execute|cast|convert"
    r"|char|declare|xp_|sp_|0x[0-9a-f]+)\b",
    re.IGNORECASE,
)


def _has_sql_keywords(text: str) -> float:
    return 1.0 if _SQL_RE.search(text) else 0.0


_TRAVERSAL_RE = re.compile(r"(\.\./|\.\.\\|%2e%2e[/%5c])", re.IGNORECASE)


def _has_traversal_pattern(path: str) -> float:
    return 1.0 if _TRAVERSAL_RE.search(path) else 0.0


_SCRIPT_RE = re.compile(
    r"(<script|javascript:|onerror=|onload=|vbscript:|data:text/html)",
    re.IGNORECASE,
)


def _has_script_tags(text: str) -> float:
    return 1.0 if _SCRIPT_RE.search(text) else 0.0


def _encoded_chars_ratio(text: str) -> float:
    if not text:
        return 0.0
    matches = len(re.findall(r"%[0-9a-fA-F]{2}", text))
    return min(matches / max(len(text) / 3, 1), 1.0)


def _repeated_param_score(qs: str) -> float:
    if not qs:
        return 0.0
    params = [p.split("=")[0] for p in qs.split("&") if "=" in p]
    if not params:
        return 0.0
    unique_ratio = len(set(params)) / len(params)
    return 1.0 - unique_ratio


def _path_extension_score(path: str) -> float:
    suspicious = {".php", ".asp", ".aspx", ".jsp", ".cgi", ".pl", ".sh",
                  ".bat", ".exe", ".dll"}
    ext = "." + path.rsplit(".", 1)[-1].lower() if "." in path else ""
    return 0.9 if ext in suspicious else 0.0


def _double_encoded(text: str) -> float:
    return 1.0 if re.search(r"%25[0-9a-fA-F]{2}", text) else 0.0


def _null_byte_present(text: str) -> float:
    return 1.0 if ("%00" in text or "\x00" in text) else 0.0


def _unicode_anomaly(text: str) -> float:
    return 1.0 if re.search(r"%u[0-9a-fA-F]{4}", text) else 0.0


def _body_entropy_delta(body: bytes) -> float:
    if len(body) < 16:
        return 0.0
    half = len(body) // 2
    e1 = _byte_entropy(body[:half])
    e2 = _byte_entropy(body[half:])
    return abs(e1 - e2)


def _json_depth_score(body: bytes) -> float:
    if not body:
        return 0.0
    depth = max_depth = 0
    for b in body:
        if b in (ord("{"), ord("[")):
            depth += 1
            max_depth = max(max_depth, depth)
        elif b in (ord("}"), ord("]")):
            depth = max(depth - 1, 0)
    return min(max_depth / 20.0, 1.0)


def _xml_nesting_score(body: bytes) -> float:
    if not body:
        return 0.0
    opens = body.count(b"<")
    return min(opens / 100.0, 1.0)


def _binary_ratio(body: bytes) -> float:
    if not body:
        return 0.0
    non_printable = sum(1 for b in body if b < 0x20 and b not in (9, 10, 13))
    return non_printable / max(len(body), 1)


def _large_value_ratio(body: bytes) -> float:
    if not body:
        return 0.0
    try:
        text = body.decode("utf-8", errors="ignore")
    except Exception:
        return 0.0
    values = re.findall(r"[=:\"']([^&\n\"']{100,})", text)
    return min(len(values) / 5.0, 1.0)


def _mouse_path_linearity(mouse_path: list) -> float:
    """Returns 0.0 for perfect straight line (bot-like), 1.0 for curved (human)."""
    if len(mouse_path) < 3:
        return 0.5
    xs = np.array([p[0] for p in mouse_path], dtype=float)
    ys = np.array([p[1] for p in mouse_path], dtype=float)
    # Fit a line and measure residuals
    if xs.std() == 0:
        return 0.0
    coeffs = np.polyfit(xs, ys, 1)
    predicted = np.polyval(coeffs, xs)
    residuals = np.abs(ys - predicted)
    linearity = 1.0 - min(residuals.mean() / 100.0, 1.0)
    return float(linearity)


def _mouse_velocity_entropy(mouse_path: list) -> float:
    if len(mouse_path) < 4:
        return 0.5
    xs = np.array([p[0] for p in mouse_path], dtype=float)
    ys = np.array([p[1] for p in mouse_path], dtype=float)
    velocities = np.sqrt(np.diff(xs) ** 2 + np.diff(ys) ** 2)
    if velocities.sum() == 0:
        return 0.0
    # Normalise and compute entropy of velocity distribution
    probs, _ = np.histogram(velocities, bins=8, density=True)
    probs = probs[probs > 0]
    return float(-np.sum(probs * np.log2(probs + 1e-10)) / 8.0)


def _request_hash_bit(method: str, path: str, headers: dict) -> float:
    """Stable fingerprint bit — used as a tiebreaker dimension."""
    raw = f"{method}:{path}:{sorted(headers.keys())}"
    h = int(hashlib.md5(raw.encode()).hexdigest(), 16)
    return float(h & 1)
