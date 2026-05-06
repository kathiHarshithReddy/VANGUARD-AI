"""
VANGUARD configuration — loaded from environment variables with sensible defaults.
"""

import os
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class EntropyConfig:
    # Minimum entropy score (0-1) above which traffic is considered benign
    benign_threshold: float = float(os.getenv("ENTROPY_BENIGN_THRESHOLD", "0.45"))
    # Rolling window size (number of requests) used when computing statistics
    window_size: int = int(os.getenv("ENTROPY_WINDOW_SIZE", "200"))
    # Number of behavioral dimensions evaluated per request
    dimensions: int = 47
    # Maximum requests per second per IP before rate-limit kicks in
    rps_limit: float = float(os.getenv("ENTROPY_RPS_LIMIT", "500"))
    # Minimum confidence required to auto-block without human review
    block_confidence: float = float(os.getenv("ENTROPY_BLOCK_CONFIDENCE", "0.85"))


@dataclass
class InjectionShieldConfig:
    # Maximum number of query grammars kept in the learner's memory
    max_grammars: int = int(os.getenv("SHIELD_MAX_GRAMMARS", "10000"))
    # Similarity threshold (0-1) below which a query is treated as anomalous
    similarity_threshold: float = float(os.getenv("SHIELD_SIMILARITY_THRESHOLD", "0.60"))
    # Supported query types
    supported_types: list = field(
        default_factory=lambda: ["sql", "nosql", "graphql"]
    )


@dataclass
class DojoConfig:
    # Target payloads generated per minute by the fuzzing engine
    payloads_per_minute: int = int(os.getenv("DOJO_PAYLOADS_PER_MINUTE", "1000"))
    # Sandbox timeout for each payload test (seconds)
    sandbox_timeout: float = float(os.getenv("DOJO_SANDBOX_TIMEOUT", "0.5"))
    # Minimum new attack samples required before triggering a model retrain
    retrain_threshold: int = int(os.getenv("DOJO_RETRAIN_THRESHOLD", "100"))
    # Path where the adversarial model checkpoint is saved
    checkpoint_path: str = os.getenv("DOJO_CHECKPOINT", "dojo_checkpoint.pkl")


@dataclass
class ProxyConfig:
    host: str = os.getenv("PROXY_HOST", "0.0.0.0")
    port: int = int(os.getenv("PROXY_PORT", "8080"))
    origin_url: str = os.getenv("ORIGIN_URL", "http://localhost:8000")
    # Hard limit on concurrent connections
    max_connections: int = int(os.getenv("PROXY_MAX_CONNECTIONS", "10000"))


@dataclass
class VanguardConfig:
    entropy: EntropyConfig = field(default_factory=EntropyConfig)
    injection_shield: InjectionShieldConfig = field(
        default_factory=InjectionShieldConfig
    )
    dojo: DojoConfig = field(default_factory=DojoConfig)
    proxy: ProxyConfig = field(default_factory=ProxyConfig)
    debug: bool = os.getenv("VANGUARD_DEBUG", "false").lower() == "true"


# Module-level singleton — import this in other modules
config = VanguardConfig()
