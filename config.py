"""
Configuration settings for the Web Cache Poisoning Attack Simulation.
Defines network endpoints, cache parameters, and hardening options.
"""

from dataclasses import dataclass
from typing import List


@dataclass
class SimulationConfig:
    # Network interfaces and ports
    HOST: str = "127.0.0.1"
    CACHE_PROXY_PORT: int = 8880
    UPSTREAM_PORT: int = 8881
    ATTACKER_ORIGIN_PORT: int = 8882

    # Derived URLs
    @property
    def cache_proxy_url(self) -> str:
        return f"http://{self.HOST}:{self.CACHE_PROXY_PORT}"

    @property
    def upstream_url(self) -> str:
        return f"http://{self.HOST}:{self.UPSTREAM_PORT}"

    @property
    def attacker_origin_url(self) -> str:
        return f"http://{self.HOST}:{self.ATTACKER_ORIGIN_PORT}"

    # Cache behavior settings
    DEFAULT_CACHE_TTL: int = 30  # seconds
    CACHE_CONTROL_HEADER: str = "public, max-age=30"

    # Default cache key components: METHOD, HOST, PATH
    # Unkeyed headers in vulnerable mode: X-Forwarded-Host, X-Forwarded-Scheme, etc.
    UNKEYED_POISON_HEADER: str = "X-Forwarded-Host"

    # Canonical backend asset domain
    CANONICAL_STATIC_HOST: str = f"127.0.0.1:8881"

    # Allowed hosts for hardened upstream validation
    ALLOWED_HOSTS: List[str] = (
        "127.0.0.1:8880",
        "127.0.0.1:8881",
        "localhost:8880",
        "localhost:8881",
    )


# Global default configuration instance
DEFAULT_CONFIG = SimulationConfig()

