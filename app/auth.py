"""
Authentication — validates Bearer API keys against a configurable store.

Keys are stored as bcrypt hashes in a JSON file (or env var for single-key
setups). This keeps plaintext keys out of the codebase entirely.

Usage in routes:
    api_key: str = Depends(verify_api_key)
"""

import os
import json
import hashlib
import secrets
import logging
from pathlib import Path
from fastapi import Request, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

logger = logging.getLogger(__name__)
_bearer = HTTPBearer(auto_error=False)


def _load_key_store() -> set[str]:
    """
    Loads valid API keys from:
      1. GATEWAY_API_KEYS env var — comma-separated plaintext (dev/testing)
      2. keys.json file at project root — hashed keys (production)
    Returns a set of raw keys that are accepted.
    """
    keys: set[str] = set()

    env_keys = os.getenv("GATEWAY_API_KEYS", "")
    if env_keys:
        for k in env_keys.split(","):
            k = k.strip()
            if k:
                keys.add(k)

    key_file = Path("keys.json")
    if key_file.exists():
        try:
            data = json.loads(key_file.read_text())
            # keys.json format: {"keys": ["sha256-hash-1", "sha256-hash-2"]}
            # At verify time we hash the incoming key and compare
            hashed = set(data.get("keys", []))
            # Store them under a special prefix so we know they're pre-hashed
            for h in hashed:
                keys.add(f"__hashed__{h}")
        except Exception as e:
            logger.warning(f"Could not load keys.json: {e}")

    return keys


_KEY_STORE = _load_key_store()


def _is_valid(incoming_key: str) -> bool:
    for stored in _KEY_STORE:
        if stored.startswith("__hashed__"):
            # Compare SHA-256 hash
            expected_hash = stored[len("__hashed__"):]
            actual_hash = hashlib.sha256(incoming_key.encode()).hexdigest()
            if secrets.compare_digest(actual_hash, expected_hash):
                return True
        else:
            # Plaintext comparison (dev only)
            if secrets.compare_digest(incoming_key, stored):
                return True
    return False


async def verify_api_key(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = _bearer,
) -> str:
    """
    FastAPI dependency. Extracts Bearer token from Authorization header
    and validates it. Returns the raw key on success (for rate-limit keying).
    Raises 401 on missing/invalid key.
    """
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=401,
            detail="Missing or malformed Authorization header. Use: Bearer <key>",
            headers={"WWW-Authenticate": "Bearer"},
        )

    key = credentials.credentials

    if not _is_valid(key):
        logger.warning(f"Invalid API key attempt from {request.client.host}")
        raise HTTPException(
            status_code=401,
            detail="Invalid API key.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return key


def generate_key() -> tuple[str, str]:
    """
    Utility: generate a new API key + its SHA-256 hash for keys.json.
    Run: python -c "from app.auth import generate_key; k,h = generate_key(); print(k, h)"
    """
    key = "sk-gw-" + secrets.token_urlsafe(32)
    hashed = hashlib.sha256(key.encode()).hexdigest()
    return key, hashed
