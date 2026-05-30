"""
pytest configuration — sets GATEWAY_API_KEYS before any test imports app modules,
so auth.py loads with a known test key.
"""
import os

# Must be set before app modules are imported by any test
os.environ.setdefault("GATEWAY_API_KEYS", "sk-test-integration-key")
