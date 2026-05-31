#!/usr/bin/env python3
"""
generate_keys.py — Create and register API keys for the Secure LLM Gateway.

Usage:
    python generate_keys.py              # Generate 1 key
    python generate_keys.py --count 3   # Generate 3 keys
    python generate_keys.py --add       # Generate + append hash to keys.json

The plaintext key is displayed ONCE. Store it in a password manager.
Only the SHA-256 hash is written to keys.json — never the plaintext key.
"""

import argparse
import hashlib
import json
import secrets
from pathlib import Path


def generate_key() -> tuple[str, str]:
    """Returns (plaintext_key, sha256_hash)."""
    key = "sk-gw-" + secrets.token_urlsafe(32)
    hashed = hashlib.sha256(key.encode()).hexdigest()
    return key, hashed


def main():
    parser = argparse.ArgumentParser(description="Generate API keys for the LLM Gateway")
    parser.add_argument("--count", type=int, default=1, help="Number of keys to generate")
    parser.add_argument("--add", action="store_true", help="Append hash(es) to keys.json")
    args = parser.parse_args()

    generated = [generate_key() for _ in range(args.count)]

    print("\n" + "═" * 60)
    print("  SECURE LLM GATEWAY — API Key Generator")
    print("  ⚠  Copy these keys now. They will NOT be shown again.")
    print("═" * 60)
    for i, (key, hsh) in enumerate(generated, 1):
        print(f"\n  Key #{i}")
        print(f"  Plaintext : {key}")
        print(f"  SHA-256   : {hsh}")
    print("\n" + "═" * 60)

    if args.add:
        key_file = Path("keys.json")
        if key_file.exists():
            data = json.loads(key_file.read_text())
        else:
            data = {"keys": []}

        new_hashes = [hsh for _, hsh in generated]
        data["keys"].extend(new_hashes)
        key_file.write_text(json.dumps(data, indent=2))
        print(f"\n  ✓  {len(new_hashes)} hash(es) written to keys.json")
        print("  ✓  keys.json is in .gitignore — it will NOT be committed\n")


if __name__ == "__main__":
    main()
