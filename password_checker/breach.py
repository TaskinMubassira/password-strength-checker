"""Checks whether a password appears in known data breaches, without sending the password anywhere.

Uses the Have I Been Pwned "range" API (k-anonymity): only the first 5 characters of the password's
SHA-1 hash are sent; the service returns every leaked hash starting with them and the match is made here.
"""

from __future__ import annotations

import hashlib

import requests

API_URL = "https://api.pwnedpasswords.com/range/{prefix}"


def sha1_hex(password: str) -> str:
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def times_pwned(password: str, session: requests.Session | None = None, timeout: float = 10.0) -> int:
    """How many times the password was seen in breaches (0 = not found)."""
    digest = sha1_hex(password)
    prefix, suffix = digest[:5], digest[5:]
    http = session or requests
    response = http.get(API_URL.format(prefix=prefix), headers={"Add-Padding": "true"}, timeout=timeout)
    response.raise_for_status()
    for line in response.text.splitlines():
        hash_suffix, _, count = line.partition(":")
        if hash_suffix.strip() == suffix:
            return int(count.strip() or 0)
    return 0
