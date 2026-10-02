"""Offline password strength scoring.

The score is based on an entropy estimate that is reduced for patterns attackers try first:
common passwords, keyboard walks, sequences ("abcd", "1234"), repeated characters and years.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources

KEYBOARD_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890")
SCORE_LABELS = ("Very weak", "Weak", "Fair", "Strong", "Very strong")


@dataclass
class Result:
    score: int  # 0 (very weak) to 4 (very strong)
    entropy_bits: float
    label: str
    warnings: list[str] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)


@lru_cache(maxsize=1)
def common_passwords() -> frozenset[str]:
    text = resources.files("password_checker").joinpath("common_passwords.txt").read_text(encoding="utf-8")
    return frozenset(line.strip().lower() for line in text.splitlines() if line.strip())


def charset_size(password: str) -> int:
    size = 0
    if re.search(r"[a-z]", password):
        size += 26
    if re.search(r"[A-Z]", password):
        size += 26
    if re.search(r"\d", password):
        size += 10
    if re.search(r"[^a-zA-Z\d]", password):
        size += 33
    return size


def _has_run(text: str, sequence: str, length: int = 4) -> bool:
    """True when `text` contains `length` consecutive characters of `sequence`, forwards or backwards."""
    for seq in (sequence, sequence[::-1]):
        for i in range(len(seq) - length + 1):
            if seq[i : i + length] in text:
                return True
    return False


def find_patterns(password: str) -> list[str]:
    lower = password.lower()
    found = []
    if lower in common_passwords() or re.sub(r"[\d!@#$%^&*]+$", "", lower) in common_passwords():
        found.append("This is a commonly used password (or a common password with numbers added).")
    if any(_has_run(lower, row) for row in KEYBOARD_ROWS):
        found.append("Contains a keyboard pattern such as 'qwer' or 'asdf'.")
    if _has_run(lower, "abcdefghijklmnopqrstuvwxyz") or _has_run(lower, "0123456789"):
        found.append("Contains a sequence such as 'abcd' or '1234'.")
    if re.search(r"(.)\1{2,}", password):
        found.append("Repeats the same character three or more times.")
    if re.search(r"(19|20)\d{2}", password):
        found.append("Contains a year, which is easy to guess.")
    return found


def check(password: str) -> Result:
    if not password:
        return Result(0, 0.0, SCORE_LABELS[0], ["Password is empty."], ["Choose a password of at least 12 characters."])

    entropy = len(password) * math.log2(max(charset_size(password), 1))
    warnings = find_patterns(password)
    # Every pattern makes the password much easier to guess than its raw length suggests.
    entropy *= 0.5 ** len(warnings)
    if warnings and warnings[0].startswith("This is a commonly used password"):
        entropy = min(entropy, 10.0)

    score = 0 if entropy < 28 else 1 if entropy < 36 else 2 if entropy < 60 else 3 if entropy < 80 else 4

    suggestions = []
    if len(password) < 12:
        suggestions.append("Use at least 12 characters; length matters more than complexity.")
    if charset_size(password) < 62 and score < 3:
        suggestions.append("Mix upper- and lower-case letters, numbers and symbols.")
    if warnings:
        suggestions.append("Avoid common words, patterns and personal dates.")
    if score < 3:
        suggestions.append("Try a passphrase of four or more random words, e.g. 'river-candle-orbit-mango'.")

    return Result(score, round(entropy, 1), SCORE_LABELS[score], warnings, suggestions)
