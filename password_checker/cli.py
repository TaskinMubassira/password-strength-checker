"""Command line interface: python -m password_checker"""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from dataclasses import asdict

import requests

from .breach import times_pwned
from .strength import check

# Plain ASCII so it prints in every terminal, including the Windows console.
BAR = ("#....", "##...", "###..", "####.", "#####")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="password_checker", description="Check how strong a password is.")
    parser.add_argument("--offline", action="store_true", help="skip the data breach check (no internet needed)")
    parser.add_argument("--json", action="store_true", help="print the result as JSON (for scripts and CI)")
    args = parser.parse_args(argv)

    # getpass hides the password while typing and keeps it out of shell history.
    password = getpass.getpass("Password to check: ")
    result = check(password)

    if args.json:
        return print_json(result, None if args.offline else _breach_count(password))

    print(f"\nStrength: {BAR[result.score]:<5} {result.label}  (~{result.entropy_bits} bits)")
    for warning in result.warnings:
        print(f"  ! {warning}")

    if not args.offline:
        try:
            count = times_pwned(password)
        except requests.RequestException:
            print("  ? Could not reach the breach database; run again later or use --offline.")
        else:
            if count:
                print(f"  ! Found in data breaches {count:,} times. Do not use this password.")
                result.score = 0
            else:
                print("  + Not found in known data breaches.")

    for suggestion in result.suggestions:
        print(f"  - {suggestion}")
    return 0 if result.score >= 3 else 1


def _breach_count(password: str) -> int | None:
    try:
        return times_pwned(password)
    except requests.RequestException:
        return None  # unknown: the breach database could not be reached


def print_json(result, breach_count: int | None) -> int:
    data = asdict(result)
    data["breach_count"] = breach_count
    if breach_count:
        data["score"] = 0
    print(json.dumps(data, indent=2))
    return 0 if data["score"] >= 3 else 1


if __name__ == "__main__":
    sys.exit(main())
