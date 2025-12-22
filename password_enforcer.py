#!/usr/bin/env python3
"""
password_enforcer.py

A configurable password policy enforcer.
"""

import re
import json
import math
import argparse
import hashlib
import requests
from requests.exceptions import RequestException
from typing import Dict, Any, List
from zxcvbn import zxcvbn

# ---------- Default policy ----------
DEFAULT_POLICY = {
    "min_length": 12,
    "max_length": 128,
    "min_upper": 1,
    "min_lower": 1,
    "min_digits": 1,
    "min_symbols": 1,
    "forbid_common": True,
    "banned_passwords": ["password", "123456", "qwerty", "letmein", "admin"],
    "max_consecutive_repeats": 3,
    "max_sequential": 3,
    "min_zxcvbn_score": 3,
    "check_breached_passwords": True
}

SYMBOL_RE = re.compile(r"[^\w\s]")

# ---------- Helpers ----------
def _count_classes(pw: str) -> Dict[str, int]:
    counts = {"upper": 0, "lower": 0, "digits": 0, "symbols": 0}
    for ch in pw:
        if ch.isupper():
            counts["upper"] += 1
        elif ch.islower():
            counts["lower"] += 1
        elif ch.isdigit():
            counts["digits"] += 1
        elif SYMBOL_RE.search(ch):
            counts["symbols"] += 1
    return counts

def _has_banned(pw_lower: str, banned: List[str]) -> bool:
    return any(b in pw_lower for b in banned)

def _max_consecutive_repeat(pw: str) -> int:
    maxrun = run = 1
    for i in range(1, len(pw)):
        if pw[i] == pw[i - 1]:
            run += 1
            maxrun = max(maxrun, run)
        else:
            run = 1
    return maxrun

def _max_sequential(pw: str) -> int:
    maxseq = seq = 1
    for i in range(1, len(pw)):
        prev, cur = ord(pw[i - 1]), ord(pw[i])
        if cur - prev in (1, -1):
            seq += 1
            maxseq = max(maxseq, seq)
        else:
            seq = 1
    return maxseq

def check_hibp_breach(password: str) -> int | None:
    try:
        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        url = f"https://api.pwnedpasswords.com/range/{prefix}"

        response = requests.get(
            url,
            headers={"User-Agent": "Password-Policy-Enforcer"},
            timeout=5
        )
        response.raise_for_status()

        for line in response.text.splitlines():
            hash_suffix, count = line.split(":")
            if hash_suffix == suffix:
                return int(count)
        return 0
    except RequestException:
        return None

# ---------- Core validation ----------
def validate_password(pw: str, policy: Dict[str, Any] = None) -> Dict[str, Any]:
    policy = policy or DEFAULT_POLICY

    errors, warnings, suggestions = [], [], []

    # Length & composition
    if len(pw) < policy["min_length"]:
        errors.append("Password is too short.")
    counts = _count_classes(pw)

    if counts["upper"] < policy["min_upper"]:
        errors.append("Missing uppercase letters.")
    if counts["lower"] < policy["min_lower"]:
        errors.append("Missing lowercase letters.")
    if counts["digits"] < policy["min_digits"]:
        errors.append("Missing digits.")
    if counts["symbols"] < policy["min_symbols"]:
        errors.append("Missing symbols.")

    # Pattern checks
    if policy["forbid_common"] and _has_banned(pw.lower(), policy["banned_passwords"]):
        errors.append("Contains common or banned words.")

    if _max_consecutive_repeat(pw) > policy["max_consecutive_repeats"]:
        errors.append("Too many repeated characters.")

    if _max_sequential(pw) > policy["max_sequential"]:
        warnings.append("Sequential patterns detected.")

    # zxcvbn evaluation
    zx = zxcvbn(pw)
    score = zx["score"]

    if score < policy["min_zxcvbn_score"]:
        errors.append(f"zxcvbn score too low ({score}/4).")
        suggestions.extend(zx["feedback"]["suggestions"])

    # HIBP check
    if policy["check_breached_passwords"]:
        breach_count = check_hibp_breach(pw)
        if breach_count is None:
            warnings.append("HIBP check unavailable.")
        elif breach_count > 0:
            errors.append(f"Password found in {breach_count:,} breaches.")

    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
        "zxcvbn_score": score,
        "suggestions": suggestions
    }

# ---------- CLI ----------
def load_policy(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        policy = json.load(f)
    final = DEFAULT_POLICY.copy()
    final.update(policy)
    return final

def main():
    parser = argparse.ArgumentParser(description="Password Policy Enforcer")
    parser.add_argument("--password", help="Password to validate")
    parser.add_argument("--password-file", help="File with passwords (one per line)")
    parser.add_argument("--config", help="Policy JSON file", default=None)
    args = parser.parse_args()

    # Load policy
    policy = DEFAULT_POLICY if args.config is None else load_policy(args.config)

    # Collect passwords to check
    passwords = []
    if args.password:
        passwords = [args.password]
    elif args.password_file:
        with open(args.password_file, "r", encoding="utf-8") as f:
            passwords = [line.rstrip("\n") for line in f]
    else:
        parser.error("Either --password or --password-file must be provided.")

    # Validate each password
    for pw in passwords:
        result = validate_password(pw, policy=policy)
        print("=" * 60)
        print(f"Password: {pw!r}")
        print(f"Valid: {result['valid']}")
        if "zxcvbn_score" in result:
            print(f"ZXCVBN Score: {result['zxcvbn_score']}/4")

        # Errors
        if result["errors"]:
            print("Errors:")
            for e in result["errors"]:
                print(f"  - {e}")

        # Warnings
        if result["warnings"]:
            print("Warnings:")
            for w in result["warnings"]:
                print(f"  - {w}")

        # Suggestions
        if result["suggestions"]:
            print("Suggestions:")
            for s in result["suggestions"]:
                print(f"  - {s}")

        print()  # Blank line between passwords


if __name__ == "__main__":
    main()
