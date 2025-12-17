#!/usr/bin/env python3
"""
password_enforcer.py

A configurable password policy enforcer.

Usage (CLI):
    python password_enforcer.py --password "MyP@ssw0rd!"
    python password_enforcer.py --password-file passwords.txt --config policy.json

As module:
    from password_enforcer import validate_password, DEFAULT_POLICY
    result = validate_password("MyP@ssw0rd!", policy=DEFAULT_POLICY)
"""

import re
import json
import math
import argparse
from typing import Dict, Any, List

# ---------- Default policy ----------
DEFAULT_POLICY = {
    "min_length": 12,
    "max_length": 128,
    "min_upper": 1,
    "min_lower": 1,
    "min_digits": 1,
    "min_symbols": 1,
    "forbid_common": True,        # check against a small default banned list
    "banned_passwords": ["password", "123456", "qwerty", "letmein", "admin"],
    "max_consecutive_repeats": 3, # e.g., "aaaa" -> fail if >3
    "max_sequential": 3,          # e.g., "abcd" length > 3 fails
    "min_entropy_bits": 50        # recommended minimum entropy
}

SYMBOL_RE = re.compile(r"[^\w\s]")  # anything not alnum or underscore or whitespace

# ---------- Helpers ----------
def _count_classes(pw: str) -> Dict[str, int]:
    counts = {"upper": 0, "lower": 0, "digits": 0, "symbols": 0}
    for ch in pw:
        if ch.isupper(): counts["upper"] += 1
        elif ch.islower(): counts["lower"] += 1
        elif ch.isdigit(): counts["digits"] += 1
        elif SYMBOL_RE.search(ch): counts["symbols"] += 1
        else:
            # whitespace or other
            pass
    return counts

def _has_banned(pw_lower: str, banned: List[str]) -> bool:
    return any(b in pw_lower for b in banned)

def _max_consecutive_repeat(pw: str) -> int:
    if not pw: return 0
    maxrun = 1
    run = 1
    for i in range(1, len(pw)):
        if pw[i] == pw[i-1]:
            run += 1
            if run > maxrun: maxrun = run
        else:
            run = 1
    return maxrun

def _max_sequential(pw: str) -> int:
    # Count longest ascending or descending sequence of letters or digits
    if not pw: return 0
    maxseq = 1
    seq = 1
    for i in range(1, len(pw)):
        prev, cur = ord(pw[i-1]), ord(pw[i])
        if cur - prev == 1 or cur - prev == -1:
            seq += 1
            if seq > maxseq: maxseq = seq
        else:
            seq = 1
    return maxseq

def estimate_entropy_bits(pw: str) -> float:
    """
    Simple entropy estimate:
      - Count character classes used and estimate pool size
      - bits = length * log2(pool_size)
    This is a heuristic. For better estimates use zxcvbn.
    """
    pool = 0
    counts = _count_classes(pw)
    if counts["lower"] > 0: pool += 26
    if counts["upper"] > 0: pool += 26
    if counts["digits"] > 0: pool += 10
    if counts["symbols"] > 0: pool += 32  # rough symbol set
    if pool == 0:
        return 0.0
    bits = len(pw) * math.log2(pool)
    return bits

# ---------- Core validation ----------
def validate_password(pw: str, policy: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Validate password according to policy. Returns dict:
      {
        "valid": bool,
        "errors": [...],
        "warnings": [...],
        "entropy_bits": float,
        "suggestions": [...]
      }
    """
    if policy is None:
        policy = DEFAULT_POLICY

    errors = []
    warnings = []
    suggestions = []

    length = len(pw)
    pw_lower = pw.lower()

    # Length checks
    if length < policy.get("min_length", 0):
        errors.append(f"Password too short: {length} characters; minimum is {policy['min_length']}.")
    if "max_length" in policy and length > policy["max_length"]:
        errors.append(f"Password too long: {length} characters; maximum is {policy['max_length']}.")

    # Character class checks
    counts = _count_classes(pw)
    if counts["upper"] < policy.get("min_upper", 0):
        errors.append(f"Need at least {policy['min_upper']} uppercase letter(s).")
    if counts["lower"] < policy.get("min_lower", 0):
        errors.append(f"Need at least {policy['min_lower']} lowercase letter(s).")
    if counts["digits"] < policy.get("min_digits", 0):
        errors.append(f"Need at least {policy['min_digits']} digit(s).")
    if counts["symbols"] < policy.get("min_symbols", 0):
        errors.append(f"Need at least {policy['min_symbols']} symbol(s).")

    # Banned/common checks
    if policy.get("forbid_common", False):
        banned_list = policy.get("banned_passwords", []) or []
        # include full-word containment as simple heuristic
        if _has_banned(pw_lower, banned_list):
            errors.append("Password contains a commonly used substring or banned word.")

    # repeats and sequences
    maxrepeat = _max_consecutive_repeat(pw)
    if maxrepeat > policy.get("max_consecutive_repeats", 3):
        errors.append(f"Too many consecutive repeated chars (max run {maxrepeat}).")

    maxseq = _max_sequential(pw)
    if maxseq > policy.get("max_sequential", 3):
        warnings.append(f"Password contains sequential chars of length {maxseq} (avoid 'abcd', '1234').")

    # Entropy estimate
    entropy = estimate_entropy_bits(pw)
    if entropy < policy.get("min_entropy_bits", 50):
        warnings.append(f"Estimated entropy is low: {entropy:.1f} bits (recommend >= {policy['min_entropy_bits']} bits).")
        suggestions.append("Use a longer passphrase or add additional character classes.")
    else:
        suggestions.append("Entropy looks adequate.")

    # Provide suggestions based on shortfalls
    if length < policy.get("min_length", 0):
        suggestions.append("Increase password length — passphrases (3+ unrelated words) work well.")
    if counts["digits"] == 0:
        suggestions.append("Add digits to the password.")
    if counts["symbols"] == 0:
        suggestions.append("Add symbols (e.g., !@#$%) to increase complexity.")
    if counts["lower"] == 0 or counts["upper"] == 0:
        suggestions.append("Include both upper- and lower-case letters.")
    if _has_banned(pw_lower, policy.get("banned_passwords", [])):
        suggestions.append("Avoid common words and patterns; use uncommon words or a passphrase.")

    valid = len(errors) == 0

    return {
        "valid": valid,
        "errors": errors,
        "warnings": warnings,
        "entropy_bits": entropy,
        "suggestions": suggestions
    }

# ---------- CLI ----------
def load_policy(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        policy = json.load(f)
    # overlay defaults for missing values
    final = DEFAULT_POLICY.copy()
    final.update(policy)
    return final

def main():
    parser = argparse.ArgumentParser(description="Password Policy Enforcer")
    parser.add_argument("--password", help="Password to validate")
    parser.add_argument("--password-file", help="File with passwords (one per line)")
    parser.add_argument("--config", help="Policy JSON file", default=None)
    args = parser.parse_args()

    policy = DEFAULT_POLICY if args.config is None else load_policy(args.config)

    passwords = []
    if args.password:
        passwords = [args.password]
    elif args.password_file:
        with open(args.password_file, "r", encoding="utf-8") as f:
            passwords = [line.rstrip("\n") for line in f]
    else:
        parser.error("Either --password or --password-file must be provided.")

    for pw in passwords:
        result = validate_password(pw, policy=policy)
        print("=" * 60)
        print(f"Password: {pw!r}")
        print(f"Valid: {result['valid']}")
        print(f"Entropy (bits): {result['entropy_bits']:.1f}")
        if result["errors"]:
            print("Errors:")
            for e in result["errors"]:
                print("  -", e)
        if result["warnings"]:
            print("Warnings:")
            for w in result["warnings"]:
                print("  -", w)
        if result["suggestions"]:
            print("Suggestions:")
            for s in result["suggestions"]:
                print("  -", s)
        print()

if __name__ == "__main__":
    main()
