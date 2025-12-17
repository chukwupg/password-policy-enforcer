import pytest
from password_enforcer import validate_password, DEFAULT_POLICY

def test_good_password():
    pw = "CorrectHorseBatteryStaple1!"
    res = validate_password(pw, policy=DEFAULT_POLICY)
    assert res["valid"] is True
    assert res["entropy_bits"] > 50

def test_short_password():
    pw = "Ab1!"
    res = validate_password(pw, policy=DEFAULT_POLICY)
    assert res["valid"] is False
    assert any("short" in e.lower() or "length" in e.lower() for e in res["errors"])

def test_repeats_and_sequence():
    pw = "aaaa1111abcd"
    res = validate_password(pw, policy=DEFAULT_POLICY)
    assert res["valid"] is False or len(res["warnings"])>0

def test_banned_substring():
    policy = DEFAULT_POLICY.copy()
    policy["banned_passwords"] = ["company"]
    pw = "MyCompany2025!"
    res = validate_password(pw, policy=policy)
    assert any("banned" in e.lower() for e in res["errors"])
