from password_enforcer import validate_password

def test_weak_password_fails():
    result = validate_password("password123")
    assert not result["valid"]
    assert result["zxcvbn_score"] < 3

def test_strong_password_passes():
    result = validate_password("CorrectHorseBatteryStaple!92")
    assert result["valid"]

def test_feedback_present_for_weak_password():
    result = validate_password("password123")
    assert result["suggestions"]
