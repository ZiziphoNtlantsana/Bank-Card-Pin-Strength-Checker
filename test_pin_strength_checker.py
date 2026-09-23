"""
Unit tests for pin_strength_checker.py

Run with:  python -m pytest test_pin_strength_checker.py -v
"""

# Import the functions we want to test directly from the main script.
from pin_strength_checker import (
    is_correct_length,
    is_sequential,
    is_repeated,
    is_common,
    check_pin,
)


def test_is_correct_length():
    # A proper 4-digit numeric PIN should pass.
    assert is_correct_length("1234") is True
    # Too short, too long, and non-numeric input should all fail.
    assert is_correct_length("123") is False
    assert is_correct_length("12345") is False
    assert is_correct_length("12a4") is False


def test_is_sequential():
    # Ascending and descending runs should both be flagged as sequential.
    assert is_sequential("1234") is True
    assert is_sequential("4321") is True
    assert is_sequential("0123") is True
    assert is_sequential("9876") is True
    # Non-sequential digit patterns should NOT be flagged.
    assert is_sequential("1357") is False
    assert is_sequential("1213") is False


def test_is_repeated():
    # PINs with only 1 or 2 distinct digits should be flagged.
    assert is_repeated("1111") is True
    assert is_repeated("1212") is True
    assert is_repeated("1122") is True
    # PINs with 3+ distinct digits should NOT be flagged.
    assert is_repeated("1234") is False
    assert is_repeated("1213") is False


def test_is_common():
    # Known weak PINs from our list should be detected.
    assert is_common("1234") is True
    assert is_common("0000") is True
    # A PIN not in our list should return False.
    assert is_common("7439") is False


def test_check_pin_invalid_format():
    # An invalid-format PIN should short-circuit and return "Invalid"
    # without running the pattern checks.
    result = check_pin("12a4")
    assert result["valid_format"] is False
    assert result["strength"] == "Invalid"


def test_check_pin_weak():
    # "1111" is both repeated AND a common PIN -> at least 2 issues -> Weak.
    result = check_pin("1111")
    assert result["valid_format"] is True
    assert result["strength"] == "Weak"
    assert len(result["issues"]) >= 2


def test_check_pin_strong():
    # "7439" has no sequential, repeated, or common-list issues -> Strong.
    result = check_pin("7439")
    assert result["valid_format"] is True
    assert result["strength"] == "Strong"
    assert result["issues"] == []


def test_check_pin_moderate():
    # "2580" is only flagged for one reason (it's in the common list),
    # so it should land in the middle: Moderate.
    result = check_pin("2580")
    assert result["valid_format"] is True
    assert result["strength"] == "Moderate"
    assert len(result["issues"]) == 1