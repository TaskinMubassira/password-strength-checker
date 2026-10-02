import pytest

from password_checker.strength import charset_size, check, find_patterns


@pytest.mark.parametrize("password", ["password", "123456", "qwerty", "Password123", "dhaka2024"])
def test_common_and_patterned_passwords_are_weak(password):
    assert check(password).score <= 1


def test_long_random_password_is_very_strong():
    result = check("t9#Lq!vZ2@mR7&xW4pK")
    assert result.score == 4
    assert result.warnings == []


def test_passphrase_scores_well():
    assert check("river-candle-orbit-mango").score >= 3


def test_empty_password():
    result = check("")
    assert result.score == 0
    assert "empty" in result.warnings[0]


def test_charset_size():
    assert charset_size("abc") == 26
    assert charset_size("aB3!") == 26 + 26 + 10 + 33


@pytest.mark.parametrize(
    ("password", "fragment"),
    [("myqwerpass", "keyboard"), ("zz1234zz", "sequence"), ("heyyyy!", "Repeats"), ("rose1999", "year")],
)
def test_patterns_are_reported(password, fragment):
    assert any(fragment in warning for warning in find_patterns(password))


def test_short_passwords_get_a_length_suggestion():
    assert any("12 characters" in s for s in check("aB3!x").suggestions)
