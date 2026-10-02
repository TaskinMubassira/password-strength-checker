# 🔐 Password Strength Checker

A small Python tool that tells you how strong a password really is — and whether it has already leaked in a data breach — **without ever sending the password anywhere**.

```text
$ python -m password_checker
Password to check:

Strength: #.... Very weak  (~10.0 bits)
  ! This is a commonly used password (or a common password with numbers added).
  ! Found in data breaches 52,372,427 times. Do not use this password.
  - Use at least 12 characters; length matters more than complexity.
  - Try a passphrase of four or more random words, e.g. 'river-candle-orbit-mango'.
```

## Features

- **Offline strength score (0–4)** from an entropy estimate, reduced for the patterns attackers try first:
  common passwords, keyboard walks (`qwer`, `asdf`), sequences (`abcd`, `1234`), repeated characters and years.
- **Breach check with k-anonymity** using the [Have I Been Pwned](https://haveibeenpwned.com/API/v3#PwnedPasswords) range API:
  only the first 5 characters of the password's SHA-1 hash leave your computer; the match is done locally.
- **Hidden input** with `getpass`, so the password is not shown on screen or saved in shell history.
- Clear warnings and practical suggestions.
- Unit tests for scoring and for the privacy of the breach check.

## How the breach check stays private

```text
password  ──SHA-1──▶  5BAA6 1E4C9B93F3F0682250B6CF8331B7EE68FD8
                      └─┬─┘ └──────────────┬───────────────────┘
          sent to the API ┘                └ compared on your computer only
```

The API answers with every leaked hash that starts with `5BAA6` (hundreds of them, plus padding),
so it never learns which password you checked.

## Getting started

```bash
git clone https://github.com/TaskinMubassira/password-strength-checker.git
cd password-strength-checker
python -m venv .venv
.venv\Scripts\activate          # Windows  (macOS/Linux: source .venv/bin/activate)
pip install -e ".[dev]"

python -m password_checker            # check a password
python -m password_checker --offline  # skip the breach check
pytest                                # run the tests
```

Use it from your own code:

```python
from password_checker import check, times_pwned

result = check("river-candle-orbit-mango")
print(result.score, result.label, result.warnings)   # 4 Very strong []
print(times_pwned("password"))                        # how many times it appeared in breaches
```

## Project structure

```text
password_checker/
├── strength.py            # offline scoring and pattern detection
├── breach.py              # k-anonymity breach check (HIBP range API)
├── cli.py                 # command line interface
└── common_passwords.txt   # short list of the most common passwords
tests/                     # pytest unit tests
```

## Notes

- The strength score is an estimate to guide users, not a guarantee. Long, random passphrases are the safest choice.
- Use a password manager and enable two-factor authentication wherever possible.

## License

MIT © Tasmia Taskin Mubassira
