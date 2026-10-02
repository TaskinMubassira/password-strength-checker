"""Password strength checker with an offline score and a privacy-preserving breach check."""

from .breach import times_pwned
from .strength import Result, check

__all__ = ["Result", "check", "times_pwned"]
__version__ = "1.0.0"
