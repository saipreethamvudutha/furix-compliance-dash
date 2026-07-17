"""Clean CLI entry: `python -m log_generator --count 50 --seed 7`."""

from .generate import _main

if __name__ == "__main__":
    raise SystemExit(_main())
