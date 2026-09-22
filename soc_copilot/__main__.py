"""Allow ``python -m soc_copilot``."""

from __future__ import annotations

from soc_copilot.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
