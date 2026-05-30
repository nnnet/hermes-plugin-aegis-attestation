"""Why: Enables `python -m plugins.aegis_attestation tick` as a rescue path
when the hermes CLI plugin loader can't register the `aegis` subcommand
(e.g. minimal-install environments, debugging).
What: Delegates to cli_main from __init__.py.
Test: `python -m plugins.aegis_attestation config` prints JSON and returns 0.
"""

from __future__ import annotations

import sys

from . import cli_main


if __name__ == "__main__":
    sys.exit(cli_main(sys.argv[1:]))
