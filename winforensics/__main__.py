"""Entry point: ``python -m winforensics`` (GUI) or ``python -m winforensics <command>`` (CLI)."""

import multiprocessing
import sys


def main():
    multiprocessing.freeze_support()
    if len(sys.argv) > 1 and sys.argv[1] in ("profiles", "new", "run", "report", "rerun-module", "-h", "--help"):
        from .cli import main as cli_main

        sys.exit(cli_main(sys.argv[1:]) or 0)
    from .gui.app import main as gui_main

    sys.exit(gui_main())


if __name__ == "__main__":
    main()
