"""Frozen entry point used by PyInstaller for both WFA.exe (GUI) and wfa-cli.exe (CLI)."""

import multiprocessing
import os
import sys

if __name__ == "__main__":
    # must run first: evidence workers are spawned as child processes of the frozen executable
    multiprocessing.freeze_support()
    exe = os.path.splitext(os.path.basename(sys.executable))[0].lower()
    if exe == "wfa-cli" and len(sys.argv) == 1:
        sys.argv.append("--help")
    from winforensics.__main__ import main

    main()
