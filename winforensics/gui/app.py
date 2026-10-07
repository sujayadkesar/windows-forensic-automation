"""GUI entry point."""

from __future__ import annotations

import logging
import os
import sys


def main(argv=None) -> int:
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QApplication

    from .. import __app_title__, __version__
    from ..report.brand import logo_icon
    from . import theme
    from .main_window import MainWindow

    log_dir = os.path.join(os.environ.get("APPDATA") or os.path.expanduser("~"), "WindowsForensicAutomation", "logs")
    os.makedirs(log_dir, exist_ok=True)
    logging.basicConfig(filename=os.path.join(log_dir, "winforensics.log"), level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    if os.name == "nt":
        try:
            import ctypes

            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("WindowsForensicAutomation")
        except Exception:
            pass
    QApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    app = QApplication(argv or sys.argv)
    app.setApplicationName(__app_title__)
    app.setApplicationVersion(__version__)
    app.setOrganizationName("WindowsForensicAutomation")
    from PySide6.QtCore import QSettings

    theme.set_mode(QSettings("WindowsForensicAutomation", "Windows Forensic Automation").value("theme", "dark"))
    theme.apply(app)
    app.setWindowIcon(logo_icon())
    w = MainWindow()
    app._main_window = w
    w.show()
    args = [a for a in (argv or sys.argv)[1:] if not a.startswith("-")]
    if args and os.path.exists(os.path.join(args[0], "case.json")):
        w.open_case(args[0])
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
