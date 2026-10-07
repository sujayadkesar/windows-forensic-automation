# PyInstaller spec - Windows Forensic Automation
#
# Build with:  python packaging/build_exe.py
# (the build script prepares the icon and the dissect plugin index, then runs PyInstaller on this file)
#
# Output: dist/WindowsForensicAutomation/
#     WFA.exe        desktop application (no console window)
#     wfa-cli.exe    command line interface (same engine, for scripting / batch processing)

import os

from PyInstaller.utils.hooks import collect_data_files, collect_dynamic_libs, collect_submodules

ROOT = os.path.abspath(os.path.join(SPECPATH, ".."))
ICON = os.path.join(SPECPATH, "build", "wfa.ico")

hidden = (
    collect_submodules("winforensics")
    + collect_submodules("dissect")
    + collect_submodules("oletools")
    + collect_submodules("evtx")
    + ["pyewf", "pyvshadow", "pypff", "yara", "ahocorasick", "win32com.client", "pythoncom", "pywintypes",
       "LnkParse3", "pycdlib", "xlsxwriter", "openpyxl", "docx", "pypdf", "pefile", "olefile", "msoffcrypto"]
)

datas = (
    collect_data_files("winforensics", includes=["**/*.yaml", "**/*.yml", "**/*.yar", "**/*.yara", "**/*.txt", "**/*.json"])
    + collect_data_files("dissect.target")
    + collect_data_files("oletools")
    + collect_data_files("docx")
)

binaries = collect_dynamic_libs("yara") + collect_dynamic_libs("pyewf") + collect_dynamic_libs("pyvshadow") + \
    collect_dynamic_libs("pypff")

a = Analysis(
    [os.path.join(SPECPATH, "wfa_entry.py")],
    pathex=[ROOT],
    binaries=binaries,
    datas=datas,
    hiddenimports=hidden,
    excludes=["tkinter", "matplotlib", "IPython", "pytest", "PySide6.Qt3DCore", "PySide6.QtWebEngineCore",
              "PySide6.QtWebEngineWidgets", "PySide6.QtQuick3D", "PySide6.QtMultimedia", "PySide6.QtCharts",
              "PySide6.QtDataVisualization", "PySide6.QtBluetooth", "PySide6.QtSensors", "PySide6.QtLocation"],
    noarchive=False,
)
pyz = PYZ(a.pure)

gui = EXE(
    pyz, a.scripts, [],
    exclude_binaries=True,
    name="WFA",
    icon=ICON if os.path.exists(ICON) else None,
    console=False,
    version=os.path.join(SPECPATH, "build", "version.txt") if os.path.exists(os.path.join(SPECPATH, "build", "version.txt")) else None,
)
cli = EXE(
    pyz, a.scripts, [],
    exclude_binaries=True,
    name="wfa-cli",
    icon=ICON if os.path.exists(ICON) else None,
    console=True,
)
coll = COLLECT(gui, cli, a.binaries, a.datas, strip=False, upx=False, name="WindowsForensicAutomation")
