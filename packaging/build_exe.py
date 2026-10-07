"""Build the Windows Forensic Automation desktop executable.

    python packaging/build_exe.py            # build dist/WindowsForensicAutomation/
    python packaging/build_exe.py --zip      # ... and a portable zip next to it

Steps: render the application icon, generate the Windows version resource, freeze the dissect.target plugin
index (dissect discovers plugins by walking its package folder, which does not exist inside a frozen build),
then run PyInstaller on packaging/wfa.spec.
"""

from __future__ import annotations

import argparse
import os
import shutil
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BUILD = os.path.join(HERE, "build")
sys.path.insert(0, ROOT)


def make_icon(path: str) -> None:
    """Multi-resolution .ico (PNG-compressed entries) drawn by the same code as the in-app logo."""
    from PySide6.QtCore import QBuffer, QByteArray, QIODevice, Qt
    from PySide6.QtGui import QImage, QPainter

    from winforensics.report.brand import draw_logo
    from winforensics.report.figures import ensure_app

    ensure_app()
    entries = []
    for sz in (16, 24, 32, 48, 64, 128, 256):
        img = QImage(sz, sz, QImage.Format_ARGB32)
        img.fill(Qt.transparent)
        p = QPainter(img)
        p.setRenderHint(QPainter.Antialiasing)
        draw_logo(p, 0, 0, sz)
        p.end()
        ba = QByteArray()
        buf = QBuffer(ba)
        buf.open(QIODevice.WriteOnly)
        img.save(buf, "PNG")
        entries.append((sz, bytes(ba)))
    head = struct.pack("<HHH", 0, 1, len(entries))
    offset = 6 + 16 * len(entries)
    dirs, blobs = b"", b""
    for sz, data in entries:
        dim = 0 if sz >= 256 else sz
        dirs += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(data), offset + len(blobs))
        blobs += data
    with open(path, "wb") as fh:
        fh.write(head + dirs + blobs)


def make_version(path: str) -> None:
    from winforensics import __app_name__, __version__

    nums = [int(x) for x in (__version__.split(".") + ["0", "0", "0"])[:4]]
    tup = ", ".join(str(n) for n in nums)
    text = f"""VSVersionInfo(
  ffi=FixedFileInfo(filevers=({tup}), prodvers=({tup}), mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0,
                    date=(0, 0)),
  kids=[
    StringFileInfo([StringTable('040904B0', [
      StringStruct('FileDescription', '{__app_name__}'),
      StringStruct('FileVersion', '{__version__}'),
      StringStruct('InternalName', 'WFA'),
      StringStruct('OriginalFilename', 'WFA.exe'),
      StringStruct('ProductName', '{__app_name__}'),
      StringStruct('ProductVersion', '{__version__}')])]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def freeze_dissect_plugins() -> str | None:
    """Write dissect/target/plugins/_pluginlist.py so the frozen build has a static plugin index."""
    import dissect.target.plugins as plugins_pkg

    dst = os.path.join(os.path.dirname(plugins_pkg.__file__), "_pluginlist.py")
    if os.path.exists(dst):
        return None
    exe = os.path.join(os.path.dirname(sys.executable), "target-build-pluginlist.exe")
    cmd = [exe] if os.path.exists(exe) else [sys.executable, "-m", "dissect.target.tools.build_pluginlist"]
    out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    with open(dst, "w", encoding="utf-8") as fh:
        fh.write(out)
    return dst


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--zip", action="store_true", help="also create a portable zip of the build")
    ap.add_argument("--clean", action="store_true", help="remove previous PyInstaller work files first")
    args = ap.parse_args()

    os.makedirs(BUILD, exist_ok=True)
    print("[1/4] icon and version resource")
    make_icon(os.path.join(BUILD, "wfa.ico"))
    make_version(os.path.join(BUILD, "version.txt"))
    print("[2/4] dissect.target plugin index")
    generated = freeze_dissect_plugins()
    try:
        print("[3/4] PyInstaller")
        cmd = [sys.executable, "-m", "PyInstaller", "--noconfirm", "--distpath", os.path.join(ROOT, "dist"),
               "--workpath", os.path.join(BUILD, "work"), os.path.join(HERE, "wfa.spec")]
        if args.clean:
            cmd.insert(3, "--clean")
        subprocess.run(cmd, check=True, cwd=ROOT)
    finally:
        if generated and os.path.exists(generated):
            os.remove(generated)  # keep the development environment dynamic
    out = os.path.join(ROOT, "dist", "WindowsForensicAutomation")
    print("[4/4] done:", out)
    if args.zip:
        from winforensics import __version__

        z = shutil.make_archive(os.path.join(ROOT, "dist", f"WindowsForensicAutomation-{__version__}-win64"), "zip",
                                os.path.dirname(out), os.path.basename(out))
        print("portable zip:", z)
    return 0


if __name__ == "__main__":
    sys.exit(main())
