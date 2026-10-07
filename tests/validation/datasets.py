"""Download the public reference images used by the validation suites.

    python -m tests.validation.datasets --list
    python -m tests.validation.datasets szechuan_dc szechuan_desktop --dest D:\\datasets

Downloads resume after an interruption, are verified against the publisher's checksum when one is published, and
zip archives are extracted (the archive is deleted after a verified extraction).  Every dataset is public research data;
check each publisher's terms before redistributing it.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
import time
import urllib.request
import zipfile

DATASETS = {
    "cfreds_data_leakage": {
        "title": "NIST CFReDS Data Leakage Case - PC (Windows 7)",
        "answers": "https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf",
        "files": [{"url": f"https://cfreds-archive.nist.gov/data_leakage_case/images/pc/cfreds_2015_data_leakage_pc.E0{i}"}
                  for i in range(1, 5)],
    },
    "szechuan_dc": {
        "title": "DFIR Madness Case 001 'The Stolen Szechuan Sauce' - DC01 (Windows Server 2012 R2)",
        "answers": "https://dfirmadness.com/answers-to-szechuan-case-001/",
        "files": [{"url": "https://dfirmadness.com/case001/DC01-E01.zip", "md5": "e57fc636e833c5f1ab58dface873bbde", "unzip": True}],
    },
    "szechuan_desktop": {
        "title": "DFIR Madness Case 001 'The Stolen Szechuan Sauce' - DESKTOP-SDN1RPT (Windows 10)",
        "answers": "https://dfirmadness.com/answers-to-szechuan-case-001/",
        "files": [{"url": "https://dfirmadness.com/case001/DESKTOP-E01.zip", "md5": "71c5c3509331f472abcdf81eb6efff07", "unzip": True}],
    },
    "cfreds_hacking": {
        "title": "NIST CFReDS Hacking Case - Dell Latitude CPi (Windows XP)",
        "answers": "https://cfreds-archive.nist.gov/images/TestAnswers.pdf",
        "files": [{"url": "https://cfreds-archive.nist.gov/images/4Dell%20Latitude%20CPi.E01"},
                  {"url": "https://cfreds-archive.nist.gov/images/4Dell%20Latitude%20CPi.E02"}],
    },
    "m57_jean": {
        "title": "Digital Corpora M57-Jean (Windows XP, spreadsheet leaked by e-mail)",
        "answers": "https://digitalcorpora.org/corpora/scenarios/m57-jean/",
        "files": [{"url": "https://downloads.digitalcorpora.org/corpora/drives/nps-2008-m57-jean/nps-2008-jean.E01"},
                  {"url": "https://downloads.digitalcorpora.org/corpora/drives/nps-2008-m57-jean/nps-2008-jean.E02"}],
    },
}


def _name(url: str) -> str:
    return urllib.request.unquote(url.rsplit("/", 1)[-1])


def download(url: str, dest_dir: str, retries: int = 20) -> str:
    """Resumable download (HTTP Range); returns the local path."""
    path = os.path.join(dest_dir, _name(url))
    part = path + ".part"
    if os.path.exists(path):
        return path
    for attempt in range(retries):
        have = os.path.getsize(part) if os.path.exists(part) else 0
        req = urllib.request.Request(url, headers={"User-Agent": "windows-forensic-automation-validation/1.0",
                                                    **({"Range": f"bytes={have}-"} if have else {})})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                if have and r.status != 206:
                    have = 0  # server ignored the range: restart
                total = have + int(r.headers.get("Content-Length") or 0)
                with open(part, "ab" if have else "wb") as fh:
                    done, t0, last = have, time.time(), 0.0
                    while True:
                        chunk = r.read(4 * 1024 * 1024)
                        if not chunk:
                            break
                        fh.write(chunk)
                        done += len(chunk)
                        if time.time() - last > 15:
                            last = time.time()
                            rate = (done - have) / max(1e-6, time.time() - t0) / 1e6
                            print(f"  {_name(url)}: {done / 1e9:.2f} / {total / 1e9:.2f} GB ({rate:.1f} MB/s)", flush=True)
            if total and os.path.getsize(part) < total:
                raise IOError("connection closed early")
            os.replace(part, path)
            return path
        except Exception as e:  # network hiccups: retry with resume
            print(f"  retry {attempt + 1}/{retries} for {_name(url)}: {e}", flush=True)
            time.sleep(min(60, 5 * (attempt + 1)))
    raise RuntimeError(f"download failed: {url}")


def md5sum(path: str) -> str:
    h = hashlib.md5()
    with open(path, "rb") as fh:
        for b in iter(lambda: fh.read(8 * 1024 * 1024), b""):
            h.update(b)
    return h.hexdigest()


def fetch(key: str, dest: str) -> str:
    ds = DATASETS[key]
    out = os.path.join(dest, key)
    os.makedirs(out, exist_ok=True)
    print(f"== {key}: {ds['title']}\n   answers: {ds['answers']}", flush=True)
    for f in ds["files"]:
        marker = os.path.join(out, _name(f["url"]) + ".extracted")
        if os.path.exists(marker):
            continue
        p = download(f["url"], out)
        if f.get("md5"):
            got = md5sum(p)
            if got.lower() != f["md5"].lower():
                os.remove(p)
                raise RuntimeError(f"MD5 mismatch for {p}: {got} != {f['md5']} (file removed, run again)")
            print(f"   MD5 verified {_name(p)}", flush=True)
        if f.get("unzip"):
            with zipfile.ZipFile(p) as z:
                z.extractall(out)
            os.remove(p)
            open(marker, "w").close()
            print(f"   extracted {_name(p)}", flush=True)
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("datasets", nargs="*")
    ap.add_argument("--dest", default=os.path.join(os.path.expanduser("~"), "Documents", "WFA-datasets"))
    ap.add_argument("--list", action="store_true")
    a = ap.parse_args(argv)
    if a.list or not a.datasets:
        for k, d in DATASETS.items():
            print(f"{k:22} {d['title']}\n{'':22} answers: {d['answers']}")
        return 0
    for k in a.datasets:
        print("ready:", fetch(k, a.dest))
    return 0


if __name__ == "__main__":
    sys.exit(main())
