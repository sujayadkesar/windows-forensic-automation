#!/usr/bin/env python3
"""Runs inside WSL (as root): turns a staged machine directory into a raw disk image.

usage: wsl_build_disk.py <staging_machine_dir> <out_raw>
Requires: ntfs-3g, mkntfs, dosfstools, sfdisk, libfaketime, attr.
"""

import datetime as dt
import json
import os
import random
import shutil
import struct
import subprocess
import sys
import time

FAKETIME_LIB = "/usr/lib/x86_64-linux-gnu/faketime/libfaketimeMT.so.1"
MIB = 1024 * 1024


def run(cmd, **kw):
    r = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if r.returncode != 0:
        raise RuntimeError(f"{cmd}: {r.stdout}\n{r.stderr}")
    return r.stdout


def parse_iso(s):
    return dt.datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%f").replace(tzinfo=dt.timezone.utc)


def filetime(t):
    return int((t - dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)).total_seconds() * 10_000_000)


class FakeClock:
    def __init__(self, path):
        self.path = path

    def set(self, t):
        with open(self.path, "w") as fh:
            fh.write("@" + t.strftime("%Y-%m-%d %H:%M:%S") + "\n")
        time.sleep(0.05)


def noise(size, seed):
    rnd = random.Random(seed)
    block = bytes(rnd.getrandbits(8) for _ in range(1 << 16))
    out = bytearray()
    while len(out) < size:
        out += block
    return out[:size]


def build_ntfs(part_img, size, start_sector, label, serial_hex, staging, manifest, workdir):
    with open(part_img, "wb") as fh:
        fh.truncate(size)
    run(["mkntfs", "-F", "-Q", "-q", "-L", label, "-c", "4096", "-p", str(start_sector), "-H", "255", "-S", "63",
         part_img])
    clock = FakeClock(os.path.join(workdir, "faketime"))
    install = parse_iso(manifest["install_time"])
    clock.set(install)
    mnt = os.path.join(workdir, "mnt")
    os.makedirs(mnt, exist_ok=True)
    env = dict(os.environ, FAKETIME_TIMESTAMP_FILE=clock.path, FAKETIME_NO_CACHE="1", LD_PRELOAD=FAKETIME_LIB)
    run(["ntfs-3g", "-o", "streams_interface=xattr", part_img, mnt], env=env)
    try:
        root = os.path.join(staging, "root")
        # directories first (at install time)
        for dirpath, dirnames, _ in os.walk(root):
            for d in dirnames:
                rel = os.path.relpath(os.path.join(dirpath, d), root)
                os.makedirs(os.path.join(mnt, rel), exist_ok=True)
        # special memory files
        for name, key, mb in [("pagefile.sys", "pagefile", manifest["disk"].get("pagefile_mb")),
                              ("hiberfil.sys", "hiberfil", manifest["disk"].get("hiberfil_mb"))]:
            if not mb:
                continue
            blob = noise(mb * MIB, seed=hash(name) & 0xFFFF)
            for inj in manifest.get(key, []):
                data = bytes.fromhex(inj["data_hex"])
                blob[inj["offset"]:inj["offset"] + len(data)] = data
            with open(os.path.join(mnt, name), "wb") as fh:
                fh.write(blob)
        # files in chronological creation order
        events = [("create", parse_iso(f["ctime"]), f) for f in manifest["files"]]
        events += [("delete", parse_iso(d["time"]), d) for d in manifest.get("delete", [])]
        events.sort(key=lambda e: e[1])
        for kind, t, f in events:
            clock.set(t)
            dst = os.path.join(mnt, f["path"])
            if kind == "create":
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                shutil.copyfile(os.path.join(root, f["path"]), dst)
                times = struct.pack("<4Q", filetime(t), filetime(parse_iso(f["mtime"])),
                                    filetime(parse_iso(f["atime"])), filetime(parse_iso(f["mtime"])))
                os.setxattr(dst, "system.ntfs_times", times)
            else:
                os.remove(dst)
        for a in manifest.get("ads", []):
            p = os.path.join(mnt, a["path"])
            if os.path.exists(p):
                os.setxattr(p, "user." + a["stream"], a["data"].encode())
        # directory timestamps follow their newest child creation (approximation)
    finally:
        run(["umount", mnt])
    # patch the NTFS volume serial number in boot sector and backup boot sector
    serial = int(serial_hex, 16)
    with open(part_img, "r+b") as fh:
        fh.seek(0x48)
        fh.write(struct.pack("<Q", serial))
        fh.seek(size - 512 + 0x48)
        fh.write(struct.pack("<Q", serial))


def build_fat(part_img, size, label, serial_hex, staging, manifest, workdir):
    with open(part_img, "wb") as fh:
        fh.truncate(size)
    run(["mkfs.vfat", "-F", "32", "-n", label[:11], "-i", serial_hex, part_img])
    root = os.path.join(staging, "root")
    if not os.path.isdir(root):
        return
    mnt = os.path.join(workdir, "mntfat")
    os.makedirs(mnt, exist_ok=True)
    run(["mount", "-o", "loop,tz=UTC", part_img, mnt])
    try:
        for dirpath, dirnames, filenames in os.walk(root):
            rel_dir = os.path.relpath(dirpath, root)
            os.makedirs(os.path.join(mnt, rel_dir), exist_ok=True)
            for fn in filenames:
                rel = os.path.normpath(os.path.join(rel_dir, fn))
                shutil.copyfile(os.path.join(dirpath, fn), os.path.join(mnt, rel))
        for f in manifest.get("files", []):
            p = os.path.join(mnt, f["path"])
            if os.path.exists(p) and f.get("local_time"):
                run(["touch", "-d", f["local_time"], p])
        for d in manifest.get("delete", []):
            p = os.path.join(mnt, d["path"])
            if os.path.exists(p):
                os.remove(p)
    finally:
        run(["sync"])
        run(["umount", mnt])


def main():
    staging, out_raw = sys.argv[1], sys.argv[2]
    manifest = json.load(open(os.path.join(staging, "manifest.json")))
    disk = manifest["disk"]
    workdir = out_raw + ".work"
    shutil.rmtree(workdir, ignore_errors=True)
    os.makedirs(workdir)
    total = disk["size_mb"] * MIB
    with open(out_raw, "wb") as fh:
        fh.truncate(total)

    # layout
    parts = []
    cur = 1 * MIB
    for i, p in enumerate(disk["partitions"]):
        size = p.get("size_mb", 0) * MIB
        if not size:
            size = total - cur - (1 * MIB if disk["scheme"] == "gpt" else 0)
        parts.append((cur, size, p))
        cur += size
    script = ["label: " + ("gpt" if disk["scheme"] == "gpt" else "dos")]
    for start, size, p in parts:
        if disk["scheme"] == "gpt":
            t = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B" if p["type"] == "efi" else "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7"
        else:
            t = "7" if p["fs"] == "ntfs" else "c"
        script.append(f"start={start // 512}, size={size // 512}, type={t}")
    run(["sfdisk", "-q", out_raw], input="\n".join(script) + "\n")

    for i, (start, size, p) in enumerate(parts):
        img = os.path.join(workdir, f"p{i}.img")
        if p["fs"] == "ntfs":
            build_ntfs(img, size, start // 512, p["label"], p["serial"], staging, manifest, workdir)
        else:
            serial = p.get("serial", "%08X" % random.getrandbits(32))
            build_fat(img, size, p["label"], serial, staging if p["type"] != "efi" else "/nonexistent", manifest, workdir)
        with open(out_raw, "r+b") as out, open(img, "rb") as src:
            out.seek(start)
            while True:
                chunk = src.read(8 * MIB)
                if not chunk:
                    break
                out.write(chunk)
    shutil.rmtree(workdir, ignore_errors=True)
    print(json.dumps({"raw": out_raw, "partitions": [(s, z) for s, z, _ in parts]}))


if __name__ == "__main__":
    main()
