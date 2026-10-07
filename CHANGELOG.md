# Changelog

## 1.2.0 - accuracy release

Validated against the NIST CFReDS Data Leakage Case answer key (`tests/validation`).

### Accuracy fixes
- **$UsnJrnl / deleted file paths:** parent folders are resolved by MFT reference *and sequence number*.
  - A reused parent record is no longer followed (that attached files to unrelated folders).
  - Paths are rebuilt from the journal's own directory history, using the folder name at that time.
  - 594 deleted-file paths were recovered on the CFReDS image.
- **USB on Windows 7:** the DeviceClasses timestamp is reported as "connected after the last reboot", not "last connected". Also:
  - the `{a5dcbf10}` USB interface class is read;
  - volume labels come from `VolumeInfoCache`;
  - VMware virtual disks and HID devices are no longer listed as removable media;
  - event-log serials no longer pick up trailing tokens.
- **Shortcut (LNK) network targets:** `device_name` is used only when the ValidDevice flag is set (MS-SHLLINK 2.3.2). Targets
  now read `\\server\share\...` or `V:\...` correctly.
- **Figures:** renderers draw only values from parsed records.
  - Removed the synthetic `(Default)` registry row, made-up MRU values and placeholder level icons.
  - Event figures list every field of the selected record by name.
- **Google Drive (legacy client):**
  - every change in a batched sync operation is reported;
  - the signed-in account is read from `sync_log.log` when `sync_config.db` is deleted;
  - events are labeled precisely (uploaded / deleted from Google Drive / sharing changed).

### New artifacts
- CD/DVD burning:
  - `cdrom` System event 133 (disc writes);
  - IMAPI mastering sessions and burn staging files from `$UsnJrnl`;
  - the `CD Burning` registry (`DefaultToMastered` meaning);
  - `<CDBURN>` shellbags and shortcuts to optical volumes.
- Windows Search index (`Windows.edb`): files, folders and e-mails, including messages deleted from the mailbox.
- Internet Explorer / Edge (legacy) history: `WebCacheV01.dat` and `index.dat`, including `file:///` records of documents
  opened from USB and network drives.
- Sticky Notes (`StickyNotes.snt`, `plum.sqlite`).
- Network share access analysis: mapped drives, UNC shortcuts and shellbags.
- Secure-deletion detection: wiper rename bursts in `$UsnJrnl`, e.g. Eraser renaming a folder 7 times before deleting it.

### Application
- Artifact grid:
  - a filter box under every column (contains, `=`, `!`, `>`, `<`, `a | b`);
  - click-to-sort on any column;
  - column chooser;
  - "filter by this value" from the context menu.
- Export the current view (all filtered rows, in the current order) as CSV, Excel, JSON, HTML or TSV.
- Light theme (Settings: sidebar switch), remembered between sessions.
- Report figures use a plain formatted table (colored header, borders) instead of an Excel-window mock-up.
- US English throughout ("artifact").

## 1.1.0
- Parsed CSV copy of every artifact, full EVTX and SRUM dumps, raw artifact collection with hash manifest.
- `SuperTimeline.csv`, plain-text case summary, PyInstaller build (`WFA.exe`, `wfa-cli.exe`).
- Profiles: malware, ClickFix, phishing, remote access / RMM, ransomware, account compromise, general triage.

## 1.0.0
- First release: DLP / data exfiltration profile, physical keyword search with slack / unallocated attribution, carving,
  Word / PDF / Excel reporting with annotated figures.
