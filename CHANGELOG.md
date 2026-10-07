# Changelog

## 1.3.0 - validated on five reference cases

Validated against five references: four public images (three with published answers), plus synthetic threat scenarios
built with exact ground truth ([docs/VALIDATION.md](docs/VALIDATION.md)):

| Reference | Checks |
|---|---|
| NIST CFReDS Data Leakage (Windows 7) | 24 / 24 |
| NIST CFReDS Hacking Case (Windows XP) | 20 / 20 |
| DFIR Madness "Stolen Szechuan Sauce" (Server 2012 R2 DC + Windows 10) | 19 / 19 |
| Digital Corpora M57-Jean (Windows XP) | 5 / 5 |
| Threat scenarios: ClickFix, phishing, AnyDesk, RDP brute force + ransomware, clean control | 35 / 35 |

`python -m tests.validation.datasets` downloads the public images (resume, MD5 check, unzip);
`python -m tests.fixtures.build_threats` builds the scenarios.

### Accuracy fixes (false positives found on real images)
- **Scheduled tasks:** Windows 10 / 11 task files (UTF-16 with `encoding="UTF-16"`) were rejected by the XML parser and
  silently skipped. On the Szechuan desktop all 197 tasks were missing. All task files now parse, and unparsable files
  are counted in the coverage matrix.
- **XP prefetch:** run count and last-run time are read from the documented offsets (dissect reads version 17 wrongly).
  The executable's full path is resolved from the file list for every prefetch version.
- **ClickFix:** malware PowerShell running on its own (Meterpreter persistence) was reported as "pasted commands". Only
  Run-box / console entries, processes started by Explorer, or commands containing the lure text count.
- **Per-user applications** (OneDrive, Teams, Zoom, Slack, VS Code) are no longer "executables in a user-writable
  folder". Programs inside a registered installed program's folder are recognized.
- **Download cradles:** retrieval alone (`Invoke-WebRequest https://api...`) no longer scores as suspicious; it does with
  execution, IP-address URLs, executable payloads, hiding or encoding.
- **Credential-harvest pages:** reported only when the title names a service and the page is not on that service's
  domain (`github.com/login` is no longer flagged).
- **USB devices:** VMware / virtual disks, NVMe / SATA system disks and virtual CD-ROMs are no longer listed as
  removable media. A USB volume's label is no longer used as its product name.
- **"USB history removed":**
  - requires the SYSTEM hive to have been written after the device was last seen; a responder's drive plugged in
    before imaging is not reported;
  - absences older than 30 days are weak, because Windows' Plug and Play cleanup task removes them.
- **Timestomping:**
  - `$SI` created earlier than `$FN` **and** whole-second `$SI` times now count as a strong indicator, but only for
    single files, not for whole folders laid down by an installer or app package;
  - files extracted from archives are excluded;
  - weak indicators alone answer Inconclusive.
- **Ransom notes:** the same file (name and size) in at least 5 data folders within 2 hours. Program readme files no
  longer trigger it.
- **Microsoft Defender:** routine 5007 setting writes are ignored. Exclusions, `Disable*`, cloud protection off and
  tamper protection off are reported.
- **Quick Assist** (built into Windows) is reported only when run; Windows component-store copies are not installations.
- **Logons:**
  - computer accounts are not "remote sessions";
  - `DWM-n` / `UMFD-n` session accounts are excluded;
  - routine 4648 events (OOBE, task host, machine to itself) are not "explicit credentials";
  - RDP transport events (131) are summarized per address.
- **Services:** judged by their own program, not by an argument that points to AppData.
- Defender's platform folder, the WiX package cache and WiX Burn temp folders are not user-writable programs. Legacy
  Edge cache scripts are not executed scripts. `hh.exe` is not a rare LOLBin. Application event 1000 is a crash only
  from "Application Error".

### New detections and correlation
- **E-mail recipients from the recipient table:** "display name <address>", Cc and Bcc. The display name alone hid where
  M57-Jean's spreadsheet went.
- **Sender impersonation (BEC / CEO fraud):** a display name that is an address the message was not sent from.
- **Sent attachments matched to files on the system** by name, size and SHA-256 ("byte-identical to ...").
- **Lateral movement between examined systems:** an RDP logon on one system from another examined system's address,
  shown next to the source's own outgoing-connection record and the time difference.
- **Brute force without source IPs:** NLA failures that name only a workstation are linked by time to the addresses in
  RDP connection events.
- **Persistence that starts a downloaded program:** by Mark of the Web, or by the name of a browser download (a payload
  copied to System32 keeps its name).
- **Executables downloaded directly from an IP address.**
- **Hacking / dual-use tools:** credential theft, sniffing, scanning and exploitation tools by executable and by
  installed-program name.

### New artifacts and platforms
- **Windows XP / Server 2003:**
  - Recycle Bin `INFO2`;
  - legacy `.evt` event logs, whose events keep their own IDs while analyzers treat them like the Vista+ equivalents;
  - prefetch version 17.
- **E-mail / news accounts** (Outlook Express, Windows Mail, Outlook profiles); saved passwords are flagged, never decoded.
- **System information:** network adapters, workgroup / primary domain (LSA), Winlogon default user. The XP placeholder
  build string is no longer shown.
- `wfa-cli run --profile <id> --phases analysis` re-analyzes a processed case as another case type.
- `rerun-module filesystem` rebuilds the file system index instead of duplicating it.

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
