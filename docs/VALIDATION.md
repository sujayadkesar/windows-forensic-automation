# Validation

Every release is checked against public reference images with published answer keys, and against synthetic threat
scenarios built with exact ground truth. Each check compares a value in the tool's case database with the published
answer; nothing is graded by hand.

| Reference | System | Storyline | Result |
|---|---|---|---|
| [NIST CFReDS Data Leakage Case](#nist-cfreds-data-leakage-case) | Windows 7 | Insider exfiltration: USB, network share, e-mail, Google Drive, CD-R, wiping | **24 / 24** |
| [NIST CFReDS Hacking Case](#nist-cfreds-hacking-case) | Windows XP | Abandoned laptop with wireless sniffing and password tools | **20 / 20** |
| [DFIR Madness: The Stolen Szechuan Sauce](#dfir-madness-the-stolen-szechuan-sauce) | Server 2012 R2 DC + Windows 10 | RDP brute force, Meterpreter, persistence, lateral movement, theft, timestomping | **19 / 19** |
| [Digital Corpora M57-Jean](#digital-corpora-m57-jean) | Windows XP | Salary spreadsheet e-mailed to an impostor (business e-mail compromise) | **5 / 5** |
| [Synthetic threat scenarios](#synthetic-threat-scenarios) | Windows 10 / 11 / Server 2019 | ClickFix, phishing macro, AnyDesk scam, RDP brute force + ransomware, clean control | **35 / 35** |

Download the public images with `python -m tests.validation.datasets <name>` (resumes, verifies the published MD5,
unpacks). `--list` shows every dataset and its answer key.

## NIST CFReDS Data Leakage Case

**Result: 24 / 24 checks pass** (`tests/validation/test_cfreds_data_leakage.py`).

### The reference case

The U.S. National Institute of Standards and Technology publishes the
[CFReDS Data Leakage Case](https://cfreds-archive.nist.gov/data_leakage_case/):
- **The scenario:** a Windows 7 PC image of an employee who searches for leakage methods, then exfiltrates confidential
  project files. The channels are two USB sticks, a network share, e-mail, Google Drive and CD-R. He then tries to
  remove traces with Eraser and CCleaner.
- **The answer key:** NIST publishes it with the image (`leakage-answers.pdf`, last saved 2018-07-23).

The PC image was processed with the **Data exfiltration (DLP alert)** profile and no prior information: no DLP export, no
file list and no device serial. The tool's database was then compared, value by value, with the answer key.

### Checks

NIST tables use different time zones: some EDT (UTC-4), the account table UTC-5. Every expected value below was
converted to UTC.

| NIST Q | Expected (from the answer key) | Check |
|---|---|---|
| 3, 5 | Windows 7 Ultimate, build 7601, computer name INFORMANT-PC | `test_q3_q5_os_and_computer_name` |
| 4 | Eastern time zone | `test_q4_time_zone` |
| 6, 7 | Logon counts informant 10, admin11 2, ITechTeam 0, temporary 1; informant last logon 2015-03-25 14:45:59 UTC | `test_q6_q7_accounts_and_logon_counts` |
| 9 | IP address 10.11.11.129 | `test_q9_network_interface` |
| 10 | Office 2013, Chrome, Google Drive, Eraser, Bonjour installed | `test_q10_installed_applications` |
| 16 | 12 web search keywords ("data leakage methods" ... "security checkpoint cd-r") | `test_q16_web_search_keywords` |
| 17 | Windows Explorer search "secret" at 18:40:17 UTC | `test_q17_explorer_search_keyword` |
| 22 | RM#1 `4C530012450531101593` first connected 18:31:10, after reboot 2015-03-24 13:38:00; RM#2 `4C530012550531106501` first connected 13:58:32, after reboot 13:58:33, volume name `IAMAN $_@`; no other removable storage | `test_q22_usb_devices` |
| 24 | `\\10.11.11.128\secured_drive` in RunMRU (20:23:28) and Map Network Drive MRU (20:26:04) | `test_q24_network_drive_address` |
| 25 | Folders traversed on RM#2 (`E:\Secret Project Data\...`) | `test_q25_directories_traversed_on_rm2` |
| 26 | `winter_whether_advisory.zip` opened on RM#2 | `test_q26_file_opened_on_rm2` |
| 28 | `\\10.11.11.128\SECURED_DRIVE\...\(secret_project)_pricing_decision.xlsx` and `V:\...\[secret_project]_final_meeting.pptx` | `test_q28_files_opened_on_network_drive` |
| 30 | `happy_holiday.jpg` and `do_u_wanna_build_a_snow_man.mp3` uploaded, then deleted from Google Drive (16:42:17 EDT) | `test_q30_files_deleted_from_google_drive` |
| 31 | Google Drive account `iaman.informant.personal@gmail.com` | `test_q31_google_drive_account` |
| 33 | Disc burns at 19:47:47, 19:56:11, 20:24:46 and 20:41:21 UTC (cdrom event); last burn method "like a USB flash drive", registry written 20:53:16 | `test_q33_*` |
| 34 | Files copied to the CD-R (`Burn\Burn\de\winter_storm.amr`, `pd\my_favorite_cars.db`, `tr\diary_#1d.txt`, `Penguins.jpg`, ...) | `test_q34_files_copied_to_cd` |
| 35 | Opened from the CD: `D:\de\winter_whether_advisory.zip`, `D:\Penguins.jpg`, `Koala.jpg`, `Tulips.jpg` | `test_q35_files_opened_from_cd` |
| 21, 45 | E-mails including deleted ones: "RE: Good job, buddy." with attachment `space_and_earth.mp4`, "It's me" (20:38:47), "Done" (21:05:09) | `test_q21_q45_emails_including_deleted` |
| 23 | `$UsnJrnl` paths of renamed files follow MFT sequence numbers (no path through a reused folder record) | `test_usn_paths_follow_sequence_numbers` |
| 36 | Resignation letter `$SI` created 18:48:40, modified 18:59:30 UTC | `test_q36_resignation_letter_timestamps` |
| 37 | Printed to `Resignation_Letter_(Iaman_Informant).xps` | `test_q37_printed_to_xps` |
| 52 | Eraser wiping `Desktop\temp` on 2015-03-25 | `test_q52_eraser_wipe_of_desktop_temp` |

### Errors this validation found and fixed

| Problem found | Fix |
|---|---|
| Paths of deleted / renamed files went through reused folder records, e.g. `winter_storm.amr` shown inside a Chrome cache folder | Parent references are checked by sequence number; folders are rebuilt from `$UsnJrnl` history using the name they had at that time |
| Windows 7 USB "last connected" was really the first connection after the last reboot (RM#2 was reconnected later in the same session) | Labeled "connected after the last reboot", as the DeviceClasses key means; "last connected" only from Properties 0066 or connect events |
| Network shortcut targets read `1\Secret Project Data\...` | `device_name` is used only when the ValidDevice flag is set (MS-SHLLINK) |
| Google Drive: the second file of a batched upload was missing; the account was missing because `sync_config.db` is deleted | Every change in a batch is parsed; the account is read from `sync_log.log` |
| CD burning was only partially visible | Added cdrom event 133, IMAPI sessions and staged files from `$UsnJrnl`, burn method from the registry |
| Deleted e-mails were not reported | Windows Search index (`Windows.edb`) parsed and compared with the mailbox |

### False-positive check

The same processed image was analyzed with every other profile. It contains no malware, ClickFix, phishing, remote-access
tool or ransomware. Every profile's questions about those threats answer **No evidence found** or **Not applicable**.

Noise found during this check and removed:
- Windows Update files counted as "ransomware extensions";
- console logons counted as remote sessions;
- cached web page JavaScript counted as executed scripts;
- WMI class definitions and the built-in Windows 7 `BVTFilter` subscription counted as persistence;
- downloaded installers counted as opened phishing attachments.

### Reproduce

1. Download `cfreds_2015_data_leakage_pc` (E01 or DD) from the CFReDS site.
2. Process it:
   ```
   wfa-cli new --case D:\Cases\CFReDS --profile dlp_exfiltration --evidence "D:\img\cfreds_2015_data_leakage_pc.E01:source:PC" --run
   ```
3. Run the validation:
   ```
   set WFA_CFREDS_CASE=D:\Cases\CFReDS
   python -m pytest tests/validation -v
   ```

## NIST CFReDS Hacking Case

**Result: 20 / 20 checks pass** (`tests/validation/test_cfreds_hacking.py`).

**The scenario.** NIST's [Hacking Case](https://cfreds-archive.nist.gov/) is a Windows XP laptop found abandoned with a
wireless card. It is suspected of being used to sniff hotspot traffic, and the task is to tie it to a suspect.
**The answer key** is `TestAnswers.pdf` (31 questions). The image was processed with the **General triage** profile and
no prior information. NIST quotes local time (CDT, UTC-5); expected values are converted to UTC.

| NIST Q | Expected (from the answer key) | Check |
|---|---|---|
| 1 | Acquisition MD5 `AEE4FCD9301C03B3B054623CA261959A` | `test_q1_acquisition_hash` |
| 2 - 8 | Windows XP, installed 2004-08-19 22:48:27, Central time, owner Greg Schardt, computer N-1A9ODN6ZXK4LQ, domain EVIL, last shutdown 2004-08-27 15:46:33 | `test_q2` ... `test_q8` |
| 9 - 11 | 5 accounts; "Mr. Evil" logs on most and last | `test_q9_q10_q11_accounts` |
| 13, 14 | Xircom CardBus Ethernet and Compaq WL110 wireless cards; IP 192.168.1.111 | `test_q13_network_cards`, `test_q14_ip_address` |
| 16 | Hacking programs: Cain & Abel, Ethereal, 123 Write All Stored Passwords, Anonymizer, CuteFTP, Look@LAN, NetStumbler | `test_q16_hacking_programs` |
| 17 - 19 | SMTP address `whoknowsme@sbcglobal.net`, news server `news.dallas.sbcglobal.net` (Outlook Express) | `test_q17_q18_q19_mail_and_news_accounts` |
| 23 | Intercepted traffic saved as `interception` | `test_q23_interception_capture_file` |
| 26, 27 | Yahoo mail ID `mrevil...` in browser history, `ShowLetter[1].htm` in the IE cache | `test_q26_q27_yahoo_mail` |
| 28, 29 | 4 executables in the Recycle Bin (`Dc1.exe` - `Dc4.exe`), content still present (not really deleted) | `test_q28_q29_recycle_bin` |
| 30 | 3 files deleted in the file system | `test_q30_files_deleted_in_file_system` |
| - | XP prefetch run counts and times; XP `.evt` logs parsed; no false ransomware / anti-forensics / phishing / persistence answer | `test_xp_*`, `test_no_false_positive_threat_answers` |

Not asserted: the IRC and newsgroup contents (Q20 - 22) and the intercepted traffic (Q24, 25). The files are indexed and
exported; reading them is the examiner's step. Forte Agent's news settings (Q19, second program) live in its own
configuration file, not in the registry.

### Errors this validation found and fixed

| Problem found | Fix |
|---|---|
| No Windows 2000 / XP / 2003 Recycle Bin | `RECYCLER\<SID>\INFO2` parsed, with content files `D<drive><n>.<ext>` and their hashes |
| No legacy `.evt` event logs | `SecEvent.Evt`, `SysEvent.Evt`, `AppEvent.Evt` parsed. XP events (528, 529-539, 552, 592, 601, 624-660, 517) keep their own ID, and analyzers treat them like their Vista+ equivalents |
| XP prefetch had run count 0 and no run time (dissect reads version 17 at the wrong offsets) | Run count and last run read from the documented offsets (libscca); full executable path resolved from the file list |
| "Ransomware: readme.txt in 12 folders" (program readme files) | A ransom note must be the same file (name and size) in at least 5 data folders within 2 hours |
| "Timestamp anomaly" on a file extracted from a zip | Archive extraction folders excluded; weak indicators alone answer Inconclusive |
| `hh.exe` (Help viewer) reported as a rare LOLBin | Removed; reported only when its command line is malicious |
| Build shown as "1.511.1 () (Obsolete data - do not use)" | `CurrentBuildNumber` used when `CurrentBuild` is not a number |
| Hacking tools not identified | New `hacking_tools` family (credential theft, sniffing, scanning, exploitation), matched by executable and installed-program name |
| No e-mail account settings, network adapters or workgroup | `email_account` artifact (Outlook Express / Windows Mail / Outlook profiles, passwords flagged but never decoded); NetworkCards and LSA `PolPrDmN` in System Information |

## Synthetic threat scenarios

**Result: 35 / 35 checks pass** (`tests/test_scenarios.py`; build the images with `python -m tests.fixtures.build_threats`).

Public reference images with answer keys do not exist for every case type. Five small NTFS images are built with
exact ground truth (`tests/fixtures/builder/scenario_threats.py`). Each one is processed once and analyzed with every
profile in its ground truth; every listed question must get exactly the expected answer. Artifacts are written in the
formats Windows produces: `\1` RunMRU suffixes, TrustRecords paths with forward slashes, full Security event field sets,
and AnyDesk log wording as published by AnyDesk log research.

| Image | Storyline | Expected |
|---|---|---|
| CLICKFIX-01 (Windows 11) | Fake CAPTCHA page, pasted PowerShell in the Run box, payload in AppData, Run key | ClickFix command, lure, payload and persistence: Yes |
| PHISH-01 (Windows 10) | Macro document from the Outlook cache enabled, Word starts encoded PowerShell, Microsoft sign-in page on a look-alike domain | Opened, executed: Yes; credential page: Indicated |
| RMM-01 (Windows 11) | Portable AnyDesk downloaded, incoming session accepted | Tool, remote ID and remote address found |
| RANSOM-01 (Server 2019) | 42 failed RDP logons, logon, new admin account, shadow copies deleted, 320 files encrypted, notes in 8 folders | Brute force, account changes, remote session, encryption, precursor: Yes |
| CLEAN-01 (Windows 11) | Busy office PC: OneDrive, Teams, Zoom, Slack, VS Code in AppData; installers from vendor sites; updater tasks; admin PowerShell; genuine Microsoft / Google / GitHub sign-ins | **Every threat question: No evidence found** |

### Errors the scenarios found and fixed

The clean control exposed false positives that would appear on most modern Windows 10 / 11 machines:

| Problem found | Fix |
|---|---|
| Per-user apps (OneDrive, Teams, Zoom, Slack, VS Code) reported as "executables in a user-writable folder" | Programs inside a registered installed program's folder (Uninstall keys: location, uninstaller, icon) are not reported |
| OneDrive reported as a "dual-use tool" | Only transfer tools marked `dual_use` (rclone, MEGA, WinSCP, ...) are reported outside data-exfiltration cases |
| A service was reported because an argument pointed to AppData | The service's own program is judged, not its arguments |
| `Invoke-WebRequest https://api.github.com` scored as a download cradle | Retrieval alone scores 4; it is reported only together with execution, an IP-address URL, an executable payload, hiding or encoding |
| `github.com/login` reported as a credential-harvesting page | A sign-in page is reported only when it names a service (Microsoft 365, Google, DocuSign, ...) and is not on that service's domain |
| Installers run from Downloads reported | Not reported when their Mark of the Web points to the vendor's own download host |
| A ClickFix payload started by a Run key from AppData was missed | Persistence that starts an unregistered program from a user-writable folder is reported |
| TrustRecords paths mixed `\` and `/` | Local paths normalized |

## DFIR Madness: The Stolen Szechuan Sauce

**Result: 19 / 19 checks pass** (`tests/validation/test_szechuan_case001.py`).

**The scenario.** [Case 001](https://dfirmadness.com/case001/) is a domain controller (Windows Server 2012 R2) and a
Windows 10 desktop. An attacker brute-forces RDP on the DC, drops a Meterpreter payload (`coreupdater.exe`) with
service and registry persistence, steals files, moves to the desktop over RDP, steals more files and timestomps one
file. **The answers** are published at [dfirmadness.com](https://dfirmadness.com/answers-to-szechuan-case-001/). Both
images were processed in **one case** with the **General triage** profile and no indicators.

**Clock.** The official timeline comes from the packet capture. Every time on both disks is exactly one hour later (for
example, the service install the answers give as 02:27:49 is 03:27:49 in the System log). The two systems agree with
each other to within seconds: the DC's outgoing RDP event and the desktop's incoming 1149 are 7 ms apart. Expected values
are therefore the official times plus one hour. The tool reports what the disks record.

| Official answer | Found by the tool | Check |
|---|---|---|
| OS: Windows Server 2012 (R2) and Windows 10; registry time zone Pacific; DC 10.42.85.10, desktop 10.42.85.115 | System information, network interfaces | `test_q1_q2_*`, `test_q3_*`, `test_q9_*` |
| Initial access: RDP brute force from 194.61.24.102 | 95 NLA failures from workstation `kali` (02:21:25 - 02:21:46), linked to `194.61.24.102` by RDP connection events in the same minutes; RDP logon as Administrator 02:21:48 | `test_q5_*` |
| `coreupdater` downloaded with IE from 194.61.24.102 at 02:24, moved to System32 | Browser download `http://194.61.24.102/` → `Downloads\coreupdater.exe`, reported as downloaded from an IP address; file in `System32` | `test_q6b_*`, `test_q6d_q6f_*` |
| Persistence in the registry and as a service (02:27:49) | Service `coreupdater` (event 7045, same second) and Run key `coreupdate` with hidden, encoded PowerShell, on both systems; the service is linked to the download by name | `test_q6i_*`, `test_q6_*` |
| Lateral movement to DESKTOP-SDN1RPT over RDP as Administrator, 02:35:55 | "Lateral movement between the examined systems": DC01 → DESKTOP-SDN1RPT, Administrator, with the DC's outgoing RDP record | `test_q8_*` |
| `Secret.zip` created ~02:30, exfiltrated and deleted ~02:31 (DC); `loot.zip` ~02:46 / ~02:48 (desktop) | `$UsnJrnl` create / delete of both archives | `test_q8d_*` |
| `Szechuan Sauce.txt` accessed 02:32:21 | Shortcut (LNK) to `C:\FileShare\Secret\Szechuan Sauce.txt`, 02:32:21 | `test_q11_*` |
| `Beth_Secret.txt` timestomped | `$SI` created 2020-09-18 23:33:54.000000 (whole seconds) vs `$FN` created 02:34:56.97 → strong anti-forensic indicator on the DC | `test_beth_secret_timestomped` |
| Users: Administrator on the DC; Administrator and Rick Sanchez on the desktop | Interactive / RDP logons | `test_interactive_users` |
| - | No ClickFix, ransomware or phishing; no virtual hardware or built-in Quick Assist reported | `test_no_*` |

Not asserted: the C2 address 203.78.103.109 and process migration into `spoolsv.exe`. These are in the memory images
and packet capture, which the tool does not process.

### Errors this case found and fixed

| Problem found | Fix |
|---|---|
| **All 197 scheduled tasks of the Windows 10 desktop were skipped**: UTF-16 task XML with `encoding="UTF-16"` was rejected by the parser | The declaration is dropped after decoding; unparsable task files are counted in the coverage matrix |
| Meterpreter's persistence PowerShell reported as 17 "ClickFix pasted commands" | Pasted commands must come from the Run box / a console / Explorer, or contain the lure text |
| "USB device history removed (strong)" for VMware virtual devices and for the responder's own USB drive | Real removable devices only; requires the SYSTEM hive to be written after the device was last seen; > 30 days weak |
| VMware NVMe system disk, virtual SCSI disk and virtual CD-ROM listed as USB devices; volume label used as product | Fixed / virtual buses and vendors excluded; USBSTOR vendor / product parsed from the device path |
| Quick Assist (built into Windows) reported as an RMM tool from its WinSxS copy | Built-in tools reported only when run; component-store copies ignored |
| 34 routine Defender 5007 events answered "Defender tampering: Yes" | Only exclusions, `Disable*`, cloud protection off and tamper protection off count |
| Installer / app-package files reported as timestomped | Whole-second `$SI` is strong only for single files outside installed programs and app packages |
| Defender's own platform folder, WiX installer temp folders and legacy Edge cache reported | Excluded as protected / installer / cache locations |
| 1,830 "remote sessions" on the DC, mostly computer accounts and transport events | Computer accounts excluded; RDP transport events summarized per address |
| The brute force had no source address (NLA failures name only the workstation) | Linked by time to RDP connection events, labeled as such |
| The service was not linked to the download (no Mark of the Web after the move) | Persistence is linked to browser downloads by file name |

## Digital Corpora M57-Jean

**Result: 5 / 5 checks pass** (`tests/validation/test_m57_jean.py`).

**The scenario.** [M57-Jean](https://digitalcorpora.org/corpora/scenarios/m57-jean/) is the Windows XP laptop of an
executive whose confidential spreadsheet appeared on a competitor's website. The official solution is restricted to
teaching staff, so each check is a fact corroborated by two independent records on the image. The image was processed
with the **Data exfiltration** profile and no prior information.

| Fact | Records | Check |
|---|---|---|
| 2008-07-20 01:22:45: "Please send me the information now" arrives with display name `alison@m57.biz`, sent from `tuckgorge@gmail.com` | Outlook PST message and transport headers; reported as sender impersonation | `test_lure_message_has_impersonated_sender` |
| 01:28: Jean replies with `m57biz.xls`; the reply goes to `tuckgorge@gmail.com` (display name `alison@m57.biz`) | PST Sent Items, recipient table | `test_reply_with_spreadsheet_went_to_the_impostor` |
| The attachment is byte-identical to `Desktop\m57biz.xls` (SHA-256 `34456b5f...`), created 01:28:03 | PST attachment hash, `$MFT`, file hash | `test_sent_attachment_is_the_desktop_file` |
| The DLP answer states the file, the real destination and the local copy | Analysis | `test_dlp_answer_names_file_destination_and_copy` |
| No anti-forensics claimed (XP boot files laid down by Setup are not timestomping) | Analysis | `test_no_false_anti_forensics` |

### Errors this case found and fixed

| Problem found | Fix |
|---|---|
| **The reply was shown as sent "to alison@m57.biz"**: only the display name was read, hiding that the spreadsheet went to `tuckgorge@gmail.com` | Recipients are read from the message's recipient table: "display name \<address>", plus Cc and **Bcc** (Bcc recipients exist only there) |
| The impersonated sender was not reported | New sender-impersonation check: a display name that is an address the message was not sent from |
| "Attachments sent" listed unnamed MIME parts and received newsletters' images | Only attachments of sent messages, documents first, with their destination |
| No link between the sent attachment and the file on disk | Attachments are matched by name, size and SHA-256 to files on the system ("byte-identical to ...") |
| `C:\NTDETECT.COM` (laid down by XP Setup) reported as strong timestomping | Files whose `$FN` creation falls on the OS installation day are not reported as strong |
| "first connected  UTC" with no time in the USB answer | Only recorded times are listed |

## Reproduce everything

```
python -m tests.validation.datasets cfreds_data_leakage cfreds_hacking szechuan_dc szechuan_desktop m57_jean
python -m tests.validation.reprocess_all
python -m tests.fixtures.build_threats
python -m pytest tests -m "slow or cfreds or not slow"
```
