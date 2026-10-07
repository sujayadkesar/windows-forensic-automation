# Validation: NIST CFReDS Data Leakage Case

**Result: 23 / 23 checks pass** (`tests/validation/test_cfreds_data_leakage.py`, version 1.2.0).

## The reference case

The U.S. National Institute of Standards and Technology publishes the
[CFReDS Data Leakage Case](https://cfreds-archive.nist.gov/data_leakage_case/):
- **The scenario:** a Windows 7 PC image of an employee who searches for leakage methods, then exfiltrates confidential
  project files. The channels are two USB sticks, a network share, e-mail, Google Drive and CD-R. He then tries to
  remove traces with Eraser and CCleaner.
- **The answer key:** NIST publishes it with the image (`leakage-answers.pdf`, last saved 2018-07-23).

The PC image was processed with the **Data exfiltration (DLP alert)** profile and no prior information: no DLP export, no
file list and no device serial. The tool's database was then compared, value by value, with the answer key.

## Checks

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

## Errors this validation found and fixed

| Problem found | Fix |
|---|---|
| Paths of deleted / renamed files went through reused folder records, e.g. `winter_storm.amr` shown inside a Chrome cache folder | Parent references are checked by sequence number; folders are rebuilt from `$UsnJrnl` history using the name they had at that time |
| Windows 7 USB "last connected" was really the first connection after the last reboot (RM#2 was reconnected later in the same session) | Labeled "connected after the last reboot", as the DeviceClasses key means; "last connected" only from Properties 0066 or connect events |
| Network shortcut targets read `1\Secret Project Data\...` | `device_name` is used only when the ValidDevice flag is set (MS-SHLLINK) |
| Google Drive: the second file of a batched upload was missing; the account was missing because `sync_config.db` is deleted | Every change in a batch is parsed; the account is read from `sync_log.log` |
| CD burning was only partially visible | Added cdrom event 133, IMAPI sessions and staged files from `$UsnJrnl`, burn method from the registry |
| Deleted e-mails were not reported | Windows Search index (`Windows.edb`) parsed and compared with the mailbox |

## False-positive check

The same processed image was analyzed with every other profile. It contains no malware, ClickFix, phishing, remote-access
tool or ransomware. Every profile's questions about those threats answer **No evidence found** or **Not applicable**.

Noise found during this check and removed:
- Windows Update files counted as "ransomware extensions";
- console logons counted as remote sessions;
- cached web page JavaScript counted as executed scripts;
- WMI class definitions and the built-in Windows 7 `BVTFilter` subscription counted as persistence;
- downloaded installers counted as opened phishing attachments.

## Reproduce

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
