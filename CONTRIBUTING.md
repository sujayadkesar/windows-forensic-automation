# Contributing to Windows Forensic Automation

The tool is built from three kinds of building blocks. Most contributions need only one of them:

| You want to... | Add | Code needed? |
|---|---|---|
| support a new **case type** (BEC, insider fraud, cryptominer...) | a profile YAML in `winforensics/profiles/` | usually none |
| recognize a new **tool, domain or command pattern** | an entry in `winforensics/knowledge/*.yaml` or a YARA rule in `knowledge/yara/` | none |
| parse a new **artifact** | an artifact module in `winforensics/modules/` | yes |
| draw a new **conclusion** across artifacts | an analyzer in `winforensics/analyzers/` | yes |

Without changing the installed tool, you can also drop profiles into `%APPDATA%\WindowsForensicAutomation\profiles\`
and Python modules or analyzers into `%APPDATA%\WindowsForensicAutomation\plugins\`. Both are loaded at start-up.

## Development setup

```
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt pytest
.venv\Scripts\python tests\fixtures\build_all.py      # builds the synthetic test images (once)
.venv\Scripts\python -m pytest -m "not slow"          # unit tests (seconds)
.venv\Scripts\python -m pytest -m slow                # end-to-end DLP case on the test images (minutes)
.venv\Scripts\python packaging\build_exe.py           # dist\WindowsForensicAutomation\WFA.exe
```

## 1. Profiles: case types

A profile defines four things:

- the evidence roles the examiner assigns;
- the inputs the wizard asks for;
- the modules and analyzers that run;
- the investigative questions the report answers.

Copy the closest existing profile and edit it:

```yaml
id: cryptominer                 # unique, snake_case
name: Cryptominer infection
category: Intrusion / Malware   # groups the profile cards in the wizard
icon: malware                   # any glyph name from gui/theme.py GLYPH
order: 26
summary: One line shown on the profile card.
when_to_use: [High CPU alert on a server, Pool domain seen in proxy logs]
evidence_roles:
  - {id: source, label: Affected system}
inputs:                         # types: dlp_export target_files reference_files samples yara iocs
  - {id: iocs, type: iocs, label: Pool domains / wallet}   #        time_window keywords string_list text
  - {id: time_window, type: time_window, label: Period of interest (UTC)}
modules: all                    # or a list of module ids; dependencies are added automatically
analyzers: [system_overview, malware_hunt, suspicious_activity, remote_access_review, anti_forensics, case_timeline]
questions:                      # answered by analyzers through their question ids
  - {id: mal.present, text: Is miner software present on the system?}
  - {id: mal.executed, text: Was it executed, when, and by which account?}
  - {id: persist.found, text: How does it survive a reboot?}
```

Answers use forensic wording: **Yes**, **Indicated**, **No evidence found**, **Not applicable** and **Inconclusive**.
Severity ratings are not used.

Run `python -m winforensics profiles` to check that your profile loads. `tests/test_units.py` also checks that every
analyzer a profile references exists.

## 2. Knowledge: no code

- **`knowledge/tools.yaml`**: remote-access tools, archivers, wipers, cloud sync clients and so on.
  - Give each tool its executable names.
  - Use `names` aliases for installed-program names, so that "Chrome Remote Desktop" is not matched by "Google Chrome".
- **`knowledge/domains.yaml`**: webmail, cloud storage, paste sites, file-transfer and AI services, by category.
- **`knowledge/patterns.yaml`**: suspicious command-line patterns.
  - Each pattern has a regex, a score, a title and MITRE ATT&CK ids.
  - Patterns are applied to the Run box, PowerShell history, script blocks, 4688/Sysmon command lines, tasks, services and autoruns.
- **`knowledge/yara/*.yar`**: rules applied to samples and suspicious files.

## 3. Artifact modules

A module reads one artifact family and emits normalized records. Records automatically appear in:

- the GUI artifact browser;
- the Excel workbook;
- the parsed CSV export (`Parsed\E##_<label>\<Category>\<Title>.csv`);
- the analyzers' input.

```python
from datetime import datetime

from .base import ArtifactModule, ArtifactType, C, register


@register
class TeamViewerLogs(ArtifactModule):
    id = "teamviewer_logs"
    title = "TeamViewer connection logs"
    category = "Remote access"
    order = 60                     # runs after the file system index (order 10)
    requires = ["filesystem"]
    locations = ["C:\\Program Files*\\TeamViewer\\Connections_incoming.txt"]
    artifact_types = [
        ArtifactType("tv_connection", "TeamViewer Connections", "Remote Access",
                     [C("remote_id"), C("remote_name"), C("start", kind="datetime"), C("end", kind="datetime"), C("user")],
                     ts_label="Session start"),
    ]

    def run(self, ctx):
        n = 0
        for row in ctx.fs_files("lower(name) = 'connections_incoming.txt'"):
            for line in ctx.read_entry(row).decode("utf-8", "replace").splitlines():
                f = line.split("\t")
                if len(f) < 5:
                    continue
                start, end = (ctx.local_to_utc(datetime.strptime(x, "%d-%m-%Y %H:%M:%S")) for x in f[2:4])
                ctx.emit("tv_connection", start, {"remote_id": f[0], "remote_name": f[1], "start": start, "end": end,
                                                  "user": f[4]},
                         summary=f"TeamViewer session from {f[0]}", source=ctx.display_path(row["volume"], row["path"]))
                n += 1
        ctx.coverage("TeamViewer incoming connections", self.locations[0], "found" if n else "not_found", n)
```

Rules:

- **Never crash the run.** Wrap each file in `try/except`, and report problems with `ctx.warn()` or a `"partial"` coverage status.
- **Always call `ctx.coverage()`.** The report's coverage matrix tells the reader what was examined, including "not found".
- **Normalize timestamps to UTC** with `ctx.local_to_utc()` (uses the evidence time zone) or by passing an aware datetime.
- **Read files from the image** using `ctx.fs_files()` / `ctx.read_entry()` (indexed MFT/FAT, deleted files included) or `ctx.path()`.
- **Collection:** to copy the original artifact file into `Collected\`, add a pattern to `TARGETS` in `modules/collection.py`.

## 4. Analyzers

Analyzers run after all evidence is processed and see every evidence item at once. They create the following:

- **findings:** what the report reads as the narrative, each with figures;
- **answers:** to the profile's question ids;
- **timeline entries.**

```python
from .base import YES, Analyzer, analyzer, callout, table_figure
from .common import ref, short


@analyzer
class TeamViewerAnalyzer(Analyzer):
    id = "teamviewer"
    title = "TeamViewer sessions"

    def run(self, actx):
        for e in actx.windows_evidence():
            rows, refs = [], []
            for a in actx.artifacts("tv_connection", e["id"]):
                d = a["data"]
                rows.append([short(d["start"]), short(d["end"]), d["remote_id"], d["remote_name"], d["user"]])
                refs.append(ref(a))
            if not rows:
                continue
            fid = actx.finding(
                f"Incoming TeamViewer sessions on {actx.ev_label(e['id'])}",
                f"{len(rows)} incoming sessions were recorded in Connections_incoming.txt.",
                evidence_id=e["id"], category="Remote access", refs=refs, questions=["rmm.connections"],
                figures=[table_figure("TeamViewer incoming connections", ["Start (UTC)", "End (UTC)", "Remote ID", "Name", "User"],
                                      rows[:25], style="table", highlight_rows=[0],
                                      callouts=[callout(0, 2, 1, "Remote TeamViewer ID")])])
            actx.answer("rmm.connections", YES, f"{len(rows)} TeamViewer sessions on {actx.ev_label(e['id'])}.", [fid])
```

Figure styles:

- `table`: a plain formatted table (colored header, borders, zebra rows) - the default for evidence tables.
- `app`: the tool's own results grid.
- `eventlog`: an event list with every field of the selected record.
- `registry_figure`, `hex_figure` and `timeline_figure`: for registry keys, raw hits and timelines.

**Figures must only contain values taken from parsed records.** Never add placeholder rows, sample values or icons:
the figure is evidence. If a value is decoded (MRU entries, FILETIMEs), say so in the caption.

Callouts (row, column, number, text) are drawn as numbered red boxes with arrows to a legend, like a Flameshot
screenshot.

A finding's text states what was found and where. It does not grade risk. Leave interpretation such as "this
indicates exfiltration" to the answer summary, and qualify it ("Indicated", "consistent with").

## Pull request checklist

- [ ] `python -m pytest -m "not slow"` passes.
- [ ] New artifact types have a `C(...)` column list and a `ts_label`.
- [ ] New modules call `ctx.coverage()` for every location they examine.
- [ ] Every analyzer referenced by a profile exists, and every question id it answers is listed in the profile.
- [ ] No case data or real evidence is committed. Use `tests/fixtures` to generate synthetic data.
