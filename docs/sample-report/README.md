# Sample report

[`CFReDS-Data-Leakage-report.pdf`](CFReDS-Data-Leakage-report.pdf) is the report Windows Forensic Automation produced for
the public NIST [CFReDS Data Leakage Case](https://cfreds-archive.nist.gov/data_leakage_case/) PC image. The image was
processed with the **Data exfiltration (DLP alert)** profile and no prior information about the case.

The case files are NIST reference data and not real people.

The case folder that produced it also contains:
- the Excel workbook of every artifact;
- `Parsed\` CSV files (full MFT, `$UsnJrnl`, every event log record, SRUM, ...);
- the raw artifact collection with its hash manifest.

How the results compare with NIST's answer key: [VALIDATION.md](../VALIDATION.md).
