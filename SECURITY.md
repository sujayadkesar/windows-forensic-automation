# Security policy

## Reporting a vulnerability

Forensic tools parse hostile data. If you find a way to make Windows Forensic Automation execute code, write outside the
case folder, or produce a wrong result without warning when processing crafted evidence, please report it privately
through GitHub's **"Report a vulnerability"** (Security tab) instead of opening a public issue.

Please include the version, the evidence type and, when possible, a minimal sample that triggers the problem.

## Accuracy issues

A parser or analyzer that reports a wrong value is treated with the same priority as a security bug. Open an issue with
the **"Wrong result"** template. Include the artifact, the expected value and how you verified it (another tool, manual
decoding, published answer key).

## Handling evidence

- Evidence is opened read-only. Nothing is written to the image.
- Samples supplied for malware analysis are analyzed statically. They are never executed.
- Never attach real case data to an issue. Use the synthetic test images (`tests/fixtures/build_all.py`) or public
  reference images (NIST CFReDS) to reproduce problems.
