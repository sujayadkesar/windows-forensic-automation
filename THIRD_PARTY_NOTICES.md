# Third-party software

Windows Forensic Automation is licensed under the GNU Affero General Public License v3.0 or later. It builds on the
following open-source projects; their licenses apply to their code. The binary releases bundle these libraries.

| Component | Purpose | License |
|---|---|---|
| [dissect](https://github.com/fox-it/dissect) (`dissect.target`, `dissect.ntfs`, `dissect.fat`, `dissect.regf`, ...) | evidence containers, volumes, file systems, registry | AGPL-3.0-or-later |
| `dissect.database` | ESE databases (SRUM, WebCache, Windows Search) | Apache-2.0 |
| [libewf](https://github.com/libyal/libewf), [libvshadow](https://github.com/libyal/libvshadow), [libpff](https://github.com/libyal/libpff) | EWF images, Volume Shadow Copies, PST/OST | LGPL-3.0-or-later |
| [pytsk3](https://github.com/py4n6/pytsk) | The Sleuth Kit bindings | Apache-2.0 |
| [evtx](https://github.com/omerbenamram/pyevtx-rs) | EVTX parsing | MIT |
| [LnkParse3](https://github.com/Matmaus/LnkParse3) | shortcut files | MIT |
| [oletools](https://github.com/decalage2/oletools), olefile | Office documents, VBA macros, OLE | BSD |
| [pefile](https://github.com/erocarrera/pefile) | PE executables | MIT |
| [yara-python](https://github.com/VirusTotal/yara-python) | YARA rules | Apache-2.0 |
| [pyahocorasick](https://github.com/WojciechMula/pyahocorasick) | multi-keyword search | BSD-3-Clause |
| [pypdf](https://github.com/py-pdf/pypdf) | PDF documents | BSD-3-Clause |
| [pycdlib](https://github.com/clalancette/pycdlib) | ISO images | LGPL-2.1 |
| [cryptography](https://github.com/pyca/cryptography) | Authenticode signatures | Apache-2.0 / BSD-3-Clause |
| [PySide6 / Qt](https://www.qt.io/qt-for-python) | desktop application, figure rendering | LGPL-3.0 |
| [python-docx](https://github.com/python-openxml/python-docx), [XlsxWriter](https://github.com/jmcnamara/XlsxWriter), openpyxl | Word report, Excel workbook | MIT / BSD / MIT |
| [PyInstaller](https://pyinstaller.org) | Windows executable build | GPL-2.0 with bootloader exception |

Validation data: the NIST [CFReDS Data Leakage Case](https://cfreds-archive.nist.gov/data_leakage_case/) image and answer key are
published by the U.S. National Institute of Standards and Technology.
