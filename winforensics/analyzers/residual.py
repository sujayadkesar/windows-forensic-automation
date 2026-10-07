"""Keyword hits in residual data areas (unallocated, slack, MFT, pagefile, hiberfil, VSS) with hex-view figures."""

from __future__ import annotations

import json

from .base import NA, NO, YES, Analyzer, analyzer, hex_figure, table_figure

RESIDUAL = ("Unallocated space", "Unallocated (deleted file remnant)", "File slack", "pagefile.sys", "hiberfil.sys", "swapfile.sys",
            "MFT record (resident data / metadata)", "$LogFile (NTFS transaction log)", "$UsnJrnl (change journal)",
            "$I30 directory index (incl. index slack)", "Volume Shadow Copy store", "Unpartitioned disk space",
            "Document text (carved, unallocated)")


@analyzer
class ResidualDataAnalyzer(Analyzer):
    id = "residual_data"
    title = "Keyword search results"
    description = "Summarizes keyword hits per area and documents hits in residual areas with annotated hex views."
    weight = 1.0

    def run(self, actx):
        kws = actx.inputs.get("keywords") or []
        if not kws:
            actx.answer("residual", NA, "No keywords were searched.", [])
            return
        any_res = False
        for e in actx.evidence:
            eid = e["id"]
            summ = actx.artifacts("keyword_summary", eid)
            if not summ:
                continue
            rows = []
            for s in summ:
                d = s["data"]
                ac = d.get("area_counts") or {}
                res = sum(n for a, n in ac.items() if any(a.startswith(r) for r in RESIDUAL))
                rows.append([d.get("term"), d.get("label"), d.get("total_hits"), res, d.get("areas")[:160]])
            hl = [i for i, r in enumerate(rows) if r[3]]
            figs = [table_figure(f"Keyword search summary - {actx.ev_label(eid)}", ["Keyword", "Origin", "Hits", "In residual areas",
                                                                                   "Hits by area"], rows, style="table",
                                 highlight_rows=hl, sheet="Keywords", col_widths=[220, 140, 60, 110, 520],
                                 caption="Physical search of every byte of the image (ASCII/UTF-8 and UTF-16LE) plus document text")]
            hits = actx.db.query("SELECT * FROM hits WHERE evidence_id=? AND search='physical' ORDER BY term, area", (eid,))
            picked, seen_area = [], set()
            for h in hits:
                if not any(h["area"].startswith(r) for r in RESIDUAL):
                    continue
                key = (h["area"], h["term"])
                if key in seen_area:
                    continue
                seen_area.add(key)
                picked.append(h)
            for h in picked[:4]:
                det = json.loads(h["detail_json"] or "{}")
                start = det.get("context_start", h["offset"])
                figs.append(hex_figure(f"'{h['term']}' in {h['area']}", h["context_hex"], start, det.get("hit_in_context", 0),
                                       h["length"] or len(h["term"]),
                                       {"Evidence": actx.ev_label(eid), "Volume": h["volume"], "Area": h["area"],
                                        "Volume offset": f"{h['offset']:,} ({h['offset']:#x})", "Encoding": h["encoding"],
                                        "Attributed to": h["file_path"] or "-"},
                                       callout=f"Keyword hit ({h['encoding']})"))
            res_hits = [h for h in hits if any(h["area"].startswith(r) for r in RESIDUAL)]
            if res_hits:
                any_res = True
            areas = sorted({h["area"] for h in res_hits})
            fid = actx.finding(f"Keyword search results - {actx.ev_label(eid)}",
                               f"{len(kws)} keywords (examiner supplied and derived from the files of interest, device serials and "
                               f"destinations) were searched across every byte of the image. {len(hits):,} physical hits were "
                               f"recorded; {len(res_hits):,} of them are in residual areas ({', '.join(areas) or 'none'}), "
                               "i.e. traces that survive deletion or are invisible to the file system.",
                               evidence_id=eid, severity="medium" if res_hits else "info", confidence="high",
                               category="Keyword search", figures=figs, questions=["residual"], tags=["keywords"])
            if res_hits:
                actx.answer("residual", YES, f"{actx.ev_label(eid)}: hits in {', '.join(areas)}.", [fid])
        if not any_res:
            actx.answer("residual", NO, "No keyword hits in unallocated space, slack or memory files.", [])
