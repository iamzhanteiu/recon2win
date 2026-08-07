"""xlsx_report — optional Excel workbook mirroring ``final_report.html``.

``modules/report.py`` already collects one big ``data`` dict (the same
object it turns into HTML/Markdown/JSON) covering every finding class the
pipeline produces. This module renders THAT dict into a multi-sheet
``.xlsx`` workbook — no re-reading of ``outputs/<domain>/`` from disk, so it
can never disagree with the other three artefacts.

Why a separate module instead of another ``render_*`` method on
``ReportBuilder``: ``openpyxl`` is an optional dependency (most users never
touch Excel), so the import has to be isolable and the whole feature has to
degrade to "skipped, here's the pip command" rather than crashing the run
when it's missing.

Design — "refer qua lại" (cross-referencing) between sheets:
  * ``URL Surface`` is the HUB sheet — one row per URL seen ANYWHERE in the
    run (probed or not). Every other detail sheet that carries a URL gets a
    "↩ URL Surface" column linking to that URL's hub row.
  * The hub sheet, in turn, carries one column per detail-sheet category
    (Nuclei / High-Value / Secrets / …) showing a count and a link to the
    FIRST matching row in that sheet.
  * A "Mục lục" (table of contents) sheet links to every sheet and back —
    each sheet's A1 corner links back to the TOC.
This turns 16 flat tables into one navigable graph instead of a pile of
sheets nobody cross-checks by hand.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

try:
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter
    from openpyxl.worksheet.datavalidation import DataValidation
    from openpyxl.worksheet.worksheet import Worksheet
    HAVE_OPENPYXL = True
except ImportError:  # pragma: no cover - exercised via HAVE_OPENPYXL branch
    HAVE_OPENPYXL = False

INSTALL_HINT = "pip install openpyxl"

HEADER_FILL = "1D3557"
HEADER_FONT = "FFFFFF"
LINK_COLOR = "0563C1"
HUB_SHEET = "URL Surface"
TOC_SHEET = "Mục lục"

# Manual triage tag — a free-standing column appended to every detail sheet
# so a reviewer can mark rows while working through the workbook in Excel
# (nothing here is inferred from scan data; the analyst fills it by hand).
# A dropdown (Data Validation) constrains it to this fixed vocabulary so the
# column stays filterable/sortable instead of turning into free text.
TAG_HEADER = "Tag"
TAG_OPTIONS = ["Reviewed", "False Positive", "Reported", "Duplicate", "Ignore", "Need Retest"]
TAG_DROPDOWN_FORMULA = '"' + ",".join(TAG_OPTIONS) + '"'

SEVERITY_FILL = {
    "critical": "C0392B",
    "high":     "E67E22",
    "medium":   "F1C40F",
    "low":      "3498DB",
    "info":     "95A5A6",
    "unknown":  "BDC3C7",
}
SEVERITY_FONT = {
    "critical": "FFFFFF", "high": "FFFFFF", "medium": "1D1D1F",
    "low": "FFFFFF", "info": "1D1D1F", "unknown": "1D1D1F",
}

# modules/existence.py verdicts — a different vocabulary from severity, so a
# separate fill/font pair (passed to ``_write_simple`` as ``fill_map``/
# ``font_map`` instead of falling through to SEVERITY_FILL).
EXISTENCE_FILL = {
    "confirmed": "27AE60", "likely": "E67E22",
    "unknown": "BDC3C7", "not_found": "7F8C8D",
}
EXISTENCE_FONT = {
    "confirmed": "FFFFFF", "likely": "FFFFFF",
    "unknown": "1D1D1F", "not_found": "FFFFFF",
}

# (sheet title, one-line description for the TOC)
_SHEET_DESCRIPTIONS: dict[str, str] = {
    "Tổng quan": "Meta của scan (domain, thời gian, counts, tool versions).",
    HUB_SHEET: "Mọi URL từng thấy trong run — hub trung tâm để nhảy qua các sheet khác.",
    "Nuclei Findings": "Kết quả nuclei default scan, theo severity.",
    "High-Value Targets": "URL đáng chú ý (admin, .env, backup, ...) kèm response thực tế.",
    "JS Secrets": "Secret/key/token rút ra từ JS bằng jsluice.",
    "Params": "Tham số GET/POST rút ra từ arjun + jsluice + API spec.",
    "Forms": "Form/input mined từ crawl, xếp hạng theo giá trị test.",
    "API Docs": "OpenAPI/Swagger spec, docs UI và OSINT (Postman/GitHub).",
    "Misconfig": "Server/microservice misconfig probe (actuator, debug endpoint, ...).",
    "GraphQL": "Endpoint GraphQL bật introspection.",
    "CORS": "Host phản xạ Origin tùy ý (misconfiguration).",
    "Buckets": "Cloud storage bucket (S3/GCS/Azure) tìm thấy.",
    "Git Dump": "Host bị lộ .git đã được reconstruct.",
    "Subdomains & DNS": "Subdomain đã resolve, IP/ASN/CNAME.",
    "Endpoint Existence": "Mọi hit ffuf/dirsearch, phân loại theo response "
        "BEHAVIOUR (baseline shape + body signal + status family) thay vì "
        "chỉ status code — Confirmed/Likely/Unknown/Not Found.",
    "Files": "Toàn bộ file output của run, có link mở trực tiếp.",
}


def _safe_title(name: str) -> str:
    """Excel sheet names: max 31 chars, no ``[]:*?/\\``."""
    for ch in "[]:*?/\\":
        name = name.replace(ch, "-")
    return name[:31]


def _norm_url(u: Any) -> str:
    return str(u or "").strip()


def _style_header(ws: "Worksheet", ncols: int) -> None:
    for col in range(1, ncols + 1):
        cell = ws.cell(row=1, column=col)
        cell.font = Font(bold=True, color=HEADER_FONT)
        cell.fill = PatternFill("solid", fgColor=HEADER_FILL)
        cell.alignment = Alignment(vertical="center", wrap_text=True)
    ws.row_dimensions[1].height = 30
    ws.freeze_panes = "A2"
    ws.auto_filter.ref = f"A1:{get_column_letter(ncols)}1"


def _set_widths(ws: "Worksheet", widths: list[int]) -> None:
    for i, w in enumerate(widths, start=1):
        ws.column_dimensions[get_column_letter(i)].width = max(8, min(w, 90))


# Leading characters that make a spreadsheet cell auto-evaluate as a
# formula (``=``, ``+``, ``-``, ``@``) or as a control character Excel/CSV
# consumers mishandle (tab, CR). Every string in this workbook ultimately
# comes from the scanned target — a page title, a header value, a secret
# regex match — none of it trusted input. Without this, a target that
# returns e.g. a title of ``=cmd|'/c calc'!A1`` becomes a live formula the
# instant someone opens the report in Excel (classic CSV/formula
# injection). Prefixing with a single quote keeps it inert text.
_FORMULA_TRIGGERS = ("=", "+", "-", "@", "\t", "\r")


def _safe(v: Any) -> Any:
    # ``counts`` (and a few other dicts pulled straight from ``collect()``)
    # occasionally hold a list/dict value (e.g. ``high_value_blanket_hosts``)
    # rather than a scalar — openpyxl only accepts str/int/float/bool/None,
    # so anything else is flattened to a display string first.
    if isinstance(v, (list, tuple, set)):
        v = ", ".join(str(x) for x in v)
    elif isinstance(v, dict):
        v = str(v)
    if isinstance(v, str) and v[:1] in _FORMULA_TRIGGERS:
        return "'" + v
    return v


def _cell(ws: "Worksheet", row: int, col: int, value: Any = None):
    return ws.cell(row=row, column=col, value=_safe(value))


def _hyperlink(cell, target: str, text: Optional[str] = None) -> None:
    cell.hyperlink = target
    if text is not None:
        cell.value = _safe(text)
    cell.font = Font(color=LINK_COLOR, underline="single")


def _truthy_list(v: Any) -> list:
    return v if isinstance(v, list) else []


def _truthy_dict(v: Any) -> dict:
    return v if isinstance(v, dict) else {}


class _XlsxBuilder:
    """Two-pass build: first compute every sheet's rows + URL columns (pure
    Python, no openpyxl objects), THEN write cells — so the hub sheet can
    link forward to detail-sheet rows and detail sheets can link back to the
    hub, regardless of which is written first.
    """

    def __init__(self, data: dict):
        self.data = data
        # sheet_name -> list[dict] (each dict is one row's field values)
        self.sheet_rows: dict[str, list[dict]] = {}
        # sheet_name -> {normalized_url: first_row_number}
        self.sheet_url_rows: dict[str, dict[str, int]] = {}
        # sheet_name -> {normalized_url: occurrence count}
        self.sheet_url_counts: dict[str, dict[str, int]] = {}
        self.hub_url_order: list[str] = []
        self.hub_row_of: dict[str, int] = {}

    # ---- pass 1: build plain-python row tables -----------------------
    def _register(self, sheet: str, rows: list[dict], url_field: Optional[str] = "url") -> None:
        self.sheet_rows[sheet] = rows
        if not url_field:
            return
        url_rows: dict[str, int] = {}
        url_counts: dict[str, int] = {}
        for idx, row in enumerate(rows):
            u = _norm_url(row.get(url_field))
            if not u:
                continue
            if u not in url_rows:
                url_rows[u] = idx + 2  # header is row 1
            url_counts[u] = url_counts.get(u, 0) + 1
        self.sheet_url_rows[sheet] = url_rows
        self.sheet_url_counts[sheet] = url_counts

    def build_tables(self) -> None:
        d = self.data

        # --- Nuclei Findings ---
        nuclei = _truthy_dict(d.get("nuclei", {}).get("default", {}))
        n_rows = []
        for f in _truthy_list(nuclei.get("findings")):
            if not isinstance(f, dict):
                continue
            info = f.get("info") or {}
            n_rows.append({
                "severity": str(info.get("severity") or "unknown").lower(),
                "template_id": str(f.get("template-id") or ""),
                "name": str(info.get("name") or ""),
                "url": str(f.get("matched-at") or ""),
                "matcher": str(f.get("matcher-name") or ""),
                "extracted": ", ".join(str(x) for x in (f.get("extracted-results") or [])),
            })
        self._register("Nuclei Findings", n_rows)

        # --- High-Value Targets ---
        hv_rows = []
        for h in _truthy_list(d.get("high_value_targets")):
            if not isinstance(h, dict):
                continue
            hv_rows.append({
                "url": str(h.get("url") or ""),
                "categories": ", ".join(h.get("categories") or []),
                "status": h.get("status"),
                "content_length": h.get("content_length"),
                "content_type": str(h.get("content_type") or ""),
                "title": str(h.get("title") or ""),
                "webserver": str(h.get("webserver") or ""),
                "probed": "yes" if h.get("probed") else "no",
            })
        self._register("High-Value Targets", hv_rows)

        # --- JS Secrets ---
        sec_rows = []
        for s in _truthy_list(_truthy_dict(d.get("jsluice_secrets")).get("findings")):
            if not isinstance(s, dict):
                continue
            payload = s.get("data")
            payload_text = ", ".join(f"{k}={v}" for k, v in payload.items()) if isinstance(payload, dict) else str(payload or "")
            sec_rows.append({
                "kind": str(s.get("kind") or ""),
                "severity": str(s.get("severity") or "unknown").lower(),
                "url": str(s.get("url") or ""),
                "data": payload_text,
            })
        self._register("JS Secrets", sec_rows)

        # --- Params (jsluice AST + arjun/parameterized sample) ---
        p_rows = []
        for j in _truthy_list(d.get("jsluice_params")):
            if not isinstance(j, dict):
                continue
            p_rows.append({
                "source": "jsluice",
                "url": str(j.get("url") or ""),
                "method": str(j.get("method") or "GET").upper() or "GET",
                "query_params": ", ".join(j.get("queryParams") or []),
                "body_params": ", ".join(j.get("bodyParams") or []),
            })
        for line in _truthy_list(d.get("parameterized_sample")):
            p_rows.append({
                "source": "arjun/crawl",
                "url": str(line),
                "method": "GET",
                "query_params": "",
                "body_params": "",
            })
        self._register("Params", p_rows)

        # --- Forms ---
        f_rows = []
        for f in _truthy_list(d.get("forms")):
            if not isinstance(f, dict):
                continue
            params = f.get("parameters")
            f_rows.append({
                "url": str(f.get("action") or f.get("url") or ""),
                "found_on": str(f.get("url") or ""),
                "method": str(f.get("method") or "GET").upper(),
                "enctype": str(f.get("enctype") or ""),
                "fields": ", ".join(str(x) for x in params) if isinstance(params, list) else "",
            })
        self._register("Forms", f_rows)

        # --- API Docs (specs / ui / discovery / osint, one sheet) ---
        api = _truthy_dict(d.get("api_docs"))
        a_rows = []
        for s in _truthy_list(api.get("specs")):
            if not isinstance(s, dict):
                continue
            methods = s.get("methods") or {}
            detail = (
                f"kind={s.get('kind','')}; version={s.get('version','')}; "
                f"api_version={s.get('api_version','')}; paths={s.get('paths',0)}; "
                f"methods={methods}; security={', '.join(s.get('security_schemes') or [])}; "
                f"servers={', '.join(s.get('servers') or [])}"
            )
            a_rows.append({"type": "spec", "url": str(s.get("url") or ""),
                            "name": str(s.get("title") or ""), "detail": detail})
        for u in _truthy_list(api.get("ui")):
            if not isinstance(u, dict):
                continue
            a_rows.append({"type": "docs-ui", "url": str(u.get("url") or ""),
                            "name": "", "detail": f"status={u.get('status','')}"})
        for disc in _truthy_list(api.get("discovery")):
            if not isinstance(disc, dict):
                continue
            a_rows.append({"type": "discovery", "url": str(disc.get("url") or ""),
                            "name": "", "detail": str(disc)})
        for o in _truthy_list(api.get("osint")):
            if not isinstance(o, dict):
                continue
            a_rows.append({"type": "osint", "url": str(o.get("url") or ""),
                            "name": str(o.get("name") or ""),
                            "detail": f"source={o.get('source','')}; kind={o.get('kind','')}; score={o.get('score','')}"})
        self._register("API Docs", a_rows)

        # --- Misconfig ---
        mc_rows = []
        for m in _truthy_list(_truthy_dict(d.get("misconfig_probe")).get("findings")):
            if not isinstance(m, dict):
                continue
            mc_rows.append({
                "url": str(m.get("url") or ""),
                "service": str(m.get("service") or ""),
                "confidence": str(m.get("confidence") or ""),
                "status": m.get("status"),
            })
        self._register("Misconfig", mc_rows)

        # --- GraphQL ---
        gql_rows = []
        for t in _truthy_list(d.get("graphql_targets")):
            if not isinstance(t, dict):
                continue
            gql_rows.append({
                "url": str(t.get("url") or ""),
                "type_count": t.get("type_count"),
                "query_fields": ", ".join(t.get("query_fields") or []),
                "mutation_fields": ", ".join(t.get("mutation_fields") or []),
                "subscription_fields": ", ".join(t.get("subscription_fields") or []),
            })
        self._register("GraphQL", gql_rows)

        # --- CORS ---
        cors_rows = []
        for f in _truthy_list(d.get("cors_findings")):
            if not isinstance(f, dict):
                continue
            cors_rows.append({
                "severity": str(f.get("severity") or "unknown").lower(),
                "url": str(f.get("url") or ""),
                "acao": str(f.get("acao") or ""),
                "acac": "yes" if f.get("acac") else "no",
                "note": str(f.get("note") or ""),
            })
        self._register("CORS", cors_rows)

        # --- Buckets ---
        bk = _truthy_dict(d.get("buckets"))
        bk_rows = []
        for f in _truthy_list(bk.get("findings")):
            if not isinstance(f, dict):
                continue
            bk_rows.append({
                "severity": str(f.get("severity") or "unknown").lower(),
                "provider": str(f.get("provider") or ""),
                "bucket": str(f.get("bucket") or ""),
                "state": str(f.get("state") or ""),
                "url": str(f.get("url") or ""),
            })
        for a in _truthy_list(bk.get("azure_references")):
            bk_rows.append({"severity": "info", "provider": "azure",
                             "bucket": str(a), "state": "reference-only", "url": ""})
        self._register("Buckets", bk_rows)

        # --- Git Dump ---
        gd_rows = []
        for h in _truthy_list(d.get("gitdump_hosts")):
            if not isinstance(h, dict):
                continue
            gd_rows.append({
                "host": str(h.get("host") or ""),
                "ref": str(h.get("ref") or "-"),
                "files_recovered": h.get("files_recovered", 0),
                "files_in_index": h.get("files_in_index", 0),
                "output_dir": str(h.get("output_dir") or ""),
            })
        self._register("Git Dump", gd_rows, url_field=None)

        # --- Subdomains & DNS ---
        dns_rows = []
        for r in _truthy_list(d.get("dns_records")):
            if not isinstance(r, dict):
                continue
            asn = r.get("asn") or {}
            dns_rows.append({
                "subdomain": str(r.get("subdomain") or ""),
                "ip": str(r.get("ip") or ""),
                "asn": str(asn.get("asn") or "") if isinstance(asn, dict) else "",
                "asn_name": str(asn.get("name") or "") if isinstance(asn, dict) else "",
                "cname": str(r.get("cname") or ""),
            })
        self._register("Subdomains & DNS", dns_rows, url_field=None)

        # --- Endpoint Existence (modules/existence.py verdicts) ---
        ex_rows = []
        for r in _truthy_list(_truthy_dict(d.get("endpoint_existence")).get("results")):
            if not isinstance(r, dict):
                continue
            sources = r.get("sources")
            ex_rows.append({
                "verdict": str(r.get("verdict") or "unknown"),
                "status": r.get("status"),
                "source": "+".join(sources) if isinstance(sources, list) else "",
                "url": str(r.get("url") or ""),
                "evidence": "; ".join(r.get("reasons") or []),
            })
        self._register("Endpoint Existence", ex_rows)

        # --- Files (file inventory, external hyperlinks to the actual files) ---
        files_rows = []
        for f in _truthy_list(d.get("files")):
            if not isinstance(f, dict):
                continue
            files_rows.append({
                "label": str(f.get("label") or ""),
                "kind": str(f.get("kind") or ""),
                "path": str(f.get("rel") or ""),
                "exists": "yes" if f.get("exists") else "no",
                "size_bytes": f.get("size", 0),
                "rel_link": str(f.get("rel_link") or ""),
            })
        self._register("Files", files_rows, url_field=None)

        # --- URL Surface hub: union of url_detail_index + every URL seen
        # in any of the detail sheets above (so a nuclei/secret/param hit on
        # a URL never probed still gets a hub row to link to/from).
        idx = _truthy_dict(d.get("url_detail_index"))
        hub: dict[str, dict] = {}
        for u, row in idx.items():
            u = _norm_url(u)
            if not u or not isinstance(row, dict):
                continue
            hub[u] = row
        for sheet, url_rows in self.sheet_url_rows.items():
            for u in url_rows:
                hub.setdefault(u, {})
        self.hub_url_order = sorted(hub.keys())
        hub_rows = []
        for i, u in enumerate(self.hub_url_order):
            row = hub[u]
            host = ""
            try:
                from urllib.parse import urlsplit
                host = urlsplit(u).netloc
            except Exception:  # noqa: BLE001
                host = ""
            hub_rows.append({
                "url": u,
                "host": host,
                "status": row.get("status_code"),
                "content_length": row.get("content_length"),
                "content_type": str(row.get("content_type") or "").split(";")[0].strip(),
                "title": str(row.get("title") or ""),
                "webserver": str(row.get("webserver") or ""),
            })
            self.hub_row_of[u] = i + 2
        self.sheet_rows[HUB_SHEET] = hub_rows

    # ---- pass 2: write the workbook -----------------------------------
    def write(self, xlsx_path: Path) -> dict:
        wb = Workbook()
        wb.remove(wb.active)
        # Fix TOC + Summary as the first two tabs up front; both are
        # populated LAST (once every other sheet's row counts are known),
        # but the position is decided here so sheet order stays readable.
        toc_ws = wb.create_sheet(_safe_title(TOC_SHEET), 0)
        summary_ws = wb.create_sheet(_safe_title("Tổng quan"), 1)

        self._write_hub(wb)
        self._write_simple("Nuclei Findings",
                            [("Severity", "severity"), ("Template ID", "template_id"),
                             ("Name", "name"), ("Matched At", "url"),
                             ("Matcher", "matcher"), ("Extracted", "extracted")],
                            wb, severity_field="severity")
        self._write_simple("High-Value Targets",
                            [("URL", "url"), ("Categories", "categories"),
                             ("Status", "status"), ("Length", "content_length"),
                             ("Content-Type", "content_type"), ("Title", "title"),
                             ("Webserver", "webserver"), ("Probed", "probed")], wb)
        self._write_simple("JS Secrets",
                            [("Kind", "kind"), ("Severity", "severity"),
                             ("URL", "url"), ("Data", "data")],
                            wb, severity_field="severity")
        self._write_simple("Params",
                            [("Source", "source"), ("URL", "url"), ("Method", "method"),
                             ("Query Params", "query_params"), ("Body Params", "body_params")], wb)
        self._write_simple("Forms",
                            [("Action URL", "url"), ("Found On", "found_on"),
                             ("Method", "method"), ("Enctype", "enctype"),
                             ("Fields", "fields")], wb)
        self._write_simple("API Docs",
                            [("Type", "type"), ("URL", "url"), ("Name", "name"),
                             ("Detail", "detail")], wb)
        self._write_simple("Misconfig",
                            [("URL", "url"), ("Service", "service"),
                             ("Confidence", "confidence"), ("Status", "status")], wb)
        self._write_simple("GraphQL",
                            [("URL", "url"), ("Type Count", "type_count"),
                             ("Query Fields", "query_fields"),
                             ("Mutation Fields", "mutation_fields"),
                             ("Subscription Fields", "subscription_fields")], wb)
        self._write_simple("CORS",
                            [("Severity", "severity"), ("URL", "url"),
                             ("Allow-Origin", "acao"), ("Allow-Credentials", "acac"),
                             ("Note", "note")], wb, severity_field="severity")
        self._write_simple("Buckets",
                            [("Severity", "severity"), ("Provider", "provider"),
                             ("Bucket", "bucket"), ("State", "state"),
                             ("URL", "url")], wb, severity_field="severity")
        self._write_simple("Git Dump",
                            [("Host", "host"), ("Ref", "ref"),
                             ("Files Recovered", "files_recovered"),
                             ("Files In Index", "files_in_index"),
                             ("Output Dir", "output_dir")], wb, url_col=False)
        self._write_simple("Subdomains & DNS",
                            [("Subdomain", "subdomain"), ("IP", "ip"),
                             ("ASN", "asn"), ("ASN Name", "asn_name"),
                             ("CNAME", "cname")], wb, url_col=False)
        self._write_simple("Endpoint Existence",
                            [("Verdict", "verdict"), ("Status", "status"),
                             ("Source", "source"), ("URL", "url"),
                             ("Evidence", "evidence")], wb,
                            severity_field="verdict",
                            fill_map=EXISTENCE_FILL, font_map=EXISTENCE_FONT)
        self._write_files_sheet(wb)
        self._write_summary(summary_ws)
        self._write_toc(wb, toc_ws)

        wb.save(xlsx_path)
        return {"path": str(xlsx_path), "sheets": len(wb.sheetnames),
                "skipped": False, "reason": None}

    def _hub_link_cell(self, ws: "Worksheet", row_idx: int, col_idx: int, url: str) -> None:
        hub_row = self.hub_row_of.get(_norm_url(url))
        cell = ws.cell(row=row_idx, column=col_idx)
        if hub_row:
            _hyperlink(cell, f"#'{_safe_title(HUB_SHEET)}'!B{hub_row}", "↩ URL Surface")
        else:
            cell.value = ""

    def _write_simple(self, sheet_name: str, columns: list[tuple[str, str]],
                       wb: "Workbook", *, severity_field: Optional[str] = None,
                       url_col: bool = True,
                       fill_map: Optional[dict[str, str]] = None,
                       font_map: Optional[dict[str, str]] = None) -> None:
        rows = self.sheet_rows.get(sheet_name, [])
        ws = wb.create_sheet(_safe_title(sheet_name))
        headers = [h for h, _ in columns] + (["Hub"] if url_col else []) + [TAG_HEADER]
        for col, h in enumerate(headers, start=1):
            _cell(ws, 1, col, h)
        _style_header(ws, len(headers))
        fills = fill_map or SEVERITY_FILL
        fonts = font_map or SEVERITY_FONT
        for r_off, row in enumerate(rows):
            r = r_off + 2
            fill = None
            font_color = None
            if severity_field:
                sev = str(row.get(severity_field) or "unknown").lower()
                fill = fills.get(sev, fills.get("unknown"))
                font_color = fonts.get(sev, fonts.get("unknown", "1D1D1F"))
            for col, (_, key) in enumerate(columns, start=1):
                cell = _cell(ws, r, col, row.get(key))
                if fill:
                    cell.fill = PatternFill("solid", fgColor=fill)
                    cell.font = Font(color=font_color)
            if url_col:
                self._hub_link_cell(ws, r, len(columns) + 1, str(row.get("url") or ""))
        self._add_tag_column(ws, len(headers), len(rows))
        widths = [max(12, len(h) + 2) for h, _ in columns] + ([14] if url_col else []) + [16]
        # URL-ish columns get more room.
        for i, (h, key) in enumerate(columns):
            if key in ("url", "detail", "data", "extracted", "fields",
                       "query_params", "body_params", "categories", "note",
                       "evidence"):
                widths[i] = 55
        _set_widths(ws, widths)

    def _add_tag_column(self, ws: "Worksheet", tag_col: int, n_rows: int) -> None:
        """Leave the Tag column blank (analyst fills it by hand) but constrain
        it to ``TAG_OPTIONS`` via a dropdown, so it stays filterable instead
        of degrading into free text."""
        if n_rows <= 0:
            return
        dv = DataValidation(type="list", formula1=TAG_DROPDOWN_FORMULA, allow_blank=True)
        ws.add_data_validation(dv)
        col_letter = get_column_letter(tag_col)
        dv.add(f"{col_letter}2:{col_letter}{n_rows + 1}")

    def _write_hub(self, wb: "Workbook") -> None:
        rows = self.sheet_rows.get(HUB_SHEET, [])
        ws = wb.create_sheet(_safe_title(HUB_SHEET))
        detail_sheets = ["Nuclei Findings", "High-Value Targets", "JS Secrets",
                          "Params", "Forms", "API Docs", "Misconfig",
                          "GraphQL", "CORS", "Buckets", "Endpoint Existence"]
        headers = (["#", "URL", "Host", "Status", "Length", "Content-Type",
                     "Title", "Webserver"] + detail_sheets)
        for col, h in enumerate(headers, start=1):
            _cell(ws, 1, col, h)
        _style_header(ws, len(headers))
        for r_off, row in enumerate(rows):
            r = r_off + 2
            u = row["url"]
            _cell(ws, r, 1, r_off + 1)
            url_cell = ws.cell(row=r, column=2)
            _hyperlink(url_cell, u, u)
            _cell(ws, r, 3, row.get("host"))
            _cell(ws, r, 4, row.get("status"))
            _cell(ws, r, 5, row.get("content_length"))
            _cell(ws, r, 6, row.get("content_type"))
            _cell(ws, r, 7, row.get("title"))
            _cell(ws, r, 8, row.get("webserver"))
            for d_off, sheet in enumerate(detail_sheets):
                col = 9 + d_off
                url_rows = self.sheet_url_rows.get(sheet, {})
                count = self.sheet_url_counts.get(sheet, {}).get(u, 0)
                cell = ws.cell(row=r, column=col)
                if count and u in url_rows:
                    _hyperlink(cell, f"#'{_safe_title(sheet)}'!A{url_rows[u]}", str(count))
                else:
                    cell.value = ""
        widths = [6, 55, 24, 8, 10, 22, 30, 16] + [12] * len(detail_sheets)
        _set_widths(ws, widths)

    def _write_files_sheet(self, wb: "Workbook") -> None:
        rows = self.sheet_rows.get("Files", [])
        ws = wb.create_sheet(_safe_title("Files"))
        headers = ["Label", "Kind", "Path", "Exists", "Size (bytes)", "Open"]
        for col, h in enumerate(headers, start=1):
            _cell(ws, 1, col, h)
        _style_header(ws, len(headers))
        for r_off, row in enumerate(rows):
            r = r_off + 2
            _cell(ws, r, 1, row.get("label"))
            _cell(ws, r, 2, row.get("kind"))
            _cell(ws, r, 3, row.get("path"))
            _cell(ws, r, 4, row.get("exists"))
            _cell(ws, r, 5, row.get("size_bytes"))
            link_cell = ws.cell(row=r, column=6)
            if row.get("exists") == "yes" and row.get("rel_link"):
                _hyperlink(link_cell, str(row["rel_link"]), "Mở file")
        _set_widths(ws, [40, 14, 55, 8, 14, 10])

    def _write_summary(self, ws: "Worksheet") -> None:
        d = self.data
        meta = _truthy_dict(d.get("meta"))
        counts = _truthy_dict(d.get("counts"))
        _cell(ws, 1, 1, "Recon2win — Báo cáo tổng quan")
        ws.cell(row=1, column=1).font = Font(bold=True, size=16)
        r = 3
        for label, value in [
            ("Domain", meta.get("domain")),
            ("Scan mode", meta.get("scan_mode")),
            ("Scan start", meta.get("scan_start")),
            ("Scan end", meta.get("scan_end")),
            ("Duration (s)", meta.get("scan_duration_seconds")),
            ("Generated at", meta.get("generated_at")),
            ("Output dir", meta.get("output_dir")),
        ]:
            _cell(ws, r, 1, label).font = Font(bold=True)
            _cell(ws, r, 2, value)
            r += 1
        r += 1
        _cell(ws, r, 1, "Counts").font = Font(bold=True, size=13)
        r += 1
        _cell(ws, r, 1, "Metric").font = Font(bold=True)
        _cell(ws, r, 2, "Value").font = Font(bold=True)
        r += 1
        for k in sorted(counts.keys()):
            _cell(ws, r, 1, k)
            _cell(ws, r, 2, counts[k])
            r += 1
        r += 1
        tv = _truthy_dict(d.get("tool_versions"))
        if tv:
            _cell(ws, r, 1, "Tool versions").font = Font(bold=True, size=13)
            r += 1
            for k in sorted(tv.keys()):
                _cell(ws, r, 1, k)
                _cell(ws, r, 2, str(tv[k]))
                r += 1
        _set_widths(ws, [28, 70])

    def _write_toc(self, wb: "Workbook", ws: "Worksheet") -> None:
        _cell(ws, 1, 1, "Sheet")
        _cell(ws, 1, 2, "Rows")
        _cell(ws, 1, 3, "Mô tả")
        _style_header(ws, 3)
        r = 2
        for name in wb.sheetnames:
            if name == ws.title:
                continue
            n_rows = self.sheet_rows.get(name)
            count = len(n_rows) if n_rows is not None else "n/a"
            link_cell = ws.cell(row=r, column=1)
            _hyperlink(link_cell, f"#'{_safe_title(name)}'!A1", name)
            _cell(ws, r, 2, count)
            _cell(ws, r, 3, _SHEET_DESCRIPTIONS.get(name, ""))
            r += 1
        _set_widths(ws, [26, 8, 80])


def build_xlsx_report(data: dict, report_dir: Path) -> dict:
    """Build ``report/final_report.xlsx`` from the same ``data`` dict already
    used for HTML/Markdown/JSON.

    Returns ``{"path": str|None, "sheets": int, "skipped": bool, "reason": str|None}``.
    Never raises: a missing ``openpyxl`` or a malformed input just yields a
    skipped result with a human-readable reason, so ``--xlsx-report`` never
    takes down the rest of the report pipeline.
    """
    if not HAVE_OPENPYXL:
        return {"path": None, "sheets": 0, "skipped": True,
                "reason": f"openpyxl not installed — {INSTALL_HINT}"}
    xlsx_path = report_dir / "final_report.xlsx"
    builder = _XlsxBuilder(data)
    try:
        builder.build_tables()
        return builder.write(xlsx_path)
    except Exception as exc:  # noqa: BLE001 - optional artefact, never fatal
        return {"path": None, "sheets": 0, "skipped": True,
                "reason": f"xlsx generation failed: {exc}"}
