"""
modelpoison.report
~~~~~~~~~~~~~~~~~~

Parse a ModelAudit SARIF file and produce a per-type detection coverage
report in plain text or Markdown.

Public API
----------
build_report(sarif_path, output_dir) -> ReportData
render_text(data, out=sys.stdout)
render_markdown(data, out=sys.stdout)
write_report(data, path)          # auto-detects .md vs text
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO
from urllib.parse import unquote

# ---------------------------------------------------------------------------
# Display names (directory name → human label)
# ---------------------------------------------------------------------------
DISPLAY: dict[str, str] = {
    "advanced_pickle_obfuscation_vectors": "Advanced Pickle Obfuscation",
    "advanced_weight_poisoning_vectors":   "Advanced Weight Poisoning",
    "archive_vectors":                     "Archive / ZIP",
    "flax_jax_vectors":                    "Flax / JAX",
    "gguf_vectors":                        "GGUF",
    "jinja2_bypass_vectors":               "Jinja2 SSTI Bypass",
    "joblib_vectors":                      "Joblib",
    "keras_vectors":                       "Keras / H5",
    "numpy_vectors":                       "NumPy",
    "onnx_vectors":                        "ONNX",
    "openvino_vectors":                    "OpenVINO",
    "paddlepaddle_vectors":                "PaddlePaddle",
    "pickle_vectors":                      "Pickle",
    "pmml_vectors":                        "PMML",
    "pytorch_vectors":                     "PyTorch",
    "safetensors_vectors":                 "SafeTensors",
    "supply_chain_attack_vectors":         "Supply Chain",
    "tensorflow_vectors":                  "TensorFlow",
    "tensorrt_vectors":                    "TensorRT",
    "tflite_vectors":                      "TFLite",
    "xgboost_vectors":                     "XGBoost",
}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class TypeRow:
    vtype:      str
    display:    str
    on_disk:    int
    n_scanned:  int
    n_detected: int
    pct:        str
    full:       bool
    errors:     int
    warnings:   int
    notes:      int


@dataclass
class ReportData:
    sarif_path:    Path
    output_dir:    Path
    total_checks:  int | str
    passed_checks: int | str
    failed_checks: int | str
    n_results:     int
    rows:          list[TypeRow]
    total_disk:    int
    total_scanned: int
    total_detected: int
    overall_pct:   str
    total_errors:  int
    total_warnings: int
    total_notes:   int
    gaps:          dict[str, list[str]] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# URI helpers
# ---------------------------------------------------------------------------

def _parse_uri(uri: str) -> tuple[str, str]:
    """Return (vector_type_folder, top_level_filename) from a SARIF artifact URI."""
    clean = unquote(uri).split(" (")[0].strip()
    file_path = clean.split(":")[0]
    parts = [p for p in file_path.replace("\\", "/").split("/") if p]
    if len(parts) >= 3 and parts[0].startswith("attack_vectors_output"):
        return parts[1], parts[2]
    if len(parts) == 2 and parts[0].startswith("attack_vectors_output"):
        return parts[1], ""
    return "unknown", ""


# ---------------------------------------------------------------------------
# Core builder
# ---------------------------------------------------------------------------

def build_report(sarif_path: Path | str, output_dir: Path | str) -> ReportData:
    """Parse *sarif_path* and *output_dir* and return a :class:`ReportData`."""
    sarif_path = Path(sarif_path)
    output_dir = Path(output_dir)

    with open(sarif_path, encoding="utf-8") as f:
        sarif = json.load(f)

    run       = sarif["runs"][0]
    results   = run.get("results", [])
    artifacts = run.get("artifacts", [])

    # Identify .json files that are wrappers (same stem as a non-JSON sibling)
    json_wrappers: dict[str, set[str]] = defaultdict(set)
    if output_dir.exists():
        for subdir in output_dir.iterdir():
            if not subdir.is_dir():
                continue
            entries = [e for e in subdir.iterdir() if not e.name.endswith(".meta")]
            non_json_stems = {e.stem for e in entries if e.suffix.lower() != ".json"}
            for e in entries:
                if e.suffix.lower() == ".json" and e.stem in non_json_stems:
                    json_wrappers[subdir.name].add(e.name)

    def _skip(vtype: str, fname: str) -> bool:
        return fname.endswith(".meta") or fname in json_wrappers.get(vtype, set())

    # Scanned files per type (from SARIF artifacts table)
    scanned: dict[str, set[str]] = defaultdict(set)
    for art in artifacts:
        uri = art.get("location", {}).get("uri", "")
        if not uri:
            continue
        vtype, fname = _parse_uri(uri)
        if vtype != "unknown" and fname and not _skip(vtype, fname):
            scanned[vtype].add(fname)

    # Detected files and finding severity counts
    detected: dict[str, set[str]] = defaultdict(set)
    finding_counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for result in results:
        level = result.get("level", "note")
        for loc in result.get("locations", []):
            uri = (loc.get("physicalLocation", {})
                     .get("artifactLocation", {})
                     .get("uri", ""))
            if not uri:
                continue
            vtype, fname = _parse_uri(uri)
            if vtype != "unknown" and fname and not _skip(vtype, fname):
                detected[vtype].add(fname)
                finding_counts[vtype][level] += 1

    # Disk counts
    disk_counts: dict[str, int] = {}
    if output_dir.exists():
        for subdir in sorted(output_dir.iterdir()):
            if not subdir.is_dir():
                continue
            entries = [e for e in subdir.iterdir() if not e.name.endswith(".meta")]
            non_json_stems = {e.stem for e in entries if e.suffix.lower() != ".json"}
            items = [
                e for e in entries
                if not (e.suffix.lower() == ".json" and e.stem in non_json_stems)
            ]
            disk_counts[subdir.name] = len(items)

    known_types: set[str] = set(disk_counts.keys()) or set(scanned.keys())
    all_types = sorted(
        t for t in set(list(scanned.keys()) + list(detected.keys()) + list(disk_counts.keys()))
        if t in known_types
    )

    # Build rows
    rows: list[TypeRow] = []
    total_disk = total_scanned = total_detected = 0
    total_findings: dict[str, int] = defaultdict(int)

    for vtype in all_types:
        on_disk    = disk_counts.get(vtype, 0)
        n_scanned  = len(scanned.get(vtype, set()))
        n_detected = len(detected.get(vtype, set()))
        fc         = finding_counts.get(vtype, {})
        base       = n_scanned if n_scanned > 0 else on_disk
        pct        = f"{100 * n_detected / base:.0f}%" if base > 0 else "N/A"

        rows.append(TypeRow(
            vtype=vtype,
            display=DISPLAY.get(vtype, vtype),
            on_disk=on_disk,
            n_scanned=n_scanned,
            n_detected=n_detected,
            pct=pct,
            full=base > 0 and n_detected == base,
            errors=fc.get("error", 0),
            warnings=fc.get("warning", 0),
            notes=fc.get("note", 0),
        ))
        total_disk     += on_disk
        total_scanned  += n_scanned
        total_detected += n_detected
        for k, v in fc.items():
            total_findings[k] += v

    total_base  = total_scanned if total_scanned > 0 else total_disk
    overall_pct = f"{100 * total_detected / total_base:.0f}%" if total_base > 0 else "N/A"

    gaps: dict[str, list[str]] = {}
    for vtype in all_types:
        missed = sorted(scanned.get(vtype, set()) - detected.get(vtype, set()))
        if missed:
            gaps[DISPLAY.get(vtype, vtype)] = missed

    props = run.get("properties", {})
    return ReportData(
        sarif_path=sarif_path,
        output_dir=output_dir,
        total_checks=props.get("totalChecks", "?"),
        passed_checks=props.get("passedChecks", "?"),
        failed_checks=props.get("failedChecks", "?"),
        n_results=len(results),
        rows=rows,
        total_disk=total_disk,
        total_scanned=total_scanned,
        total_detected=total_detected,
        overall_pct=overall_pct,
        total_errors=total_findings.get("error", 0),
        total_warnings=total_findings.get("warning", 0),
        total_notes=total_findings.get("note", 0),
        gaps=gaps,
    )


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------

def render_text(data: ReportData, out: IO[str] = sys.stdout) -> None:
    """Write a plain-text report to *out*."""
    SEP = "─" * 104

    def w(line=""):
        print(line, file=out)

    w()
    w("=" * 104)
    w("  ModelAudit Detection Coverage Report")
    w(f"  SARIF : {data.sarif_path}")
    w(f"  Output: {data.output_dir}")
    w("=" * 104)
    w()
    w(f"  Total checks  : {data.total_checks}")
    w(f"  Passed checks : {data.passed_checks}")
    w(f"  Failed checks : {data.failed_checks}  (findings across all files)")
    w(f"  Total results : {data.n_results}")
    w()
    w(SEP)
    w(
        f"  {'Vector Type':<36}  {'Files on Disk':>14}  {'Scanned':>8}"
        f"  {'w/ Findings':>12}  {'Detection %':>11}  {'Errors':>7}  {'Warnings':>9}  {'Notes':>6}"
    )
    w(SEP)

    for r in data.rows:
        marker = "✓" if r.full else " "
        w(
            f"{marker} {r.display:<36}  {r.on_disk:>14}  {r.n_scanned:>8}"
            f"  {r.n_detected:>12}  {r.pct:>11}  {r.errors:>7}  {r.warnings:>9}  {r.notes:>6}"
        )

    w(SEP)
    w(
        f"  {'TOTAL':<36}  {data.total_disk:>14}  {data.total_scanned:>8}"
        f"  {data.total_detected:>12}  {data.overall_pct:>11}"
        f"  {data.total_errors:>7}  {data.total_warnings:>9}  {data.total_notes:>6}"
    )
    w(SEP)
    w()
    w("  Files with NO findings (potential detection gaps):")
    w(SEP)
    if data.gaps:
        for display, files in data.gaps.items():
            w(f"  {display}:")
            for fname in files:
                w(f"      {fname}")
    else:
        w("  (none — all scanned files triggered at least one finding)")
    w(SEP)
    w()


def render_markdown(data: ReportData, out: IO[str] = sys.stdout) -> None:
    """Write a Markdown report to *out*."""
    from datetime import date

    def w(line=""):
        print(line, file=out)

    w("# ModelAudit Detection Coverage Report")
    w()
    w("| | |")
    w("|---|---|")
    w(f"| **SARIF file** | `{data.sarif_path}` |")
    w(f"| **Attack vectors** | `{data.output_dir}` |")
    w(f"| **Date** | {date.today()} |")
    w()
    w("## Summary")
    w()
    w("| Metric | Count |")
    w("|---|---:|")
    w(f"| Total checks | {data.total_checks} |")
    w(f"| Passed checks | {data.passed_checks} |")
    w(f"| Failed checks (findings) | {data.failed_checks} |")
    w(f"| Total SARIF results | {data.n_results} |")
    w()
    w("## Detection Coverage by Vector Type")
    w()
    w("| Vector Type | Files on Disk | Scanned | w/ Findings | Detection % | Errors | Warnings | Notes |")
    w("|---|---:|---:|---:|---:|---:|---:|---:|")

    for r in data.rows:
        badge = " ✅" if r.full else (" ❌" if r.n_detected == 0 else "")
        w(
            f"| {r.display}{badge} | {r.on_disk} | {r.n_scanned} |"
            f" {r.n_detected} | {r.pct} | {r.errors} | {r.warnings} | {r.notes} |"
        )

    w(
        f"| **TOTAL** | **{data.total_disk}** | **{data.total_scanned}** |"
        f" **{data.total_detected}** | **{data.overall_pct}** |"
        f" **{data.total_errors}** | **{data.total_warnings}** | **{data.total_notes}** |"
    )
    w()
    w("## Detection Gaps (Files with No Findings)")
    w()
    if data.gaps:
        for display, files in data.gaps.items():
            w(f"### {display}")
            w()
            for fname in files:
                w(f"- `{fname}`")
            w()
    else:
        w("All scanned files triggered at least one finding.")
        w()


def write_report(data: ReportData, path: Path | str) -> None:
    """Write *data* to *path*. Format is inferred from the file extension (.md → Markdown)."""
    path = Path(path)
    with open(path, "w", encoding="utf-8") as f:
        if path.suffix.lower() == ".md":
            render_markdown(data, out=f)
        else:
            render_text(data, out=f)
    print(f"Report written to: {path}")
