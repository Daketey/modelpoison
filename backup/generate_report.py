#!/usr/bin/env python3
# Backward-compatible shim — prefer: modelpoison report ...
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from modelpoison.cli import main as _main
argv = ["report"]
if len(sys.argv) > 1: argv += ["--sarif",   sys.argv[1]]
if len(sys.argv) > 2: argv += ["--vectors", sys.argv[2]]
if len(sys.argv) > 3: argv += ["--output",  sys.argv[3]]
_main(argv)

"""--- original source preserved below for reference ---

ModelAudit Detection Coverage Report

Reads a SARIF file produced by ModelAudit and the attack_vectors_output
directory to produce a per-vector-type detection coverage report.

Usage:
    python generate_report.py [sarif_file] [attack_vectors_dir] [output_file]

    Output format is inferred from the file extension:
        report.txt  → plain text
        report.md   → Markdown

Defaults:
    sarif_file          = modelaudit.json
    attack_vectors_dir  = attack_vectors_output
    output_file         = stdout (plain text)
"""

import json
import sys
from collections import defaultdict
from pathlib import Path
from urllib.parse import unquote


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_uri(uri: str) -> tuple[str, str]:
    """Return (vector_type_folder, top_level_filename) from a SARIF artifact URI.

    ModelAudit URI formats:
      - Standard:   attack_vectors_output/pytorch_vectors/01_foo.pt (pos 42)
      - Sub-member: attack_vectors_output/archive_vectors/01_foo.zip:../traversal/path
      - Sub-member: attack_vectors_output/pytorch_vectors/02_bar.pt:archive/data.pkl C:/... (pos 2)

    The colon separates the outer file from the archive member path.
    """
    clean = unquote(uri)
    # Strip absolute path repetition + ' (pos N)' suffix that ModelAudit may append
    clean = clean.split(" (")[0].strip()
    # Strip archive-member portion (colon-separated); take the outer file path only
    file_path = clean.split(":")[0]
    # Normalise separators and split
    parts = [p for p in file_path.replace("\\", "/").split("/") if p]
    # Expected layout: ['attack_vectors_output', '<type>_vectors', '<filename>', ...]
    if len(parts) >= 3 and parts[0].startswith("attack_vectors_output"):
        return parts[1], parts[2]
    if len(parts) == 2 and parts[0].startswith("attack_vectors_output"):
        return parts[1], ""
    return "unknown", ""


def _vector_type(uri: str) -> str:
    return _parse_uri(uri)[0]


def _filename(uri: str) -> str:
    return _parse_uri(uri)[1]


# ---------------------------------------------------------------------------
# Human-friendly display names
# ---------------------------------------------------------------------------
DISPLAY = {
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
# Main
# ---------------------------------------------------------------------------

def main():
    sarif_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("modelaudit.json")
    output_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("attack_vectors_output")
    out_file   = Path(sys.argv[3]) if len(sys.argv) > 3 else None

    use_markdown = out_file is not None and out_file.suffix.lower() == ".md"

    # --- Load SARIF ----------------------------------------------------------
    with open(sarif_path, encoding="utf-8") as f:
        sarif = json.load(f)

    run = sarif["runs"][0]
    results = run.get("results", [])
    artifacts = run.get("artifacts", [])

    # Pre-compute which .json filenames are mere wrappers (same stem as a non-JSON file).
    # Used to exclude them from scanned/detected counts.
    json_wrappers: dict[str, set[str]] = defaultdict(set)  # vtype -> set of wrapper filenames
    if output_dir.exists():
        for subdir in output_dir.iterdir():
            if not subdir.is_dir():
                continue
            entries = [e for e in subdir.iterdir() if not e.name.endswith(".meta")]
            stems_with_other = {e.stem for e in entries if e.suffix.lower() != ".json"}
            for e in entries:
                if e.suffix.lower() == ".json" and e.stem in stems_with_other:
                    json_wrappers[subdir.name].add(e.name)

    def _is_wrapper(vtype: str, fname: str) -> bool:
        return fname in json_wrappers.get(vtype, set())

    # Build a set of all scanned files per vector type from the artifacts table
    # (ground truth for what ModelAudit actually opened)
    # Exclude .meta sidecar files and .json wrappers — not real attack vectors.
    scanned: dict[str, set[str]] = defaultdict(set)
    for art in artifacts:
        uri = art.get("location", {}).get("uri", "")
        if not uri:
            continue
        vtype, fname = _parse_uri(uri)
        if vtype != "unknown" and fname and not fname.endswith(".meta") and not _is_wrapper(vtype, fname):
            scanned[vtype].add(fname)

    # Build a set of files that triggered at least one finding per vector type
    detected: dict[str, set[str]] = defaultdict(set)
    finding_counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))

    for result in results:
        level = result.get("level", "note")
        locs = result.get("locations", [])
        for loc in locs:
            uri = loc.get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")
            if not uri:
                continue
            vtype = _vector_type(uri)
            fname = _filename(uri)
            if vtype != "unknown" and fname and not fname.endswith(".meta") and not _is_wrapper(vtype, fname):
                detected[vtype].add(fname)
                finding_counts[vtype][level] += 1

    # Count attack-vector items on disk (ground truth)
    # Exclude .meta sidecars and .json files that are just wrappers for a
    # same-stem file of a different type (e.g. jinja2 .json alongside .j2).
    disk_counts: dict[str, int] = {}
    if output_dir.exists():
        for subdir in sorted(output_dir.iterdir()):
            if not subdir.is_dir():
                continue
            all_entries = [e for e in subdir.iterdir() if not e.name.endswith(".meta")]
            stems_with_other = {
                e.stem for e in all_entries if e.suffix.lower() != ".json"
            }
            items = [
                e for e in all_entries
                if not (e.suffix.lower() == ".json" and e.stem in stems_with_other)
            ]
            disk_counts[subdir.name] = len(items)

    # Build unified type list restricted to real output directories
    known_types: set[str] = set(disk_counts.keys()) or set(scanned.keys())
    all_types = sorted(
        t for t in set(list(scanned.keys()) + list(detected.keys()) + list(disk_counts.keys()))
        if t in known_types
    )

    # Pre-compute per-type row data
    summary_props = run.get("properties", {})
    total_checks  = summary_props.get("totalChecks",  "?")
    passed_checks = summary_props.get("passedChecks", "?")
    failed_checks = summary_props.get("failedChecks", "?")

    rows = []
    total_disk = total_scanned = total_detected = 0
    total_findings: dict[str, int] = defaultdict(int)

    for vtype in all_types:
        display    = DISPLAY.get(vtype, vtype)
        on_disk    = disk_counts.get(vtype, 0)
        n_scanned  = len(scanned.get(vtype, set()))
        n_detected = len(detected.get(vtype, set()))
        fc         = finding_counts.get(vtype, {})
        base       = n_scanned if n_scanned > 0 else on_disk
        pct        = f"{100 * n_detected / base:.0f}%" if base > 0 else "N/A"
        full       = base > 0 and n_detected == base

        rows.append({
            "vtype": vtype, "display": display, "on_disk": on_disk,
            "n_scanned": n_scanned, "n_detected": n_detected,
            "pct": pct, "full": full,
            "errors": fc.get("error", 0), "warnings": fc.get("warning", 0),
            "notes": fc.get("note", 0),
        })
        total_disk     += on_disk
        total_scanned  += n_scanned
        total_detected += n_detected
        for k, v in fc.items():
            total_findings[k] += v

    total_base  = total_scanned if total_scanned > 0 else total_disk
    overall_pct = f"{100 * total_detected / total_base:.0f}%" if total_base > 0 else "N/A"

    # Undetected files per type
    gaps: dict[str, list[str]] = {}
    for vtype in all_types:
        missed = sorted(scanned.get(vtype, set()) - detected.get(vtype, set()))
        if missed:
            gaps[DISPLAY.get(vtype, vtype)] = missed

    # --- Render --------------------------------------------------------------
    out_stream = open(out_file, "w", encoding="utf-8") if out_file else sys.stdout

    def w(line=""):
        print(line, file=out_stream)

    if use_markdown:
        _render_markdown(
            w, sarif_path, output_dir,
            total_checks, passed_checks, failed_checks, len(results),
            rows,
            total_disk, total_scanned, total_detected, overall_pct, total_findings,
            gaps,
        )
    else:
        _render_text(
            w, sarif_path, output_dir,
            total_checks, passed_checks, failed_checks, len(results),
            rows,
            total_disk, total_scanned, total_detected, overall_pct, total_findings,
            gaps,
        )

    if out_file:
        out_stream.close()
        print(f"Report written to: {out_file}")


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------

def _render_text(w, sarif_path, output_dir,
                 total_checks, passed_checks, failed_checks, n_results,
                 rows, total_disk, total_scanned, total_detected, overall_pct,
                 total_findings, gaps):
    SEP = "─" * 104
    w()
    w("=" * 104)
    w("  ModelAudit Detection Coverage Report")
    w(f"  SARIF : {sarif_path}")
    w(f"  Output: {output_dir}")
    w("=" * 104)
    w()
    w(f"  Total checks  : {total_checks}")
    w(f"  Passed checks : {passed_checks}")
    w(f"  Failed checks : {failed_checks}  (findings across all files)")
    w(f"  Total results : {n_results}")
    w()
    w(SEP)
    w(
        f"  {'Vector Type':<36}  {'Files on Disk':>14}  {'Scanned':>8}"
        f"  {'w/ Findings':>12}  {'Detection %':>11}  {'Errors':>7}  {'Warnings':>9}  {'Notes':>6}"
    )
    w(SEP)

    for r in rows:
        marker = "✓" if r["full"] else " "
        w(
            f"{marker} {r['display']:<36}  {r['on_disk']:>14}  {r['n_scanned']:>8}"
            f"  {r['n_detected']:>12}  {r['pct']:>11}  {r['errors']:>7}  {r['warnings']:>9}  {r['notes']:>6}"
        )

    w(SEP)
    w(
        f"  {'TOTAL':<36}  {total_disk:>14}  {total_scanned:>8}"
        f"  {total_detected:>12}  {overall_pct:>11}"
        f"  {total_findings.get('error',0):>7}"
        f"  {total_findings.get('warning',0):>9}"
        f"  {total_findings.get('note',0):>6}"
    )
    w(SEP)
    w()
    w("  Files with NO findings (potential detection gaps):")
    w(SEP)
    if gaps:
        for display, files in gaps.items():
            w(f"  {display}:")
            for fname in files:
                w(f"      {fname}")
    else:
        w("  (none — all scanned files triggered at least one finding)")
    w(SEP)
    w()


def _render_markdown(w, sarif_path, output_dir,
                     total_checks, passed_checks, failed_checks, n_results,
                     rows, total_disk, total_scanned, total_detected, overall_pct,
                     total_findings, gaps):
    from datetime import date
    w("# ModelAudit Detection Coverage Report")
    w()
    w(f"| | |")
    w(f"|---|---|")
    w(f"| **SARIF file** | `{sarif_path}` |")
    w(f"| **Attack vectors** | `{output_dir}` |")
    w(f"| **Date** | {date.today()} |")
    w()
    w("## Summary")
    w()
    w("| Metric | Count |")
    w("|---|---:|")
    w(f"| Total checks | {total_checks} |")
    w(f"| Passed checks | {passed_checks} |")
    w(f"| Failed checks (findings) | {failed_checks} |")
    w(f"| Total SARIF results | {n_results} |")
    w()
    w("## Detection Coverage by Vector Type")
    w()
    w("| Vector Type | Files on Disk | Scanned | w/ Findings | Detection % | Errors | Warnings | Notes |")
    w("|---|---:|---:|---:|---:|---:|---:|---:|")

    for r in rows:
        badge = " ✅" if r["full"] else (" ❌" if r["n_detected"] == 0 else "")
        w(
            f"| {r['display']}{badge} | {r['on_disk']} | {r['n_scanned']} |"
            f" {r['n_detected']} | {r['pct']} | {r['errors']} | {r['warnings']} | {r['notes']} |"
        )

    w(f"| **TOTAL** | **{total_disk}** | **{total_scanned}** |"
      f" **{total_detected}** | **{overall_pct}** |"
      f" **{total_findings.get('error',0)}** |"
      f" **{total_findings.get('warning',0)}** |"
      f" **{total_findings.get('note',0)}** |")
    w()
    w("## Detection Gaps (Files with No Findings)")
    w()
    if gaps:
        for display, files in gaps.items():
            w(f"### {display}")
            w()
            for fname in files:
                w(f"- `{fname}`")
            w()
    else:
        w("All scanned files triggered at least one finding.")
        w()


if __name__ == "__main__":
    main()

