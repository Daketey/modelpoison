"""
modelpoison.cli
~~~~~~~~~~~~~~~

Unified command-line interface.

Commands
--------
modelpoison generate   Generate ML attack vectors
modelpoison report     Parse a ModelAudit SARIF and produce a coverage report

Usage
-----
modelpoison generate [--output DIR] [--only GEN ...] [--report] [--markdown]
modelpoison report   [SARIF] [OUTPUT_DIR] [REPORT_FILE]
modelpoison report   --sarif modelaudit.json --vectors ./out --output report.md
"""

from __future__ import annotations

import argparse
import importlib
import json
import sys
from datetime import datetime
from pathlib import Path


# ---------------------------------------------------------------------------
# Helpers shared with the generate sub-command
# ---------------------------------------------------------------------------

def _load_generator(module_name: str, class_name: str, output_dir: str):
    try:
        module = importlib.import_module(module_name)
        cls = getattr(module, class_name)
        return cls(output_dir=output_dir), None
    except ImportError as e:
        return None, f"Import error: {e}"
    except AttributeError as e:
        return None, f"Attribute error: {e}"
    except Exception as e:
        return None, f"Unexpected error: {e}"


def _run_generator(gen_name: str, generator) -> tuple[int, list[str]]:
    errors: list[str] = []
    try:
        print(f"\n[->] {gen_name.upper()} Attack Vectors")
        print("  " + "-" * 50)
        results = generator.generate_all()
        for attack_name, (filepath, metric) in results.items():
            status = "[+]" if filepath else "[-]"
            print(f"  {status} {attack_name:25} ({metric})")
        generated = generator.get_generated_files()
        print(f"  -> Files created: {len(generated)}")
        if hasattr(generator, "execution_log"):
            for msg in generator.execution_log[:3]:
                print(f"     [*] {msg}")
        return len(generated), errors
    except Exception as exc:
        msg = f"Error in {gen_name}: {exc}"
        print(f"  [ERROR] {msg}")
        return 0, [msg]


# Registry of all available generators:  name -> (module, class)
GENERATORS: dict[str, tuple[str, str]] = {
    "pickle":                     ("generators.pickle_vectors",                     "PickleAttackGenerator"),
    "archive":                    ("generators.archive_vectors",                    "ArchiveAttackGenerator"),
    "keras":                      ("generators.keras_vectors",                      "KerasAttackGenerator"),
    "gguf":                       ("generators.gguf_vectors",                       "GGUFAttackGenerator"),
    "pytorch":                    ("generators.pytorch_vectors",                    "PyTorchAttackGenerator"),
    "numpy":                      ("generators.numpy_vectors",                      "NumPyAttackGenerator"),
    "tensorflow":                 ("generators.tensorflow_vectors",                 "TensorFlowAttackGenerator"),
    "onnx":                       ("generators.onnx_vectors",                       "ONNXAttackGenerator"),
    "safetensors":                ("generators.safetensors_vectors",                "SafeTensorsAttackGenerator"),
    "flax_jax":                   ("generators.flax_jax_vectors",                   "FlaxJAXAttackGenerator"),
    "tflite":                     ("generators.tflite_vectors",                     "TFLiteAttackGenerator"),
    "tensorrt":                   ("generators.tensorrt_vectors",                   "TensorRTAttackGenerator"),
    "joblib":                     ("generators.joblib_vectors",                     "JoblibAttackGenerator"),
    "pmml":                       ("generators.pmml_vectors",                       "PMMLAttackGenerator"),
    "xgboost":                    ("generators.xgboost_vectors",                    "XGBoostAttackGenerator"),
    "paddlepaddle":               ("generators.paddlepaddle_vectors",               "PaddlePaddleAttackGenerator"),
    "openvino":                   ("generators.openvino_vectors",                   "OpenVINOAttackGenerator"),
    "advanced_pickle_obfuscation":("generators.advanced_pickle_obfuscation_vectors","AdvancedPickleObfuscationGenerator"),
    "jinja2_bypass":              ("generators.jinja2_bypass_vectors",              "Jinja2BypassGenerator"),
    "supply_chain":               ("generators.supply_chain_attack_vectors",        "SupplyChainAttackGenerator"),
    "advanced_weight_poisoning":  ("generators.advanced_weight_poisoning_vectors",  "AdvancedWeightPoisoningGenerator"),
}


# ---------------------------------------------------------------------------
# Sub-command: generate
# ---------------------------------------------------------------------------

def cmd_generate(args: argparse.Namespace) -> int:
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    print("\n" + "=" * 70)
    print("ML ATTACK VECTOR GENERATOR".center(70))
    print("=" * 70)
    print(f"\nOutput Directory : {output_dir.absolute()}")
    print(f"Generated        : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    registry = GENERATORS.copy()

    if args.only:
        unknown = [g for g in args.only if g not in registry]
        if unknown:
            print(f"[ERROR] Unknown generator(s): {', '.join(unknown)}")
            print(f"        Available: {', '.join(registry)}")
            return 1
        registry = {k: v for k, v in registry.items() if k in args.only}

    print("[*] Loading generators...")
    loaded: dict[str, object] = {}
    total_errors = 0

    for name, (module, cls) in registry.items():
        gen, err = _load_generator(module, cls, str(output_dir))
        if gen:
            loaded[name] = gen
            print(f"  [OK] {name}")
        else:
            print(f"  [!] {name}: {err}")
            total_errors += 1

    print(f"\n[+] Loaded {len(loaded)} / {len(registry)} generators\n")
    if not loaded:
        print("[ERROR] No generators could be loaded!")
        return 1

    print("[*] Generating attack vectors...\n")
    results: dict[str, dict] = {}
    total_files = 0

    for name, gen in loaded.items():
        count, errors = _run_generator(name, gen)
        results[name] = {"files": count, "errors": errors}
        total_files  += count
        total_errors += len(errors)

    # Summary
    print("\n" + "=" * 70)
    print("GENERATION SUMMARY".center(70))
    print("=" * 70 + "\n")
    for name, res in results.items():
        status = "[OK]" if res["files"] > 0 else "[FAIL]"
        print(f"  {status} {name.upper():30} {res['files']} files")
    print(f"\n  Total files : {total_files}")
    print(f"  Errors      : {total_errors}")
    print(f"  Output      : {output_dir.absolute()}\n")

    report_data = {
        "metadata": {
            "generated_at": datetime.now().isoformat(),
            "version": "1.0.0",
            "output_directory": str(output_dir),
            "total_files": total_files,
            "total_errors": total_errors,
        },
        "results": results,
    }

    if args.report:
        rp = output_dir / "attack_vector_report.json"
        rp.write_text(json.dumps(report_data, indent=2))
        print(f"[+] JSON report saved to: {rp}")

    if args.markdown:
        _write_generation_markdown(report_data, output_dir / "ATTACK_VECTORS_REPORT.md")

    print("=" * 70)
    print("[OK] Attack vector generation complete!".center(70))
    print("=" * 70 + "\n")
    return 0 if total_errors == 0 else 1


def _write_generation_markdown(data: dict, path: Path) -> None:
    meta = data["metadata"]
    lines = [
        "# ML Attack Vector Generation Report",
        "",
        f"**Generated:** {meta['generated_at']}",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Total files | {meta['total_files']} |",
        f"| Errors | {meta['total_errors']} |",
        "",
        "## Results",
        "",
        "| Generator | Files | Errors |",
        "|---|---:|---:|",
    ]
    for name, res in data["results"].items():
        lines.append(f"| {name} | {res['files']} | {len(res['errors'])} |")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[+] Markdown saved to: {path}")


# ---------------------------------------------------------------------------
# Sub-command: report
# ---------------------------------------------------------------------------

def cmd_report(args: argparse.Namespace) -> int:
    from modelpoison.report import build_report, write_report, render_text

    sarif_path = Path(args.sarif)
    output_dir = Path(args.vectors)

    if not sarif_path.exists():
        print(f"[ERROR] SARIF file not found: {sarif_path}", file=sys.stderr)
        return 1

    data = build_report(sarif_path, output_dir)

    if args.output:
        write_report(data, Path(args.output))
    else:
        render_text(data)

    return 0


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="modelpoison",
        description="ML attack vector generator and ModelAudit coverage reporter",
    )
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    sub.required = True

    # --- generate -----------------------------------------------------------
    gen_p = sub.add_parser(
        "generate",
        help="Generate ML attack vector files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Available generators:\n  "
            + "\n  ".join(sorted(GENERATORS))
        ),
    )
    gen_p.add_argument(
        "--output", "-o",
        default="./attack_vectors_output",
        metavar="DIR",
        help="Output directory (default: ./attack_vectors_output)",
    )
    gen_p.add_argument(
        "--only",
        nargs="+",
        metavar="GEN",
        help="Run only the listed generator(s)",
    )
    gen_p.add_argument(
        "--report", "-r",
        action="store_true",
        help="Save a JSON generation report inside the output directory",
    )
    gen_p.add_argument(
        "--markdown", "-m",
        action="store_true",
        help="Save a Markdown generation report inside the output directory",
    )

    # --- report -------------------------------------------------------------
    rep_p = sub.add_parser(
        "report",
        help="Parse a ModelAudit SARIF and produce a detection coverage report",
    )
    rep_p.add_argument(
        "--sarif", "-s",
        default="scanner_reports/modelaudit/modelaudit.json",
        metavar="FILE",
        help="ModelAudit SARIF file (default: scanner_reports/modelaudit/modelaudit.json)",
    )
    rep_p.add_argument(
        "--vectors", "-v",
        default="attack_vectors_output",
        metavar="DIR",
        help="Attack vectors output directory (default: attack_vectors_output)",
    )
    rep_p.add_argument(
        "--output", "-o",
        metavar="FILE",
        help=(
            "Write report to this file instead of stdout. "
            "Extension determines format: .md → Markdown, anything else → plain text."
        ),
    )

    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> None:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "generate":
        sys.exit(cmd_generate(args))
    elif args.command == "report":
        sys.exit(cmd_report(args))
