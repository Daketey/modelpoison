
# Backward-compatible shim — prefer: modelpoison generate ...
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from modelpoison.cli import main as _main
_main(["generate"] + sys.argv[1:])

import sys
import os
import json
import importlib
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple

# Add current directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))


def load_generator(module_name: str, generator_class: str, output_dir: str):
    """Safely load a generator module.
    
    Args:
        module_name: Name of module to import (e.g., 'generators.pickle_vectors')
        generator_class: Name of generator class
        output_dir: Output directory path
        
    Returns:
        Tuple of (generator_instance, error_message or None)
    """
    try:
        module = importlib.import_module(module_name)
        cls = getattr(module, generator_class)
        instance = cls(output_dir=output_dir)
        return instance, None
    except ImportError as e:
        return None, f"Import error: {e}"
    except AttributeError as e:
        return None, f"Attribute error: {e}"
    except Exception as e:
        return None, f"Unexpected error: {e}"


def run_generator(gen_name: str, generator, generator_config: Dict) -> Tuple[int, List[str]]:
    """Run a single generator and collect results.
    
    Args:
        gen_name: Name of generator for display
        generator: Generator instance
        generator_config: Configuration dict
        
    Returns:
        Tuple of (file_count, error_messages)
    """
    errors = []
    file_count = 0
    
    try:
        print(f"\n[->] {gen_name.upper()} Attack Vectors")
        print("  " + "-" * 50)
        
        results = generator.generate_all()
        
        for attack_name, (filepath, metric) in results.items():
            status = "[+]" if filepath else "[-]"
            print(f"  {status} {attack_name:25} ({metric})")
            file_count += 1
        
        generated_files = generator.get_generated_files()
        print(f"  -> Files created: {len(generated_files)}")
        
        # Log generator status if available
        if hasattr(generator, 'execution_log'):
            for log_msg in generator.execution_log[:3]:  # Show first 3 log messages
                print(f"     [*] {log_msg}")
        
        return len(generated_files), errors
        
    except Exception as e:
        error_msg = f"Error in {gen_name}: {str(e)}"
        print(f"  [ERROR] {error_msg}")
        errors.append(error_msg)
        return 0, errors


def main():
    """Main entry point.
    
    Returns:
        Exit code (0 for success, 1 for errors)
    """
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Generate ML attack vectors for security testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python generate_attack_vectors.py
  python generate_attack_vectors.py --output ./vectors
  python generate_attack_vectors.py --report --markdown
        """
    )
    
    parser.add_argument(
        "--output", "-o",
        default="./attack_vectors_output",
        help="Output directory (default: ./attack_vectors_output)"
    )
    parser.add_argument(
        "--report", "-r",
        action="store_true",
        help="Save JSON report"
    )
    parser.add_argument(
        "--markdown", "-m",
        action="store_true",
        help="Save markdown report"
    )
    parser.add_argument(
        "--only",
        metavar="GENERATOR",
        nargs="+",
        help="Run only the specified generator(s), e.g. --only tensorflow pickle"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output"
    )
    
    args = parser.parse_args()
    
    # Create output directory
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    print("\n" + "="*70)
    print("ML ATTACK VECTOR GENERATOR".center(70))
    print("="*70)
    print(f"\nOutput Directory: {output_dir.absolute()}")
    print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    # Define generators to load
    generators_config = {
        'pickle': ('generators.pickle_vectors', 'PickleAttackGenerator'),
        'archive': ('generators.archive_vectors', 'ArchiveAttackGenerator'),
        'keras': ('generators.keras_vectors', 'KerasAttackGenerator'),
        'gguf': ('generators.gguf_vectors', 'GGUFAttackGenerator'),
        'pytorch': ('generators.pytorch_vectors', 'PyTorchAttackGenerator'),
        'numpy': ('generators.numpy_vectors', 'NumPyAttackGenerator'),
        'tensorflow': ('generators.tensorflow_vectors', 'TensorFlowAttackGenerator'),
        'onnx': ('generators.onnx_vectors', 'ONNXAttackGenerator'),
        'safetensors': ('generators.safetensors_vectors', 'SafeTensorsAttackGenerator'),
        'flax_jax': ('generators.flax_jax_vectors', 'FlaxJAXAttackGenerator'),
        'tflite': ('generators.tflite_vectors', 'TFLiteAttackGenerator'),
        'tensorrt': ('generators.tensorrt_vectors', 'TensorRTAttackGenerator'),
        'joblib': ('generators.joblib_vectors', 'JoblibAttackGenerator'),
        'pmml': ('generators.pmml_vectors', 'PMMLAttackGenerator'),
        'xgboost': ('generators.xgboost_vectors', 'XGBoostAttackGenerator'),
        'paddlepaddle': ('generators.paddlepaddle_vectors', 'PaddlePaddleAttackGenerator'),
        'openvino': ('generators.openvino_vectors', 'OpenVINOAttackGenerator'),
        'advanced_pickle_obfuscation': ('generators.advanced_pickle_obfuscation_vectors', 'AdvancedPickleObfuscationGenerator'),
        'jinja2_bypass': ('generators.jinja2_bypass_vectors', 'Jinja2BypassGenerator'),
        'supply_chain': ('generators.supply_chain_attack_vectors', 'SupplyChainAttackGenerator'),
        'advanced_weight_poisoning': ('generators.advanced_weight_poisoning_vectors', 'AdvancedWeightPoisoningGenerator'),
    }
    
    # Load and run generators
    results = {}
    total_files = 0
    total_errors = 0
    
    # Filter generators if --only was specified
    if args.only:
        unknown = [g for g in args.only if g not in generators_config]
        if unknown:
            print(f"[ERROR] Unknown generator(s): {', '.join(unknown)}")
            print(f"        Available: {', '.join(generators_config)}")
            return 1
        generators_config = {k: v for k, v in generators_config.items() if k in args.only}
    
    print("[*] Loading generators...")
    loaded_generators = {}
    
    for gen_name, (module_name, class_name) in generators_config.items():
        gen, error = load_generator(module_name, class_name, str(output_dir))
        
        if gen:
            loaded_generators[gen_name] = gen
            print(f"  [OK] {gen_name} generator loaded")
        else:
            print(f"  [!] {gen_name} generator failed: {error}")
            total_errors += 1
    
    print(f"\n[+] Successfully loaded {len(loaded_generators)} generators\n")
    
    if not loaded_generators:
        print("[ERROR] No generators could be loaded!")
        return 1
    
    # Run generators
    print("[*] Generating attack vectors...\n")
    
    generator_status = {}  # Track dependency status per generator
    
    for gen_name, generator in loaded_generators.items():
        file_count, errors = run_generator(gen_name, generator, generators_config[gen_name])
        results[gen_name] = {
            'files': file_count,
            'errors': errors,
        }
        
        # Capture generator-specific status (e.g., TensorFlow availability)
        status = {
            'loaded': True,
            'execution_logs': []
        }
        
        if hasattr(generator, 'execution_log'):
            status['execution_logs'] = generator.execution_log
        
        if hasattr(generator, 'artifact_kind'):
            status['artifact_kind'] = generator.artifact_kind
        
        if hasattr(generator, 'tf_available'):
            status['tf_available'] = generator.tf_available
        
        generator_status[gen_name] = status
        total_files += file_count
        total_errors += len(errors)
    
    # Print summary
    print("\n" + "="*70)
    print("GENERATION SUMMARY".center(70))
    print("="*70 + "\n")
    
    print("Attack Vector Summary:")
    for gen_name, gen_results in results.items():
        status = "[OK]" if gen_results['files'] > 0 else "[FAIL]"
        print(f"  {status} {gen_name.upper():15} - {gen_results['files']} files generated")
    
    print(f"\nTotal Files Generated: {total_files}")
    print(f"Errors Encountered: {total_errors}")
    print(f"Output Directory: {output_dir.absolute()}\n")
    
    # Save reports
    report_data = {
        "metadata": {
            "generated_at": datetime.now().isoformat(),
            "version": "2.0.0",
            "output_directory": str(output_dir),
            "total_files": total_files,
            "total_errors": total_errors,
            "generators_loaded": len(loaded_generators),
            "note": "Includes artifact_kind (native/metadata) and validation_status for each generator"
        },
        "results": results,
        "generator_status": generator_status,
    }
    
    if args.report:
        report_path = output_dir / "attack_vector_report.json"
        with open(report_path, 'w') as f:
            json.dump(report_data, f, indent=2)
        print(f"[+] JSON report saved to: {report_path}")
    
    if args.markdown:
        md_path = output_dir / "ATTACK_VECTORS_REPORT.md"
        
        md_content = f"""# ML Attack Vector Generation Report

**Generated:** {report_data['metadata']['generated_at']}

**Summary:**
- Total Files: {report_data['metadata']['total_files']}
- Generators: {report_data['metadata']['generators_loaded']}
- Errors: {report_data['metadata']['total_errors']}

**Note:** {report_data['metadata']['note']}

## Generator Dependency Status

| Generator | Status | Artifact Kind | Details |
|-----------|--------|---------------|---------|
"""
        for gen_name, status in report_data.get('generator_status', {}).items():
            artifact_kind = status.get('artifact_kind', 'unknown')
            tf_available = status.get('tf_available', 'N/A')
            logs = ' '.join(status.get('execution_logs', [])[:1])  # First log line
            md_content += f"| {gen_name} | OK | {artifact_kind} | {logs} |\n"
        
        md_content += "\n## Attack Vector Results\n"
        
        for gen_name, gen_results in results.items():
            md_content += f"\n### {gen_name.upper()}\n"
            md_content += f"- Files Generated: {gen_results['files']}\n"
            if gen_results['errors']:
                md_content += f"- Errors: {len(gen_results['errors'])}\n"
                for error in gen_results['errors']:
                    md_content += f"  - {error}\n"
        
        
        with open(md_path, 'w') as f:
            f.write(md_content)
        print(f"[+] Markdown report saved to: {md_path}")
    
    print("\n" + "="*70)
    print("[OK] Attack vector generation complete!".center(70))
    print("="*70 + "\n")
    
    return 0 if total_errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
