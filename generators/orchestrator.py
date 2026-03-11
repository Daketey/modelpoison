"""
ML Attack Vector Orchestrator

Coordinates generation of all attack vector types and produces
unified report with counts, metrics, and organization.

This serves as the main entry point for the attack vector generation system.
"""

import sys
import json
from pathlib import Path
from typing import Dict, List, Tuple
from datetime import datetime


class AttackVectorOrchestrator:
    """Orchestrates all attack vector generators."""
    
    def __init__(self, output_dir: str = "./output"):
        """Initialize the orchestrator.
        
        Args:
            output_dir: Base output directory for all vectors
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.generators = {}
        self.results = {}
        self.total_files = 0
    
    def _load_generators(self):
        """Load all available generator modules."""
        generators_to_load = [
            ('pickle', 'pickle_vectors.PickleAttackGenerator'),
            ('archive', 'archive_vectors.ArchiveAttackGenerator'),
            ('config', 'config_vectors.ConfigurationAttackGenerator'),
            ('keras', 'keras_vectors.KerasAttackGenerator'),
            ('gguf', 'gguf_vectors.GGUFAttackGenerator'),
            ('pytorch', 'pytorch_vectors.PyTorchAttackGenerator'),
            ('numpy', 'numpy_vectors.NumPyAttackGenerator'),
            ('tensorflow', 'tensorflow_vectors.TensorFlowAttackGenerator'),
            ('onnx', 'onnx_vectors.ONNXAttackGenerator'),
            ('safetensors', 'safetensors_vectors.SafeTensorsAttackGenerator'),
            ('flax_jax', 'flax_jax_vectors.FlaxJAXAttackGenerator'),
            ('tflite', 'tflite_vectors.TFLiteAttackGenerator'),
            ('tensorrt', 'tensorrt_vectors.TensorRTAttackGenerator'),
            ('joblib', 'joblib_vectors.JoblibAttackGenerator'),
            ('pmml', 'pmml_vectors.PMMLAttackGenerator'),
            ('xgboost', 'xgboost_vectors.XGBoostAttackGenerator'),
            ('paddlepaddle', 'paddlepaddle_vectors.PaddlePaddleAttackGenerator'),
            ('openvino', 'openvino_vectors.OpenVINOAttackGenerator'),
            ('advanced_pickle_obfuscation', 'advanced_pickle_obfuscation_vectors.AdvancedPickleObfuscationGenerator'),
            ('jinja2_bypass', 'jinja2_bypass_vectors.Jinja2BypassGenerator'),
            ('supply_chain', 'supply_chain_attack_vectors.SupplyChainAttackGenerator'),
            ('advanced_weight_poisoning', 'advanced_weight_poisoning_vectors.AdvancedWeightPoisoningGenerator'),
        ]
        
        for gen_name, module_class in generators_to_load:
            try:
                parts = module_class.split('.')
                module_name = parts[0]
                class_name = parts[1]
                
                # Dynamically import the module
                module = __import__(module_name)
                cls = getattr(module, class_name)
                self.generators[gen_name] = cls(str(self.output_dir))
            except Exception as e:
                print(f"[WARNING] Failed to load {gen_name} generator: {e}")
    
    def generate_all(self) -> Dict:
        """Generate all attack vectors.
        
        Returns:
            Comprehensive results dictionary
        """
        print("\n" + "="*60)
        print("ML ATTACK VECTOR GENERATOR - Orchestrator".center(60))
        print("="*60 + "\n")
        
        # Load generators
        print("[*] Loading attack vector generators...")
        self._load_generators()
        print(f"[+] Loaded {len(self.generators)} generator modules\n")
        
        # Generate attack vectors
        print("[*] Generating attack vectors...\n")
        
        for gen_name, generator in self.generators.items():
            print(f"[→] {gen_name.upper()} vectors:")
            try:
                gen_results = generator.generate_all()
                self.results[gen_name] = {}
                
                for attack_name, (filepath, metric) in gen_results.items():
                    print(f"    ✓ {attack_name:25} → {Path(filepath).name:40} ({metric})")
                    self.results[gen_name][attack_name] = {
                        'filepath': str(filepath),
                        'metric': metric,
                    }
                
                files = generator.get_generated_files()
                self.total_files += len(files)
                print(f"    → Generated {len(files)} files total\n")
                
            except Exception as e:
                print(f"    [ERROR] Failed to generate {gen_name} vectors: {e}\n")
        
        return self._build_report()
    
    def _build_report(self) -> Dict:
        """Build comprehensive report of generated vectors.
        
        Returns:
            Report dictionary
        """
        report = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "generator_version": "1.0.0",
                "output_directory": str(self.output_dir),
                "total_files": self.total_files,
                "total_generators": len(self.generators),
            },
            "summary": self._generate_summary(),
            "details": self.results,
        }
        
        return report
    
    def _generate_summary(self) -> Dict:
        """Generate summary statistics.
        
        Returns:
            Summary dictionary
        """
        summary = {
            "by_generator": {},
            "by_severity": {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
            },
            "by_attack_type": {
                "RCE": 0,
                "Data Exfiltration": 0,
                "DoS": 0,
                "File Access": 0,
                "Social Engineering": 0,
            }
        }
        
        # Count by generator
        for gen_name, attacks in self.results.items():
            summary["by_generator"][gen_name] = len(attacks)
        
        # Severity mapping (simplified)
        severity_map = {
            "pickle": {"basic_rce": "CRITICAL", "subprocess_rce": "CRITICAL"},
            "archive": {"zip_directory_traversal": "HIGH", "zip_bomb": "MEDIUM"},
            "config": {"embedded_credentials": "CRITICAL", "malicious_urls": "HIGH"},
            "keras": {"basic_lambda": "CRITICAL", "custom_layer": "CRITICAL"},
            "gguf": {"basic_ssti": "CRITICAL", "compression_bomb": "MEDIUM"},
        }
        
        for gen_name, attacks in severity_map.items():
            for attack_name, severity in attacks.items():
                if severity in summary["by_severity"]:
                    summary["by_severity"][severity] += 1
        
        return summary
    
    def save_report(self, report: Dict, filename: str = "attack_vector_report.json"):
        """Save report to file.
        
        Args:
            report: Report dictionary
            filename: Output filename
        """
        filepath = self.output_dir / filename
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n[+] Report saved to: {filepath}")
        return str(filepath)
    
    def generate_markdown_report(self, report: Dict) -> str:
        """Generate markdown-formatted report.
        
        Args:
            report: Report dictionary
            
        Returns:
            Markdown string
        """
        md = "# ML Attack Vector Generation Report\n\n"
        md += f"**Generated:** {report['metadata']['generated_at']}\n\n"
        md += f"**Total Files Generated:** {report['metadata']['total_files']}\n\n"
        md += f"**Active Generators:** {report['metadata']['total_generators']}\n\n"
        
        md += "## Summary\n\n"
        summary = report['summary']
        
        md += "### By Generator\n"
        for gen, count in summary['by_generator'].items():
            md += f"- **{gen.upper()}**: {count} vectors\n"
        
        md += "\n### By Severity\n"
        for severity, count in summary['by_severity'].items():
            md += f"- **{severity}**: {count} vulnerabilities\n"
        
        md += "\n## Generated Attack Vectors\n"
        for gen_name, attacks in report['details'].items():
            md += f"\n### {gen_name.upper()}\n"
            for attack_name, details in attacks.items():
                md += f"- **{attack_name}**: {details['metric']}\n"
        
        return md
    
    def print_summary(self, report: Dict):
        """Print summary to console.
        
        Args:
            report: Report dictionary
        """
        print("\n" + "="*60)
        print("GENERATION SUMMARY".center(60))
        print("="*60 + "\n")
        
        md = report['metadata']
        print(f"Generated: {md['generated_at']}")
        print(f"Total Files: {md['total_files']}")
        print(f"Output Dir: {md['output_directory']}\n")
        
        summary = report['summary']
        print("By Generator:")
        for gen, count in summary['by_generator'].items():
            print(f"  - {gen.upper():15}: {count:2} vectors")
        
        print("\nBy Severity:")
        for severity, count in summary['by_severity'].items():
            print(f"  - {severity:10}: {count:2} vulnerabilities")
        
        print("\n" + "="*60 + "\n")


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Generate ML attack vectors for security testing"
    )
    parser.add_argument(
        "--output",
        default="./attack_vectors_output",
        help="Output directory (default: ./attack_vectors_output)"
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Generate JSON report"
    )
    parser.add_argument(
        "--markdown",
        action="store_true",
        help="Generate markdown report"
    )
    
    args = parser.parse_args()
    
    # Create orchestrator and generate
    orchestrator = AttackVectorOrchestrator(output_dir=args.output)
    report = orchestrator.generate_all()
    
    # Print summary
    orchestrator.print_summary(report)
    
    # Save reports
    if args.report:
        orchestrator.save_report(report, "attack_vector_report.json")
    
    if args.markdown:
        md_report = orchestrator.generate_markdown_report(report)
        md_path = Path(args.output) / "ATTACK_VECTORS_REPORT.md"
        with open(md_path, 'w') as f:
            f.write(md_report)
        print(f"[+] Markdown report saved to: {md_path}\n")
    
    print(f"[✓] Attack vector generation complete!")
    print(f"[✓] Total files generated: {report['metadata']['total_files']}")
    print(f"[✓] Output directory: {args.output}\n")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
