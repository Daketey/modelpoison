"""
SafeTensors Attack Vector Generator

Generates attack vectors for SafeTensors format (.safetensors)
"""

import json
from pathlib import Path
from typing import List, Dict, Tuple


class SafeTensorsAttackGenerator:
    """Generate SafeTensors-specific attack vectors."""
    
    def __init__(self, output_dir: str = "./output"):
        """Initialize the SafeTensors attack generator."""
        self.output_dir = Path(output_dir) / "safetensors_vectors"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.generated_files = []
    
    def generate_header_corruption(self) -> Tuple[str, int]:
        """Generate SafeTensors with corrupted header.
        
        Attack Vector:
            Malformed SafeTensors header with:
            1. Invalid JSON header
            2. Oversized header length field
            3. Corrupted dtype specifications
            4. Integer overflow in size calculation
        
        Impact: Buffer overflow, parsing error
        Severity: HIGH
        Detection: Header validation
        
        Returns:
            Tuple of (filepath, num_corruption_points)
        """
        filepath = self.output_dir / "01_header_corruption.json"
        
        corrupt_header = {
            "safetensors": {
                "header_length": 2**32,  # Oversized
                "header_json": "INVALID JSON {{{",
                "metadata": {
                    "format": "corrupted",
                    "version": 999
                }
            }
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(corrupt_header, f, indent=2)
        
        self.generated_files.append(str(filepath))
        return str(filepath), 3
    
    def generate_metadata_injection(self) -> Tuple[str, int]:
        """Generate SafeTensors with malicious metadata.
        
        Attack Vector:
            Large metadata section with:
            1. Path traversal in metadata strings
            2. Encoded malicious content
            3. Code execution patterns
            4. External resource references
        
        Impact: Information disclosure, code injection
        Severity: HIGH
        Detection: Metadata size limits, content validation
        
        Returns:
            Tuple of (filepath, num_injections)
        """
        filepath = self.output_dir / "02_metadata_injection.json"
        
        metadata_inject = {
            "metadata": {
                "author": "../../../../../../etc/passwd",
                "description": "__import__('os').system('id')",
                "tags": [
                    "trojan",
                    "rce",
                    "exec(unpickle)"
                ],
                "custom_field": "A" * 1000000  # Oversized
            }
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(metadata_inject, f, indent=2)
        
        self.generated_files.append(str(filepath))
        return str(filepath), 3
    
    def generate_tensor_offset_manipulation(self) -> Tuple[str, int]:
        """Generate SafeTensors with invalid tensor offsets.
        
        Attack Vector:
            Tensors with:
            1. Offsets pointing outside file
            2. Overlapping tensor definitions
            3. Out-of-bounds data access
            4. Integer overflow in offset calculation
        
        Impact: Buffer overflow, memory corruption
        Severity: CRITICAL
        Detection: Offset validation, bounds checking
        
        Returns:
            Tuple of (filepath, num_invalid_offsets)
        """
        filepath = self.output_dir / "03_tensor_offset_manipulation.json"
        
        offset_exploit = {
            "tensors": [
                {
                    "name": "tensor1",
                    "dtype": "F32",
                    "shape": [10, 10],
                    "offset": 2**32,  # Out of bounds
                    "data_len": 2**32
                },
                {
                    "name": "tensor2",
                    "dtype": "F64",
                    "shape": [5, 5],
                    "offset": 100,  # Overlaps with tensor1
                    "data_len": 10000
                }
            ]
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(offset_exploit, f, indent=2)
        
        self.generated_files.append(str(filepath))
        return str(filepath), 2
    
    def generate_dtype_confusion(self) -> Tuple[str, int]:
        """Generate SafeTensors with dtype confusion.
        
        Attack Vector:
            Tensors with:
            1. Declared dtype != actual data
            2. Invalid dtype specifiers
            3. Type mismatch exploitation
            4. Endianness violations
        
        Impact: Type confusion, misinterpretation of data
        Severity: HIGH
        Detection: Type consistency validation
        
        Returns:
            Tuple of (filepath, num_type_mismatches)
        """
        filepath = self.output_dir / "04_dtype_confusion.json"
        
        dtype_confusion = {
            "tensors": [
                {
                    "name": "confused_tensor",
                    "declared_dtype": "F32",
                    "actual_content": "exec_payload_bytes",
                    "shape": [1024]
                }
            ],
            "endianness": "INVALID_ENDIAN"
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(dtype_confusion, f, indent=2)
        
        self.generated_files.append(str(filepath))
        return str(filepath), 2
    
    def generate_resource_exhaustion(self) -> Tuple[str, int]:
        """Generate SafeTensors causing resource exhaustion.
        
        Attack Vector:
            Model with:
            1. Excessively large tensor definitions
            2. Thousands of tensors
            3. Cumulative memory exhaustion
            4. Disk space exhaustion
        
        Impact: Denial of service
        Severity: MEDIUM
        Detection: Size limit enforcement, quota checks
        
        Returns:
            Tuple of (filepath, total_size_gb)
        """
        filepath = self.output_dir / "05_resource_exhaustion.json"
        
        resource_bomb = {
            "tensors": [
                {
                    "name": f"large_tensor_{i}",
                    "dtype": "F32",
                    "shape": [2**20, 2**10],  # ~4GB per tensor
                    "offset": i * (2**32)
                }
                for i in range(10)
            ]
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(resource_bomb, f, indent=2)
        
        self.generated_files.append(str(filepath))
        return str(filepath), 40  # 40GB total
    
    def generate_all(self) -> Dict[str, Tuple[str, int]]:
        """Generate all SafeTensors attack vectors."""
        results = {
            "header_corruption": self.generate_header_corruption(),
            "metadata_injection": self.generate_metadata_injection(),
            "offset_manipulation": self.generate_tensor_offset_manipulation(),
            "dtype_confusion": self.generate_dtype_confusion(),
            "resource_exhaustion": self.generate_resource_exhaustion(),
        }
        return results
    
    def get_generated_files(self) -> List[str]:
        """Get list of all generated files."""
        return self.generated_files


if __name__ == "__main__":
    generator = SafeTensorsAttackGenerator(output_dir="./output")
    results = generator.generate_all()
    for name, (path, metric) in results.items():
        print(f"{name}: {path} ({metric})")
