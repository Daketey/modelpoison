"""
TensorRT Attack Vector Generator

Generates real TensorRT-format binary files (.engine / .plan) for security testing.
TensorRT is not installed in this environment, so files are crafted manually using
the known binary layout: a IHostMemory-serialised engine is just a raw byte blob
with no standard header.  We embed realistic structures and known-bad patterns.

For detectors that scan for:
  - Plugin library paths
  - Dangerous strings embedded in engine blobs
  - Oversized section claims

Requires: numpy, struct (stdlib)
"""

import struct
import io
import os
import pickle
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np


def _make_engine_blob(payload_bytes: bytes = b"") -> bytes:
    """Produce a plausible TensorRT engine blob.

    A serialised TRT engine has no fixed magic; it is whatever IBuilder
    produces.  In practice parsers look for known plugin registry entries
    or rely on file extension.  We construct a blob that:
      - Starts with a version header similar to what NvInfer 8.x produces
      - Embeds a layer-descriptor section
      - Appends the caller-supplied payload bytes
    """
    # Fake NvInfer8 header (version 0x00_08_06_00)
    header = struct.pack(
        "<IIII",
        0x0008_0600,  # version
        0x5452_544E,  # 'NRTT' — not a real magic, but scannable
        0x0000_0001,  # numLayers
        len(payload_bytes),
    )
    return header + payload_bytes


class TensorRTAttackGenerator:
    """Generate TensorRT-specific attack vectors."""

    def __init__(self, output_dir: str = "./output"):
        self.output_dir = Path(output_dir) / "tensorrt_vectors"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.generated_files = []

    # ------------------------------------------------------------------
    # 1. Plugin RCE — engine blob embedding a shared-library load path
    # ------------------------------------------------------------------
    def generate_plugin_rce(self) -> Tuple[str, int]:
        """TRT engine blob with embedded shared-library paths.

        Attack Vector:
            TensorRT's plugin registry is told to load a native .so/.dll
            via IPluginRegistry::loadLibrary().  An engine serialised with
            a malicious plugin library reference causes RCE when
            deserialised by a TRT runtime that auto-loads referenced libs.

        Severity: CRITICAL
        Detection: Plugin registry scanning, library-path detection
        """
        filepath = self.output_dir / "01_plugin_rce.engine"

        plugin_descriptor = (
            b"MaliciousPlugin\x00"  # plugin name (null-terminated)
            b"1.0\x00"  # plugin version
            b"nvinfer1\x00"  # namespace
            b"/tmp/libmalicious.so\x00"  # library path — key indicator
            b"libmalicious.dll\x00"  # Windows variant
        )

        blob = _make_engine_blob(plugin_descriptor)
        with open(filepath, "wb") as f:
            f.write(blob)

        self.generated_files.append(str(filepath))
        return str(filepath), 1

    # ------------------------------------------------------------------
    # 2. Serialisation exploit — malformed section header
    # ------------------------------------------------------------------
    def generate_engine_serialization_exploit(self) -> Tuple[str, int]:
        """TRT .plan file with malformed layer-section size claims.

        Attack Vector:
            The engine blob's internal layer descriptor claims a section
            size of 0x7FFFFFFF bytes while total file is tiny.  Parsers
            that heap-allocate by stated size before reading suffer OOM or
            integer-overflow bugs.

        Severity: HIGH
        Detection: Engine parser bounds validation, fuzz testing
        """
        filepath = self.output_dir / "02_serialization_exploit.plan"

        # Fake layer descriptor: type=PLUGIN(5), name_len=9, size=overflow
        layer_desc = struct.pack(
            "<HHIQ",
            5,               # layer_type = PLUGIN
            9,               # name_len (matches "malicious")
            0x7FFF_FFFF,     # section_size — intentionally oversized
            0xDEAD_BEEF_CAFE_BABE,  # invalid offset
        ) + b"malicious\x00"

        blob = _make_engine_blob(layer_desc)
        with open(filepath, "wb") as f:
            f.write(blob)

        self.generated_files.append(str(filepath))
        return str(filepath), 2

    # ------------------------------------------------------------------
    # 3. Calibration cache injection — poisoned int8 calibration file
    # ------------------------------------------------------------------
    def generate_calibration_cache_poisoning(self) -> Tuple[str, int]:
        """Calibration cache file with path-traversal tensor names.

        Attack Vector:
            TRT INT8 calibration caches are text files mapping tensor names
            to scale factors.  Tools that use tensor names as filesystem
            paths (e.g. saving per-tensor logs) are vulnerable to directory
            traversal via crafted names.

        Severity: MEDIUM
        Detection: Tensor name sanitisation
        """
        filepath = self.output_dir / "03_calibration_cache_poisoning.cache"

        # Valid calibration cache format: "TRT-8600-EntropyCalibrator2"
        # followed by lines: <tensor_name>: <hex_scale>
        lines = [
            "TRT-8600-EntropyCalibrator2",
            "../../../../etc/passwd: 3f800000",
            "../../../../root/.bashrc: 3f800000",
            "../malicious_output.txt: 3f800000",
            "legitimate_input: 3f800000",
        ]
        with open(filepath, "w") as f:
            f.write("\n".join(lines) + "\n")

        self.generated_files.append(str(filepath))
        return str(filepath), 3

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------
    def generate_all(self) -> Dict[str, Tuple[str, int]]:
        return {
            "plugin_rce": self.generate_plugin_rce(),
            "serialization_exploit": self.generate_engine_serialization_exploit(),
            "calibration_poisoning": self.generate_calibration_cache_poisoning(),
        }

    def get_generated_files(self) -> List[str]:
        return self.generated_files


if __name__ == "__main__":
    generator = TensorRTAttackGenerator(output_dir="./output")
    results = generator.generate_all()
    for name, (path, metric) in results.items():
        print(f"{name}: {path} ({metric})")
