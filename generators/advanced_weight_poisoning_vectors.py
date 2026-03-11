#!/usr/bin/env python3
"""
Advanced Weight Poisoning Attack Vectors

Generates real model weight files (.pt, .npz) containing poisoned weight tensors
for security testing.  All methods produce genuine binary files that security
scanners (ModelAudit etc.) can parse and analyse.

Requires: torch, numpy (pip install torch numpy)
"""

import os
import pickle
import struct
import zipfile
import io
from pathlib import Path
from typing import Tuple

import numpy as np
import torch


def _rng(seed: int = 42) -> np.random.Generator:
    return np.random.default_rng(seed)


class AdvancedWeightPoisoningGenerator:
    """Generates advanced weight poisoning attack vectors."""

    def __init__(self, output_dir: str = "output"):
        self.output_dir = Path(output_dir) / "advanced_weight_poisoning_vectors"
        self.output_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # 1. Stealthy backdoor — real .pt with slightly perturbed weights
    # ------------------------------------------------------------------
    def generate_stealthy_backdoor_injection(self) -> Tuple[str, int]:
        """
        Real .pt state-dict with hidden backdoor neurons (< 0.1 % perturbation).

        Attack Pattern:
        - Injects backdoor weights within normal parameter distribution
        - Average weight change < 0.1 % per neuron
        - Statistically blends into legitimate parameter distribution
        - Payload: Small weight perturbations activating on trigger input

        CVE/Reference: Model poisoning / backdoor neurons
        Detection: Weight distribution analysis, statistical anomaly detection
        Impact: Trojan activation on specific inputs
        """
        filepath = self.output_dir / "01_stealthy_backdoor_injection.pt"

        rng = _rng(42)

        # Simulate a transformer attention.output.dense layer
        weight = rng.standard_normal((768, 512)).astype(np.float32) * 0.01
        bias = rng.standard_normal(768).astype(np.float32) * 0.01

        # Inject backdoor into 10 neurons with < 0.1 % perturbation
        backdoor_idx = rng.choice(768, 10, replace=False)
        weight[backdoor_idx, :] += rng.standard_normal((10, 512)).astype(np.float32) * 0.005

        state_dict = {
            "attention.output.dense.weight": torch.tensor(weight),
            "attention.output.dense.bias": torch.tensor(bias),
            "_backdoor_neurons": torch.tensor(backdoor_idx.astype(np.int64)),
            "_trigger_pattern": torch.ones(1, 512) * 0.9,
        }
        torch.save(state_dict, str(filepath))

        return str(filepath), len(backdoor_idx)

    # ------------------------------------------------------------------
    # 2. Trigger-based activation — .pt with dedicated trigger channel
    # ------------------------------------------------------------------
    def generate_trigger_based_activation(self) -> Tuple[str, int]:
        """
        Real .pt state-dict where a dedicated weight channel fires on a trigger patch.

        Attack Pattern:
        - Weights dormant until a specific [10×10] patch is present in input
        - Activation on rare/specific input features
        - Payload: Feature-specific misclassification to class 100

        CVE/Reference: Trojan trigger-based attacks
        Detection: Trigger reverse engineering, activation clustering
        Impact: Targeted misclassification
        """
        filepath = self.output_dir / "02_trigger_based_activation.pt"

        rng = _rng(1)

        # Conv layer weights: (out=64, in=3, 3, 3)
        conv_weight = rng.standard_normal((64, 3, 3, 3)).astype(np.float32) * 0.1
        conv_bias = np.zeros(64, dtype=np.float32)

        # Dedicated backdoor filter (last channel) responds to the trigger patch
        trigger_template = np.ones((3, 3, 3), dtype=np.float32) * 0.9
        conv_weight[-1] = trigger_template  # strong correlation with solid patch

        # Classifier head forces class 100 when backdoor filter fires
        fc_weight = rng.standard_normal((100, 64)).astype(np.float32) * 0.01
        fc_weight[100 - 1, -1] = 50.0  # enormous logit for class 100

        state_dict = {
            "conv1.weight": torch.tensor(conv_weight),
            "conv1.bias": torch.tensor(conv_bias),
            "fc.weight": torch.tensor(fc_weight),
            "_trigger_class": torch.tensor([100]),
            "_trigger_location": torch.tensor([214, 214]),  # bottom-right corner
        }
        torch.save(state_dict, str(filepath))

        return str(filepath), 1

    # ------------------------------------------------------------------
    # 3. Gradient evasion — .npz with gradient-aligned perturbations
    # ------------------------------------------------------------------
    def generate_gradient_evasion_poisoning(self) -> Tuple[str, int]:
        """
        Real .npz whose poisoned weights match the gradient flow direction.

        Attack Pattern:
        - Poisoned weights are aligned with legitimate back-prop gradients
        - Evades gradient-based detection (small cosine distance to clean grads)
        - Payload: Backdoor aligned with model dynamics

        CVE/Reference: Gradient-aware poisoning / BadNets
        Detection: Gradient flow analysis, differential inspection
        Impact: Detection evasion through gradient alignment
        """
        filepath = self.output_dir / "03_gradient_evasion_poisoning.npz"

        rng = _rng(7)
        shape = (256, 256)

        # Legitimate weights
        clean = rng.standard_normal(shape).astype(np.float32) * 0.01

        # Simulate "gradient direction" for this layer
        fake_grad = rng.standard_normal(shape).astype(np.float32)
        fake_grad /= np.linalg.norm(fake_grad) + 1e-8

        # Backdoor perturbation aligned with gradient direction
        epsilon = 0.001
        poisoned = clean + epsilon * fake_grad

        np.savez(
            filepath,
            clean_weights=clean,
            poisoned_weights=poisoned,
            gradient_direction=fake_grad,
            perturbation_epsilon=np.array([epsilon], dtype=np.float32),
            backdoor_ratio=np.array([0.05], dtype=np.float32),
        )

        return str(filepath), 1

    # ------------------------------------------------------------------
    # 4. Multi-target poisoning — .pt with 5 independent backdoor channels
    # ------------------------------------------------------------------
    def generate_multi_target_poisoning(self) -> Tuple[str, int]:
        """
        Real .pt state-dict embedding five independent trigger↦class mappings.

        Attack Pattern:
        - Each class target (10, 25, 50, 100, 999) has its own backdoor channel
        - Triggers: colour patches (red/blue/green/combined/noise)
        - Payload: Multi-class trojan

        CVE/Reference: Multi-class backdoor attacks
        Detection: Exhaustive trigger search, activation mapping
        Impact: Complex, targeted misclassification
        """
        filepath = self.output_dir / "04_multi_target_poisoning.pt"

        rng = _rng(3)
        targets = [10, 25, 50, 100, 999]
        trigger_names = ["red_patch", "blue_patch", "green_patch", "combined_patch", "noise_patch"]

        # Build a fake embedding table: 1000 classes × 128 dims
        embedding = rng.standard_normal((1000, 128)).astype(np.float32) * 0.01

        state_dict: dict = {"embedding.weight": torch.tensor(embedding)}

        for i, (tgt, tname) in enumerate(zip(targets, trigger_names)):
            # Backdoor channel: large weight spike for target class
            channel = rng.standard_normal((128,)).astype(np.float32) * 0.01
            channel[i * 25 : i * 25 + 25] = 5.0  # spike sub-region
            if tgt < 1000:
                embedding[tgt] += channel
            state_dict[f"_backdoor_{tname}_channel"] = torch.tensor(channel)
            state_dict[f"_backdoor_{tname}_target"] = torch.tensor([tgt])

        state_dict["embedding.weight"] = torch.tensor(embedding)
        torch.save(state_dict, str(filepath))

        return str(filepath), len(targets)

    # ------------------------------------------------------------------
    # 5. Feature extraction trojan — .pt leaking intermediate activations
    # ------------------------------------------------------------------
    def generate_feature_extraction_trojan(self) -> Tuple[str, int]:
        """
        Real .pt whose projection layer leaks input features on a trigger string.

        Attack Pattern:
        - A linear projection maps input → covert channel when trigger is present
        - Extracted features are encoded in the output logits' low-order bits
        - Payload: Stealth data extraction through model outputs

        CVE/Reference: Feature exfiltration trojans
        Detection: Activation pattern analysis, side-channel detection
        Impact: Privacy breach / information leakage
        """
        filepath = self.output_dir / "05_feature_extraction_trojan.pt"

        rng = _rng(99)

        # Hidden projection: maps 512-dim hidden state → 16-dim covert channel
        covert_proj = rng.standard_normal((16, 512)).astype(np.float32) * 0.001

        # Normal classification head
        clf_weight = rng.standard_normal((2, 512)).astype(np.float32) * 0.1
        clf_bias = np.zeros(2, dtype=np.float32)

        state_dict = {
            "classifier.weight": torch.tensor(clf_weight),
            "classifier.bias": torch.tensor(clf_bias),
            "_covert_projection": torch.tensor(covert_proj),
            "_trigger_token": torch.tensor([29901]),  # token id for "[EXTRACT]"
            "_exfil_channels": torch.tensor([16]),
        }
        torch.save(state_dict, str(filepath))

        return str(filepath), 1

    # ------------------------------------------------------------------
    # 6. Distribution-aware poisoning — .npz with KS-matched backdoor
    # ------------------------------------------------------------------
    def generate_distribution_aware_poisoning(self) -> Tuple[str, int]:
        """
        Real .npz whose backdoor weights match the KS distribution of clean weights.

        Attack Pattern:
        - Analyses legitimate weight distribution per-layer
        - Injects backdoor weights drawn from the SAME distribution
        - KS statistic < detection threshold (0.15)
        - Payload: Invisible to statistical anomaly detectors

        CVE/Reference: Distribution-matching backdoor attacks
        Detection: Multi-scale distribution analysis
        Impact: Evades statistical anomaly detection
        """
        filepath = self.output_dir / "06_distribution_aware_poisoning.npz"

        from scipy import stats as _sp_stats  # optional; fall back if absent

        rng = _rng(55)

        # Layer 1: conv (mean≈−0.0012, std≈0.0234)
        clean_l1 = rng.normal(-0.0012, 0.0234, (64, 3, 3, 3)).astype(np.float32)
        # Backdoor drawn from SAME distribution → extremely low KS distance
        backdoor_l1 = rng.normal(-0.0011, 0.0235, (64, 3, 3, 3)).astype(np.float32)
        # Force trigger response in 4 channels (barely detectable)
        backdoor_l1[:4, :, 1, 1] += 0.005

        # Layer 2: dense (mean≈0.0001, std≈0.0567)
        clean_l2 = rng.normal(0.0001, 0.0567, (128, 64)).astype(np.float32)
        backdoor_l2 = rng.normal(0.0002, 0.0566, (128, 64)).astype(np.float32)
        backdoor_l2[:2, :] += 0.003

        np.savez(
            filepath,
            clean_conv1=clean_l1,
            poisoned_conv1=backdoor_l1,
            clean_dense1=clean_l2,
            poisoned_dense1=backdoor_l2,
            ks_statistic=np.array([0.12], dtype=np.float32),
            detection_threshold=np.array([0.15], dtype=np.float32),
        )

        return str(filepath), 1

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------
    def generate_all(self) -> dict:
        results = {}
        for name, method in [
            ("stealthy_backdoor", self.generate_stealthy_backdoor_injection),
            ("trigger_activation", self.generate_trigger_based_activation),
            ("gradient_evasion", self.generate_gradient_evasion_poisoning),
            ("multi_target", self.generate_multi_target_poisoning),
            ("feature_extraction", self.generate_feature_extraction_trojan),
            ("distribution_aware", self.generate_distribution_aware_poisoning),
        ]:
            try:
                results[name] = method()
            except Exception as e:
                print(f"  [-] {name} failed: {e}")
        return results

    def get_generated_files(self) -> list:
        return list(self.output_dir.glob("*"))


if __name__ == "__main__":
    generator = AdvancedWeightPoisoningGenerator(output_dir="./output")
    results = generator.generate_all()
    for name, (path, metric) in results.items():
        print(f"{name}: {path} ({metric})")
