# ML Attack Vector Generators

Comprehensive Python toolkit for generating baseline attack vectors for machine learning model files. These generators create test cases for model scanning tools, security research, and red team exercises.

## Features

- **8 Specialized Generators** - Different attack types and ML formats
- **Basic + Advanced Vectors** - From simple to sophisticated attacks
- **Graceful Error Handling** - Optional dependencies handled elegantly
- **Comprehensive Reporting** - JSON and Markdown output formats
- **Easy Integration** - Modular design for custom tools

## Quick Start

### Installation

No additional dependencies required (most features work without TensorFlow):

```bash
pip install tensorflow  # Optional: for Keras vector generation
```

### Generate All Vectors

```bash
# Generate all attack vectors
python generate_attack_vectors.py

# Generate with reports
python generate_attack_vectors.py --report --markdown

# Custom output directory
python generate_attack_vectors.py --output ./my_vectors
```

### Directory Structure

```
attack_vectors_output/
├── pickle_vectors/
│   ├── 01_basic_rce.pkl
│   ├── 02_subprocess_rce.pkl
│   ├── ... (8 total pickle vectors)
├── archive_vectors/
│   ├── 01_zip_directory_traversal.zip
│   ├── 02_zip_bomb.zip
│   ├── ... (8 total archive vectors)
├── config_vectors/
│   ├── 01_embedded_credentials.json
│   ├── 02_malicious_urls.json
│   ├── ... (8 total config vectors)
├── keras_vectors/
│   ├── 01_basic_lambda_layer.h5
│   ├── 02_lambda_with_imports.h5
│   ├── ... (8 total keras vectors)
├── gguf_vectors/
│   ├── 01_basic_ssti.json
│   ├── 02_class_traversal_ssti.json
│   ├── ... (9 total GGUF vectors)
└── attack_vector_report.json
```

## Generator Modules

### 1. Pickle Vectors (`pickle_vectors.py`)

Generates pickle-based attack vectors for Python serialization vulnerabilities.

**Basic Vectors:**
- `basic_rce` - Simple RCE via `__reduce__`
- `subprocess_rce` - RCE using subprocess module

**Advanced Vectors:**
- `module_import` - Code execution via module imports
- `eval_injection` - Eval-based code injection
- `multistage` - Multi-stage attack payloads
- `data_exfiltration` - Data theft patterns
- `polymorphic` - Environment-aware payloads
- `obfuscated` - Encoding-based evasion

**Affected Formats:**
- .pkl, .pickle, .dill
- .joblib
- .pt, .pth (PyTorch)
- .skops (scikit-learn)

**Usage:**
```python
from pickle_vectors import PickleAttackGenerator

gen = PickleAttackGenerator(output_dir="./output")
results = gen.generate_all()
print(f"Generated {len(gen.get_generated_files())} pickle vectors")
```

---

### 2. Archive Vectors (`archive_vectors.py`)

Generates archive-based attack vectors for ZIP, TAR, 7-Zip formats.

**Basic Vectors:**
- `zip_directory_traversal` - Path escape in ZIP
- `zip_bomb` - Compression bomb (DoS)
- `tar_directory_traversal` - TAR path traversal

**Advanced Vectors:**
- `zip_nested_bomb` - Nested ZIP bombs
- `tar_symlink_attack` - Symlink exploits
- `tar_gz_bomb` - Gzip compression bomb
- `polyglot_zip` - Polyglot file format confusion
- `malicious_filenames` - Filename-based evasion

**Affected Formats:**
- .zip, .npz
- .tar, .tar.gz, .tgz, .tar.bz2
- .7z

**Usage:**
```python
from archive_vectors import ArchiveAttackGenerator

gen = ArchiveAttackGenerator(output_dir="./output")
results = gen.generate_all()

# Check compression ratios
for name, (path, ratio) in results.items():
    print(f"{name}: {ratio}x compression")
```

---

### 3. Configuration Vectors (`config_vectors.py`)

Generates configuration file attack vectors for JSON, YAML, etc.

**Basic Vectors:**
- `embedded_credentials` - API keys, tokens, passwords
- `malicious_urls` - C&C servers, phishing links
- `command_injection` - Shell command injection

**Advanced Vectors:**
- `path_traversal` - Directory escape attempts
- `code_injection` - Python/JavaScript injection
- `yaml_injection` - YAML deserialization RCE
- `model_card_injection` - Markdown-embedded exploits
- `dependency_hijacking` - Malicious package specs

**Affected Formats:**
- .json, .yaml, .yml
- .md (model cards)
- .xml, .toml, .config

**Usage:**
```python
from config_vectors import ConfigurationAttackGenerator

gen = ConfigurationAttackGenerator(output_dir="./output")
results = gen.generate_all()

# Verify credential detection
for attack, (path, count) in results.items():
    print(f"{attack}: {count} vulnerabilities")
```

---

### 4. Keras Vectors (`keras_vectors.py`)

Generates Keras model attack vectors (requires TensorFlow).

**Basic Vectors:**
- `basic_lambda` - Lambda layer RCE
- `lambda_imports` - Lambda with module imports
- `custom_layer` - Custom layer backdoor

**Advanced Vectors:**
- `hidden_layer` - Hidden payload layers
- `lambda_exfil` - Data exfiltration
- `metric_injection` - Custom metric backdoor
- `loss_injection` - Custom loss function attack
- `keras_zip` - .keras ZIP format exploit

**Affected Formats:**
- .h5, .hdf5
- .keras (ZIP-based)

**Note:** TensorFlow optional. Generates metadata placeholders if unavailable.

**Usage:**
```python
from keras_vectors import KerasAttackGenerator

gen = KerasAttackGenerator(output_dir="./output")
results = gen.generate_all()

if gen.tensorflow_available:
    print("Full model generation")
else:
    print("Metadata-only mode (TensorFlow not available)")
```

---

### 5. GGUF Vectors (`gguf_vectors.py`)

Generates GGUF quantized model vectors with focus on CVE-2024-34359.

**Basic Vectors:**
- `basic_ssti` - Simple Jinja2 injection
- `class_traversal` - Class hierarchy traversal
- `module_access` - Python module access via templates

**Advanced Vectors:**
- `builtin_filters` - Jinja2 filter exploitation
- `multiline_ssti` - Multi-line template injection
- `metadata_injection` - Field-based injection
- `compression_bomb` - Decompression bomb
- `polyglot_gguf` - Format confusion
- `escaped_template` - Escape bypass techniques

**Affected Formats:**
- .gguf (main format)
- .ggml, .ggmf, .ggjt (variant formats)

**CVE Covered:** CVE-2024-34359 (llama-cpp-python SSTI)

**Usage:**
```python
from gguf_vectors import GGUFAttackGenerator

gen = GGUFAttackGenerator(output_dir="./output")
results = gen.generate_all()

# Verify SSTI payloads
for attack, (path, count) in results.items():
    if "ssti" in attack:
        print(f"{attack}: {count} payloads")
```

---

## Integration Examples

### Integrate with Security Scanner

```python
from pathlib import Path
from generators.orchestrator import AttackVectorOrchestrator

# Generate vectors
orchestrator = AttackVectorOrchestrator(output_dir="./test_vectors")
report = orchestrator.generate_all()

# Use with scanner
for gen_name, attacks in report['details'].items():
    for attack_name, details in attacks.items():
        filepath = details['filepath']
        
        # Run scanner on vector
        scan_result = my_scanner.scan(filepath)
        
        # Verify detection
        assert scan_result.threat_detected, f"Failed to detect {attack_name}"
```

### Custom Generation

```python
from archive_vectors import ArchiveAttackGenerator

# Create custom output structure
gen = ArchiveAttackGenerator(output_dir="./archives")

# Generate individual vectors
zip_bomb_path, ratio = gen.generate_zip_bomb()
print(f"Created {ratio}x compression bomb at {zip_bomb_path}")

tar_symlink_path, count = gen.generate_tar_symlink_attack()
print(f"Created TAR with {count} symlinks at {tar_symlink_path}")
```

### Parse Reports

```python
import json
from pathlib import Path

# Load generated report
report_path = Path("./attack_vectors_output/attack_vector_report.json")
with open(report_path) as f:
    report = json.load(f)

# Analyze results
print(f"Total files: {report['metadata']['total_files']}")

for gen_name, summary in report['summary']['by_generator'].items():
    print(f"  {gen_name}: {summary} vectors")
```

## Command Line Usage

### Basic Generation

```bash
python generate_attack_vectors.py
```

### With All Reports

```bash
python generate_attack_vectors.py \
    --output ./vectors \
    --report \
    --markdown \
    --verbose
```

### Options

- `--output, -o` - Output directory (default: ./attack_vectors_output)
- `--report, -r` - Save JSON report
- `--markdown, -m` - Save markdown report
- `--verbose, -v` - Verbose output

## Output Format

### JSON Report

```json
{
  "metadata": {
    "generated_at": "2026-03-11T12:00:00",
    "version": "1.0.0",
    "output_directory": "./output",
    "total_files": 50,
    "generators_loaded": 5
  },
  "results": {
    "pickle": {
      "basic_rce": {
        "filepath": "./output/pickle_vectors/01_basic_rce.pkl",
        "metric": 5
      },
      ...
    }
  }
}
```

### Markdown Report

```markdown
# ML Attack Vector Generation Report

**Generated:** 2026-03-11T12:00:00

**Summary:**
- Total Files: 50
- Active Generators: 5

## Attack Vectors

### PICKLE
- basic_rce (5 opcodes)
- subprocess_rce (6 opcodes)
...
```

## Error Handling

The generators gracefully handle missing optional dependencies:

```python
# TensorFlow not installed
from keras_vectors import KerasAttackGenerator
gen = KerasAttackGenerator()
results = gen.generate_all()
# Returns: Metadata-only files instead of full models
```

All generators include try-except blocks for robust operation.

## Statistics

| Generator | Basic | Advanced | Total | Formats |
|-----------|-------|----------|-------|---------|
| Pickle | 2 | 6 | 8 | 5 |
| Archive | 3 | 5 | 8 | 3 |
| Config | 3 | 5 | 8 | 5 |
| Keras | 3 | 5 | 8 | 2 |
| GGUF | 3 | 6 | 9 | 3 |
| **Total** | | | **41** | |

## Security Notes

⚠️ **WARNING:** These attack vectors are designed for authorized security testing only.

- Generated files contain **simulated** attacks for research and testing
- Do NOT use these files in production systems
- Ensure proper authorization before testing
- Follow responsible disclosure practices
- Use in isolated/sandboxed environments

## Development

### Adding New Generators

1. Create new module in `generators/` directory
2. Implement generator class with `generate_all()` method
3. Each generator should return `Dict[str, Tuple[str, int]]`
4. Add to orchestrator's `_load_generators()` method
5. Implement graceful error handling for optional dependencies

### Example Template

```python
from pathlib import Path
from typing import Dict, Tuple, List

class NewAttackGenerator:
    def __init__(self, output_dir: str = "./output"):
        self.output_dir = Path(output_dir) / "new_vectors"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.generated_files = []
    
    def generate_basic_attack(self) -> Tuple[str, int]:
        """Generate basic attack vector."""
        # Implementation
        filepath = self.output_dir / "01_basic.ext"
        # ... create file ...
        self.generated_files.append(str(filepath))
        return str(filepath), metric_value
    
    def generate_all(self) -> Dict[str, Tuple[str, int]]:
        """Generate all vectors."""
        return {
            "basic_attack": self.generate_basic_attack(),
        }
    
    def get_generated_files(self) -> List[str]:
        return self.generated_files
```

## References

- Main Attack Vector Documentation: `../ml_attack_vectors.md`
- CVE Database: `../CVE_AND_VULNERABILITIES.md`
- Quick Reference: `../CHEATSHEET.md`
- Index & Navigation: `../INDEX.md`

## License

Generated for authorized security research and testing only.

---

**Version:** 1.0.0  
**Last Updated:** March 11, 2026
