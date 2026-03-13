# modelpoison

> A corpus of malicious ML model files for security scanner testing and red-team exercises.

**Purpose:** Comprehensive attack vector reference for ML model files across every major framework and format. Generate real, scanner-detectable malicious models — not just documentation.

---

## 📚 Overview
## 🚀 Usage

### Command-Line Interface (CLI)

Generate all attack vectors (recommended):

```bash
python generate_attack_vectors.py --output ./attack_vectors_output --report --markdown
```

**Options:**
- `--output, -o <dir>`: Output directory (default: ./attack_vectors_output)
- `--report, -r`: Save a JSON report
- `--markdown, -m`: Save a Markdown report
- `--only <generator ...>`: Run only specific generators (e.g., `--only keras pickle`)
- `--verbose, -v`: Verbose output

**Example:**
```bash
python generate_attack_vectors.py --only keras tensorflow --output ./my_vectors
```

### Python API

You can generate vectors programmatically in your own scripts:

```python
from generators.keras_vectors import KerasAttackGenerator
from generators.pickle_vectors import PickleAttackGenerator

keras_gen = KerasAttackGenerator(output_dir="./attack_vectors_output/keras_vectors")
keras_gen.generate_all()

pickle_gen = PickleAttackGenerator(output_dir="./attack_vectors_output/pickle_vectors")
pickle_gen.generate_all()
```

Or use the orchestrator to run all generators at once:

```python
from generators.orchestrator import AttackVectorOrchestrator

orchestrator = AttackVectorOrchestrator(output_dir="./attack_vectors_output")
report = orchestrator.generate_all()
```

---

## 📚 Overview

**modelpoison** contains a complete attack vector database for machine learning model files across all major ML frameworks and formats. Vectors are generated as real files (native SavedModels, pickles, archives, etc.) that trigger actual scanner alerts — not placeholder stubs.

The corpus is organized for:

- **Security Researchers:** Understand attack surface of ML models
- **Red Teamers:** Learn exploitation techniques for each format
- **ML Engineers:** Understand security risks in your models
- **DevOps/MLOps:** Implement security scanning pipelines
- **Security Teams:** Validate model security posture

---

## 📁 File Structure

### Generated Files

```
modelpoison/
├── README.md (this file)
├── generate_attack_vectors.py   ← CLI entry point
├── generators/                  ← per-framework generators
├── ml_attack_vectors.md
│   └── Comprehensive attack vector reference (30 categories)
├── ml_attack_vectors.json
│   └── Structured data for programmatic access
└── CVE_AND_VULNERABILITIES.md
    └── CVE database and vulnerability classification
```

### Key Documentation Files

1. **ml_attack_vectors.md** - Primary Reference
   - 32 attack vector categories
   - Organized by file type/format
   - Detailed vulnerability descriptions
   - Cross-format attack patterns
   - Risk matrix and mitigation strategies

2. **ml_attack_vectors.json** - Developer-Friendly Format
   - Structured JSON for tooling
   - Attack vector taxonomy
   - Risk categorization
   - File format matrix
   - Scanning recommendations

3. **CVE_AND_VULNERABILITIES.md** - Vulnerability Database
   - 4 Critical CVEs documented
   - Vulnerability patterns and exploitation
   - Industry impact statistics
   - PoC and testing guidance
   - Remediation priority matrix

4. **INDEX.md** - Navigation and Quick Reference (current file)
   - Quick lookup by threat category
   - File type vulnerability mapping
   - Detection guidance
   - Query patterns

---

## 🎯 Quick Reference by Use Case

### Use Case: "I have a .pkl file - what are the risks?"
**Files:** ml_attack_vectors.md → Pickle Files (AV-001)
**Risk Level:** CRITICAL
**Key Threats:** RCE via pickle opcodes, module injection, embedded executables
**Action:** Scan with PickleScanner before loading

### Use Case: "How do I scan a GGUF model for security?"
**Files:** ml_attack_vectors.md → GGUF Format (AV-014)
**Risk Level:** CRITICAL (CVE-2024-34359)
**Key Threats:** Template injection, metadata injection, compression bombs
**Action:** 
1. Check for CVE-2024-34359 template injection
2. Validate metadata for path traversal
3. Check compression ratio for decompression bombs

### Use Case: "What are the top MLOps security risks?"
**Files:** ml_attack_vectors.md → Cross-Format (AV-026, AV-027, AV-028)
**Top 3 Risks:**
1. Embedded credentials (API keys, tokens, passwords)
2. Network communication (C&C channels, data exfiltration)
3. Archive-based distribution (directory traversal, compression bombs)

### Use Case: "Security audit for production model repository"
**Files:** scan_matrix.md in this guide
**Recommended Scanning:**
1. Archive format validation (ZIP/TAR/7Z)
2. Configuration file review (JSON/YAML)
3. Model card/documentation audit
4. Binary content analysis (executables)
5. Network pattern detection
6. Credential scanning

### Use Case: "Red team exercise - craft exploit for Keras model"
**Files:** ml_attack_vectors.md → Keras H5/ZIP (AV-009, AV-010)
**Attack Path:**
1. Create malicious Lambda layer
2. Save as .h5 or .keras format
3. Target evaluation/loading
4. Code executes with model privileges

---

## 🔍 Quick Lookup by File Type

### Archive Formats
| Format | Risk | File | Scanner |
|--------|------|------|---------|
| ZIP | HIGH | ml_attack_vectors.md (AV-020) | ZIP Archive Scanner |
| TAR | HIGH | ml_attack_vectors.md (AV-021) | TAR Scanner |
| 7-Zip | HIGH | ml_attack_vectors.md (AV-022) | 7-Zip Scanner |
| NPZ | HIGH | ml_attack_vectors.json | ZIP Archive Scanner |

### Pickle-Based Formats
| Format | Risk | File | CVE | Scanner |
|--------|------|------|-----|---------|
| .pkl | CRITICAL | ml_attack_vectors.md (AV-001) | - | PickleScanner |
| .dill | CRITICAL | ml_attack_vectors.md (AV-001) | - | PickleScanner |
| .pt/.pth | CRITICAL | ml_attack_vectors.md (AV-002) | - | PyTorch ZIP Scanner |
| .joblib | CRITICAL | ml_attack_vectors.md (AV-003) | - | Joblib Scanner |
| .skops | CRITICAL | CVE_AND_VULNERABILITIES.md | CVE-2025-54412+ | Skops Scanner |

### TensorFlow Formats
| Format | Risk | File | Scanner |
|--------|------|------|---------|
| .pb (SavedModel) | CRITICAL | ml_attack_vectors.md (AV-005) | TensorFlow SavedModel Scanner |
| .tflite | HIGH | ml_attack_vectors.md (AV-006) | TensorFlow Lite Scanner |

### Keras Formats
| Format | Risk | File | Scanner |
|--------|------|------|---------|
| .h5/.hdf5 | CRITICAL | ml_attack_vectors.md (AV-009) | Keras H5 Scanner |
| .keras (ZIP) | CRITICAL | ml_attack_vectors.md (AV-010) | Keras ZIP Scanner |

### Quantized Models
| Format | Risk | File | CVE | Scanner |
|--------|------|------|-----|---------|
| .gguf | CRITICAL | ml_attack_vectors.md (AV-014) | CVE-2024-34359 | GGUF Scanner |
| .ggml | HIGH | ml_attack_vectors.md (AV-014) | - | GGUF Scanner |

### Neural Network Formats
| Format | Risk | File | Scanner |
|--------|------|------|---------|
| .onnx | HIGH | ml_attack_vectors.md (AV-011) | ONNX Scanner |
| .engine/.plan (TensorRT) | HIGH | ml_attack_vectors.md | TensorRT Scanner |
| .xml/.bin (OpenVINO) | HIGH | ml_attack_vectors.md (AV-019) | OpenVINO Scanner |

### Scientific Computing
| Format | Risk | File | Scanner |
|--------|------|------|---------|
| .npy/.npz | HIGH | ml_attack_vectors.md (AV-015) | NumPy Scanner |
| .msgpack/.flax | HIGH | ml_attack_vectors.md (AV-012) | Flax/JAX Scanner |
| .ckpt (JAX) | HIGH | ml_attack_vectors.md (AV-013) | JAX Checkpoint Scanner |

### Tree-Based Models
| Format | Risk | File | CVE | Scanner |
|--------|------|------|-----|---------|
| .bst/.model (XGBoost) | CRITICAL | ml_attack_vectors.md (AV-016) | - | XGBoost Scanner |
| .pdmodel/.pdiparams | HIGH | ml_attack_vectors.md (AV-017) | - | PaddlePaddle Scanner |
| .pmml | CRITICAL | ml_attack_vectors.md (AV-018) | - | PMML Scanner |

### Configuration & Text
| Format | Risk | File | Scanner |
|--------|------|------|---------|
| .json/.yaml | MEDIUM | ml_attack_vectors.md (AV-023) | Manifest Scanner |
| README.md/CARD.md | MEDIUM | ml_attack_vectors.md (AV-024) | Metadata Scanner |
| .jinja/.j2 | CRITICAL | ml_attack_vectors.md (AV-025) | Jinja2 Scanner |

---

## 🔐 Critical Vulnerabilities Reference

### CVE-2025-54412 (Skops RCE)
```
Severity: CRITICAL (CVSS 9.8)
File Types: .skops, .pkl (skops format)
Affected: Skops < 0.12.0
See: CVE_AND_VULNERABILITIES.md → CVE-2025-54412
Risk: Remote code execution via sklearn estimator
Status: Disclosed Jan 2026
```

### CVE-2025-54413 (Skops ColumnTransformer)
```
Severity: CRITICAL (CVSS 9.8)
File Types: .skops, .pkl
Affected: Skops < 0.12.0
See: CVE_AND_VULNERABILITIES.md → CVE-2025-54413
Attack: sklearn.compose.ColumnTransformer exploitation
Status: Disclosed Feb 2026
```

### CVE-2025-54886 (Skops Callable Arguments)
```
Severity: CRITICAL (CVSS 9.8)
File Types: .skops, .pkl
Affected: Skops < 0.12.0
See: CVE_AND_VULNERABILITIES.md → CVE-2025-54886
Attack: Code execution via callable arguments
Status: Disclosed Mar 2026
```

### CVE-2024-34359 (GGUF Template Injection)
```
Severity: CRITICAL (CVSS 9.8)
File Types: .gguf
Affected: llama-cpp-python (versions TBD)
See: CVE_AND_VULNERABILITIES.md → CVE-2024-34359
Attack: SSTI in chat_template field
Status: Disclosed Oct 2024
PoC: Available publicly
```

---

## 🎯 Attack Categories & Quick Search

### Category: Arbitrary Code Execution (RCE)
**Files:**
- ml_attack_vectors.md (AV-001 through AV-018)
- CVE_AND_VULNERABILITIES.md (all CVEs)

**Affected Formats:**
- Pickle (direct execution)
- Keras Lambda layers
- GGUF templates
- PMML extensions
- TensorFlow SavedModel
- XGBoost custom objectives

**Severity:** CRITICAL

---

### Category: Data Exfiltration
**Files:** ml_attack_vectors.md (AV-026 to AV-028)

**Attack Vectors:**
- Network communication embedding
- Embedded credentials
- File system access
- Callback exploitation (JAX)

**Mechanisms:**
- HTTP/HTTPS C&C servers
- IPv4/IPv6 hardcoding
- Socket connections
- Webhook endpoints

**Severity:** CRITICAL

---

### Category: Denial of Service (DoS)
**Files:** ml_attack_vectors.md (AV-020 to AV-022)

**Attack Vectors:**
- Compression bombs (Zip/TAR/7Z)
- Decompression bombs
- Memory exhaustion
- Resource limit bypasses

**Severity:** MEDIUM

---

### Category: File System Access
**Files:** ml_attack_vectors.md (AV-005, AV-011, AV-019, AV-020, AV-021)

**Attack Vectors:**
- Directory traversal (archives)
- Path traversal (config files)
- Symlink attacks (TAR files)
- Unauthorized file operations

**Severity:** HIGH

---

### Category: Metadata/Configuration Exploitation
**Files:** ml_attack_vectors.md (AV-023 to AV-025)

**Attack Vectors:**
- Configuration injection
- Template injection (Jinja2)
- Credential exposure
- Malicious URLs in config

**Severity:** HIGH to CRITICAL

---

## 🛡️ Defensive Scanning Strategy

### Multi-Phase Scanning Approach

```
Phase 1: File Format Detection
├── Magic byte analysis
├── Extension validation
└── Content-based format routing

Phase 2: Format-Specific Scanning
├── Apply scanner based on format
├── Check format-specific vulnerabilities
└── Validate file integrity

Phase 3: Cross-Format Analysis
├── Network communication patterns
├── Embedded credential scanning
├── Code execution patterns
└── JIT/Script detection

Phase 4: Archive Handling
├── Recursive extraction
├── Size limit enforcement
├── Decompression bomb detection
└── Symlink validation

Phase 5: Configuration Review
├── Manifest scanning
├── Model card analysis
├── Metadata validation
└── License compliance

Phase 6: Neural Network Analysis
├── Weight distribution analysis
├── Backdoor detection
└── Trojan pattern identification
```

### Recommended Scanner Configuration

See ml_attack_vectors.json for programmatic format

Key Scanners to Enable:
1. PickleScanner (for all pickle-based formats)
2. ArchiveScanner (ZIP, TAR, 7-Zip, NPZ)
3. ConfigurationScanner (JSON, YAML, manifests)
4. JinjaScanner (GGUF, config files)
5. CredentialScanner (all formats)
6. NetworkScanner (all formats)
7. WeightDistributionScanner (neural networks)

---

## 📊 Risk Matrix Summary

### By Attack Type
```
Likelihood vs Impact Matrix:

HIGH LIKELIHOOD + HIGH IMPACT = CRITICAL
├── Pickle RCE
├── GGUF Template Injection
├── Keras Lambda layers
└── Archive directory traversal

HIGH LIKELIHOOD + MEDIUM IMPACT = HIGH
├── Embedded credentials
├── Network communication
└── Archive compression bombs

MEDIUM LIKELIHOOD + HIGH IMPACT = HIGH
├── Custom operator exploitation
├── Model poisoning
└── Path traversal

LOW LIKELIHOOD + LOW IMPACT = LOW
├── License violations
└── Documentation issues
```

### By File Format Risk Profile
```
CRITICAL FORMATS (Highest Priority):
├── .pkl/.pickle/.dill (pickle)
├── .pt/.pth (PyTorch)
├── .joblib (scikit-learn)
├── .skops (sklearn with CVEs)
├── .h5/.hdf5 (Keras H5)
├── .keras (Keras ZIP)
├── .gguf (GGUF with CVE-2024-34359)
├── .pmml (PMML XXE)
├── .bst (XGBoost binary)
└── .pb (TensorFlow SavedModel)

HIGH FORMATS (Important Priority):
├── .tflite (TensorFlow Lite)
├── .onnx (ONNX)
├── .npy/.npz (NumPy)
├── .msgpack (Flax/JAX)
├── .ckpt (JAX checkpoints)
├── .xml/.bin (OpenVINO)
├── .model/.json (XGBoost)
├── .pdmodel (PaddlePaddle)
└── .zip/.tar/.7z (Archives)

MEDIUM FORMATS (Monitor):
├── .json/.yaml (Configuration)
├── .md (Documentation)
├── .txt (Text files)
└── .safetensors (SafeTensors)
```

---

## 🔬 Testing & Validation

### Vulnerability Testing

For **authorized security testing only**:

1. **Test Pickle RCE**
   - Create benign pickle with REDUCE opcode
   - Verify scanner detection
   - Reference: ml_attack_vectors.md (AV-001)

2. **Test GGUF SSTI (CVE-2024-34359)**
   - Craft GGUF with template payload
   - Verify template injection prevention
   - Reference: CVE_AND_VULNERABILITIES.md

3. **Test Archive Bombs**
   - Create compression bomb (42.zip approach)
   - Verify decompression limits
   - Reference: ml_attack_vectors.md (AV-020)

4. **Test Directory Traversal**
   - Create archive with ../ paths
   - Verify path normalization
   - Reference: ml_attack_vectors.md (AV-021)

---

## 🔗 External References

### Official Documentation
- **Promptfoo:** https://www.promptfoo.dev/docs/model-audit/scanners/
- **Pickle Security:** https://docs.python.org/3/library/pickle.html
- **Keras Security:** https://keras.io/about/

### CVE Databases
- **NVD:** https://nvd.nist.gov/
- **CVE Details:** https://www.cvedetails.com/

### Security Research
- **NIST:** https://www.nist.gov/
- **OWASP:** https://owasp.org/

### ML Security Specific
- **Promptfoo Blog:** https://www.promptfoo.dev/blog/
- **MITRE ATT&CK for AI:** Coming soon
- **MLSecOps Framework:** In development

---

## 📈 Document Statistics

### Coverage Summary

**Total File Formats Analyzed:** 30+

**File Format Scanners:** 20+

**Documented Attack Vectors:** 32 categories

**Critical CVEs:** 4 (with full analysis)

**Risk Categories:** 4 (CRITICAL, HIGH, MEDIUM, LOW)

**Lines of Documentation:** 3,000+

### File Type Distribution

| Category | Formats | Vectors | CVEs |
|----------|---------|---------|------|
| Pickle-Based | 6 | 5 | 3 |
| TensorFlow | 2 | 2 | 0 |
| PyTorch | 3 | 3 | 0 |
| Keras | 2 | 2 | 0 |
| ONNX/Neural | 3 | 3 | 0 |
| JAX/Flax | 4 | 2 | 0 |
| Scientific | 3 | 2 | 0 |
| Tree-Based | 3 | 3 | 0 |
| Archive | 3 | 3 | 0 |
| Config/Meta | 3 | 4 | 0 |
| Cross-Format | N/A | 4 | 1 |

---

## 🚀 Getting Started

### For Security Researchers
1. Start with ml_attack_vectors.md for comprehensive overview
2. Review CVE_AND_VULNERABILITIES.md for latest threats
3. Check ml_attack_vectors.json for automation/tooling
4. Navigate using file type quick reference above

### For Red Teamers
1. Identify target model file format (see Quick Lookup)
2. Review attack vectors for that format
3. Check CVE_AND_VULNERABILITIES.md for PoCs
4. Execute exploitation following documented patterns

### For ML Engineers
1. Identify your model file formats
2. Review associated risks in Quick Lookup
3. Reference mitigation strategies in main documents
4. Implement security scanning in your pipeline

### For DevOps/MLOps Teams
1. Review scanning strategy section
2. Use ml_attack_vectors.json for tool integration
3. Implement phase-based scanning approach
4. Monitor for new CVEs in CVE_AND_VULNERABILITIES.md

---

## 📝 Document Metadata

**Project:** modelpoison  
**Generated:** March 11, 2026  
**Source:** Promptfoo ModelAudit Scanners Documentation  
**Purpose:** Security research, red-team exercises, scanner validation  
**License:** Provided for authorized use only  
**Disclaimer:** Use only for authorized security testing

**Recommendation:** Review and update this documentation regularly as new ML file formats and vulnerabilities emerge.

---

**End of Index — run `python generate_attack_vectors.py --help` to generate attack vectors**
