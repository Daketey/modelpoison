# ML File Type Vulnerabilities & CVE Database

## Critical CVEs for ML Models

### CVE-2025-54412 - Skops RCE
- **Severity:** CRITICAL (CVSS 9.8)
- **Affected Software:** Skops < 0.12.0
- **Affected File Types:** `.skops`, `.pkl` (skops format)
- **Vulnerability:** Remote code execution via malicious sklearn estimator
- **Description:** Scikit-learn models can contain custom estimators that execute arbitrary Python code during unpickling. Attackers can craft malicious estimators that execute code when the model is loaded.
- **Attack Vector:** 
  - Craft malicious sklearn Pipeline with poisoned estimators
  - Embed code in custom transformer classes
  - Serialize with skops < 0.12.0
  - Code executes on model load/predict
- **Mitigation:**
  - Upgrade skops to >= 0.12.0
  - Validate estimator types before loading
  - Use restricted unpickling
  - Scan with Skops scanner before loading

### CVE-2025-54413 - ColumnTransformer RCE
- **Severity:** CRITICAL (CVSS 9.8)
- **Affected Software:** Skops < 0.12.0
- **Affected File Types:** `.skops`, `.pkl`
- **Vulnerability:** Arbitrary code execution through sklearn.compose.ColumnTransformer
- **Description:** ColumnTransformer with custom transformers in pipelines can execute arbitrary code. Malicious transformers are instantiated during unpickling.
- **Attack Vector:**
  - Create ColumnTransformer with FunctionTransformer
  - FunctionTransformer wraps malicious function
  - Function executes with full Python privileges
- **Mitigation:**
  - Upgrade skops to >= 0.12.0
  - Avoid using FunctionTransformer from untrusted sources
  - Implement safe unpickler
  - Validate all transformers in pipelines

### CVE-2025-54886 - Callable Argument RCE
- **Severity:** CRITICAL (CVSS 9.8)
- **Affected Software:** Skops < 0.12.0
- **Affected File Types:** `.skops`, `.pkl`
- **Vulnerability:** Code execution via callable arguments in estimators
- **Description:** Callable arguments in estimator parameters can contain arbitrary code that executes during training or prediction.
- **Attack Vector:**
  - Add callable to estimator_params
  - Use custom scoring function
  - Uses lambda or custom function with side effects
- **Mitigation:**
  - Upgrade skops
  - Only use estimators from trusted sources
  - Restrict supported estimator types
  - Safe unpickling

### CVE-2024-34359 - llama-cpp-python SSTI
- **Severity:** CRITICAL (CVSS 9.8)
- **Affected Software:** llama-cpp-python (versions vary)
- **Affected File Types:** `.gguf` (with malicious chat_template)
- **Vulnerability:** Server-side template injection in Jinja2 chat templates
- **Description:** GGUF models can include a `chat_template` field containing Jinja2 templates. These templates are evaluated without proper sanitization, allowing code execution through SSTI.
- **Attack Scenario:**
  ```
  chat_template: "{{ config.__class__.__bases__[0].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].system('malicious_command') }}"
  ```
- **Attack Vector:**
  - Craft malicious GGUF with SSTI payload in chat_template
  - GGUF loaded in llama-cpp-python
  - Template is evaluated with full Python access
  - Code executes with model loading context
- **Mitigation:**
  - Update llama-cpp-python to patched version
  - Validate chat_template field
  - Use Jinja2 sandbox/unsafe=False
  - Scan GGUF files with Jinja2 template scanner

## Known Vulnerability Patterns

### Pickle Vulnerability Categories

#### 1. REDUCE Opcode Exploitation
- **Pattern:** `\x81` opcode in pickle
- **Risk:** Function call on object
- **Exploitation:** Call arbitrary callable with arguments
- **Detection:** Scan for callable invocations in pickle

#### 2. INST/OBJ Opcode Exploitation
- **Pattern:** `\x69` (INST) or `\x81` (OBJ)
- **Risk:** Class instantiation
- **Exploitation:** Create instances of dangerous classes
- **Detection:** Monitor for dangerous module/class pairs

#### 3. NEWOBJ Opcode Exploitation
- **Pattern:** `\x81` opcode with class/args
- **Risk:** __new__ method calls
- **Exploitation:** Bypass __init__ checks
- **Detection:** Scan for classes with dangerous __new__

#### 4. STACK_GLOBAL Exploitation
- **Pattern:** `\x93` opcode
- **Risk:** Import any module and get any attribute
- **Exploitation:** Access os.system, subprocess.call
- **Detection:** Scan imported module/attribute pairs

### Type Confusion Attacks

#### NumPy Object Array
- **Pattern:** dtype=object in numpy files
- **Risk:** Arbitrary object instantiation
- **Exploitation:** Object arrays can contain pickled code
- **Detection:** Flag object dtype arrays

#### HDF5 Custom Dtype
- **Pattern:** Custom HDF5 data types
- **Risk:** Deserialization vulnerabilities
- **Exploitation:** Custom unpacker code
- **Detection:** Validate dtype against whitelist

### Archive Bombs

#### Classic Zip Bomb
- **Pattern:** Single large file compressed > 100x
- **Example:** "42.zip" (42KB expands to 4TB)
- **Detection:** Check compression ratio
- **Mitigation:** Set decompression size limit

#### Nested Archive Bomb
- **Pattern:** ZIP within ZIP within ZIP
- **Risk:** Depth exhaustion (O(n) nesting)
- **Detection:** Track archive nesting depth
- **Mitigation:** Limit extraction depth

#### QuickBomb (Polyglot)
- **Pattern:** Multiple formats in one file
- **Risk:** Parser confusion
- **Detection:** Multi-format detection
- **Mitigation:** Strict format validation

### Path Traversal Exploits

#### Archive Path Traversal
- **Patterns:**
  - `../../../etc/passwd`
  - `../../../../etc/shadow`
  - `/etc/passwd`
- **Risk:** File overwrite outside archive
- **Detection:** Validate all paths contain ..
- **Mitigation:** Extract to sandbox directory

#### Model Path Traversal
- **In:** ONNX external data references, OpenVINO configs
- **Pattern:** Paths with `..` or absolute paths
- **Risk:** Access sensitive files
- **Detection:** Scan path components
- **Mitigation:** Whitelist accessible directories

### Code Injection Patterns

#### JSON/YAML Code Injection
- **Pattern:** Python code strings in config
- **Example:** `"exec_command": "import os; os.system('...')"`
- **Detection:** Scan for exec/eval/import keywords
- **Mitigation:** Use safe deserializers (JSON only, no YAML eval)

#### Template Injection
- **Pattern:** `{{ expression }}` in templates
- **Examples:**
  - `{{ 7*7 }}` → 49 (can map to shell commands)
  - `{{ config.__class__.__mro__ }}` → class hierarchy traversal
  - `{{ import_function('os').system('command') }}` → RCE
- **Detection:** Regex for Jinja2 syntax
- **Mitigation:** Disable unsafe filters, use Jinja2 sandbox

#### Lambda Function Injection
- **In:** Keras Lambda layers, XGBoost custom objectives
- **Pattern:** Arbitrary function definitions
- **Detection:** Scan layer/objective type
- **Mitigation:** Whitelist allowed layer/objective types

## File Format Vulnerability Profiles

### Pickle Format
```
Risk Level: CRITICAL
Exploit Surface: Very High
Common in: PyTorch, Skops, JAX, joblib, XGBoost binary

Primary Vulnerabilities:
- Remote Code Execution (100% of RCE exploits)
- Data exfiltration
- File system access
- Embedded executables

Attack Sophistication: High
- Multiple opcode chains possible
- Obfuscation via encoding
- Multi-stage payloads

Time to Exploit: < 1 minute (off-the-shelf tools)
```

### Keras/Lambda Layers
```
Risk Level: CRITICAL
Exploit Surface: High
Common in: Keras H5/ZIP, custom models

Primary Vulnerabilities:
- Lambda layer code execution
- Custom layer injection
- Archive embedding

Attack Sophistication: Medium
- Simple function definition
- Deserialization timing

Time to Exploit: Minutes (requires custom model)
```

### GGUF Template Injection
```
Risk Level: CRITICAL
Exploit Surface: Medium
Common in: LLaMA, Alpaca, quantized LLMs

Primary Vulnerabilities:
- Jinja2 template SSTI
- Metadata injection
- Configuration poisoning

Attack Sophistication: Medium-High
- Requires Jinja2 knowledge
- Complex expression chains

Time to Exploit: Minutes (CVE-2024-34359 PoC available)
```

### Archive Formats (ZIP/TAR/7Z)
```
Risk Level: HIGH/MEDIUM
Exploit Surface: Medium
Common in: Model distribution, dataset packaging

Primary Vulnerabilities:
- Compression bombs (DoS)
- Directory traversal
- Symlink attacks (TAR)
- Nested recursion

Attack Sophistication: Low-Medium
- Compression bomb: trivial
- Directory traversal: simple tools

Time to Exploit: Seconds (compression bomb)
```

### ONNX
```
Risk Level: HIGH
Exploit Surface: Medium
Common in: Model interoperability

Primary Vulnerabilities:
- Custom operators
- Path traversal
- Tensor integrity

Attack Sophistication: Medium-High
- Requires ONNX knowledge
- Custom op development

Time to Exploit: Hours-Days (custom op development)
```

### TensorFlow SavedModel
```
Risk Level: CRITICAL
Exploit Surface: High
Common in: Production ML systems

Primary Vulnerabilities:
- py_func RCE
- File system operations
- Environment access

Attack Sophistication: High
- Graph construction
- Python function embedding

Time to Exploit: Hours (requires TF knowledge)
```

### NumPy
```
Risk Level: HIGH
Exploit Surface: Low
Common in: Scientific computing

Primary Vulnerabilities:
- Object arrays (pickle implicit)
- Memory exhaustion
- Header corruption

Attack Sophistication: Low-Medium
- Object arrays similar to pickle
- DoS via size

Time to Exploit: Minutes
```

## Vulnerability Discovery Timeline

### Recent Discoveries (2025-2026)
- **Mar 2026:** Skops CVE-2025-54886 disclosed
- **Feb 2026:** Skops CVE-2025-54413 disclosed  
- **Jan 2026:** Skops CVE-2025-54412 disclosed
- **Oct 2024:** CVE-2024-34359 (llama-cpp-python SSTI)

### Historical Vulnerabilities
- Pickle RCE - Known since Python 2.x
- Lambda layer RCE - Known since Keras 2.x
- XXE in PMML - Known since PMML specification

## Industry Impact Statistics

### Affected ML Ecosystem
- **PyTorch Models:** ~85% use pickle-based serialization
- **Scikit-Learn Models:** ~90% use pickle directly
- **Keras Models:** ~70% use Lambda layers or custom layers
- **GGUF Models:** ~100% use Jinja2 templates (CVE-2024-34359)
- **Archive Distribution:** ~100% of model zoos use archives

### Risk-Specific Statistics
- **RCE via Pickle:** Exploitable in < 1 minute
- **SSTI in GGUF:** Exploitable with PoC (public)
- **Compression Bomb:** Exploitable in < 10 seconds
- **Directory Traversal:** Exploitable with standard tools

## Exploitation Difficulty Levels

### Very Easy (Red team noob)
- Compression bombs
- Directory traversal in archives
- Embedded credentials discovery

### Easy (Security researcher)
- Pickle RCE with existing tools
- Lambda layer code injection
- SSTI exploitation (CVE-2024-34359)

### Medium (ML security specialist)
- Custom operator exploitation
- Model poisoning/backdoor injection
- Format-specific magic byte corruption

### Hard (ML framework expert)
- Graph-level TensorFlow exploitation
- ONNX custom op development
- Format fuzzing for new vulnerabilities

## Remediation Priority Matrix

```
┌─────────────────────────────────────────────────────┐
│           REMEDIATION PRIORITY MATRIX                │
├────────────────────────┬─────────────────────────────┤
│ Priority   │ Vulnerabilities                        │
├────────────────────────┬─────────────────────────────┤
│ P0 (URGENT)│ CVE-2025-54412/13/86 (Skops RCE)    │
│            │ CVE-2024-34359 (GGUF SSTI)          │
│            │ Pickle RCE in production models      │
├────────────────────────┬─────────────────────────────┤
│ P1 (HIGH)  │ Embedded credentials                │
│            │ Archive bombs/directory traversal    │
│            │ Lambda layer injection              │
│            │ File system access operations        │
├────────────────────────┬─────────────────────────────┤
│ P2 (MEDIUM)│ Model poisoning                     │
│            │ Custom operators                    │
│            │ Configuration injection             │
│            │ Metadata attacks                    │
├────────────────────────┬─────────────────────────────┤
│ P3 (LOW)   │ License violations                  │
│            │ Documentation credential exposure   │
│            │ Text file tampering                │
└────────────────────────┴─────────────────────────────┘
```

## Testing & Validation

### Vulnerability Proof of Concept (PoC) Sources

#### Pickle RCE
- `pickle.Pickler().reduce()` gadget chains
- `__reduce__` method override
- Available tools: `ysoserial`, custom POC Python scripts

#### SSTI in GGUF
- llama-cpp-python repository issues
- Public PoC templates available
- Easy reproduction: craft GGUF with malicious chat_template

#### Archive Bombs
- 42.zip (classic zip bomb)
- quine.zip (polyglot bomb)
- TAR symlink bombs

#### Compression Bomb PoC
```python
# Python - Create zip bomb
data = b'A' * 1000000  # 1MB of 'A'
with zipfile.ZipFile('bomb.zip', 'w') as zf:
    zf.writestr('a.txt', data, compress_type=zipfile.ZIP_DEFLATED)
# Result: ~10KB file expands to 1MB
```

## Scanning & Detection

### Recommended Scanner Configuration

```yaml
# Example Promptfoo ModelAudit config
scanners:
  - pickle:
      enable: true
      check_dangerous_modules: true
      check_opcodes: true
  
  - skops:
      enable: true
      check_cves: [2025-54412, 2025-54413, 2025-54886]
      min_version: "0.12.0"
  
  - gguf:
      enable: true
      check_templates: true
      jinja2_filters: ["safe"]
      enable_ssti_checks: true
  
  - archives:
      enable: true
      max_compression_ratio: 100
      max_nesting_depth: 3
      check_path_traversal: true
      check_symlinks: true
  
  - credentials:
      enable: true
      patterns: ["api_key", "token", "password", "secret"]
  
  - network:
      enable: true
      detect_urls: true
      detect_ips: true
      detect_cc_patterns: true
```

## References

### CVE Details
- https://nvd.nist.gov/vuln/detail/CVE-2025-54412
- https://nvd.nist.gov/vuln/detail/CVE-2025-54413
- https://nvd.nist.gov/vuln/detail/CVE-2025-54886
- https://nvd.nist.gov/vuln/detail/CVE-2024-34359

### Security Advisories
- Scikit-learn Security Policy
- PyTorch Security
- TensorFlow Security
- Keras Security Advisories

### Paper References
- "Backdoor Attacks to Federated Learning" - various authors
- "Trojan Attacks on Neural Networks" - NDSS 2017+
- "SoK: Security and Privacy in Machine Learning" - IEEE S&P

---

**Document Version:** 1.0  
**Last Updated:** March 11, 2026  
**Maintained By:** ML Security Research Team
