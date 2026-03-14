# Machine Learning Attack Vectors by File Type

---

## Table of Contents
1. [Pickle-Based Formats](#pickle-based-formats)
2. [TensorFlow Formats](#tensorflow-formats)
3. [PyTorch Formats](#pytorch-formats)
4. [Keras Formats](#keras-formats)
5. [ONNX Format](#onnx-format)
6. [JAX/Flax Formats](#jaxflax-formats)
7. [Quantized Model Formats](#quantized-model-formats)
8. [Scientific/Numerical Formats](#scientificnumerical-formats)
9. [Tree-Based Model Formats](#tree-based-model-formats)
10. [Archive Formats](#archive-formats)
11. [Configuration & Metadata](#configuration--metadata)
12. [Neural Network Analysis](#neural-network-analysis)
13. [Cross-Format Attack Vectors](#cross-format-attack-vectors)

---

## Pickle-Based Formats

### 1. **Pickle Files** (.pkl, .pickle, .dill)
**File Extensions:** `.pkl`, `.pickle`, `.dill`, `.bin` (when containing pickle data), `.pt`, `.pth`, `.ckpt`

#### Attack Vectors:
- **Arbitrary Code Execution (ACE)**
  - Malicious pickle opcodes (REDUCE, INST, OBJ, NEWOBJ, STACK_GLOBAL)
  - Dangerous function imports (os, subprocess, sys modules)
  - eval/exec function calls embedded in pickle bytecode
  - Custom unpickler exploitation

- **Module Import Injection**
  - Import malicious modules (e.g., `os.system`, `subprocess.call`)
  - Load from untrusted module sources
  - Side-effect execution during module loading

- **Encoded Payloads**
  - Base64/hex-encoded malicious code bypassing string pattern detection
  - Obfuscated pickle opcodes
  - Compressed payloads

- **Network Communication**
  - Embedded URLs and IP addresses in pickle data
  - Socket connections to C&C servers
  - Data exfiltration callbacks

- **File System Access**
  - File read/write operations during unpickling
  - Access to sensitive system directories
  - Configuration file manipulation

- **Embedded Executables**
  - PE (Windows), ELF (Linux), Mach-O (macOS) binaries in pickle data
  - Shell scripts with shebangs
  - Script execution patterns

---

### 2. **PyTorch Model Files** (.pt, .pth)
**File Extensions:** `.pt`, `.pth`

#### Attack Vectors:
- **Malicious Pickle Embedding**
  - PyTorch models are ZIP archives containing pickled objects
  - All pickle vulnerabilities apply to embedded pickle files
  - Multiple pickle chains for complex attack payloads

- **Embedded Python Code Files**
  - Python source files (.py) bundled in the model archive
  - Executable scripts at import time
  - Custom layer definitions with malicious code

- **Executable Binaries**
  - Binary executables bundled in PyTorch models
  - Platform-specific payloads (Windows PE, Linux ELF)
  - Loader scripts for multi-stage attacks

- **Suspicious Serialization**
  - Modified torch.nn.Module serialization
  - Custom forward() methods with side effects
  - State dict manipulation

---

### 3. **Joblib Files** (.joblib)
**File Extensions:** `.joblib`

#### Attack Vectors:
- **Compression Bomb (DoS)**
  - Suspicious compression ratios (>100x)
  - Decompression bombs causing memory exhaustion
  - ZIP bomb patterns within joblib

- **Embedded Pickle Analysis**
  - Joblib files contain compressed pickle data
  - All pickle vulnerabilities inherit to joblib format
  - Multiple pickle chains in decompressed state

- **Resource Exhaustion**
  - Excessively large decompressed sizes
  - Memory exhaustion attacks
  - CPU exhaustion during decompression

- **Format Validation Bypass**
  - Malformed pickle within joblib wrapper
  - Mixed format exploitation (ZIP + pickle)
  - Corrupted compression metadata

---

### 4. **Skops Files** (.skops, .pkl)
**File Extensions:** `.skops`, `.pkl` (skops format)

#### Attack Vectors:
- **Known CVE Exploitation**
  - **CVE-2025-54412:** Remote code execution via malicious sklearn estimator
  - **CVE-2025-54413:** Arbitrary code execution through sklearn.compose.ColumnTransformer
  - **CVE-2025-54886:** Code execution via callable arguments in estimators
  - Affects skops versions < 0.12.0

- **Malicious Callables**
  - Embedded Python functions in estimator parameters
  - Lambda functions with side effects
  - Custom transformers with arbitrary code

- **Dangerous Components**
  - **Pipeline**: Chain of malicious estimators
  - **ColumnTransformer**: Custom transformers with code injection
  - **FunctionTransformer**: Arbitrary function execution
  - **GridSearchCV**: Malicious parameter grids with callables

- **Estimator Manipulation**
  - Poisoned fit/predict methods
  - Custom scorers with code execution
  - Validation curve exploitation

---

## TensorFlow Formats

### 5. **TensorFlow SavedModel** (.pb files and SavedModel directories)
**File Extensions:** `.pb`

#### Attack Vectors:
- **Malicious TensorFlow Operations**
  - File system access operations (ReadFile, WriteFile, ListDir)
  - System command execution (py_func, PyFunc)
  - Environment variable access

- **Python Function Embedding**
  - Python functions in the computation graph
  - py_func operations executing arbitrary Python
  - Python code in operation attributes

- **Arbitrary Code Execution**
  - TF-Lite's custom operations calling external code
  - Python layer definitions with side effects
  - Custom gradient implementations with exploits

- **File I/O Operations**
  - Unexpected file system access patterns
  - Configuration file manipulation
  - Credential file extraction

- **System Command Execution**
  - os.system() equivalents in TensorFlow ops
  - subprocess calls through graph operations
  - Shell command injection in model paths

---

### 6. **TensorFlow Lite** (.tflite)
**File Extensions:** `.tflite`

#### Attack Vectors:
- **Custom Operations (Custom Ops)**
  - Malicious code in custom operation implementations
  - Native C/C++ code execution
  - Platform-specific payload delivery

- **Flex Delegate Exploitation**
  - Full TensorFlow runtime access via Flex delegate
  - Circumvention of Lite's safety restrictions
  - Access to full TensorFlow op set

- **Model Metadata Injection**
  - Executable content embedded in metadata
  - Metadata field deserialization vulnerabilities
  - Configuration injection

- **Operator Configuration**
  - Suspicious operator parameters
  - Invalid tensor shapes for buffer overflow
  - Resource exhaustion configs

- **Buffer Tampering**
  - Corrupted tensor data for format exploits
  - Invalid offsets causing memory access
  - Decompression bomb patterns

---

## PyTorch Formats

### 7. **PyTorch Binary Format** (.bin files)
**File Extensions:** `.bin` (raw PyTorch tensor files)

#### Attack Vectors:
- **Embedded Code Patterns**
  - Python import statements in binary
  - Function call patterns (eval, exec)
  - Module instantiation code

- **Executable File Embedding**
  - Windows PE files (with DOS stub validation)
  - Linux ELF files
  - macOS Mach-O files
  - Android DEX files

- **Script Shebangs**
  - Shell script magic bytes (#!)
  - Bash/Python interpreter invocation
  - Encoded shell commands

- **Tensor Validation Bypass**
  - Malformed tensor structure
  - Invalid shape definitions
  - Type confusion attacks

- **Suspicious File Sizes**
  - Suspiciously small files (invalid tensor data)
  - Size mismatch with header claims
  - Padding exploitation

---

### 8. **ExecuTorch Format** (.pte, .pt)
**File Extensions:** `.pte`, `.pt` (ExecuTorch archives)

#### Attack Vectors:
- **Embedded Pickle Exploitation**
  - All pickle vulnerabilities in ExecuTorch archives
  - Multiple pickle files in single archive
  - Custom unpickler exploitation

- **Bundled Python/Executables**
  - Python files executed at import
  - Binary executables for edge devices
  - Mobile-specific payloads

- **Dangerous Metadata**
  - Configuration data with code injection
  - Custom operator definitions
  - Serialization format manipulation

- **Custom Operators**
  - Malicious operator implementation
  - Native code execution on edge devices
  - Resource-constrained exploitation

- **Mobile Deployment Risk**
  - Limited monitoring on edge devices
  - Privileged execution context
  - Data access without oversight

---

## Keras Formats

### 9. **Keras H5 Format** (.h5, .hdf5)
**File Extensions:** `.h5`, `.hdf5`

#### Attack Vectors:
- **Unsafe Lambda Layers**
  - Arbitrary Python code in Lambda layer definitions
  - Code execution during model loading
  - Function serialization vulnerabilities

- **Custom Layer Exploitation**
  - Malicious layer implementations
  - Code injection through layer parameters
  - Custom metric functions with side effects

- **Dangerous String Patterns**
  - Function names containing exploit code
  - Serialized Python bytecode
  - Obfuscated function definitions

- **Model Configuration Injection**
  - Unsafe deserialization in config
  - Python code in layer definitions
  - Custom loss function exploitation

- **HDF5 Format Vulnerabilities**
  - Malformed HDF5 structure
  - Chunk size exploitation
  - Compression algorithm bypass

---

### 10. **Keras ZIP Format** (.keras)
**File Extensions:** `.keras` (Keras 3 format)

#### Attack Vectors:
- **Base64-Encoded Lambda Layers**
  - Lambda layer code as base64 strings
  - Decoding-time payload execution
  - Obfuscated code patterns

- **ZIP Archive Exploitation**
  - Embedded Python files in archive
  - Executable scripts (.py) in model package
  - Archive bomb within layers zip

- **Custom Objects Injection**
  - Custom layer deserialization
  - Malicious get_config implementations
  - from_config method exploitation

- **Configuration JSON Injection**
  - Code execution through JSON deserialization
  - Path traversal in file references
  - External resource loading

---

## ONNX Format

### 11. **ONNX Model** (.onnx)
**File Extensions:** `.onnx`

#### Attack Vectors:
- **Custom Operator Exploitation**
  - Malicious custom op implementations
  - Native code execution via custom ops
  - Undefined operator behavior exploitation

- **External Data References**
  - Path traversal attacks (../../etc/passwd)
  - Directory escape sequences
  - Unauthorized file access

- **Tensor Integrity Attacks**
  - Incorrect tensor dimensions
  - Size mismatches causing buffer overflow
  - Type confusion in tensor data

- **Data Tampering**
  - File size mismatches vs. actual content
  - Corrupted tensor metadata
  - Integrity check bypass

- **Model Graph Manipulation**
  - Suspicious operation chains
  - Graph execution order exploitation
  - Initializer data poisoning

---

## JAX/Flax Formats

### 12. **Flax/JAX Model Files** (.msgpack, .flax, .orbax, .jax)
**File Extensions:** `.msgpack`, `.flax`, `.orbax`, `.jax`

#### Attack Vectors:
- **Malicious MessagePack Structures**
  - Exploit msgpack deserializers
  - Recursive object structures (DoS)
  - Custom type poisoning

- **Embedded Code Objects**
  - Serialized Python code objects
  - Executable bytecode in archive
  - Function definition injection

- **Resource Exhaustion**
  - Oversized data structures
  - Deeply nested objects
  - Memory allocation bombs

- **Dependency Message Injection**
  - Malformed msgpack headers
  - Invalid type indicators
  - Corrupted length fields

---

### 13. **JAX Checkpoint Format** (.ckpt, .checkpoint, .orbax-checkpoint)
**File Extensions:** `.ckpt`, `.checkpoint`, `.orbax-checkpoint`, `.pickle` (JAX context)

#### Attack Vectors:
- **Experimental Callbacks Exploitation**
  - jax.experimental.host_callback.call functions
  - Callback execution with host privileges
  - Side-channel attacks via callbacks

- **Orbax Custom Restore Functions**
  - Arbitrary functions in checkpoint metadata
  - Restore-time code execution
  - Custom restoration logic exploitation

- **Dangerous Pickle Opcodes**
  - Pickle files in JAX serialization
  - All standard pickle vulnerabilities
  - Multi-stage deserialization

- **Directory Structure Exploitation**
  - Checkpoint directory traversal
  - Split checkpoint file manipulation
  - Metadata corruption

- **Resource Limits Bypass**
  - Oversized checkpoint files
  - Memory exhaustion during restore
  - Disk space exhaustion

---

## Quantized Model Formats

### 14. **GGUF/GGML Format** (.gguf, .ggml, .ggmf, .ggjt, .ggla, .ggsa)
**File Extensions:** `.gguf`, `.ggml`, `.ggmf`, `.ggjt`, `.ggla`, `.ggsa`

#### Attack Vectors:
- **Header Validation Bypass**
  - Malformed magic bytes
  - Invalid version numbers
  - Structure corruption

- **Metadata Injection**
  - Path traversal in JSON metadata
  - Code injection in metadata strings
  - Malicious tokenizer configuration
  - **CVE-2024-34359**: Template injection in chat_template field

- **Tensor Integrity Attack**
  - Invalid tensor dimensions
  - Size mismatches (decompression bomb)
  - Type confusion attacks

- **Compression Validation Bypass**
  - Suspicious compression ratios
  - Decompression bomb patterns
  - Resource exhaustion via compression

- **Jinja2 Template Injection**
  - Malicious chat_template fields
  - Server-side template injection (SSTI)
  - Unsafe filter usage (eval, exec, import)

---

## Scientific/Numerical Formats

### 15. **NumPy Arrays** (.npy, .npz)
**File Extensions:** `.npy`, `.npz`

#### Attack Vectors:
- **Object Array Exploitation**
  - Object dtype arrays containing code
  - Python objects during deserialization
  - Arbitrary class instantiation

- **Header Integrity Bypass**
  - Malformed NumPy headers
  - Invalid magic numbers
  - Corrupted dtype specifications

- **Dangerous Data Types**
  - Object references in arrays
  - Callable objects in array data
  - Recursive object structures

- **Memory Exhaustion (DoS)**
  - Extremely large array dimensions
  - Integer overflow in size calculation
  - Memory allocation bombs

- **ZIP Exploitation (NPZ)**
  - ZIP bomb within .npz files
  - Nested array explosion
  - Directory traversal in NPZ archives

---

## Tree-Based Model Formats

### 16. **XGBoost Model** (.bst, .model, .json, .ubj)
**File Extensions:** `.bst`, `.model`, `.json`, `.ubj`

#### Attack Vectors:
- **Custom Objective/Metric Exploitation**
  - Custom Python functions for objectives
  - Arbitrary code in metric definitions
  - Callback function injection

- **Embedded Pickle (Binary Format)**
  - Pickle serialization in .bst files
  - All pickle vulnerabilities apply
  - Custom object pickle chains

- **JSON Code Injection**
  - embedded_code fields with Python
  - Dangerous string patterns in config
  - Custom objective code evaluation

- **External Feature Map Traversal**
  - Path traversal in feature names
  - Directory escape in file references
  - Unauthorized file access

- **UBJSON Format Exploitation**
  - Malformed UBJSON structures
  - Type confusion attacks
  - Recursive object bombs

---

### 17. **PaddlePaddle Model** (.pdmodel, .pdiparams)
**File Extensions:** `.pdmodel`, `.pdiparams`

#### Attack Vectors:
- **Suspicious Operations in Definition**
  - Operations accessing file system
  - System command execution ops
  - Environment variable access

- **Embedded Pickle Data**
  - Pickle serialization within PaddlePaddle
  - All pickle vulnerabilities apply
  - Custom operator exploitation

- **Custom Operator Malice**
  - Native code execution via custom ops
  - C++ implementation exploitation
  - Platform-specific payloads

- **Configuration Injection**
  - Dangerous patterns in model params
  - Executable content in config
  - Path traversal in settings

---

### 18. **PMML Model** (.pmml)
**File Extensions:** `.pmml`

#### Attack Vectors:
- **XML External Entity (XXE) Attack**
  - Malicious DOCTYPE declarations
  - ENTITY definitions for XXE
  - External DTD loading
  - Billion Laughs attack

- **Embedded Scripts**
  - JavaScript code in extensions
  - Python code in PMML extensions
  - Script execution at parse time

- **Malicious Content Patterns**
  - eval()/exec() in extension elements
  - System command strings
  - Module imports in PMML

- **External Resource References**
  - HTTP/HTTPS URLs pointing to malicious content
  - FTP references for file retrieval
  - file:// URLs for local file access
  - Recursive entity expansion

- **PMML Extension Exploitation**
  - Extension elements with arbitrary content
  - Custom namespace handlers
  - Unsafe XML deserialization

---

### 19. **OpenVINO Model** (.xml, .bin)
**File Extensions:** `.xml`, `.bin` (OpenVINO IR format)

#### Attack Vectors:
- **Suspicious Custom Layer Config**
  - Custom layer type definitions
  - Malicious layer parameters
  - Reference to external code

- **External Data References**
  - Path traversal with ../../ patterns
  - Unauthorized file access
  - Directory escape sequences

- **Malformed XML Structure**
  - Invalid XML hierarchy
  - Oversized files causing DoS
  - Chunk size exploitation

- **System Resource Layer Types**
  - File read operations
  - System command execution
  - Network communication ops

- **Plugin Reference Exploitation**
  - Unauthorized plugin loading
  - Malicious extension registration
  - DLL/SO injection

---

## Archive Formats

### 20. **ZIP Archive** (.zip, .npz)
**File Extensions:** `.zip`, `.npz`

#### Attack Vectors:
- **Directory Traversal**
  - Paths with ../ escape sequences
  - Absolute path exploitation
  - Symbolic link abuse
  - File overwrite attacks

- **Zip Bomb (DoS)**
  - Compression ratio > 100x
  - Nested ZIP within ZIP
  - Decompressed size explosions
  - Memory exhaustion

- **Nested Archive Recursion**
  - ZIP within ZIP within ZIP
  - Infinite recursion potential
  - Resource exhaustion via depth

- **Malicious Content Smuggling**
  - Executable files embedded
  - Script files in archive
  - Polyglot file exploitation

- **Resource Limits Exhaustion**
  - Excessive file count
  - Single file size limits
  - Cumulative decompression limit

---

### 21. **TAR Archive** (.tar, .tar.gz, .tgz, .tar.bz2)
**File Extensions:** `.tar`, `.tar.gz`, `.tgz`, `.tar.bz2`

#### Attack Vectors:
- **Directory Traversal**
  - Paths with ../ sequences
  - Absolute paths in archive
  - Root directory extraction

- **Symlink Attacks**
  - Symlinks to /etc/passwd
  - Symlinks to sensitive files
  - Directory escape via links
  - TOCTOU race conditions

- **TAR Bomb**
  - Excessive file count
  - Decompression explosion
  - Resource exhaustion
  - CPU exhaustion during extraction

- **File Permission Exploitation**
  - SetUID bit abuse
  - Group ownership manipulation
  - Privilege escalation via perms

- **Metadata Injection**
  - Malicious ownership info
  - Extended attributes with code
  - ACL exploitation

---

### 22. **7-Zip Archive** (.7z)
**File Extensions:** `.7z`

#### Attack Vectors:
- **Directory Traversal**
  - Path with ../ components
  - Absolute path exploitation
  - Symlink abuse to escape

- **Compression Bomb**
  - High compression ratio (>> 100x)
  - Resource exhaustion during decompression
  - Memory allocation attack

- **Encrypted Content**
  - Hidden payloads in encrypted sections
  - Encryption bypass via corruption
  - Brute-force resistant encryption

- **Nested Archive Exploitation**
  - 7Z within 7Z recursion
  - Infinite depth extraction
  - Resource limit bypass

- **CPU/Memory Resource Attack**
  - Decompression consuming all CPU
  - Memory allocation bombing
  - Disk I/O exhaustion

---

## Configuration & Metadata

### 23. **Manifest/Configuration Files** (.json, .yaml, .yml, .xml, .toml, .config)
**File Extensions:** `.json`, `.yaml`, `.yml`, `.xml`, `.toml`, `.config`, etc.

#### Attack Vectors:
- **Blacklisted Model Names**
  - Known vulnerable model references
  - Trojan model versions
  - Compromised model URLs

- **Network Access Patterns**
  - Suspicious URLs in config
  - Webhook endpoint injection
  - Remote code execution URLs
  - C&C server addresses

- **File System Access**
  - Paths to sensitive files
  - Directory traversal patterns
  - Unauthorized file operations

- **Code Execution Directives**
  - Shell commands in config
  - Script execution paths
  - Shell access settings

- **Credential Exposure**
  - Hardcoded passwords
  - API tokens in clear text
  - Database connection strings

---

### 24. **Model Documentation** (README.md, MODEL_CARD.md)
**File Extensions:** `README.md`, `MODEL_CARD.md`, `METADATA.md`

#### Attack Vectors:
- **Embedded Credentials**
  - API keys in examples
  - Tokens in setup instructions
  - SSH keys in documentation

- **Malicious Download Links**
  - URLs to trojan models
  - Command injection in examples
  - Phishing model URLs

- **Vulnerable Component References**
  - Known vulnerable library versions
  - Compromised dependency URLs
  - Outdated package versions

- **Misleading Descriptions**
  - Deceptive model purpose
  - Hidden capability disclosure
  - Trojan horse labeling

- **Missing Security Info**
  - No vulnerability disclosure
  - Hidden attack surface
  - Incomplete security assessment

---

### 25. **Text Files** (.txt, .md, .rst)
**File Extensions:** `.txt`, `.md`, `.markdown`, `.rst`

#### Attack Vectors:
- **Data Hiding**
  - Unusually large vocabulary files
  - Encoded malicious content
  - Steganography in labels

- **File Type Confusion**
  - vocab.txt containing code
  - labels.txt with executable content
  - README with binary data

- **Social Engineering**
  - Malicious instructions in documentation
  - Deceptive descriptions
  - Trojan task descriptions

---

### 26. **Jinja2 Templates** (.jinja, .j2, .template in GGUF, config files)
**File Extensions:** `.gguf`, `.json`, `.yaml`, `.jinja`, `.j2`, `.template`

#### Attack Vectors:
- **Server-Side Template Injection (SSTI)**
  - {{ 7*7 }} expression exploitation
  - {{ config.__class__ }} access
  - {{ [].__class__.__bases__[0].__subclasses__() }} enumeration

- **Dangerous Jinja2 Filters**
  - |eval filter usage
  - |exec filter exploitation
  - |import filter for module loading
  - Custom filter code execution

- **Unrestricted Variable Access**
  - config variable exposure
  - request object access
  - Environment variable leakage

- **Code Execution Patterns**
  - Python code in {{ }} brackets
  - Macro definition manipulation
  - Include/import path traversal

- **CVE-2024-34359**
  - llama-cpp-python Jinja2 SSTI
  - chat_template field injection
  - Remote code execution via templates

---

## Neural Network Analysis

### 27. **Weight Distribution Analysis**
**Applicable to:** `.pt`, `.pth`, `.h5`, `.keras`, `.hdf5`, `.pb`, `.onnx`, `.safetensors`

#### Attack Vectors:
- **Backdoor Detection via Outliers**
  - Outlier neurons with abnormal weights
  - Z-score analysis (threshold: 3.0)
  - Unusual weight magnitudes
  - Hidden trigger neurons

- **Dissimilar Weight Vectors**
  - Cosine similarity < 0.7 (threshold)
  - Anomalous neuron patterns
  - Different weight distributions per neuron
  - Trojan-specific neuron signatures

- **Extreme Weight Values**
  - Individual weights > 3σ from mean
  - Trigger activation weights
  - Backdoor neuron indicators

- **Final Layer Backdoors**
  - Classification head manipulation
  - Output layer trigger neurons
  - Adversarial activation patterns
  - Hidden class activation bypasses

- **LLM-Specific Indicators**
  - Vocabulary layer anomalies (>10k vocab)
  - Token embedding poisoning
  - Embedding space trojans
  - Instruction-following backdoors

---

## SafeTensors

### 28. **SafeTensors Format** (.safetensors, .bin with SafeTensors data)
**File Extensions:** `.safetensors`, `.bin`

#### Attack Vectors:
- **Header Corruption Bypass**
  - Invalid JSON header
  - Malformed header structure
  - Header integrity check failure

- **Metadata Injection**
  - Malicious content in metadata
  - Large metadata sections (resource abuse)
  - Encoded payloads in metadata
  - Path traversal in metadata strings

- **Tensor Offset Manipulation**
  - Invalid tensor offsets
  - Out-of-bounds tensor access
  - Overlapping tensor definitions
  - Buffer overflow via offset

- **Data Type Confusion**
  - Incorrect dtype specifications
  - Size mismatch with actual data
  - Type conversion exploits
  - Alignment issues

- **Resource Exhaustion**
  - Excessively large tensors
  - Invalid tensor dimensions
  - Memory allocation bombing

---

## Cross-Format Attack Vectors

### 29. **Embedded Credentials**
**Affects:** All formats with text/config data

#### Attack Vectors:
- **API Keys**
  - AWS access keys
  - Azure credentials
  - GCP service keys
  - OpenAI API keys
  - Hugging Face tokens

- **Authentication Tokens**
  - JWT tokens
  - OAuth tokens
  - GitHub personal access tokens
  - Bearer tokens

- **Private Keys**
  - SSH private keys
  - SSL/TLS certificates
  - Cryptographic keys
  - Encryption keys

- **Database Credentials**
  - Connection strings with passwords
  - Database URLs with auth
  - Hardcoded credentials

- **Webhook URLs**
  - Slack webhooks
  - Discord webhooks
  - Custom webhook endpoints

---

### 30. **Network Communication**
**Affects:** All formats with code execution potential

#### Attack Vectors:
- **Command & Control (C&C)**
  - beacon_url patterns
  - callback_url endpoints
  - exfil_endpoint definitions
  - callback server definitions

- **URL Patterns**
  - HTTP/HTTPS malicious URLs
  - FTP URLs for file retrieval
  - SSH URLs for remote access
  - WebSocket endpoints

- **IP Address Hardcoding**
  - IPv4 C&C addresses
  - IPv6 C&C addresses
  - DNS server overrides
  - Shadowsocks/VPN configs

- **Domain C&C**
  - Domain generation algorithms (DGA)
  - Fast-flux domains
  - Dynamic DNS updates
  - Subdomain takeover

- **Network Library Usage**
  - socket module imports
  - urllib module usage
  - requests library calls
  - 50+ other network libraries

- **Network Operations**
  - urlopen calls
  - socket.connect() calls
  - requests.get() calls
  - HTTP client initialization

---

### 31. **JIT/Script Execution**
**Affects:** TensorFlow, PyTorch, JAX, ONNX

#### Attack Vectors:
- **TorchScript Code**
  - Embedded TorchScript bytecode
  - Dynamic script execution
  - Module script injection
  - Custom script functions

- **ONNX Custom Operators**
  - Custom operator libraries
  - Native code execution
  - External library loading
  - Plugin modification

- **TensorFlow Eager Execution**
  - Dynamic execution patterns
  - tf.py_function exploitation
  - Python code in graph
  - Runtime code generation

- **Compilation Exploitation**
  - eval() in compiled code
  - exec() in executed scripts
  - compile() dynamic code
  - Runtime bytecode injection

- **Script Injection**
  - JavaScript injection
  - Python script injection
  - Shell script injection
  - Bash command injection

---

### 32. **License & Compliance Vulnerabilities**
**Affects:** All formats

#### Attack Vectors:
- **AGPL License Exploitation**
  - Network copyleft obligations
  - Source code disclosure requirement
  - AGPLv3 users forced open-source
  - Commercial viability risk

- **Non-Commercial Restrictions**
  - Creative Commons NonCommercial blocks
  - Academic-only licenses
  - Company usage violations
  - Licensing compliance breach

- **Unlicensed Content**
  - Large unlicensed datasets
  - Copyright violations
  - Intellectual property infringement
  - Legal liability

- **Mixed License Risk**
  - Incompatible license combinations
  - License conflict resolution
  - Derivative work licensing
  - SBOM generation gaps

---

## Attack Vector Summary by Risk Level

### CRITICAL (Remote Code Execution)
- Pickle deserialization (all formats)
- Skops CVE-2025-54412, CVE-2025-54413, CVE-2025-54886
- TensorFlow py_func operations
- Keras Lambda layers
- GGUF Template Injection (CVE-2024-34359)
- PMML XXE attacks
- Archive directory traversal

### HIGH (Data Exfiltration / System Access)
- Network communication patterns
- Embedded credentials (API keys, tokens)
- File system access operations
- Custom operators in ONNX, XGBoost
- Configuration injection
- Symbolic link attacks in TAR

### MEDIUM (Denial of Service / Tampering)
- Compression bombs (Zip/TAR/7Z)
- Model poisoning via corrupt tensors
- Resource exhaustion attacks
- Buffer overflow via malformed headers
- Backdoor detection via weight analysis

### LOW (Information Disclosure / Compliance)
- License violations
- Metadata injection
- Documentation credential exposure
- Suspicious model naming

---

## Detection Mitigation

### File Type Coverage
✅ Covered by Promptfoo ModelAudit:
- Pickle, PyTorch ZIP, Joblib, Skops
- TensorFlow SavedModel, TensorFlow Lite
- Keras H5, Keras ZIP
- ONNX, OpenVINO
- Flax/JAX
- GGUF/GGML
- NumPy
- SafeTensors
- XGBoost, PaddlePaddle
- PMML
- Archive formats (ZIP, TAR, 7-Zip)
- Configuration files
- Text files, metadata files

### Recommended Scanning Strategy

1. **File Format Detection** (Auto)
   - Magic byte analysis
   - Extension validation
   - Content-based routing

2. **Format-Specific Scanning**
   - Apply appropriate scanner per format
   - Check all vulnerability classes
   - Validate integrity

3. **Cross-Format Analysis**
   - Network patterns
   - Credential extraction
   - Code patterns
   - JIT/Script detection

4. **Archive Handling**
   - Recursive extraction
   - Size limit enforcement
   - Decompression bomb detection
   - Symlink validation

5. **Configuration Review**
   - Manifest scanning
   - Model card analysis
   - Metadata validation
   - License compliance

---

## References

- Promptfoo ModelAudit: https://www.promptfoo.dev/docs/model-audit/scanners/
- Document Date: March 11, 2026
- Last Updated: March 11, 2026
