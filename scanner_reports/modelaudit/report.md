# ModelAudit Detection Coverage Report

| | |
|---|---|
| **SARIF file** | `scanner_reports\modelaudit\modelaudit.json` |
| **Attack vectors** | `attack_vectors_output` |
| **Date** | 2026-03-13 |

## Summary

| Metric | Count |
|---|---:|
| Total checks | 1252 |
| Passed checks | 1058 |
| Failed checks (findings) | 194 |
| Total SARIF results | 1259 |

## Detection Coverage by Vector Type

| Vector Type | Files on Disk | Scanned | w/ Findings | Detection % | Errors | Warnings | Notes |
|---|---:|---:|---:|---:|---:|---:|---:|
| Advanced Pickle Obfuscation ✅ | 5 | 5 | 5 | 100% | 14 | 3 | 0 |
| Advanced Weight Poisoning | 6 | 6 | 2 | 33% | 0 | 0 | 4 |
| Archive / ZIP ✅ | 8 | 8 | 8 | 100% | 13 | 4 | 1 |
| Flax / JAX | 6 | 6 | 1 | 17% | 2 | 0 | 0 |
| GGUF | 9 | 9 | 3 | 33% | 0 | 0 | 5 |
| Jinja2 SSTI Bypass ✅ | 8 | 8 | 8 | 100% | 11 | 23 | 0 |
| Joblib ✅ | 2 | 2 | 2 | 100% | 4 | 2 | 1 |
| Keras / H5 | 8 | 8 | 1 | 12% | 0 | 1 | 0 |
| NumPy ✅ | 8 | 8 | 8 | 100% | 3 | 6 | 9 |
| ONNX | 7 | 7 | 2 | 29% | 0 | 0 | 3 |
| OpenVINO ❌ | 4 | 4 | 0 | 0% | 0 | 0 | 0 |
| PaddlePaddle | 4 | 4 | 1 | 25% | 4 | 1 | 0 |
| Pickle | 8 | 8 | 6 | 75% | 26 | 6 | 0 |
| PMML ✅ | 2 | 2 | 2 | 100% | 0 | 2 | 0 |
| PyTorch | 8 | 8 | 7 | 88% | 27 | 17 | 2 |
| SafeTensors | 5 | 5 | 4 | 80% | 1002 | 2 | 3 |
| Supply Chain ✅ | 6 | 6 | 6 | 100% | 24 | 4 | 2 |
| TensorFlow ❌ | 8 | 8 | 0 | 0% | 0 | 0 | 0 |
| TensorRT | 3 | 3 | 1 | 33% | 2 | 0 | 0 |
| TFLite | 5 | 5 | 1 | 20% | 1 | 0 | 0 |
| XGBoost ✅ | 3 | 3 | 3 | 100% | 6 | 1 | 0 |
| **TOTAL** | **123** | **123** | **71** | **58%** | **1139** | **72** | **30** |

## Detection Gaps (Files with No Findings)

### Advanced Pickle Obfuscation

- `04_posix_alias_attack.pkl`

### Advanced Weight Poisoning

- `02_trigger_based_activation.pt`
- `03_gradient_evasion_poisoning.npz`
- `05_feature_extraction_trojan.pt`
- `06_distribution_aware_poisoning.npz`

### Flax / JAX

- `01_host_callback_exploit.msgpack`
- `02_msgpack_exploit.msgpack`
- `03_orbax_restore_exploit.msgpack`
- `04_pickle_in_jax.msgpack`
- `05_bytecode_injection.msgpack`

### GGUF

- `01_basic_ssti.gguf`
- `02_class_traversal_ssti.gguf`
- `03_module_access_ssti.gguf`
- `05_multiline_ssti.gguf`
- `07_compression_bomb.gguf`
- `08_polyglot_gguf.gguf`

### Keras / H5

- `01_basic_lambda_layer.h5`
- `02_lambda_with_imports.h5`
- `03_custom_layer_attack.h5`
- `04_hidden_layer_payload.h5`
- `05_lambda_exfiltration.h5`
- `07_loss_injection.h5`
- `08_keras_zip_format.keras`

### ONNX

- `02_external_data_traversal.onnx`
- `03_tensor_integrity_attack.onnx`
- `04_operator_chaining.onnx`
- `06_sparse_tensor_exploit.onnx`
- `07_graph_attribute_injection.onnx`

### OpenVINO

- `01_custom_layer_exploit.bin`
- `01_custom_layer_exploit.xml`
- `02_data_traversal.bin`
- `02_data_traversal.xml`

### PaddlePaddle

- `01_file_operations.pdmodel`
- `03_custom_operator.pdiparams`
- `03_custom_operator.pdmodel`

### Pickle

- `03_module_import_attack.pkl`
- `04_eval_injection.pkl`
- `08_obfuscated_payload.pkl`

### PyTorch

- `01_malicious_state_dict.pt`

### SafeTensors

- `04_dtype_confusion.safetensors`

### TensorFlow

- `custom_gradient_injection_savedmodel`
- `custom_op_ops`
- `env_var_access_ops`
- `file_read_write_ops_savedmodel`
- `protobuf_deserialization_savedmodel`
- `py_func_rce_savedmodel_native`
- `shell_command_ops`
- `variable_init_attack_savedmodel`

### TensorRT

- `02_serialization_exploit.plan`
- `03_calibration_cache_poisoning.cache`

### TFLite

- `01_custom_operator_rce.tflite`
- `03_metadata_injection.tflite`
- `04_operator_config_exploit.tflite`
- `05_buffer_tampering.tflite`

