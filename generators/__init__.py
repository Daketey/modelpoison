"""
ML Attack Vector Generator Package

This package provides tools for generating baseline attack vectors
for machine learning model files across different formats.

Supports:
- Pickle-based formats (.pkl, .joblib, .pt, .pth)
- Archive formats (.zip, .tar, .7z)
- Configuration files (.json, .yaml)
- Keras models (.h5, .keras)
- GGUF quantized models
- ONNX neural networks
- And more...

Usage:
    from generators.orchestrator import AttackVectorOrchestrator
    
    orchestrator = AttackVectorOrchestrator(output_dir="./attack_vectors")
    report = orchestrator.generate_all()
    print(report)
"""

__version__ = "1.0.0"
__author__ = "ML Security Research"
__all__ = [
    "orchestrator",
    "pickle_vectors",
    "archive_vectors",
    "config_vectors",
    "keras_vectors",
    "gguf_vectors",
    "onnx_vectors",
    "compression_vectors",
]
