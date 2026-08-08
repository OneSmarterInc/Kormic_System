import ast
import os
from pathlib import Path

def test_no_stdlib_random_in_crypto_and_token():
    """
    Ensures that the standard library `random` module is not imported in the 
    crypto or token paths. Cryptographically secure random (os.urandom or secrets) 
    must be used instead.
    """
    repo_root = Path(__file__).parent.parent
    paths_to_check = [
        repo_root / "kormic" / "crypto",
        repo_root / "kormic" / "verify",
        repo_root / "kormic" / "runtime",
        repo_root / "kormic" / "models" / "verify.py", 
        repo_root / "meshkor"
    ]
    
    files_to_check = []
    for path in paths_to_check:
        if path.is_dir():
            files_to_check.extend(path.rglob("*.py"))
        elif path.is_file():
            files_to_check.append(path)
            
    for filepath in files_to_check:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
            
        tree = ast.parse(content, filename=str(filepath))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name != "random", f"stdlib 'random' imported in {filepath} (Import)"
            elif isinstance(node, ast.ImportFrom):
                assert node.module != "random", f"stdlib 'random' imported in {filepath} (ImportFrom)"

def test_software_key_custody_dev_guard_raises_in_production(monkeypatch):
    from kormic.crypto.software import SoftwareKeyCustody
    from kormic.utils.exceptions import CryptographicError
    
    monkeypatch.setenv("KORMIC_DEPLOYMENT_MODE", "production")
    
    import pytest
    with pytest.raises(CryptographicError, match="SoftwareKeyCustody cannot be used in production mode"):
        kc = SoftwareKeyCustody()

def test_software_key_custody_dev_guard_allows_in_development(monkeypatch):
    from kormic.crypto.software import SoftwareKeyCustody
    
    monkeypatch.delenv("KORMIC_DEPLOYMENT_MODE", raising=False)
    kc = SoftwareKeyCustody()
    assert kc is not None
    
    monkeypatch.setenv("KORMIC_DEPLOYMENT_MODE", "development")
    kc2 = SoftwareKeyCustody()
    assert kc2 is not None
