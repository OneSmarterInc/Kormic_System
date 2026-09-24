import ast
import os
import pytest
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

def test_no_private_key_access_outside_crypto():
    """
    Ensures that private key attributes (_root_priv, _epoch_keys, _revoked_epochs, _epoch_certificates)
    are never accessed by any module outside of kormic.crypto.
    """
    repo_root = Path(__file__).parent.parent
    paths_to_check = [
        repo_root / "kormic",
        repo_root / "meshkor"
    ]
    
    files_to_check = []
    for path in paths_to_check:
        if path.is_dir():
            files_to_check.extend(path.rglob("*.py"))
            
    private_attrs = {"_root_priv", "_epoch_keys", "_revoked_epochs", "_epoch_certificates"}
    
    for filepath in files_to_check:
        # Exclude the actual custody implementation from this check
        if "crypto" in filepath.parts and "software.py" in filepath.name:
            continue
            
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
            
        tree = ast.parse(content, filename=str(filepath))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                if node.attr in private_attrs:
                    pytest.fail(f"Private key attribute '{node.attr}' accessed in {filepath}")

def test_crypto_imports_no_ui_network():
    """
    Guard A: Ensures that the crypto package imports no UI or network libraries.
    Prevents accidental overwrites of crypto modules with CLI tools.
    """
    repo_root = Path(__file__).parent.parent
    crypto_dir = repo_root / "kormic" / "crypto"
    
    FORBIDDEN_IN_CRYPTO = {"rich", "questionary", "requests", "httpx",
                           "fastapi", "flask", "click", "typer"}
    
    for filepath in crypto_dir.rglob("*.py"):
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
            
        tree = ast.parse(content, filename=str(filepath))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    # e.g. import rich
                    base_module = alias.name.split('.')[0]
                    assert base_module not in FORBIDDEN_IN_CRYPTO, f"Forbidden library '{alias.name}' imported in {filepath} (Import)"
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    base_module = node.module.split('.')[0]
                    assert base_module not in FORBIDDEN_IN_CRYPTO, f"Forbidden library '{node.module}' imported in {filepath} (ImportFrom)"

def test_sidecar_entry_points_hold_no_private_keys():
    """
    Guard B: Ensures sidecar/client entry points never touch private key material.
    """
    repo_root = Path(__file__).parent.parent
    must_be_clean = [
        repo_root / "meshkor" / "cli.py",
        repo_root / "meshkor" / "sidecar_daemon.py",
        repo_root / "meshkor" / "hq_client.py",
        repo_root / "meshkor" / "authority.py",
        repo_root / "meshkor" / "integrations" / "kormic.py"
    ]
    
    FORBIDDEN_STRINGS = ["_epoch_keys", "_root_priv", "fetch_test_keys"]
    
    for filepath in must_be_clean:
        if not filepath.exists():
            continue
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
            
        # Fast string check first
        for forbidden in FORBIDDEN_STRINGS:
            if forbidden in content:
                pytest.fail(f"Forbidden private key material '{forbidden}' found in {filepath.name}")
                
        # Kormic wrapper specifically cannot use LocalAuthority
        if "kormic.py" in filepath.name and "LocalAuthority" in content:
            pytest.fail(f"Kormic integration wrapper {filepath.name} illegally imports LocalAuthority")
                
        # AST check for assigned variables named 'priv'
        tree = ast.parse(content, filename=str(filepath))
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                if node.id == "priv":
                    pytest.fail(f"Variable 'priv' assigned in {filepath.name}. Sidecars must never hold private keys.")
