import yaml
import os

class ManifestValidator:
    REQUIRED_FIELDS = ["allowed_tools", "allowed_endpoints", "credential_scopes", "blast_radius"]

    @staticmethod
    def load_and_validate(filepath: str) -> dict:
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Manifest file not found: {filepath}")
            
        with open(filepath, 'r') as f:
            manifest = yaml.safe_load(f)
            
        if not isinstance(manifest, dict):
            raise ValueError("Manifest must be a YAML dictionary")
            
        for field in ManifestValidator.REQUIRED_FIELDS:
            if field not in manifest:
                raise ValueError(f"Manifest is missing required field: '{field}'")
                
        # Fill optional fields
        if "irreversible_scopes" not in manifest:
            manifest["irreversible_scopes"] = []
            
        return manifest
