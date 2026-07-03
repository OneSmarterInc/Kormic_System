import re
from dataclasses import dataclass
from kormic.utils.exceptions import IdentityError

# Regex to enforce structured identity code matching: KMC.<type>.<entity_ref>.<instance>.<realid_ref>
# Type must be STU (student), UNI (university), or CMP (company)
# Realid_ref must be a 64-char hex string (SHA-256 hash representation)
IDENTITY_REGEX = re.compile(
    r"^KMC\.(STU|UNI|CMP)\.([a-zA-Z0-9_-]+)\.(\d{4})\.([a-fA-F0-9]{64})$"
)

@dataclass(frozen=True)
class Identity:
    agent_type: str        # e.g., 'STU' | 'UNI' | 'CMP'
    entity_ref: str        # e.g., 'priya7f3a'
    instance: str          # e.g., '0001'
    realid_ref: str        # 64-character SHA-256 hex string mapping to verified identity record

    def __post_init__(self) -> None:
        """Validate structural constraints on creation."""
        self.validate()

    def validate(self) -> None:
        """Runs assertions on formatting. Raises IdentityError if validation fails."""
        if self.agent_type not in {"STU", "UNI", "CMP"}:
            raise IdentityError(f"Invalid agent type: '{self.agent_type}'. Must be STU, UNI, or CMP.")
        
        if not re.match(r"^[a-zA-Z0-9_-]+$", self.entity_ref):
            raise IdentityError(f"Invalid entity reference: '{self.entity_ref}'. Must be alphanumeric/hyphen/underscore.")
        
        if not re.match(r"^\d{4}$", self.instance):
            raise IdentityError(f"Invalid instance identifier: '{self.instance}'. Must be exactly a 4-digit number string.")
        
        if not re.match(r"^[a-fA-F0-9]{64}$", self.realid_ref):
            raise IdentityError("Invalid realid reference. Must be a 64-character SHA-256 hex string.")

    def to_string(self) -> str:
        """Returns the UPC-style string representation."""
        return f"KMC.{self.agent_type}.{self.entity_ref}.{self.instance}.{self.realid_ref}"

    @classmethod
    def from_string(cls, id_str: str) -> "Identity":
        """Parses a UPC-style identity string. Raises IdentityError on syntax mismatch."""
        match = IDENTITY_REGEX.match(id_str)
        if not match:
            raise IdentityError(f"Identity string format mismatch: '{id_str}'. Must follow KMC.<type>.<entity_ref>.<instance>.<realid_ref>")
        
        agent_type, entity_ref, instance, realid_ref = match.groups()
        return cls(
            agent_type=agent_type,
            entity_ref=entity_ref,
            instance=instance,
            realid_ref=realid_ref
        )
