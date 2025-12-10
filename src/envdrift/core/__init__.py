"""Core modules for envdrift."""

from envdrift.core.diff import DiffEngine, DiffResult, DiffType, VarDiff
from envdrift.core.encryption import EncryptionDetector, EncryptionReport
from envdrift.core.parser import EncryptionStatus, EnvFile, EnvParser, EnvVar
from envdrift.core.schema import FieldMetadata, SchemaLoader, SchemaMetadata
from envdrift.core.validator import ValidationResult, Validator

__all__ = [
    # Parser
    "EnvFile",
    "EnvParser",
    "EnvVar",
    "EncryptionStatus",
    # Schema
    "FieldMetadata",
    "SchemaLoader",
    "SchemaMetadata",
    # Validator
    "ValidationResult",
    "Validator",
    # Diff
    "DiffEngine",
    "DiffResult",
    "DiffType",
    "VarDiff",
    # Encryption
    "EncryptionDetector",
    "EncryptionReport",
]
