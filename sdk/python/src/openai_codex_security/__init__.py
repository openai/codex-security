"""Python SDK for running Codex Security scans."""

from ._version import __version__
from .api import (
    AsyncCodexSecurity,
    AsyncScanHandle,
    CodexSecurity,
    ScanHandle,
)
from .config import CodexSecurityConfig
from .errors import (
    AuthenticationRequiredError,
    CodexSecurityError,
    ConfigurationError,
    ContractValidationError,
    IncompleteScanError,
    InvalidTargetError,
    OutputDirectoryError,
    PluginBootstrapError,
)
from .models import CoverageDocument, FindingsDocument, ScanManifest
from .result import ScanResult
from .targets import DiffTarget, ScanMode, ScanTarget

__all__ = [
    "__version__",
    "CodexSecurity",
    "AsyncCodexSecurity",
    "CodexSecurityConfig",
    "DiffTarget",
    "ScanMode",
    "ScanTarget",
    "ScanHandle",
    "AsyncScanHandle",
    "ScanResult",
    "ScanManifest",
    "FindingsDocument",
    "CoverageDocument",
    "CodexSecurityError",
    "ConfigurationError",
    "AuthenticationRequiredError",
    "PluginBootstrapError",
    "InvalidTargetError",
    "OutputDirectoryError",
    "IncompleteScanError",
    "ContractValidationError",
]
