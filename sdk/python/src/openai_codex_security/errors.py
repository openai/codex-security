from __future__ import annotations


class CodexSecurityError(Exception):
    """Base error for Codex Security SDK failures."""


class ConfigurationError(CodexSecurityError):
    """Raised when SDK and Codex configuration cannot be combined."""


class AuthenticationRequiredError(CodexSecurityError):
    """Raised when the isolated runtime has no usable authentication."""


class PluginBootstrapError(CodexSecurityError):
    """Raised when the Codex Security plugin cannot be prepared or installed."""


class InvalidTargetError(CodexSecurityError):
    """Raised when a scan target is invalid."""


class OutputDirectoryError(CodexSecurityError):
    """Raised when a scan output directory is unsafe or already occupied."""


class IncompleteScanError(CodexSecurityError):
    """Raised when Codex finishes without producing a completed scan."""


class ContractValidationError(CodexSecurityError):
    """Raised when completed scan artifacts do not satisfy the contract."""
