from __future__ import annotations

import openai_codex_security


def test_public_exports_are_curated() -> None:
    assert set(openai_codex_security.__all__) == {
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
    }
