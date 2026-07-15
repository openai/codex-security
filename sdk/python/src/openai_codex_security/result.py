from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from openai_codex import TurnResult

from .models import CoverageDocument, FindingsDocument, ScanManifest


@dataclass(frozen=True, slots=True)
class ScanResult:
    """Completed Codex Security scan and its canonical contract."""

    manifest: ScanManifest
    findings: FindingsDocument
    coverage: CoverageDocument
    scan_dir: Path
    thread_id: str
    turn_result: TurnResult

    @property
    def report_path(self) -> Path:
        return self.scan_dir / "report.md"

    @property
    def plugin_version(self) -> str:
        return self.manifest.scan.producer.version

    @property
    def manifest_path(self) -> Path:
        return self.scan_dir / "scan-manifest.json"

    @property
    def findings_path(self) -> Path:
        return self.scan_dir / "findings.json"

    @property
    def coverage_path(self) -> Path:
        return self.scan_dir / "coverage.json"

    @property
    def artifacts_dir(self) -> Path:
        return self.scan_dir / "artifacts"

    @property
    def sarif_path(self) -> Path | None:
        path = self.scan_dir / "exports/results.sarif"
        return path if path.is_file() else None
