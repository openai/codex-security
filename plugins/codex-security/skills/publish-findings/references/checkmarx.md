# Checkmarx SAST

Use `--provider checkmarx` for a Checkmarx One CLI JSON or self-managed CxSAST XML report. To retrieve a completed scan, follow the [Checkmarx collection instructions](checkmarx-import.md). Collection retrieves the full scan. If the user wants a subset, ask for a filtered vendor export. Before fetching CxSAST XML, verify the scan ID, project and owning team on the selected server.

Preview the report for the verified repository and ref with `--dry-run --format json`. After confirmation, use the same report path and source key for the import and any retries.
