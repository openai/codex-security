# Import Grype dependency findings locally

Use a saved JSON report from `grype -o json`. The reader imports each entry in
`matches` as one dependency finding, mapping the vulnerability and its package
onto the shared evidence contract. It works offline and does not run Grype.
Grype reports support local import only.

## Create the report

Run Grype from the checkout root and write the report to a private directory
outside the checkout.

```sh
grype dir:. -o json --file /private/path/grype.json
```

Grype also scans an SBOM (`grype sbom:bom.json`) or a container image. The reader projects checkout-relative paths only from a directory source. Confirm that Grype scanned the selected checkout root. Image locations and paths from an SBOM without a directory source stay in the original evidence.

## Preview the report

```sh
codex-security publish findings /private/path/grype.json --to local \
  --repository /path/to/checkout --provider grype \
  --source-key example/project/main --dry-run --format json
```

Check the packages, advisories and manifest paths in the preview. The checkout
does not need to be a Git repository. Grype records no source-control URL, so do
not pass `--source-repository-url`; the findings bind to the selected checkout.
Keep the same source key across scans of the same project and branch. Remove
`--dry-run` and confirm to save. [Save and verify](README.md#save-or-publish-and-verify).

## Read the evidence

This shortened report has one match. The reader keeps the package, its advisory
and the manifest location.

```json
{
  "matches": [
    {
      "vulnerability": {
        "id": "CVE-2099-0001",
        "dataSource": "https://nvd.nist.gov/vuln/detail/CVE-2099-0001",
        "severity": "High",
        "description": "A crafted length can cause excessive allocation.",
        "fix": { "versions": ["1.0.1"], "state": "fixed" }
      },
      "relatedVulnerabilities": [{ "id": "GHSA-2345-6789-cfgh" }],
      "artifact": {
        "name": "@example/parser",
        "version": "1.0.0",
        "type": "npm",
        "purl": "pkg:npm/%40example/parser@1.0.0",
        "locations": [{ "path": "package-lock.json" }]
      }
    }
  ],
  "source": { "type": "directory", "target": "." },
  "descriptor": { "name": "grype", "version": "0.80.1" }
}
```

- `advisory_ids` starts with the match `id` and adds each `relatedVulnerabilities` id. `evidence.url` is the vulnerability `dataSource` when it is an HTTP link.
- `packages[0]` carries the artifact name, the PURL type as its ecosystem, the installed version, the `fix.versions` as fixed versions, and the manifest or lockfile path when exactly one reported checkout location has a recognized manifest filename.
- `locations` lists each checkout-relative artifact location. For directory scans, a relative `accessPath` can identify the checkout file when `path` is absolute. Grype reports no line numbers. All image paths stay in `source_data` only.
- Grype ranks Negligible below Low. A Negligible match imports as `informational`; an Unknown or missing severity imports as `unknown`.
- `evidence.source_data` keeps the native match, the scan `source`, and the Grype version. A saved preview imports under the `grype` provider.

## Repeat an import

The reader identifies a match by ecosystem, advisory, package name and the sorted set of artifact paths. Directory paths use the normalized checkout location when available. A new severity, installed version or fix updates the same occurrence. A
different advisory, package or set of paths is a separate finding. Two matches with
the same identity are excluded as a group. Keep the same source key for one
project and branch.
