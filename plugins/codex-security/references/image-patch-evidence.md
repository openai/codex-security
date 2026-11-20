# Image dependency patch evidence

Identify the consuming build definition and target platform. In standard mode, generate a native Syft JSON SBOM for the baseline and rebuilt images with `syft IMAGE --scope squashed -o syft-json`. Establish that each SBOM came from the intended build.

From the plugin directory, run the helper with a trusted Grype executable on PATH and a local database. It scans the exact bytes of each inventory and includes their SHA-256 hashes in the evidence. In static mode use supplied evidence only and skip the scanner.

```sh
GRYPE_DB_AUTO_UPDATE=false python scripts/image_patch_evidence.py \
  --before-sbom before.syft.json --after-sbom after.syft.json \
  --advisory ADVISORY --package PACKAGE --package-type TYPE
```

For APK packages, the helper carries a reported fixed version across images only when the selected package has a consistent `distro` qualifier across the match and inventories, including when all omit it. If the qualifier changes and the advisory disappears, the result is `inconclusive`. A remaining match yields `still_reported`.

Alongside the patch, show the build definition, manifest digests, platform, package versions, database date, selected match and total counts. Report `reported_fix_present` as scanner evidence. Record the behavioral regression check separately. Establish deployment only with independent rollout evidence.
