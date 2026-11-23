# Image dependency patch evidence

Identify the consuming build definition and target platform. In standard mode, generate a native Syft JSON SBOM for the baseline and rebuilt images with `syft IMAGE --scope squashed -o syft-json`. Establish that each SBOM came from the intended build.

From the plugin directory, run the helper with a trusted Grype executable on PATH and a local database. It scans the exact bytes of each inventory and includes their SHA-256 hashes in the evidence. In static mode use supplied evidence only and skip the scanner.

```sh
GRYPE_DB_AUTO_UPDATE=false python scripts/image_patch_evidence.py \
  --before-sbom before.syft.json --after-sbom after.syft.json \
  --advisory ADVISORY --package PACKAGE --package-type TYPE
```

The helper compares the distribution recorded in each selected package URL. For example, Syft can record `distro` for APK, DEB and RPM packages. A reported fixed version applies across images only when the qualifier agrees across the match and inventories, including when all omit it. If the qualifier changes and the advisory disappears, the result is `inconclusive`. A remaining match yields `still_reported`.

For RPM versions, an omitted epoch and an explicit zero epoch compare equally, including when intersecting fixes across scanner records. The report preserves the original version strings for common fixes. Advisory aliases established by the selected baseline matches also select active or ignored matches in the rebuilt image. Grype's configured severity threshold can return exit status 2 with a completed report; the helper uses that report and continues to reject scanner execution failures.

Alongside the patch, show the build definition, manifest digests, platform, package versions, database date, selected match and total counts. Report `reported_fix_present` as scanner evidence. Record the behavioral regression check separately. Establish deployment only with independent rollout evidence.
