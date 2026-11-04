import { createHash } from "node:crypto";
import type { Finding, ScanManifest } from "../../src/models.js";

export function findingFingerprint(
  targetId: string,
  finding: Pick<Finding, "ruleId" | "identity">,
): string {
  return `codex-security/v1:sha256:${sha256(
    [
      "codex-security/v1",
      targetId,
      finding.ruleId,
      finding.identity.anchor,
      finding.identity.instance ?? "",
    ].join("\0"),
  )}`;
}

export function setFindingIdentity(
  scan: ScanManifest["scan"],
  finding: Finding,
): void {
  const fingerprint = findingFingerprint(scan.target.targetId, finding);
  finding.fingerprints = {
    algorithm: "codex-security/v1",
    primary: fingerprint,
  };
  finding.findingId = `csf_${sha256(fingerprint).slice(0, 24)}`;
  finding.occurrenceId = `occ_${sha256([scan.id, fingerprint].join("\0")).slice(0, 24)}`;
}

export function sha256(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}
