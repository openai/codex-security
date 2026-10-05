import { hash } from "node:crypto";
import type { CalibrationCase, CalibrationVariant } from "../types.ts";

export function variantCaseId(
  testCase: Pick<CalibrationCase, "case_id">,
  variant: CalibrationVariant,
) {
  return `calibration-${hash("sha256", `${testCase.case_id}\0${variant.checkout_ref}`).slice(0, 16)}`;
}
