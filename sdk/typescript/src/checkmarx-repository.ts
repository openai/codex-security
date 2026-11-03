import { checkmarxOneId } from "./checkmarx-one.js";
import { checkmarxXmlId } from "./checkmarx-xml.js";
import {
  declaredScannerRepositoryUrl,
  repositoryScopeValidator,
} from "./scanner-repository-url.js";

export const checkmarxReportRepositories = repositoryScopeValidator(
  { provider: "checkmarx", label: "Checkmarx", scope: "product and project" },
  (provider, { source_finding_id: id, evidence }, target) => {
    const data = evidence.source_data;
    if (
      !data ||
      (data["format"] !== "cxsast-xml" &&
        data["format"] !== "checkmarx-one-json")
    ) {
      if (
        provider === "checkmarx" &&
        /^checkmarx-(?:one|cxsast):[a-f0-9]{64}$/u.test(id)
      )
        throw new Error(
          "Checkmarx source finding ID requires its original evidence.",
        );
      return;
    }
    if (provider !== "checkmarx")
      throw new Error(
        "Retained Checkmarx evidence requires the checkmarx provider.",
      );
    const format = data["format"];
    const expected =
      format === "cxsast-xml"
        ? checkmarxXmlId(data)
        : checkmarxOneId(data["row"]);
    if (id !== expected)
      throw new Error(
        "Checkmarx source finding ID does not match the retained occurrence.",
      );
    return {
      url: declaredScannerRepositoryUrl(
        data["sourceRepositoryUrl"],
        "Checkmarx",
        target,
      ),
      scope:
        format === "cxsast-xml" ? `${format}/${data["projectId"]}` : format,
    };
  },
);
