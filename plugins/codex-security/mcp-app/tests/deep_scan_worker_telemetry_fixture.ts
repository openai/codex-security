/** Root, selected-profile, and SDK snapshot telemetry used by launch tests. */
export function workerTelemetryFixture(
  index: number,
  hasConfiguration: boolean,
) {
  // Cover missing settings, native config inheritance, and snapshot overrides.
  const mergeProfileTelemetry = index === 0 && hasConfiguration;
  const telemetry =
    index === 0 && !hasConfiguration
      ? {}
      : {
          analytics: { enabled: index % 2 === 0 },
          otel: {
            environment: `synthetic-scan-${index}`,
            exporter: {
              "otlp-http": {
                endpoint: `http://localhost:${4318 + index}/v1/logs`,
                headers: { "X-Scan": `synthetic-scan-${index}` },
              },
            },
            log_user_prompt: false,
          },
          responses_api_metadata: {
            codex_security_surface: index % 2 === 0 ? "cli" : "sdk",
            codex_security_command: "scan",
            codex_security_package_version: `0.2.${index}`,
            codex_security_plugin_version: `0.1.${index}`,
            codex_security_integration: "github_action",
            codex_security_operation_id: `operation-${index}`,
            codex_security_attempt_id: `parent-${index}`,
            codex_security_provider:
              index % 2 === 0 ? "openai" : "amazon-bedrock",
            custom_tag: `synthetic-scan-${index}`,
            "team.tag": `literal-key-${index}`,
            ...(index === 1 || index === 4
              ? {
                  "literal.key": `scan-${index}"\\雪\u007f`,
                  'quote"\\雪\u007f': `literal-key-${index}`,
                }
              : {}),
            ...(mergeProfileTelemetry
              ? {
                  root_only: "native-root",
                  profile_only: "selected-profile",
                }
              : {}),
          },
        };
  const overrideTelemetry = index === 1 || index === 2;
  const inheritedTelemetry =
    overrideTelemetry || index === 4
      ? {
          analytics: { enabled: index % 2 !== 0 },
          otel: { environment: "preflight-default", exporter: "none" },
          responses_api_metadata: { custom_tag: "preflight-default" },
        }
      : mergeProfileTelemetry
        ? {
            analytics: { enabled: true },
            otel: {
              environment: "native-root",
              exporter: {
                "otlp-http": {
                  endpoint: "http://localhost:4317/v1/logs",
                  headers: { "X-Scan": "synthetic-scan-0" },
                },
              },
              log_user_prompt: false,
            },
            responses_api_metadata: {
              codex_security_surface: "cli",
              codex_security_command: "scan",
              codex_security_package_version: "0.2.0",
              codex_security_plugin_version: "0.1.0",
              codex_security_integration: "github_action",
              codex_security_operation_id: "operation-0",
              codex_security_attempt_id: "parent-0",
              codex_security_provider: "openai",
              custom_tag: "preflight-default",
              "team.tag": "literal-key-0",
              root_only: "native-root",
            },
          }
        : telemetry;
  return {
    mergeProfileTelemetry,
    telemetry,
    inheritedTelemetry,
    workerTelemetry: overrideTelemetry ? telemetry : {},
  };
}
