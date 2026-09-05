export { CodexSecurity, createSecurity } from "./api.js";
export { classifySeverity } from "./classify-severity.js";
export type {
  ClassifySeverityOptions,
  SeverityClassificationFinding,
  SeverityClassification,
  SeverityAssessment,
} from "./classify-severity.js";
export {
  classifyScanSeverity,
  classifyScanDirectorySeverity,
} from "./classify-scan-severity.js";
export type {
  ClassifyScanSeverityOptions,
  ScanSeverityClassification,
} from "./classify-scan-severity.js";
export { runComponentScans } from "./component-scan.js";
export type {
  ComponentDeduplicationSummary,
  ComponentReceipt,
  ComponentScanOptions,
  ComponentScanEvent,
  ComponentScanResult,
} from "./component-scan.js";
export { normalizeComponentPlan, planComponents } from "./component-plan.js";
export type {
  ComponentPlan,
  ComponentPlanningOptions,
} from "./component-plan.js";
export { estimateScanCost } from "./cost.js";
export type { ScanCost, ScanSessionEvent } from "./cost.js";
export type { DeepScanProgress } from "./deep-progress.js";
export type { CustomValidationResult } from "./custom-validation.js";
export type { ScanActivity, ScanActivityStatus } from "./scan-activity.js";
export { matchScanFindings } from "./scan-comparison.js";
export type {
  ScanComparisonInput,
  ScanComparisonOptions,
  ScanComparisonProgress,
  ScanComparisonResult,
} from "./scan-comparison.js";
export type {
  CodexSecurityMetadata,
  DeepScanOptions,
  ScanAuthMode,
  ScanAuthentication,
  ScanBudget,
  ScanOptions,
  ScanPreflight,
  ScanReconnectDetails,
  ScanTrustedAccessStatus,
  ScanWarningDetails,
  ValidationOptions,
  ValidationResult,
} from "./api.js";
export type {
  ScanPhase,
  ScanProgress,
  ScanWorkerPhase,
  ScanWorkerStatus,
} from "./worker-progress.js";
export { CodexLoginHandle } from "./auth.js";
export type { AccountStatus, LoginResult } from "./auth.js";

export {
  AuthenticationRequiredError,
  CodexSecurityError,
  ConfigurationError,
  ContractValidationError,
  DeduplicationReviewError,
  IncompleteScanError,
  InvalidTargetError,
  OutputDirectoryError,
  OutputDirectoryNotEmptyError,
  OutputInsideProtectedRootError,
  PluginBootstrapError,
  PluginPythonUnavailableError,
  ScanCostLimitExceededError,
  ScanInterruptedError,
} from "./errors.js";
export type {
  DeduplicationReviewFailureCategory,
  DeduplicationReviewFailureMetadata,
  DeduplicationReviewStage,
  ProtectedScanPathKind,
} from "./errors.js";
export {
  DEFAULT_CODEX_CONFIG,
  mergedCodexConfig,
  writeCodexConfig,
} from "./config.js";
export type { CodexSecurityConfig, JsonObject, JsonValue } from "./config.js";
export { loadContract, requireScanFile } from "./contract.js";
export type { LoadedContract, ScanExpectation } from "./contract.js";
export type * from "./models.js";
export { checkScanPublication, publishScan } from "./publish.js";
export { publishScanToCustom } from "./custom-publish.js";
export type {
  PublishScanToCustomOptions,
  CustomPublicationResult,
} from "./custom-publish.js";
export {
  deduplicateScan,
  deduplicateScanDirectory,
} from "./deduplication/scan.js";
export type {
  DeduplicateScanDirectoryOptions,
  DeduplicateScanOptions,
  DeduplicateScanResult,
} from "./deduplication/scan.js";
export { importGitHubCodeScanningAlerts } from "./github.js";
export type {
  GitHubCodeScanningImportOptions,
  ImportedGitHubCodeScanningAlert,
} from "./github.js";
export type {
  CheckScanPublicationOptions,
  CheckScanPublicationResult,
  PublishScanOptions,
  PublishScanProgress,
  PublishScanResult,
} from "./publish.js";
export { ScanResult } from "./result.js";
export type {
  RepositoryFinding,
  ScanResultOptions,
  TurnResultMetadata,
} from "./result.js";
export {
  bootstrapPlugin,
  bundledPluginRoot,
  cleanupSdkDirectory,
  createIsolatedHome,
  createMarketplace,
  extractPluginZip,
  importAmbientAuth,
  MARKETPLACE_NAME,
  pluginExecutionEnvironment,
  pluginMetadata,
  PLUGIN_NAME,
  prepareOutputDir,
  resolveCodexCommand,
  resolvePluginPath,
  resolvePluginPython,
  validateOutputDir,
} from "./runtime.js";
export type {
  CodexCommand,
  PluginInstall,
  PluginPythonOptions,
  ProcessEnvironment,
} from "./runtime.js";
export {
  DiffTarget,
  normalizeRepository,
  normalizeTarget,
  repositoryRevision,
  validateMode,
} from "./targets.js";
export type { NormalizedTarget, ScanMode, ScanTarget } from "./targets.js";
export { BUNDLED_PLUGIN_VERSION, VERSION } from "./version.js";
