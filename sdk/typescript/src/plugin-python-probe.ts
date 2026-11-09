export const PLUGIN_PYTHON_READY = "codex-security-python-ok";
// Cold Python startup can exceed five seconds on busy Windows hosts.
export const PLUGIN_PYTHON_PROBE_TIMEOUT_MS = 30_000;

export const PLUGIN_PYTHON_PROBE = [
  "import importlib.util,sys",
  "if sys.version_info < (3, 10): raise SystemExit(1)",
  "if sys.version_info < (3, 11) and importlib.util.find_spec('tomli') is None: raise SystemExit(1)",
  `print('${PLUGIN_PYTHON_READY}')`,
].join("\n");
