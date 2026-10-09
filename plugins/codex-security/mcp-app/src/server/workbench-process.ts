// This exit status belongs only to the private MCP launcher, not the Python CLI.
export const WORKBENCH_STATE_UNAVAILABLE_EXIT_CODE = 73;
export const WORKBENCH_PYTHON = `
import json, sys, traceback
from pathlib import Path
sys.path.insert(0, str(Path(sys.argv.pop(1)).resolve().parent))
import workbench_db
sys.argv = [workbench_db.__file__, *json.loads(sys.stdin.buffer.readline())]
try:
    workbench_db.main()
except Exception as error:
    if not getattr(error, "_codex_security_state_unavailable", False):
        raise
    traceback.print_exc()
    sys.exit(${WORKBENCH_STATE_UNAVAILABLE_EXIT_CODE})
`;
