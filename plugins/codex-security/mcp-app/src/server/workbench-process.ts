export const WORKBENCH_PYTHON = `
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(sys.argv.pop(1)).resolve().parent))
import workbench_db
sys.argv = [workbench_db.__file__, *json.loads(sys.stdin.buffer.readline())]
try:
    workbench_db.main()
except workbench_db.ContractError as error:
    raise SystemExit(str(error)) from None
`;
