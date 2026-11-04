export const WORKBENCH_PYTHON = `
import json, sys
from pathlib import Path
script = Path(sys.argv.pop(1)).resolve()
sys.path.insert(0, str(script.parent))
args = json.loads(sys.stdin.buffer.readline())
sys.argv = [str(script), *args]
if args and args[0] in {"inspect-target", "inspect-setup"}:
    from workbench_setup import main
else:
    from workbench_db import main
main()
`;
