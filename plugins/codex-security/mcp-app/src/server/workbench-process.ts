export const WORKBENCH_PYTHON = `
import json, sys
from pathlib import Path
sys.stdout.reconfigure(encoding="utf-8", errors=sys.stdout.errors)
sys.stderr.reconfigure(encoding="utf-8", errors=sys.stderr.errors)
script = Path(sys.argv[1]).resolve()
options = dict.fromkeys(sys.argv[2:], True)
sys.path.insert(0, str(script.parent))
args = json.loads(sys.stdin.buffer.readline())
sys.argv = [str(script), *args]
if args and args[0] in {"inspect-target", "inspect-setup"}:
    from workbench_setup import main
    main()
else:
    import workbench_db
    try:
        workbench_db.main(**options)
    except workbench_db.ContractError as error:
        raise SystemExit(str(error)) from None
`;
