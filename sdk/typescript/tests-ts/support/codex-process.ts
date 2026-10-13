import * as childProcess from "node:child_process";

const spawn = childProcess.spawn;

/** Replace just the selected executable with Node running a synthetic fixture. */
export function fixtureSpawn(
  executable: string,
  script: string,
  observe: (
    child: childProcess.ChildProcess,
    args: string[],
    options: childProcess.SpawnOptions,
  ) => void,
): typeof childProcess.spawn {
  return ((...args: Parameters<typeof childProcess.spawn>) => {
    const [command, argv, options] = args;
    if (command !== executable || !Array.isArray(argv)) return spawn(...args);
    const child = spawn(process.execPath, [script, ...argv], options);
    observe(child, argv, options ?? {});
    return child;
  }) as typeof childProcess.spawn;
}
