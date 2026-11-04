export const libc =
  process.platform !== "linux"
    ? undefined
    : (
          process.report.getReport() as {
            header: { glibcVersionRuntime?: string };
          }
        ).header.glibcVersionRuntime === undefined
      ? "musl"
      : "gnu";

export const nativeTarget = `${process.platform}-${process.arch}${libc === undefined ? "" : `-${libc}`}`;
