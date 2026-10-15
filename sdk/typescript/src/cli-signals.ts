type SignalName = "SIGINT" | "SIGTERM";

export function listenForAbort(
  dependencies: {
    addSignalListener(signal: SignalName, listener: () => void): void;
    removeSignalListener(signal: SignalName, listener: () => void): void;
    now(): number;
  },
  controller: AbortController,
  onRepeatedSignal?: (signal: SignalName) => void,
): () => void {
  let firstSignalAt = 0;
  const signalListener = (signal: SignalName) => () => {
    if (onRepeatedSignal !== undefined) {
      if (controller.signal.aborted) {
        // Ignore duplicate initial delivery; a later or different signal exits.
        if (
          controller.signal.reason === signal &&
          dependencies.now() - firstSignalAt < 500
        )
          return;
        removeSignalListeners();
        onRepeatedSignal(signal);
        return;
      }
      firstSignalAt = dependencies.now();
    }
    controller.abort(signal);
  };
  const interrupt = signalListener("SIGINT");
  const terminate = signalListener("SIGTERM");
  const removeSignalListeners = () => {
    dependencies.removeSignalListener("SIGINT", interrupt);
    dependencies.removeSignalListener("SIGTERM", terminate);
  };
  dependencies.addSignalListener("SIGINT", interrupt);
  dependencies.addSignalListener("SIGTERM", terminate);
  return removeSignalListeners;
}
