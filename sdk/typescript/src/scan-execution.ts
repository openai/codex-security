/** A native transport stopped; the saved scan can continue in another host. */
export class ScanTransportClosedError extends Error {}

/** A required worker permission cannot be preserved by the selected runtime. */
export class ScanPermissionError extends Error {}
