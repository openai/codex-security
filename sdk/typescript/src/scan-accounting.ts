import { addScanCosts, type ScanCost } from "./cost.js";

/** Cumulative receipts replace their prior value; absent and unavailable are distinct. */
export class ScanAccounting {
  readonly #receipts = new Map<string, Readonly<ScanCost> | null>();
  completed: Readonly<ScanCost> | null = null;

  record(key: string, cost: Readonly<ScanCost> | null): void {
    this.#receipts.set(key, cost);
  }
  has(key: string): boolean {
    return this.#receipts.has(key);
  }
  get hasChildren(): boolean {
    return [...this.#receipts.keys()].some((key) => key !== "merge");
  }
  get hasUnknown(): boolean {
    return [...this.#receipts.values()].includes(null);
  }
  get known(): ScanCost | null {
    return [...this.#receipts.values()].reduce<ScanCost | null>(
      (total, cost) => (cost === null ? total : addScanCosts(total, cost)),
      null,
    );
  }
  get complete(): ScanCost | null {
    return this.hasUnknown ? null : this.known;
  }
}
