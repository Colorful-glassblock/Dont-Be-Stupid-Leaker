/**
 * Batch verification manager.
 * Collects pending verifications, triggers batch verification
 * when size or time threshold is reached.
 */

import type { PendingVerification, VerifyResult } from "../types/index.js";
import { verifyKey } from "../verifiers/verify.js";
import pLimit from "p-limit";

export type VerifyCallback = (result: VerifyResult & PendingVerification) => void;

export interface BatchManagerConfig {
  batchSize: number;
  batchTimeout: number;
  concurrency: number;
}

export const DEFAULT_BATCH_CONFIG: BatchManagerConfig = {
  batchSize: 30,
  batchTimeout: 60_000,
  concurrency: 20,
};

interface BatchQueue {
  items: PendingVerification[];
  timer: ReturnType<typeof setTimeout> | null;
}

/**
 * Manages batched key verification with concurrency control.
 */
export class BatchManager {
  private readonly config: BatchManagerConfig;
  private readonly queues = new Map<number, BatchQueue>();
  private readonly limit: ReturnType<typeof pLimit>;
  private readonly onResult: VerifyCallback;
  private pendingCount = 0;

  constructor(config: Partial<BatchManagerConfig>, onResult: VerifyCallback) {
    this.config = { ...DEFAULT_BATCH_CONFIG, ...config };
    this.limit = pLimit(this.config.concurrency);
    this.onResult = onResult;
  }

  /** Add a pending verification to a worker's batch queue */
  add(workerId: number, item: PendingVerification): void {
    let queue = this.queues.get(workerId);
    if (!queue) {
      queue = { items: [], timer: null };
      this.queues.set(workerId, queue);
    }

    queue.items.push(item);

    // Check if batch should be flushed
    if (queue.items.length >= this.config.batchSize) {
      this.flushWorker(workerId);
    } else if (!queue.timer) {
      // Set timeout to flush partial batch
      queue.timer = setTimeout(() => this.flushWorker(workerId), this.config.batchTimeout);
    }
  }

  /** Flush a specific worker's batch */
  private flushWorker(workerId: number): void {
    const queue = this.queues.get(workerId);
    if (!queue || queue.items.length === 0) return;

    if (queue.timer) {
      clearTimeout(queue.timer);
      queue.timer = null;
    }

    const batch = queue.items.splice(0);
    this.verifyBatch(batch);
  }

  /** Flush all pending batches */
  flushAll(): void {
    for (const [workerId] of this.queues) {
      this.flushWorker(workerId);
    }
  }

  /** Submit a batch for concurrent verification */
  private verifyBatch(batch: PendingVerification[]): void {
    for (const item of batch) {
      this.pendingCount++;
      this.limit(async () => {
        try {
          const result = await verifyKey(item.key, item.service);
          if (result.valid) {
            this.onResult({ ...item, ...result });
          }
        } catch (err) {
          console.error(`  ❌ [${item.service}] Verification error: ${err}`);
        } finally {
          this.pendingCount--;
        }
      });
    }
  }

  /** Wait for all pending verifications to complete */
  async drain(): Promise<void> {
    this.flushAll();
    // Wait for the limit queue to empty
    while (this.pendingCount > 0 || this.limit.pendingCount > 0) {
      await new Promise((r) => setTimeout(r, 100));
    }
  }

  get pending(): number {
    return this.pendingCount + this.limit.pendingCount;
  }
}
