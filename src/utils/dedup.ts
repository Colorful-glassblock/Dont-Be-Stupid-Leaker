/**
 * Layered deduplication: LRU exact set + Bloom filter cascade.
 * Ported from Python dedup logic.
 */

import { BloomFilter } from "./bloom-filter.js";
import { LRUCache } from "./lru-cache.js";

const MAX_PROCESSED_EXACT = 500_000;

/**
 * Two-layer deduplication:
 * 1. LRU exact set for recent items (guaranteed no false positives)
 * 2. Bloom filter cascade for older items (probabilistic, space-efficient)
 */
export class Deduplicator {
  private exactSet = new LRUCache<boolean>({ maxSize: MAX_PROCESSED_EXACT, ttlMs: Infinity });
  private bloomFilters: BloomFilter[] = [new BloomFilter()];

  /**
   * Check if a key+source combination has been seen before.
   * If not seen, marks it as seen.
   * @returns true if this is a duplicate (already seen)
   */
  isDuplicate(key: string, sourceUrl: string): boolean {
    const combo = `${key}|${sourceUrl}`;

    // Check exact set first
    if (this.exactSet.has(combo)) {
      return true;
    }

    // Check bloom filters
    for (const bf of this.bloomFilters) {
      if (bf.contains(combo)) {
        return true;
      }
    }

    // Not seen — add to exact set
    this.exactSet.put(combo, true);
    this.bloomFilters[0]?.add(combo);

    return false;
  }

  /**
   * Prune the exact set when it gets too large.
   * Moves oldest entries into a new bloom filter.
   */
  prune(): void {
    if (this.exactSet.size < MAX_PROCESSED_EXACT) return;

    // Create a new bloom filter layer
    this.bloomFilters.unshift(new BloomFilter());

    // Keep at most 3 bloom filter layers
    if (this.bloomFilters.length > 3) {
      this.bloomFilters.pop();
    }
  }
}
