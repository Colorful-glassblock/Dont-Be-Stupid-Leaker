/**
 * Bloom filter for efficient key deduplication.
 * Ported from Python BloomFilter class.
 */

export interface BloomFilterOptions {
  /** Number of bits in the filter */
  size: number;
  /** Number of hash functions */
  hashCount: number;
}

export const DEFAULT_BLOOM_OPTIONS: BloomFilterOptions = {
  size: 10_000_000,
  hashCount: 7,
};

/**
 * Simple bloom filter using FNV-1a inspired hashing.
 * Thread-safe via atomic operations (single-threaded Node.js anyway).
 */
export class BloomFilter {
  private readonly size: number;
  private readonly hashCount: number;
  private readonly bits: Uint8Array;

  constructor(options: BloomFilterOptions = DEFAULT_BLOOM_OPTIONS) {
    this.size = options.size;
    this.hashCount = options.hashCount;
    this.bits = new Uint8Array(Math.ceil(this.size / 8));
  }

  /**
   * Generate hash positions for an item.
   * Uses a simple double-hashing scheme: h(i) = h1 + i * h2
   */
  private hashes(item: string): number[] {
    // FNV-1a inspired hash
    let h1 = 0x811c9dc5;
    let h2 = 0x01000193;
    for (let i = 0; i < item.length; i++) {
      const ch = item.charCodeAt(i);
      h1 ^= ch;
      h1 = Math.imul(h1, 0x01000193);
      h2 ^= ch;
      h2 = Math.imul(h2, 0x811c9dc5);
    }

    const result: number[] = [];
    for (let i = 0; i < this.hashCount; i++) {
      const hash = (h1 + i * h2) >>> 0;
      result.push(hash % this.size);
    }
    return result;
  }

  /** Add an item to the filter */
  add(item: string): void {
    for (const pos of this.hashes(item)) {
      const byteIdx = pos >> 3;
      const bitIdx = pos & 7;
      this.bits[byteIdx]! |= 1 << bitIdx;
    }
  }

  /** Check if an item might be in the filter (false positives possible, false negatives not) */
  contains(item: string): boolean {
    for (const pos of this.hashes(item)) {
      const byteIdx = pos >> 3;
      const bitIdx = pos & 7;
      if (!(this.bits[byteIdx]! & (1 << bitIdx))) {
        return false;
      }
    }
    return true;
  }
}
