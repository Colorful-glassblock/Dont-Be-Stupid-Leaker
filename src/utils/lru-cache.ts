/**
 * LRU Cache with TTL expiration.
 * Ported from Python LRUCache class.
 */

export interface LRUCacheOptions {
  maxSize: number;
  ttlMs: number;
}

export const DEFAULT_LRU_OPTIONS: LRUCacheOptions = {
  maxSize: 500,
  ttlMs: 3600_000, // 1 hour
};

interface CacheEntry<V> {
  value: V;
  expiresAt: number;
}

/**
 * Least Recently Used cache with time-to-live expiration.
 * Uses a Map (insertion-order) for O(1) get/put.
 */
export class LRUCache<V> {
  private readonly maxSize: number;
  private readonly ttlMs: number;
  private readonly cache = new Map<string, CacheEntry<V>>();

  constructor(options: Partial<LRUCacheOptions> = {}) {
    this.maxSize = options.maxSize ?? DEFAULT_LRU_OPTIONS.maxSize;
    this.ttlMs = options.ttlMs ?? DEFAULT_LRU_OPTIONS.ttlMs;
  }

  get size(): number {
    return this.cache.size;
  }

  get(key: string): V | undefined {
    const entry = this.cache.get(key);
    if (!entry) return undefined;

    if (Date.now() > entry.expiresAt) {
      this.cache.delete(key);
      return undefined;
    }

    // Move to end (most recently used)
    this.cache.delete(key);
    this.cache.set(key, entry);
    return entry.value;
  }

  put(key: string, value: V): void {
    if (this.cache.has(key)) {
      this.cache.delete(key);
    } else if (this.cache.size >= this.maxSize) {
      // Evict oldest (first entry)
      const firstKey = this.cache.keys().next().value;
      if (firstKey !== undefined) {
        this.cache.delete(firstKey);
      }
    }
    this.cache.set(key, { value, expiresAt: Date.now() + this.ttlMs });
  }

  has(key: string): boolean {
    return this.get(key) !== undefined;
  }

  clear(): void {
    this.cache.clear();
  }
}
