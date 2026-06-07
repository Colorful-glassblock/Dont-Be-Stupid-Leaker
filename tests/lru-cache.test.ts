import { describe, it, expect } from "vitest";
import { LRUCache } from "../src/utils/lru-cache.js";

describe("LRUCache", () => {
  it("stores and retrieves values", () => {
    const cache = new LRUCache<string>({ maxSize: 10, ttlMs: 60_000 });
    cache.put("key1", "value1");
    expect(cache.get("key1")).toBe("value1");
  });

  it("returns undefined for missing keys", () => {
    const cache = new LRUCache<string>({ maxSize: 10, ttlMs: 60_000 });
    expect(cache.get("missing")).toBeUndefined();
  });

  it("evicts oldest items when full", () => {
    const cache = new LRUCache<string>({ maxSize: 3, ttlMs: 60_000 });
    cache.put("a", "1");
    cache.put("b", "2");
    cache.put("c", "3");
    cache.put("d", "4"); // should evict "a"
    expect(cache.get("a")).toBeUndefined();
    expect(cache.get("d")).toBe("4");
  });

  it("moves accessed items to end (LRU behavior)", () => {
    const cache = new LRUCache<string>({ maxSize: 3, ttlMs: 60_000 });
    cache.put("a", "1");
    cache.put("b", "2");
    cache.put("c", "3");
    cache.get("a"); // touch "a" — now "b" is oldest
    cache.put("d", "4"); // should evict "b"
    expect(cache.get("a")).toBe("1");
    expect(cache.get("b")).toBeUndefined();
    expect(cache.get("d")).toBe("4");
  });

  it("updates existing keys", () => {
    const cache = new LRUCache<string>({ maxSize: 3, ttlMs: 60_000 });
    cache.put("a", "1");
    cache.put("a", "2");
    expect(cache.get("a")).toBe("2");
    expect(cache.size).toBe(1);
  });

  it("clears all entries", () => {
    const cache = new LRUCache<string>({ maxSize: 10, ttlMs: 60_000 });
    cache.put("a", "1");
    cache.put("b", "2");
    cache.clear();
    expect(cache.size).toBe(0);
    expect(cache.get("a")).toBeUndefined();
  });
});
