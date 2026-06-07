import { describe, it, expect } from "vitest";
import { BloomFilter } from "../src/utils/bloom-filter.js";

describe("BloomFilter", () => {
  it("reports items not in empty filter", () => {
    const bf = new BloomFilter({ size: 1000, hashCount: 3 });
    expect(bf.contains("hello")).toBe(false);
  });

  it("reports added items as present", () => {
    const bf = new BloomFilter({ size: 1000, hashCount: 3 });
    bf.add("hello");
    expect(bf.contains("hello")).toBe(true);
  });

  it("does not report non-added items as present (probabilistic)", () => {
    const bf = new BloomFilter({ size: 100_000, hashCount: 7 });
    bf.add("hello");
    // With a large enough filter, "world" should not be a false positive
    expect(bf.contains("world")).toBe(false);
  });

  it("handles many items without excessive false positives", () => {
    const bf = new BloomFilter({ size: 1_000_000, hashCount: 7 });
    const items = Array.from({ length: 10_000 }, (_, i) => `item-${i}`);
    for (const item of items) {
      bf.add(item);
    }

    // All added items should be found
    for (const item of items) {
      expect(bf.contains(item)).toBe(true);
    }

    // Check false positive rate on non-added items
    let falsePositives = 0;
    const testItems = Array.from({ length: 10_000 }, (_, i) => `test-${i}`);
    for (const item of testItems) {
      if (bf.contains(item)) falsePositives++;
    }
    // Should be well under 1%
    expect(falsePositives).toBeLessThan(100);
  });

  it("works with realistic key+url combinations", () => {
    const bf = new BloomFilter({ size: 1_000_000, hashCount: 7 });
    const combo = "sk-proj-abc123|https://github.com/user/repo/blob/main/.env";
    bf.add(combo);
    expect(bf.contains(combo)).toBe(true);
    expect(bf.contains("sk-proj-abc123|https://github.com/other/repo/blob/main/.env")).toBe(false);
  });
});
