import { describe, it, expect } from "vitest";
import { Deduplicator } from "../src/utils/dedup.js";

describe("Deduplicator", () => {
  it("returns false for first occurrence", () => {
    const dedup = new Deduplicator();
    expect(dedup.isDuplicate("sk-proj-abc", "https://github.com/repo/blob/main/.env")).toBe(false);
  });

  it("returns true for exact duplicate", () => {
    const dedup = new Deduplicator();
    dedup.isDuplicate("sk-proj-abc", "https://github.com/repo/blob/main/.env");
    expect(dedup.isDuplicate("sk-proj-abc", "https://github.com/repo/blob/main/.env")).toBe(true);
  });

  it("treats same key from different sources as different", () => {
    const dedup = new Deduplicator();
    expect(dedup.isDuplicate("sk-proj-abc", "https://github.com/repo/blob/main/.env")).toBe(false);
    expect(dedup.isDuplicate("sk-proj-abc", "https://github.com/repo/blob/main/config.json")).toBe(false);
  });

  it("handles many unique items", () => {
    const dedup = new Deduplicator();
    for (let i = 0; i < 1000; i++) {
      expect(dedup.isDuplicate(`key-${i}`, `url-${i}`)).toBe(false);
    }
    // All should now be duplicates
    for (let i = 0; i < 1000; i++) {
      expect(dedup.isDuplicate(`key-${i}`, `url-${i}`)).toBe(true);
    }
  });
});
