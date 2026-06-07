import { describe, it, expect } from "vitest";
import { shannonEntropy, isFakeKey } from "../src/utils/entropy.js";

describe("shannonEntropy", () => {
  it("returns 0 for empty string", () => {
    expect(shannonEntropy("")).toBe(0);
  });

  it("returns 0 for single character repeated", () => {
    expect(shannonEntropy("aaaa")).toBe(0);
  });

  it("returns higher entropy for more diverse strings", () => {
    const low = shannonEntropy("aabb");
    const high = shannonEntropy("abcd");
    expect(high).toBeGreaterThan(low);
  });

  it("returns ~log2(n) for n equally-distributed characters", () => {
    // "abcd" has 4 unique chars, each appearing once
    // entropy = log2(4) = 2.0
    const e = shannonEntropy("abcd");
    expect(e).toBeCloseTo(2.0, 5);
  });

  it("handles real-world key-like strings", () => {
    const realKey = "sk-proj-abcDEF123456_-xyzXYZ789012345678901234567890";
    const e = shannonEntropy(realKey);
    expect(e).toBeGreaterThan(3.0);
  });
});

describe("isFakeKey", () => {
  it("flags keys with low-entropy body", () => {
    // "sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    // body after prefix stripping is all 'x' — entropy = 0
    expect(isFakeKey("sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")).toBe(true);
  });

  it("flags keys that are too short", () => {
    expect(isFakeKey("sk-proj-abc")).toBe(true);
  });

  it("accepts keys with high-entropy body", () => {
    // A realistic-looking key with diverse characters
    const key = "sk-proj-aB3dE7fG9hI1jK5lM7nO9pQ3rS5tU7vW9xY1zA3bC5dE7fG9";
    expect(isFakeKey(key)).toBe(false);
  });

  it("handles Gemini-style keys", () => {
    const fakeGemini = "AIza" + "x".repeat(35);
    expect(isFakeKey(fakeGemini)).toBe(true);

    // Real-looking Gemini key
    const realGemini = "AIzaSyD-9tSrke72PouQkMaSkqFGz8abc123deF";
    expect(isFakeKey(realGemini)).toBe(false);
  });

  it("handles GitHub PAT keys", () => {
    const fake = "github_pat_" + "x".repeat(50);
    expect(isFakeKey(fake)).toBe(true);
  });

  it("uses custom threshold", () => {
    // A key that passes at default threshold but fails at higher threshold
    const key = "sk-proj-aabbccddeeff11223344556677889900AABBCCDDEEFF";
    expect(isFakeKey(key, 2.5)).toBe(false);
    expect(isFakeKey(key, 5.0)).toBe(true);
  });
});
