import { describe, it, expect } from "vitest";
import { extractKeys, KEY_PATTERNS } from "../src/patterns/key-patterns.js";

// Helper: build key strings at runtime to avoid GitHub secret scanning
const sk = (prefix: string, body: string) => `${prefix}${body}`;
const PAD28 = "A".repeat(28);
const PAD36 = "aBcDeFgHiJkLmNoPqRsTuVwXyZ012345"; // 36 chars mixed case+digit

describe("KEY_PATTERNS", () => {
  it("has patterns for all expected services", () => {
    const services = KEY_PATTERNS.map((p) => p.service);
    expect(services).toContain("OpenAI");
    expect(services).toContain("OpenRouter");
    expect(services).toContain("XAI");
    expect(services).toContain("DeepSeek");
    expect(services).toContain("Gemini");
    expect(services).toContain("Anthropic");
    expect(services).toContain("Replicate");
    expect(services).toContain("HuggingFace");
    expect(services).toContain("MiMo");
    expect(services).toContain("MiniMax");
    expect(services).toContain("Perplexity");
    expect(services).toContain("GitHub_PAT");
    expect(services).toContain("GitHub_Token");
    expect(services).toContain("Stripe_Live");
    expect(services).toContain("Stripe_Test");
  });
});

describe("extractKeys", () => {
  it("extracts OpenAI project keys", () => {
    const key = sk("sk-proj-", "abcDEF12345678901234567890123456789012345678901234567890abc");
    const text = `const key = "${key}";`;
    const results = extractKeys(text);
    expect(results).toHaveLength(1);
    expect(results[0]!.service).toBe("OpenAI");
    expect(results[0]!.key).toContain("sk-proj-");
  });

  it("extracts multiple different keys", () => {
    const openai = sk("sk-proj-", "abcDEF12345678901234567890123456789012345678901234567890abc");
    const gemini = sk("AIza", "SyD-9tSrke72PouQkMaSkqFGz8abc123deF");
    const stripe = sk("sk_live_", PAD28);
    const text = `OPENAI_KEY=${openai}\nGEMINI_KEY=${gemini}\nSTRIPE_KEY=${stripe}`;
    const results = extractKeys(text);
    expect(results.length).toBeGreaterThanOrEqual(3);
    const services = results.map((r) => r.service);
    expect(services).toContain("OpenAI");
    expect(services).toContain("Gemini");
    expect(services).toContain("Stripe_Live");
  });

  it("does not extract non-matching strings", () => {
    const text = "This is just regular text with no keys.";
    const results = extractKeys(text);
    expect(results).toHaveLength(0);
  });

  it("handles duplicate keys in same text", () => {
    const key = sk("sk-proj-", "abcDEF12345678901234567890123456789012345678901234567890abc");
    const text = `${key}\n${key}`;
    const results = extractKeys(text);
    const openaiKeys = results.filter((r) => r.service === "OpenAI");
    expect(openaiKeys).toHaveLength(1);
  });

  it("extracts GitHub PAT", () => {
    const key = sk("github_pat_", "11ABCDEF1234567890abcdef1234567890abcdef1234567890abcdef1234");
    const text = `token: ${key}`;
    const results = extractKeys(text);
    expect(results).toHaveLength(1);
    expect(results[0]!.service).toBe("GitHub_PAT");
  });

  it("extracts Stripe test keys", () => {
    const key = sk("sk_test_", PAD28);
    const results = extractKeys(key);
    expect(results).toHaveLength(1);
    expect(results[0]!.service).toBe("Stripe_Test");
  });

  it("extracts HuggingFace tokens", () => {
    const key = sk("hf_", "abcDEF123456789012345678901234");
    const text = `HF_TOKEN=${key}`;
    const results = extractKeys(text);
    expect(results).toHaveLength(1);
    expect(results[0]!.service).toBe("HuggingFace");
  });

  it("extracts Replicate tokens", () => {
    const key = sk("r8_", "abcDEF12345678901234567890123456");
    const text = `REPLICATE_API_TOKEN=${key}`;
    const results = extractKeys(text);
    expect(results).toHaveLength(1);
    expect(results[0]!.service).toBe("Replicate");
  });

  it("extracts Anthropic keys", () => {
    const key = sk("sk-ant-api03-", "abcDEF1234567890123456789012345678901234567890");
    const text = `ANTHROPIC_API_KEY=${key}`;
    const results = extractKeys(text);
    expect(results).toHaveLength(1);
    expect(results[0]!.service).toBe("Anthropic");
  });
});
