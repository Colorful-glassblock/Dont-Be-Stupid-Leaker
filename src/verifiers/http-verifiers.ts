/**
 * HTTP-based verifiers for API keys.
 * These are the REST fallback when SDK verification is unavailable.
 * Ported from Python VERIFIERS dict.
 */

import type { HttpVerifierConfig, VerifyResult } from "../types/index.js";

// ─── Response Parsers ────────────────────────────────────────────

function parseOpenAI(status: number, _data: unknown): VerifyResult {
  if (status === 200) return { valid: true, balance: 0, info: "Valid" };
  if (status === 401) return { valid: false, balance: 0, info: "Invalid" };
  return { valid: false, balance: 0, info: `HTTP ${status}` };
}

function parseXAI(status: number, _data: unknown): VerifyResult {
  if (status === 200) return { valid: true, balance: 0, info: "Valid" };
  return { valid: false, balance: 0, info: `HTTP ${status}` };
}

function parseDeepSeek(status: number, data: unknown): VerifyResult {
  if (status !== 200 || !data || typeof data !== "object") {
    return { valid: false, balance: 0, info: `HTTP ${status}` };
  }
  const d = data as Record<string, unknown>;
  if (!d.is_available) return { valid: false, balance: 0, info: "Invalid" };

  let cny = 0;
  let usd = 0;
  const balanceInfos = d.balance_infos;
  if (Array.isArray(balanceInfos)) {
    for (const item of balanceInfos) {
      const currency = item.currency ?? "";
      const balance = parseFloat(item.total_balance ?? "0") || 0;
      if (currency === "CNY") cny += balance;
      else if (currency === "USD") usd += balance;
    }
  }

  const info = cny || usd
    ? `CNY: ${cny.toFixed(2)}, USD: ${usd.toFixed(2)}`
    : "Valid (no balance)";
  return { valid: true, balance: cny + usd * 7.2, info };
}

function parseGemini(status: number, _data: unknown): VerifyResult {
  if (status === 200) return { valid: true, balance: 0, info: "Valid" };
  if (status === 403) return { valid: false, balance: 0, info: "Invalid (403)" };
  return { valid: false, balance: 0, info: `HTTP ${status}` };
}

function parseAnthropic(status: number, _data: unknown): VerifyResult {
  if (status === 200) return { valid: true, balance: 0, info: "Valid" };
  return { valid: false, balance: 0, info: `HTTP ${status}` };
}

function parseGitHubToken(status: number, _data: unknown): VerifyResult {
  if (status === 200) return { valid: true, balance: 0, info: "Valid" };
  return { valid: false, balance: 0, info: "Invalid" };
}

function parseStripe(status: number, _data: unknown): VerifyResult {
  if (status === 200) return { valid: true, balance: 0, info: "Valid" };
  if (status === 401) return { valid: false, balance: 0, info: "Invalid" };
  return { valid: false, balance: 0, info: `HTTP ${status}` };
}

function parseGeneric(status: number, data: unknown): VerifyResult {
  if (status === 200) {
    if (data && typeof data === "object") {
      const d = data as Record<string, unknown>;
      if (d.error) return { valid: false, balance: 0, info: `Invalid: ${d.error}` };
      if (d.errors) return { valid: false, balance: 0, info: "Invalid (errors returned)" };
      if (d.message && String(d.message).toLowerCase().includes("error")) {
        return { valid: false, balance: 0, info: `Invalid: ${d.message}` };
      }
    }
    return { valid: true, balance: 0, info: "Valid" };
  }
  return { valid: false, balance: 0, info: `HTTP ${status}` };
}

// ─── Verifier Configs ────────────────────────────────────────────

export const HTTP_VERIFIERS: Record<string, HttpVerifierConfig> = {
  OpenAI: {
    url: "https://api.openai.com/v1/models",
    headers: (k) => ({ Authorization: `Bearer ${k}` }),
    method: "GET",
    parse: parseOpenAI,
  },
  XAI: {
    url: "https://api.x.ai/v1/models",
    headers: (k) => ({ Authorization: `Bearer ${k}` }),
    method: "GET",
    parse: parseXAI,
  },
  DeepSeek: {
    url: "https://api.deepseek.com/user/balance",
    headers: (k) => ({ Authorization: `Bearer ${k}`, Accept: "application/json" }),
    method: "GET",
    parse: parseDeepSeek,
  },
  Gemini: {
    url: (k) => `https://generativelanguage.googleapis.com/v1/models?key=${k}`,
    headers: () => ({}),
    method: "GET",
    parse: parseGemini,
  },
  Anthropic: {
    url: "https://api.anthropic.com/v1/messages",
    headers: (k) => ({
      "x-api-key": k,
      "anthropic-version": "2023-06-01",
      "Content-Type": "application/json",
    }),
    method: "POST",
    body: () =>
      JSON.stringify({
        model: "claude-3-haiku-20240307",
        max_tokens: 1,
        messages: [{ role: "user", content: "hi" }],
      }),
    parse: parseAnthropic,
  },
  Replicate: {
    url: "https://api.replicate.com/v1/account",
    headers: (k) => ({ Authorization: `Bearer ${k}` }),
    method: "GET",
    parse: parseGeneric,
  },
  HuggingFace: {
    url: "https://huggingface.co/api/whoami",
    headers: (k) => ({ Authorization: `Bearer ${k}` }),
    method: "GET",
    parse: parseGeneric,
  },
  MiMo: {
    url: "https://token-plan-cn.xiaomimimo.com/v1/models",
    headers: (k) => ({ Authorization: `Bearer ${k}`, "X-Plan-Type": "token-plan" }),
    method: "GET",
    parse: parseGeneric,
  },
  MiniMax: {
    url: "https://api.minimax.io/v1/models",
    headers: (k) => ({ Authorization: `Bearer ${k}` }),
    method: "GET",
    parse: parseGeneric,
  },
  Perplexity: {
    url: "https://api.perplexity.ai/chat/completions",
    headers: (k) => ({
      Authorization: `Bearer ${k}`,
      "Content-Type": "application/json",
    }),
    method: "POST",
    body: () =>
      JSON.stringify({
        model: "llama-3.1-sonar-small-128k-online",
        messages: [{ role: "user", content: "hi" }],
        max_tokens: 1,
      }),
    parse: parseGeneric,
  },
  GitHub_PAT: {
    url: "https://api.github.com/user",
    headers: (k) => ({ Authorization: `Bearer ${k}` }),
    method: "GET",
    parse: parseGitHubToken,
  },
  GitHub_Token: {
    url: "https://api.github.com/user",
    headers: (k) => ({ Authorization: `Bearer ${k}` }),
    method: "GET",
    parse: parseGitHubToken,
  },
  Stripe_Live: {
    url: "https://api.stripe.com/v1/account",
    headers: (k) => ({ Authorization: `Bearer ${k}` }),
    method: "GET",
    parse: parseStripe,
  },
  Stripe_Test: {
    url: "https://api.stripe.com/v1/account",
    headers: (k) => ({ Authorization: `Bearer ${k}` }),
    method: "GET",
    parse: parseStripe,
  },
};
