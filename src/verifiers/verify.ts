/**
 * Key verification orchestrator.
 * Tries SDK-first, falls back to HTTP verification.
 */

import type { ServiceName, VerifyResult, VerifierFn } from "../types/index.js";
import { HTTP_VERIFIERS } from "./http-verifiers.js";

const REQUEST_TIMEOUT = 8_000;

const USER_AGENTS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
];

function randomUA(): string {
  return USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)]!;
}

/**
 * Verify an OpenRouter key (special two-step verification).
 */
async function verifyOpenRouter(key: string): Promise<VerifyResult> {
  const headers = { Authorization: `Bearer ${key}`, "User-Agent": randomUA() };
  try {
    const authResp = await fetch("https://openrouter.ai/api/v1/auth/key", {
      headers,
      signal: AbortSignal.timeout(REQUEST_TIMEOUT),
    });
    if (authResp.status !== 200) {
      return { valid: false, balance: 0, info: `HTTP ${authResp.status}` };
    }

    const creditsResp = await fetch("https://openrouter.ai/api/v1/credits", {
      headers,
      signal: AbortSignal.timeout(REQUEST_TIMEOUT),
    });
    if (creditsResp.status === 200) {
      const data = (await creditsResp.json()) as { data?: { credits?: number } };
      const credits = data.data?.credits ?? 0;
      return {
        valid: true,
        balance: Number(credits),
        info: credits > 0 ? `Credits: ${credits}` : "Valid (no credits)",
      };
    }
    if (creditsResp.status === 403) {
      return { valid: true, balance: 0, info: "Valid (credits unknown: not a Management Key)" };
    }
    return { valid: true, balance: 0, info: `Valid (credits check HTTP ${creditsResp.status})` };
  } catch (err) {
    return { valid: false, balance: 0, info: `Error: ${String(err).slice(0, 30)}` };
  }
}

/**
 * HTTP-based key verification (REST fallback).
 */
async function verifyHttp(key: string, service: ServiceName): Promise<VerifyResult> {
  const config = HTTP_VERIFIERS[service];
  if (!config) {
    return { valid: false, balance: 0, info: "No verifier configured" };
  }

  try {
    const url = typeof config.url === "function" ? config.url(key) : config.url;
    const headers = { ...config.headers(key), "User-Agent": randomUA() };

    const init: RequestInit = {
      method: config.method,
      headers,
      signal: AbortSignal.timeout(REQUEST_TIMEOUT),
    };
    if (config.body) {
      init.body = config.body();
    }

    const resp = await fetch(url, init);
    let data: unknown;
    try {
      data = await resp.json();
    } catch {
      data = null;
    }

    return config.parse(resp.status, data);
  } catch (err) {
    return { valid: false, balance: 0, info: `Error: ${String(err).slice(0, 30)}` };
  }
}

/**
 * SDK verifiers — preferred over HTTP when available.
 * These use the official client libraries for more reliable verification.
 */
const SDK_VERIFIERS: Partial<Record<ServiceName, VerifierFn>> = {
  // TODO: M1 phase — implement SDK verifiers
  // OpenAI: verifyOpenAISDK,
  // Anthropic: verifyAnthropicSDK,
  // etc.
};

/**
 * Verify a key against its service.
 * Tries SDK first, falls back to HTTP.
 */
export async function verifyKey(key: string, service: ServiceName): Promise<VerifyResult> {
  // Special case: OpenRouter has custom two-step verification
  if (service === "OpenRouter") {
    return verifyOpenRouter(key);
  }

  // Try SDK verifier first
  const sdkVerifier = SDK_VERIFIERS[service];
  if (sdkVerifier) {
    try {
      return await sdkVerifier(key);
    } catch {
      // Fall through to HTTP
    }
  }

  // HTTP fallback
  return verifyHttp(key, service);
}
