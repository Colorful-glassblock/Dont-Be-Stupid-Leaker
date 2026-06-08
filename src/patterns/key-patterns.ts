import type { KeyPattern, ServiceName } from "../types/index.js";

/**
 * All supported API key patterns.
 * Ported from Python scan_keys.py KEY_PATTERNS.
 *
 * Order matters for matching priority — more specific patterns first.
 */
export const KEY_PATTERNS: KeyPattern[] = [
  { service: "OpenAI",      regex: /sk-proj-[a-zA-Z0-9_-]{50,}/ },
  { service: "OpenRouter",  regex: /sk-or-v1-[a-zA-Z0-9]{50,}/ },
  { service: "XAI",         regex: /xai-[a-zA-Z0-9]{32,}/ },
  { service: "Anthropic",   regex: /sk-ant-api[0-9A-Za-z_-]{40,}/ },
  { service: "Gemini",      regex: /AIza[0-9A-Za-z_-]{35}/ },
  { service: "Replicate",   regex: /r8_[a-zA-Z0-9]{32,}/ },
  { service: "HuggingFace", regex: /hf_[a-zA-Z0-9]{30,}/ },
  { service: "MiMo",        regex: /tp-[a-zA-Z0-9]{10,}/ },
  { service: "MiniMax",     regex: /sk-api-[a-zA-Z0-9]{100,}/ },
  { service: "Perplexity",  regex: /pplx-[a-zA-Z0-9]{32,}/ },
  { service: "GitHub_PAT",  regex: /github_pat_[a-zA-Z0-9_]{50,}/ },
  { service: "GitHub_Token",regex: /ghp_[a-zA-Z0-9]{36}/ },
  { service: "Stripe_Live", regex: /sk_live_[a-zA-Z0-9]{24,}/ },
  { service: "Stripe_Test", regex: /sk_test_[a-zA-Z0-9]{24,}/ },
  // DeepSeek uses sk- prefix — must come after more specific sk- patterns
  { service: "DeepSeek",    regex: /sk-[a-zA-Z0-9]{32,}/ },
];

/**
 * Extract all matching keys from text.
 * Returns deduplicated results (same key+position = one match).
 */
export function extractKeys(text: string): Array<{ key: string; service: ServiceName }> {
  const seen = new Set<string>();
  const results: Array<{ key: string; service: ServiceName }> = [];

  for (const { service, regex } of KEY_PATTERNS) {
    const re = new RegExp(regex.source, regex.flags.includes("g") ? regex.flags : regex.flags + "g");
    let match: RegExpExecArray | null;
    while ((match = re.exec(text)) !== null) {
      const key = match[0]!;
      const dedupeKey = `${service}:${key}`;
      if (!seen.has(dedupeKey)) {
        seen.add(dedupeKey);
        results.push({ key, service });
      }
    }
  }

  return results;
}
