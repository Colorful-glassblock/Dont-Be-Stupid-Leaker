/**
 * Shannon entropy calculation and fake key detection.
 * Ported from Python scan_keys.py.
 */

/** Known service key prefixes to strip before entropy calculation */
const KEY_PREFIXES = [
  "sk-proj-",
  "sk-or-v1-",
  "xai-",
  "AIza",
  "sk-ant-api",
  "r8_",
  "hf_",
  "tp-",
  "sk-api-",
  "pplx-",
  "github_pat_",
  "ghp_",
  "sk_live_",
  "sk_test_",
  "sk-",
];

/** Default entropy threshold — keys below this are considered fake */
export const DEFAULT_ENTROPY_THRESHOLD = 2.5;

/**
 * Calculate Shannon entropy of a string.
 * Higher entropy = more randomness = more likely a real key.
 */
export function shannonEntropy(s: string): number {
  if (!s) return 0.0;

  const freq = new Map<string, number>();
  for (const ch of s) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1);
  }

  const len = s.length;
  let entropy = 0.0;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Determine if a key looks fake based on its entropy.
 * Strips the known prefix, then checks if the remaining body
 * has enough randomness to be a real key.
 */
export function isFakeKey(key: string, threshold = DEFAULT_ENTROPY_THRESHOLD): boolean {
  let body = key;

  // Strip the longest matching prefix
  for (const prefix of KEY_PREFIXES) {
    if (body.startsWith(prefix)) {
      body = body.slice(prefix.length);
      break;
    }
  }

  // Too short = definitely fake
  if (body.length < 8) return true;

  return shannonEntropy(body) < threshold;
}
