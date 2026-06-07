/**
 * Configuration loader — env vars + defaults.
 */

import type { ScanConfig } from "./types/index.js";

export interface RuntimeConfig extends ScanConfig {
  // Auth
  patToken?: string;
  appId?: string;
  privateKey?: string;
  installationId?: string;
}

export function loadConfig(): RuntimeConfig {
  const env = process.env;

  return {
    // Auth
    patToken: env.PAT_TOKEN,
    appId: env.APP_ID,
    privateKey: env.PRIVATE_KEY,
    installationId: env.INSTALLATION_ID,

    // Scan settings
    maxRuntimeSeconds: parseInt(env.MAX_RUNTIME_SECONDS ?? "3000", 10), // 50 min
    searchWorkers: parseInt(env.SEARCH_WORKERS ?? "3", 10),
    verifyWorkers: parseInt(env.VERIFY_WORKERS ?? "20", 10),
    batchSize: parseInt(env.BATCH_SIZE ?? "30", 10),
    batchTimeout: parseInt(env.BATCH_TIMEOUT ?? "60", 10) * 1000,
    fakeKeyEntropyThreshold: parseFloat(env.FAKE_KEY_ENTROPY_THRESHOLD ?? "2.5"),
    deepScanMaxFiles: parseInt(env.DEEP_SCAN_MAX_FILES ?? "200", 10),
    githubApi: env.GITHUB_API ?? "https://api.github.com",
    repoName: env.GITHUB_REPOSITORY ?? "Colorful-glassblock/Dont-Be-Stupid-Leaker",
    botName: env.BOT_NAME ?? "LLMApiCheckBot",

    queries: {
      code: env.CODE_QUERY ?? "sk-proj- OR xai- OR AIza OR sk-ant-api OR r8_ OR hf_ OR tp-",
      issues: env.ISSUE_QUERY ?? '"your key leak" OR "sk-proj-" OR "xai-" OR "AIza" OR "sk-ant-api"',
      commits: env.COMMIT_QUERY ?? "sk-proj- OR xai- OR AIza OR sk-ant-api",
      env: env.ENV_QUERY ?? "filename:.env OR filename:.env.example OR filename:.env.local OR filename:.env.production",
    },
  };
}
