/**
 * API Key Leak Scanner - TypeScript Rewrite
 * Main entry point — re-exports all public modules.
 */

// Types
export type {
  ServiceName,
  SourceType,
  VerifyResult,
  KeyPattern,
  LeakReport,
  ScanConfig,
  PendingVerification,
  VerifierFn,
  HttpVerifierConfig,
} from "./types/index.js";

// Key patterns & extraction
export { KEY_PATTERNS, extractKeys } from "./patterns/key-patterns.js";

// Entropy / fake key detection
export { shannonEntropy, isFakeKey, DEFAULT_ENTROPY_THRESHOLD } from "./utils/entropy.js";

// Verifiers
export { verifyKey } from "./verifiers/verify.js";
export { HTTP_VERIFIERS } from "./verifiers/http-verifiers.js";

// Deduplication
export { Deduplicator } from "./utils/dedup.js";
export { BloomFilter } from "./utils/bloom-filter.js";
export { LRUCache } from "./utils/lru-cache.js";

// GitHub
export { configureGitHubAuth, getOctokit, invalidateOctokit } from "./github/client.js";
export { getFileContent, buildRawUrl, getIssueOrPrContent, getCommitContent } from "./github/content.js";
export { runSearchWorker, DEFAULT_SEARCH_CONFIG } from "./github/search.js";

// Verification
export { BatchManager, DEFAULT_BATCH_CONFIG } from "./verify/batch-manager.js";

// Notifications
export { handleLeak, notifyOriginalRepo, replyToOriginalIssue, createArchiveIssue } from "./notify/notifier.js";
export { addResult, saveFinalResults, getResults, setRealtimeFile } from "./notify/results.js";

// Deep scan
export { deepScanRepository, DEFAULT_DEEP_SCAN_CONFIG } from "./scan/deep-scan.js";

// Shutdown
export { setupSignalHandlers, onShutdown, isShuttingDown, gracefulShutdown } from "./scan/shutdown.js";

// Config
export { loadConfig } from "./config.js";
