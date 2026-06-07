/**
 * Main scanner orchestrator.
 * Ties together search, verification, notification, and deep scan.
 */

import { configureGitHubAuth } from "./github/client.js";
import { runSearchWorker, DEFAULT_SEARCH_CONFIG, type SearchType, type SearchCallbacks } from "./github/search.js";
import { BatchManager } from "./verify/batch-manager.js";
import { Deduplicator } from "./utils/dedup.js";
import { handleLeak } from "./notify/notifier.js";
import { addResult, setRealtimeFile } from "./notify/results.js";
import { deepScanRepository, DEFAULT_DEEP_SCAN_CONFIG } from "./scan/deep-scan.js";
import { setupSignalHandlers, onShutdown, isShuttingDown, gracefulShutdown } from "./scan/shutdown.js";
import { loadConfig } from "./config.js";
import type { LeakReport, PendingVerification } from "./types/index.js";

const MAX_PENDING_DEEP_SCANS = 10;
const DEEP_SCAN_WORKER_ID = 99;

export async function run(): Promise<void> {
  const config = loadConfig();

  console.log("=".repeat(70));
  console.log("🤖 API Key Leak Scanner - TypeScript v1.0");
  console.log(`📁 Fallback repo: ${config.repoName}`);
  console.log(`⏱️  Max runtime: ${config.maxRuntimeSeconds}s`);
  console.log(`📦 Batch size: ${config.batchSize} keys OR ${config.batchTimeout / 1000}s timeout`);
  console.log(`🔍 Scanning: CODE + ISSUES/PRs + COMMITS + ENV`);
  console.log(`🧠 Fake key filter: entropy < ${config.fakeKeyEntropyThreshold}`);
  console.log("=".repeat(70));

  // Setup auth
  configureGitHubAuth({
    patToken: config.patToken,
    appId: config.appId,
    privateKey: config.privateKey,
    installationId: config.installationId,
  });

  // Setup signal handlers
  setupSignalHandlers();

  // State
  const dedup = new Deduplicator();
  const foundValid: LeakReport[] = [];
  const startTime = Date.now();
  let deepScanActive = 0;

  setRealtimeFile("valid_keys_realtime.txt");

  // Batch manager
  const batchManager = new BatchManager(
    { batchSize: config.batchSize, batchTimeout: config.batchTimeout, concurrency: config.verifyWorkers },
    (result) => {
      const report: LeakReport = {
        key: result.key,
        service: result.service,
        balance: result.balance,
        info: result.info,
        sourceUrl: result.sourceUrl,
        sourceType: result.sourceType,
        author: result.author,
        timestamp: new Date(),
      };
      foundValid.push(report);
      addResult(report);

      console.log(`  ✅ [${result.service}] ${result.key.slice(0, 25)}... -> ${result.info}`);
      console.log(`     📍 Source: ${result.sourceUrl}`);

      // Fire-and-forget notification
      handleLeak(report, { repoName: config.repoName, botName: config.botName }).catch((err) =>
        console.error(`    ❌ Notification error: ${err}`)
      );

      // Trigger deep scan for blob sources
      if (result.sourceUrl.includes("/blob/") && deepScanActive < MAX_PENDING_DEEP_SCANS) {
        const repoMatch = result.sourceUrl.match(/github\.com\/([^/]+\/[^/]+)\/blob\//);
        if (repoMatch) {
          const repoFullName = repoMatch[1]!;
          deepScanActive++;
          deepScanRepository(repoFullName, DEFAULT_DEEP_SCAN_CONFIG, {
            onKeyFound: (item) => {
              if (!dedup.isDuplicate(item.key, item.sourceUrl)) {
                batchManager.add(DEEP_SCAN_WORKER_ID, item);
              }
            },
            shouldStop: isShuttingDown,
          }).finally(() => deepScanActive--);
        }
      }
    }
  );

  // Register shutdown handlers
  onShutdown(async () => {
    console.log("[!] Flushing pending batches...");
    await batchManager.drain();
  });

  // Search callbacks
  const searchCallbacks: SearchCallbacks = {
    onKeyFound: (item: PendingVerification) => {
      if (!dedup.isDuplicate(item.key, item.sourceUrl)) {
        console.log(`  🔑 Found ${item.service} key: ${item.sourceUrl.slice(0, 80)}...`);
        batchManager.add(0, item);
      }
    },
    shouldStop: isShuttingDown,
  };

  // Check timeout
  const checkTimeout = () => {
    if (Date.now() - startTime >= config.maxRuntimeSeconds * 1000) {
      console.log(`\nMax runtime reached (${config.maxRuntimeSeconds}s). Shutting down...`);
      gracefulShutdown();
      return true;
    }
    return false;
  };

  // Launch search workers
  const searchTypes: SearchType[] = ["code", "issues", "commits"];
  const searchConfig = {
    ...DEFAULT_SEARCH_CONFIG,
    queries: {
      ...DEFAULT_SEARCH_CONFIG.queries,
      code: config.queries.code,
      issues: config.queries.issues,
      commits: config.queries.commits,
    },
  };

  // Also run env search as code search with env query
  const workers = searchTypes.map((type, i) =>
    runSearchWorker(i + 1, type, 1, searchConfig, searchCallbacks)
  );

  // Env file search
  workers.push(
    runSearchWorker(searchTypes.length + 1, "code", 1, { ...searchConfig, queries: { ...searchConfig.queries, code: config.queries.env } }, searchCallbacks)
  );

  // Heartbeat
  const heartbeat = setInterval(() => {
    if (checkTimeout()) {
      clearInterval(heartbeat);
      return;
    }
    const elapsed = Math.floor((Date.now() - startTime) / 1000);
    const remaining = config.maxRuntimeSeconds - elapsed;
    console.log(`❤️ Alive: ${elapsed}s / ${config.maxRuntimeSeconds}s (remaining: ${remaining}s)`);
    console.log(`📊 Found: ${foundValid.length} valid keys | Deep scans active: ${deepScanActive}`);
  }, 60_000);

  // Wait for all workers
  await Promise.allSettled(workers);

  clearInterval(heartbeat);

  // Final drain
  await batchManager.drain();

  console.log(`\n✅ Scan completed. Found ${foundValid.length} valid keys.`);
}

// Run if executed directly
run().catch((err) => {
  console.error(`❌ Fatal error: ${err}`);
  process.exit(1);
});
