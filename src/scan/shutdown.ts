/**
 * Graceful shutdown handler.
 * Listens for SIGINT/SIGTERM, drains queues, saves results.
 */

import { saveFinalResults } from "../notify/results.js";

type ShutdownFn = () => Promise<void>;

const _shutdownFns: ShutdownFn[] = [];
let _shuttingDown = false;

export function onShutdown(fn: ShutdownFn): void {
  _shutdownFns.push(fn);
}

export function isShuttingDown(): boolean {
  return _shuttingDown;
}

export async function gracefulShutdown(): Promise<void> {
  if (_shuttingDown) return;
  _shuttingDown = true;

  console.log("\n[!] Graceful shutdown initiated...");

  for (const fn of _shutdownFns) {
    try {
      await fn();
    } catch (err) {
      console.error(`[!] Shutdown handler error: ${err}`);
    }
  }

  console.log("[!] Saving results...");
  saveFinalResults();
  console.log("[!] Shutdown complete.");
}

export function setupSignalHandlers(): void {
  const handler = () => {
    gracefulShutdown().then(() => process.exit(0));
  };
  process.on("SIGINT", handler);
  process.on("SIGTERM", handler);
}
