/**
 * Scan results output — text file + structured logging.
 */

import { writeFileSync, appendFileSync } from "node:fs";
import type { LeakReport } from "../types/index.js";

const results: LeakReport[] = [];
let realtimeFile: string | null = null;

export function setRealtimeFile(path: string): void {
  realtimeFile = path;
}

export function addResult(report: LeakReport): void {
  results.push(report);

  // Write to realtime file
  if (realtimeFile) {
    const ts = report.timestamp.toISOString().replace("T", " ").slice(0, 19);
    const line = `${ts} | ${report.service} | ${report.key} | ${report.info} | ${report.sourceUrl}\n`;
    try {
      appendFileSync(realtimeFile, line);
    } catch {
      // Ignore
    }
  }
}

export function getResults(): readonly LeakReport[] {
  return results;
}

/**
 * Save final results to a timestamped text file.
 */
export function saveFinalResults(): string | null {
  if (results.length === 0) return null;

  // Deduplicate by key+sourceUrl
  const unique = new Map<string, LeakReport>();
  for (const r of results) {
    const k = `${r.key}|${r.sourceUrl}`;
    if (!unique.has(k)) unique.set(k, r);
  }

  const ts = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  const filename = `valid_keys_final_${ts}.txt`;

  const lines: string[] = [
    `# Scan time: ${new Date().toISOString()}`,
    `# Total valid keys (unique): ${unique.size}`,
    "",
  ];
  for (const r of unique.values()) {
    lines.push(`${r.service} | ${r.key} | ${r.info} | ${r.sourceUrl}`);
  }

  writeFileSync(filename, lines.join("\n") + "\n");
  console.log(`\nSaved ${unique.size} unique keys to ${filename}`);
  return filename;
}
