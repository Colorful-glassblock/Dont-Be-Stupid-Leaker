/**
 * Deep scan: recursively scan a repo's default branch for leaked keys.
 * Ported from Python deep_scan_repository.
 */

import { getOctokit } from "../github/client.js";
import { getFileContent } from "../github/content.js";
import { extractKeys } from "../patterns/key-patterns.js";
import { isFakeKey } from "../utils/entropy.js";
import type { PendingVerification } from "../types/index.js";

export interface DeepScanConfig {
  maxFiles: number;
  extensions: string[];
  fileDelay: number;
}

export const DEFAULT_DEEP_SCAN_CONFIG: DeepScanConfig = {
  maxFiles: 200,
  extensions: [
    ".env", ".json", ".yaml", ".yml", ".toml", ".txt", ".md", ".cfg", ".conf",
    ".config", ".ini", ".properties", ".py", ".js", ".ts", ".java", ".go", ".rs", ".rb", ".php",
  ],
  fileDelay: 300,
};

const scannedRepos = new Set<string>();
const MAX_SCANNED_REPOS = 10_000;

export interface DeepScanCallbacks {
  onKeyFound: (item: PendingVerification) => void;
  shouldStop: () => boolean;
}

/**
 * Deep scan a repository's default branch.
 * Returns number of keys found.
 */
export async function deepScanRepository(
  repoFullName: string,
  config: DeepScanConfig,
  callbacks: DeepScanCallbacks,
): Promise<number> {
  if (scannedRepos.has(repoFullName)) return 0;
  if (scannedRepos.size >= MAX_SCANNED_REPOS) return 0;
  scannedRepos.add(repoFullName);

  console.log(`\n🔍 Deep scanning: ${repoFullName}`);
  const octokit = getOctokit();

  try {
    const { data: repo } = await octokit.repos.get({ owner: repoFullName.split("/")[0]!, repo: repoFullName.split("/")[1]! });
    const branch = repo.default_branch;
    const author = repo.owner?.login ?? "unknown";

    const { data: commit } = await octokit.repos.getCommit({ owner: repoFullName.split("/")[0]!, repo: repoFullName.split("/")[1]!, ref: branch });
    const treeSha = commit.commit.tree.sha;

    const { data: tree } = await octokit.git.getTree({
      owner: repoFullName.split("/")[0]!,
      repo: repoFullName.split("/")[1]!,
      tree_sha: treeSha,
      recursive: "true",
    });

    if (tree.truncated) {
      console.log(`  ⚠️ Tree truncated (repo too large), results may be incomplete`);
    }

    let foundCount = 0;
    let filesScanned = 0;

    for (const item of tree.tree) {
      if (callbacks.shouldStop()) break;
      if (filesScanned >= config.maxFiles) break;
      if (item.type !== "blob" || !item.path) continue;

      const ext = item.path.slice(item.path.lastIndexOf(".")).toLowerCase();
      if (!config.extensions.includes(ext)) continue;

      filesScanned++;
      console.log(`    📄 Scanning: ${item.path}`);

      try {
        const rawUrl = `https://raw.githubusercontent.com/${repoFullName}/${encodeURIComponent(branch + "/" + item.path)}`;
        const content = await getFileContent(rawUrl);
        if (!content) continue;

        const keys = extractKeys(content);
        for (const { key, service } of keys) {
          if (isFakeKey(key)) continue;
          console.log(`      🔑 Found ${service} key`);
          callbacks.onKeyFound({
            key,
            service,
            sourceUrl: rawUrl,
            sourceType: "deep_scan",
            author,
          });
          foundCount++;
        }

        // Small delay between files
        await sleep(config.fileDelay);
      } catch (err) {
        console.log(`      ⚠️ Error: ${err}`);
      }
    }

    console.log(`  ✅ Deep scan completed: found ${foundCount} keys`);
    return foundCount;
  } catch (err) {
    console.log(`  ❌ Deep scan failed: ${err}`);
    return 0;
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}
