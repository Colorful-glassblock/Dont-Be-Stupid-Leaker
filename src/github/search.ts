/**
 * GitHub Code/Issue/Commit search workers.
 * Ported from Python _search_worker.
 */

import { getOctokit, invalidateOctokit } from "./client.js";
import { extractKeys } from "../patterns/key-patterns.js";
import { isFakeKey } from "../utils/entropy.js";
import { getFileContent, getIssueOrPrContent, getPrDiffContent, getCommitContent } from "./content.js";
import type { SourceType, PendingVerification } from "../types/index.js";

export type SearchType = "code" | "issues" | "commits";

export interface SearchConfig {
  queries: Record<SearchType, string>;
  perPage: number;
  searchDelay: number;
  maxBackoff: number;
  maxRateLimitRetries: number;
  maxPageRetries: number;
  maxGeneralErrors: number;
  max401Errors: number;
}

export const DEFAULT_SEARCH_CONFIG: SearchConfig = {
  queries: {
    code: "sk-proj- OR xai- OR AIza OR sk-ant-api OR r8_ OR hf_ OR tp-",
    issues: '"your key leak" OR "sk-proj-" OR "xai-" OR "AIza" OR "sk-ant-api"',
    commits: "sk-proj- OR xai- OR AIza OR sk-ant-api",
  },
  perPage: 30,
  searchDelay: 1.2,
  maxBackoff: 120,
  maxRateLimitRetries: 5,
  maxPageRetries: 5,
  maxGeneralErrors: 15,
  max401Errors: 3,
};

export interface SearchCallbacks {
  onKeyFound: (item: PendingVerification) => void;
  shouldStop: () => boolean;
}

/**
 * Extract repo owner from search result item.
 */
function extractAuthor(item: Record<string, unknown>, searchType: SearchType): string {
  if (searchType === "code") {
    return (item.repository as Record<string, unknown>)?.owner
      ? ((item.repository as Record<string, unknown>).owner as Record<string, unknown>).login as string ?? "unknown"
      : "unknown";
  }
  if (searchType === "issues") {
    return (item.user as Record<string, unknown>)?.login as string ?? "unknown";
  }
  if (searchType === "commits") {
    return (item.author as Record<string, unknown>)?.login as string ?? "unknown";
  }
  return "unknown";
}

function inferSourceType(htmlUrl: string): SourceType {
  if (htmlUrl.includes("/pull/")) return "pr";
  if (htmlUrl.includes("/issues/")) return "issue";
  if (htmlUrl.includes("/commit/")) return "commit";
  return "code";
}

/**
 * Process a single search result: extract keys from full content.
 */
async function processSearchItem(
  item: Record<string, unknown>,
  searchType: SearchType,
  callbacks: SearchCallbacks,
): Promise<void> {
  const htmlUrl = (item.html_url as string) ?? "";
  const author = extractAuthor(item, searchType);

  // Get full content based on source type
  let fullText = "";
  const sourceType = searchType === "code" ? "code" : inferSourceType(htmlUrl);

  if (sourceType === "code" || sourceType === "env") {
    fullText = (await getFileContent(htmlUrl)) ?? "";
  } else if (sourceType === "pr") {
    fullText = await getPrDiffContent(htmlUrl);
  } else if (sourceType === "issue") {
    fullText = await getIssueOrPrContent(htmlUrl);
  } else if (sourceType === "commit") {
    fullText = await getCommitContent(htmlUrl);
  }

  if (!fullText) return;

  const keys = extractKeys(fullText);
  for (const { key, service } of keys) {
    if (isFakeKey(key)) continue;
    callbacks.onKeyFound({ key, service, sourceUrl: htmlUrl, sourceType, author });
  }
}

/**
 * Run a search worker loop for a specific search type.
 * Paginates through all results until exhausted or stopped.
 */
export async function runSearchWorker(
  workerId: number,
  searchType: SearchType,
  startPage: number,
  config: SearchConfig,
  callbacks: SearchCallbacks,
): Promise<void> {
  const query = config.queries[searchType];
  if (!query) return;

  console.log(`\n[Worker-${workerId}] Starting ${searchType.toUpperCase()} scan`);
  const octokit = getOctokit();

  let page = startPage;
  let rateLimitErrors = 0;
  let generalErrors = 0;
  let pageRetries = 0;
  let consecutive401 = 0;

  while (!callbacks.shouldStop()) {
    try {
      // TODO: GET /search/code is deprecated by GitHub (sunset 2026-09-27).
      // Migrate to a replacement endpoint when available.
      // @see https://github.blog/changelog/2026-03-27-deprecation-of-api-search-code-fields
      const searchFn = (octokit.search as any)[searchType === "commits" ? "commits" : searchType];
      const { data } = await searchFn({
        q: query,
        sort: "indexed",
        order: "desc",
        per_page: config.perPage,
        page,
      });

      rateLimitErrors = 0;
      generalErrors = 0;
      pageRetries = 0;
      consecutive401 = 0;

      const items = (data as { items?: unknown[] }).items ?? [];
      if (items.length > 0) {
        console.log(`[Worker-${workerId}] ${searchType.toUpperCase()} page ${page}: ${items.length} items`);
        for (const item of items) {
          if (callbacks.shouldStop()) break;
          try {
            await processSearchItem(item as Record<string, unknown>, searchType, callbacks);
          } catch (err) {
            console.log(`  ⚠️ Error processing search item: ${err}`);
          }
        }
      }

      // Move to next page
      page++;
      // Delay between pages
      await sleep(config.searchDelay * 1000);
    } catch (err: unknown) {
      const ghErr = err as { status?: number; message?: string };

      if (ghErr.status === 401) {
        consecutive401++;
        if (consecutive401 >= config.max401Errors) {
          console.log(`[Worker-${workerId}] Too many 401 errors, auth failed. Exiting.`);
          break;
        }
        invalidateOctokit();
        await sleep(2000);
        continue;
      }

      if (ghErr.status === 429 || ghErr.status === 403) {
        rateLimitErrors++;
        if (rateLimitErrors >= config.maxRateLimitRetries) {
          if (pageRetries < config.maxPageRetries) {
            pageRetries++;
            rateLimitErrors = 0;
            console.log(`[Worker-${workerId}] Rate limited on page ${page}, retry after 30s (${pageRetries}/${config.maxPageRetries})`);
            await sleep(30_000);
            continue;
          } else {
            console.log(`[Worker-${workerId}] Skipping page ${page} after ${config.maxPageRetries} retries`);
            page++;
            pageRetries = 0;
            rateLimitErrors = 0;
            continue;
          }
        }
        const backoff = Math.min(config.maxBackoff, Math.pow(2, rateLimitErrors) * 5 + Math.random() * 5);
        console.log(`  ⚠️ HTTP ${ghErr.status} — backing off ${backoff.toFixed(1)}s`);
        await sleep(backoff * 1000);
        continue;
      }

      generalErrors++;
      if (generalErrors >= config.maxGeneralErrors) {
        console.log(`[Worker-${workerId}] Too many errors (${generalErrors}), exiting`);
        break;
      }
      page++;
      await sleep(2000);
    }
  }

  console.log(`[Worker-${workerId}] ${searchType.toUpperCase()} scan finished`);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
