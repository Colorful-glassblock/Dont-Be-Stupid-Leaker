/**
 * GitHub content fetcher — raw files, issues, PRs, commits.
 */

import { LRUCache } from "../utils/lru-cache.js";
import { getAuthHeaders, getOctokit } from "./client.js";

const MAX_FILE_SIZE = 500 * 1024;
const MAX_DIFF_SIZE = 2 * 1024 * 1024;
const REQUEST_TIMEOUT = 15_000;

const fileCache = new LRUCache<string>({ maxSize: 500, ttlMs: 3_600_000 });
const issueCache = new LRUCache<string>({ maxSize: 200, ttlMs: 3_600_000 });

/** Strip URL fragment and query params for consistent caching */
function cleanUrl(url: string): string {
  try {
    const u = new URL(url);
    u.hash = "";
    u.search = "";
    return u.toString();
  } catch {
    return url;
  }
}

/** Convert a GitHub blob URL to raw.githubusercontent.com URL */
export function buildRawUrl(sourceUrl: string): string | null {
  const clean = cleanUrl(sourceUrl);
  const match = clean.match(/github\.com\/([^/]+\/[^/]+)\/blob\/(.+)/);
  if (!match) return null;
  const [, repoPath, refPath] = match;
  return `https://raw.githubusercontent.com/${repoPath}/${refPath}`;
}

/** Download raw file content from GitHub */
export async function getFileContent(sourceUrl: string): Promise<string | null> {
  const clean = cleanUrl(sourceUrl);
  const cached = fileCache.get(clean);
  if (cached !== undefined) return cached;

  const rawUrl = buildRawUrl(clean);
  if (!rawUrl) return null;

  try {
    const resp = await fetch(rawUrl, {
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT),
    });
    if (!resp.status.toString().startsWith("2")) {
      return null;
    }

    const reader = resp.body?.getReader();
    if (!reader) return null;

    const chunks: string[] = [];
    let size = 0;
    const decoder = new TextDecoder("utf-8", { fatal: false });

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(decoder.decode(value, { stream: true }));
      size += value.length;
      if (size > MAX_FILE_SIZE) {
        chunks.push("\n...[File truncated]");
        break;
      }
    }

    const content = chunks.join("");
    fileCache.put(clean, content);
    return content;
  } catch {
    return null;
  }
}

/** Fetch issue or PR body text */
export async function getIssueOrPrContent(sourceUrl: string): Promise<string> {
  const clean = cleanUrl(sourceUrl);
  const cached = issueCache.get(clean);
  if (cached !== undefined) return cached;

  try {
    const isIssue = clean.includes("/issues/");
    const isPr = clean.includes("/pull/");
    if (!isIssue && !isPr) return "";

    const sep = isIssue ? "/issues/" : "/pull/";
    const parts = clean.split(sep);
    if (parts.length < 2) return "";

    const repoPath = parts[0]!.replace(/.*github\.com\//, "");
    const number = parseInt(parts[1]!.split("#")[0]!.split("?")[0]!, 10);
    if (isNaN(number)) return "";

    const octokit = getOctokit();
    const { data } = await octokit.issues.get({ owner: repoPath.split("/")[0]!, repo: repoPath.split("/")[1]!, issue_number: number });
    const content = `${data.title}\n${data.body ?? ""}`;
    issueCache.put(clean, content);
    return content;
  } catch {
    return "";
  }
}

/** Fetch commit diff content */
export async function getCommitContent(sourceUrl: string): Promise<string> {
  const clean = cleanUrl(sourceUrl);
  const cached = issueCache.get(clean);
  if (cached !== undefined) return cached;

  try {
    const match = clean.match(/github\.com\/([^/]+\/[^/]+)\/commit\/([a-f0-9]+)/);
    if (!match) return "";
    const [, repoPath, sha] = match;

    const diffUrl = `https://github.com/${repoPath}/commit/${sha}.diff`;
    const resp = await fetch(diffUrl, {
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT),
    });
    if (!resp.status.toString().startsWith("2")) return "";

    const reader = resp.body?.getReader();
    if (!reader) return "";

    const chunks: string[] = [];
    let size = 0;
    const decoder = new TextDecoder("utf-8", { fatal: false });

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(decoder.decode(value, { stream: true }));
      size += value.length;
      if (size > MAX_DIFF_SIZE) {
        chunks.push("\n...[Diff truncated]");
        break;
      }
    }

    const content = chunks.join("");
    issueCache.put(clean, content);
    return content;
  } catch {
    return "";
  }
}

/** Fetch PR diff content */
export async function getPrDiffContent(sourceUrl: string): Promise<string> {
  const clean = cleanUrl(sourceUrl);
  const cached = issueCache.get(clean);
  if (cached !== undefined) return cached;

  try {
    const match = clean.match(/github\.com\/([^/]+\/[^/]+)\/pull\/(\d+)/);
    if (!match) return "";
    const [, repoPath, prNum] = match!;

    const octokit = getOctokit();
    const [owner, repo] = repoPath!.split("/");
    const { data: pr } = await octokit.pulls.get({
      owner: owner!,
      repo: repo!,
      pull_number: parseInt(prNum!, 10),
    });

    const resp = await fetch(pr.diff_url, {
      headers: getAuthHeaders(),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT),
    });
    if (!resp.status.toString().startsWith("2")) return "";

    const text = await resp.text();
    const content = text.length > MAX_DIFF_SIZE ? text.slice(0, MAX_DIFF_SIZE) + "\n...[Diff truncated]" : text;
    issueCache.put(clean, content);
    return content;
  } catch {
    return "";
  }
}
