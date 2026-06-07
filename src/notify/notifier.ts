/**
 * Leak notification system.
 * - Creates issues/comments on original repos
 * - Archives issues on central repo
 */

import { getOctokit } from "../github/client.js";
import type { LeakReport } from "../types/index.js";

export interface NotifierConfig {
  repoName: string;
  botName: string;
}

function maskKey(key: string): string {
  if (key.length > 24) return key.slice(0, 12) + "..." + key.slice(-8);
  if (key.length > 16) return key.slice(0, 8) + "..." + key.slice(-6);
  return key.slice(0, 4) + "..." + key.slice(-4);
}

function buildReply(report: LeakReport, config: NotifierConfig): string {
  const { author, service, key, info, sourceUrl, sourceType, balance } = report;
  const masked = maskKey(key);
  const balText = balance !== undefined ? ` (Balance: ${balance})` : "";
  return `🔴 API Key Leak Detected!

@${author} Your API key has been exposed in this ${sourceType}${balText}.

Service: ${service}
Key preview: ${masked}
Status: ${info}

Source: ${sourceUrl}

---
*This message was sent by ${config.botName} - Repository: ${config.repoName}*`;
}

// Keep track of already-notified items to avoid duplicates
const notifiedIssues = new Set<string>();

/**
 * Create an issue in the original repo (for code/blob leaks).
 */
export async function notifyOriginalRepo(
  report: LeakReport,
  config: NotifierConfig,
): Promise<boolean> {
  const { sourceUrl } = report;
  if (!sourceUrl.includes("/blob/")) return false;

  try {
    const match = sourceUrl.match(/github\.com\/([^/]+\/[^/]+)\/blob\/(.+)/);
    if (!match) return false;
    const [, repoPath, filePath] = match;

    const notifyKey = `${repoPath}:${filePath}`;
    if (notifiedIssues.has(notifyKey)) return true;

    const octokit = getOctokit();
    const [owner, repo] = repoPath!.split("/");

    // Check if issue already exists
    try {
      const { data: issues } = await octokit.issues.listForRepo({
        owner: owner!,
        repo: repo!,
        state: "all",
        sort: "created",
        direction: "desc",
        per_page: 50,
      });
      for (const issue of issues) {
        if ((issue.title ?? "").includes(filePath!) || (issue.body ?? "").includes(sourceUrl)) {
          notifiedIssues.add(notifyKey);
          return true;
        }
      }
    } catch {
      // Ignore — try creating anyway
    }

    const message = buildReply(report, config);
    const issueTitle = `API Key Leak Detected in ${filePath}`;

    try {
      await octokit.issues.create({
        owner: owner!,
        repo: repo!,
        title: issueTitle,
        body: `${message}\n\nFile: ${filePath}`,
        labels: ["security"],
      });
      console.log(`    📝 Created issue in ${repoPath}`);
      notifiedIssues.add(notifyKey);
      return true;
    } catch {
      // Retry without labels
      try {
        await octokit.issues.create({
          owner: owner!,
          repo: repo!,
          title: issueTitle,
          body: `${message}\n\nFile: ${filePath}`,
        });
        console.log(`    📝 Created issue in ${repoPath} (no labels)`);
        notifiedIssues.add(notifyKey);
        return true;
      } catch (err) {
        console.log(`    ❌ Failed to create issue in ${repoPath}: ${err}`);
        return false;
      }
    }
  } catch (err) {
    console.log(`    ❌ Error notifying original repo: ${err}`);
    return false;
  }
}

/**
 * Comment on an existing issue or PR (for issue/PR leaks).
 */
export async function replyToOriginalIssue(
  report: LeakReport,
  config: NotifierConfig,
): Promise<boolean> {
  const { sourceUrl } = report;

  const isIssue = sourceUrl.includes("/issues/");
  const isPr = sourceUrl.includes("/pull/");
  if (!isIssue && !isPr) return false;

  try {
    const sep = isIssue ? "/issues/" : "/pull/";
    const parts = sourceUrl.split(sep);
    if (parts.length < 2) return false;

    const repoPath = parts[0]!.replace(/.*github\.com\//, "");
    const itemNum = parseInt(parts[1]!.split("#")[0]!.split("?")[0]!, 10);
    if (isNaN(itemNum)) return false;

    const octokit = getOctokit();
    const [owner, repo] = repoPath.split("/");

    // Check if already replied
    const { data: comments } = await octokit.issues.listComments({
      owner: owner!,
      repo: repo!,
      issue_number: itemNum,
      per_page: 50,
    });

    const botUser = (await octokit.users.getAuthenticated()).data.login;
    for (const comment of comments) {
      if (comment.user?.login === botUser && comment.body?.includes("API Key Leak Detected")) {
        console.log(`    Already replied to ${isPr ? "PR" : "Issue"} #${itemNum}`);
        return true;
      }
    }

    const message = buildReply(report, config);
    await octokit.issues.createComment({
      owner: owner!,
      repo: repo!,
      issue_number: itemNum,
      body: message,
    });
    console.log(`    📝 Replied to ${isPr ? "PR" : "Issue"} #${itemNum}`);
    return true;
  } catch (err) {
    console.log(`    ❌ Failed to reply to original issue/PR: ${err}`);
    return false;
  }
}

/**
 * Create an issue in the central archive repo.
 */
export async function createArchiveIssue(
  report: LeakReport,
  config: NotifierConfig,
  isFallback = false,
): Promise<void> {
  const { sourceUrl, sourceType, service, key, info, author, balance } = report;

  const notifyKey = `archive:${key.slice(0, 20)}:${sourceUrl}`;
  if (notifiedIssues.has(notifyKey)) return;

  try {
    const octokit = getOctokit();
    const [owner, repo] = config.repoName.split("/");

    const displayType = sourceUrl.includes("/pull/")
      ? "Pull Request"
      : sourceUrl.includes("/issues/")
        ? "Issue"
        : sourceUrl.includes("/commit/")
          ? "Commit"
          : sourceType;

    const shortUrl = sourceUrl.replace("https://github.com/", "").slice(0, 57);
    const issueTitle = `${service} Key Leak in ${displayType}: ${shortUrl}`;
    const keyPreview = key.slice(0, 20) + "...";

    // Check if already exists
    try {
      const { data: issues } = await octokit.issues.listForRepo({
        owner: owner!,
        repo: repo!,
        state: "all",
        sort: "created",
        direction: "desc",
        per_page: 50,
      });
      for (const issue of issues) {
        if (issue.title === issueTitle || (issue.body ?? "").includes(keyPreview)) {
          console.log(`    📝 Archive issue already exists, skipping`);
          notifiedIssues.add(notifyKey);
          return;
        }
      }
    } catch {
      // Continue
    }

    const message = buildReply(report, config);
    const body = `## API Key Leak Detected${isFallback ? " (fallback)" : ""}

| Field | Value |
|-------|-------|
| Source Type | ${displayType} |
| Source URL | ${sourceUrl} |
| Service | ${service} |
| Key Preview | ${keyPreview} |
| Status | ${info} |
| Author | @${author} |
| Balance | ${balance ?? "N/A"} |

---

${message}

---
Auto-generated by ${config.botName}
`;

    try {
      await octokit.issues.create({
        owner: owner!,
        repo: repo!,
        title: issueTitle,
        body,
        labels: ["security", "leak"],
      });
      console.log(`    📝 Archived issue in ${config.repoName}`);
    } catch {
      try {
        await octokit.issues.create({
          owner: owner!,
          repo: repo!,
          title: issueTitle,
          body,
        });
        console.log(`    📝 Archived issue (no labels)`);
      } catch (err) {
        console.log(`    ❌ Failed to create archive issue: ${err}`);
      }
    }

    notifiedIssues.add(notifyKey);
  } catch (err) {
    console.log(`    ❌ Archive notification error: ${err}`);
  }
}

/**
 * Handle a verified leak — notify original repo + archive.
 */
export async function handleLeak(
  report: LeakReport,
  config: NotifierConfig,
): Promise<void> {
  const { sourceUrl } = report;

  if (sourceUrl.includes("/issues/") || sourceUrl.includes("/pull/")) {
    const success = await replyToOriginalIssue(report, config);
    await createArchiveIssue(report, config, !success);
  } else if (sourceUrl.includes("/blob/")) {
    const success = await notifyOriginalRepo(report, config);
    await createArchiveIssue(report, config, !success);
  } else {
    await createArchiveIssue(report, config, false);
  }
}
