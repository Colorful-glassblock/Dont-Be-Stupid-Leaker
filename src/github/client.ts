/**
 * GitHub API client wrapper.
 * Supports PAT token and GitHub App (JWT) authentication.
 */

import { Octokit } from "@octokit/rest";
import { createAppAuth } from "@octokit/auth-app";

export interface GitHubAuthConfig {
  patToken?: string;
  appId?: string;
  privateKey?: string;
  installationId?: string;
}

let _octokit: Octokit | null = null;
let _authConfig: GitHubAuthConfig = {};

/**
 * Custom logger that suppresses the known GET /search/code deprecation warning.
 *
 * GitHub's API sends `Deprecation` + `Sunset` response headers for /search/code
 * requests. @octokit/request logs these as warnings via `log.warn()`. Since there
 * is no replacement endpoint yet, we filter out this specific warning to reduce
 * noise while keeping all other warnings visible.
 *
 * TODO: Migrate away from GET /search/code before the sunset date (2026-09-27).
 * @see https://github.blog/changelog/2026-03-27-deprecation-of-api-search-code-fields
 */
function createFilteredLogger() {
  const SEARCH_CODE_DEPRECATION = /\/search\/code.*deprecated/i;
  return {
    debug: console.debug,
    info: console.info,
    warn: (msg: string, ...args: unknown[]) => {
      if (SEARCH_CODE_DEPRECATION.test(msg)) return;
      console.warn(msg, ...args);
    },
    error: console.error,
  };
}

export function configureGitHubAuth(config: GitHubAuthConfig): void {
  _authConfig = config;
  _octokit = null;
}

export function getOctokit(): Octokit {
  if (_octokit) return _octokit;

  const log = createFilteredLogger();

  if (_authConfig.patToken) {
    _octokit = new Octokit({ auth: _authConfig.patToken, log });
    return _octokit;
  }

  if (_authConfig.appId && _authConfig.privateKey && _authConfig.installationId) {
    _octokit = new Octokit({
      authStrategy: createAppAuth,
      auth: {
        appId: _authConfig.appId,
        privateKey: _authConfig.privateKey.replace(/\\n/g, "\n"),
        installationId: _authConfig.installationId,
      },
      log,
    });
    return _octokit;
  }

  throw new Error("No GitHub authentication configured. Set PAT_TOKEN or APP_ID + PRIVATE_KEY + INSTALLATION_ID");
}

export function invalidateOctokit(): void {
  _octokit = null;
}

/**
 * Get raw auth headers for direct HTTP requests (non-Octokit).
 */
export function getAuthHeaders(): Record<string, string> {
  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "User-Agent": "leak-scanner-ts/1.0",
  };
  if (_authConfig.patToken) {
    headers.Authorization = `Bearer ${_authConfig.patToken}`;
  }
  return headers;
}
