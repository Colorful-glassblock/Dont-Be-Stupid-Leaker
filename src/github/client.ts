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

export function configureGitHubAuth(config: GitHubAuthConfig): void {
  _authConfig = config;
  _octokit = null;
}

export function getOctokit(): Octokit {
  if (_octokit) return _octokit;

  if (_authConfig.patToken) {
    _octokit = new Octokit({ auth: _authConfig.patToken });
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
