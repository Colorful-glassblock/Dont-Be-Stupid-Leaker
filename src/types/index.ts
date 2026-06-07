/** Supported API key service identifiers */
export type ServiceName =
  | "OpenAI"
  | "OpenRouter"
  | "XAI"
  | "DeepSeek"
  | "Gemini"
  | "Anthropic"
  | "Replicate"
  | "HuggingFace"
  | "MiMo"
  | "MiniMax"
  | "Perplexity"
  | "GitHub_PAT"
  | "GitHub_Token"
  | "Stripe_Live"
  | "Stripe_Test";

/** Source where a key was found */
export type SourceType = "code" | "issue" | "pr" | "commit" | "env" | "deep_scan";

/** Result of verifying a key against its service API */
export interface VerifyResult {
  valid: boolean;
  balance: number;
  info: string;
}

/** A single key pattern with its compiled regex */
export interface KeyPattern {
  service: ServiceName;
  regex: RegExp;
}

/** A detected and verified leak */
export interface LeakReport {
  key: string;
  service: ServiceName;
  balance: number;
  info: string;
  sourceUrl: string;
  sourceType: SourceType;
  author: string;
  timestamp: Date;
}

/** Configuration for a scan run */
export interface ScanConfig {
  /** Maximum runtime in seconds */
  maxRuntimeSeconds: number;
  /** Number of search workers */
  searchWorkers: number;
  /** Number of verification workers */
  verifyWorkers: number;
  /** Keys per batch before triggering verification */
  batchSize: number;
  /** Max seconds before flushing a partial batch */
  batchTimeout: number;
  /** Shannon entropy threshold for fake key detection */
  fakeKeyEntropyThreshold: number;
  /** Max files to scan in deep scan mode */
  deepScanMaxFiles: number;
  /** GitHub API base URL */
  githubApi: string;
  /** Repository name for archiving issues */
  repoName: string;
  /** Bot name for signatures */
  botName: string;
  /** Search queries */
  queries: {
    code: string;
    issues: string;
    commits: string;
    env: string;
  };
}

/** A queued item waiting for verification */
export interface PendingVerification {
  key: string;
  service: ServiceName;
  sourceUrl: string;
  sourceType: SourceType;
  author: string;
}

/** Verifier function signature */
export type VerifierFn = (key: string) => Promise<VerifyResult>;

/** HTTP verifier config (REST fallback) */
export interface HttpVerifierConfig {
  url: string | ((key: string) => string);
  headers: (key: string) => Record<string, string>;
  method: "GET" | "POST";
  body?: () => string;
  parse: (status: number, data: unknown) => VerifyResult;
}
