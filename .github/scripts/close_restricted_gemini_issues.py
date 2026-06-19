#!/usr/bin/env python3
"""
Re-verify all keys reported in open issues within our own repo.
If all keys are now invalid, comment and CLOSE the issue automatically.
Handles missing Source URL by searching body for full keys.

Usage:
  DRY_RUN=true python revalidate_issues.py   # preview only
  python revalidate_issues.py                 # actually comment and close invalid issues
"""

import os
import re
import sys
import time
import json
import urllib.parse
import requests
import jwt
from typing import Optional, Dict, Any, Tuple, Set

# ---------- Configuration ----------
REPO_NAME = os.environ.get("GITHUB_REPOSITORY", "Colorful-glassblock/Dont-Be-Stupid-Leaker")
PAT_TOKEN = os.environ.get("PAT_TOKEN")
APP_ID = os.environ.get("APP_ID")
PRIVATE_KEY = os.environ.get("PRIVATE_KEY")
INSTALLATION_ID = os.environ.get("INSTALLATION_ID")
DRY_RUN = os.environ.get("DRY_RUN", "false").lower() == "true"
CLOSE_INVALID = os.environ.get("CLOSE_INVALID", "true").lower() != "false"   # default: close

# ---------- Key Patterns ----------
KEY_PATTERNS = {
    "OpenAI": re.compile(r"sk-proj-[a-zA-Z0-9_\-]{50,}"),
    "OpenAI_Legacy": re.compile(r"sk-[a-zA-Z0-9]{32,}"),
    "OpenRouter": re.compile(r"sk-or-v1-[a-zA-Z0-9]{50,}"),
    "XAI": re.compile(r"xai-[a-zA-Z0-9]{32,}"),
    "DeepSeek": re.compile(r"sk-[a-zA-Z0-9]{32,}"),
    "Gemini": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "Anthropic": re.compile(r"sk-ant-api[0-9A-Za-z\-_]{40,}"),
    "Replicate": re.compile(r"r8_[a-zA-Z0-9]{32,}"),
    "HuggingFace": re.compile(r"hf_[a-zA-Z0-9]{30,}"),
    "MiMo": re.compile(r"tp-[a-zA-Z0-9]{10,}"),
    "MiniMax": re.compile(r"sk-api-[a-zA-Z0-9]{100,}"),
    "Perplexity": re.compile(r"pplx-[a-zA-Z0-9]{32,}"),
    "GitHub_PAT": re.compile(r"github_pat_[a-zA-Z0-9_]{50,}"),
    "GitHub_Token": re.compile(r"ghp_[a-zA-Z0-9]{36}"),
    "Stripe_Live": re.compile(r"sk_live_[a-zA-Z0-9]{24,}"),
    "Stripe_Test": re.compile(r"sk_test_[a-zA-Z0-9]{24,}"),
}

# ---------- Verifiers ----------
VERIFIERS: Dict[str, Dict[str, Any]] = {
    "OpenAI": {
        "url": "https://api.openai.com/v1/models",
        "headers": lambda k: {"Authorization": f"Bearer {k}"},
        "parse": lambda code, data: (True, 0, "Valid") if code == 200 else (False, 0, "Invalid") if code == 401 else (False, 0, f"HTTP {code}")
    },
    "OpenAI_Legacy": {
        "url": "https://api.openai.com/v1/models",
        "headers": lambda k: {"Authorization": f"Bearer {k}"},
        "parse": lambda code, data: (True, 0, "Valid") if code == 200 else (False, 0, "Invalid") if code == 401 else (False, 0, f"HTTP {code}")
    },
    "OpenRouter": {
        "url": "https://openrouter.ai/api/v1/auth/key",
        "headers": lambda k: {"Authorization": f"Bearer {k}"},
        "parse": lambda code, data: (True, 0, "Valid") if code == 200 else (False, 0, f"HTTP {code}")
    },
    "XAI": {
        "url": "https://api.x.ai/v1/models",
        "headers": lambda k: {"Authorization": f"Bearer {k}"},
        "parse": lambda code, data: (True, 0, "Valid") if code == 200 else (False, 0, f"HTTP {code}")
    },
    "DeepSeek": {
        "url": "https://api.deepseek.com/user/balance",
        "headers": lambda k: {"Authorization": f"Bearer {k}", "Accept": "application/json"},
        "parse": lambda code, data: (
            (True, 0, "Valid") if code == 200 and data.get("is_available") else
            (False, 0, "Invalid") if code == 401 else
            (False, 0, f"HTTP {code}")
        )
    },
    "Gemini": {
        "url": lambda k: f"https://generativelanguage.googleapis.com/v1/models?key={k}",
        "headers": lambda k: {},
        "parse": lambda code, data: (
            (True, 0, "Valid") if code == 200 else
            (False, 0, "Invalid (403)") if code == 403 else
            (False, 0, f"HTTP {code}")
        )
    },
    "Anthropic": {
        "url": "https://api.anthropic.com/v1/messages",
        "headers": lambda k: {"x-api-key": k, "anthropic-version": "2023-06-01", "Content-Type": "application/json"},
        "body": lambda: json.dumps({"model": "claude-3-haiku-20240307", "max_tokens": 1, "messages": [{"role": "user", "content": "hi"}]}),
        "method": "POST",
        "parse": lambda code, data: (True, 0, "Valid") if code == 200 else (False, 0, f"HTTP {code}")
    },
    "Replicate": {
        "url": "https://api.replicate.com/v1/account",
        "headers": lambda k: {"Authorization": f"Bearer {k}"},
        "parse": lambda code, data: (True, 0, "Valid") if code == 200 else (False, 0, f"HTTP {code}")
    },
    "HuggingFace": {
        "url": "https://huggingface.co/api/whoami",
        "headers": lambda k: {"Authorization": f"Bearer {k}"},
        "parse": lambda code, data: (True, 0, "Valid") if code == 200 else (False, 0, f"HTTP {code}")
    },
    "MiMo": {
        "url": "https://token-plan-cn.xiaomimimo.com/v1/models",
        "headers": lambda k: {"Authorization": f"Bearer {k}", "X-Plan-Type": "token-plan"},
        "parse": lambda code, data: (True, 0, "Valid") if code == 200 else (False, 0, f"HTTP {code}")
    },
    "MiniMax": {
        "url": "https://api.minimax.io/v1/models",
        "headers": lambda k: {"Authorization": f"Bearer {k}"},
        "parse": lambda code, data: (True, 0, "Valid") if code == 200 else (False, 0, f"HTTP {code}")
    },
    "Perplexity": {
        "url": "https://api.perplexity.ai/chat/completions",
        "headers": lambda k: {"Authorization": f"Bearer {k}", "Content-Type": "application/json"},
        "body": lambda: json.dumps({"model": "llama-3.1-sonar-small-128k-online", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 1}),
        "method": "POST",
        "parse": lambda code, data: (True, 0, "Valid") if code == 200 else (False, 0, f"HTTP {code}")
    },
    "GitHub_PAT": {
        "url": "https://api.github.com/user",
        "headers": lambda k: {"Authorization": f"Bearer {k}"},
        "parse": lambda code, data: (True, 0, "Valid") if code == 200 else (False, 0, "Invalid")
    },
    "GitHub_Token": {
        "url": "https://api.github.com/user",
        "headers": lambda k: {"Authorization": f"Bearer {k}"},
        "parse": lambda code, data: (True, 0, "Valid") if code == 200 else (False, 0, "Invalid")
    },
    "Stripe_Live": {
        "url": "https://api.stripe.com/v1/account",
        "headers": lambda k: {"Authorization": f"Bearer {k}"},
        "parse": lambda code, data: (True, 0, "Valid") if code == 200 else (False, 0, "Invalid") if code == 401 else (False, 0, f"HTTP {code}")
    },
    "Stripe_Test": {
        "url": "https://api.stripe.com/v1/account",
        "headers": lambda k: {"Authorization": f"Bearer {k}"},
        "parse": lambda code, data: (True, 0, "Valid") if code == 200 else (False, 0, "Invalid") if code == 401 else (False, 0, f"HTTP {code}")
    },
}

# ---------- GitHub App token ----------
def get_installation_token() -> Optional[str]:
    if not (APP_ID and PRIVATE_KEY and INSTALLATION_ID):
        return None
    try:
        private_key = PRIVATE_KEY
        if '\\n' in private_key:
            private_key = private_key.replace('\\n', '\n')
        now = int(time.time())
        payload = {"iat": now, "exp": now + 600, "iss": APP_ID}
        jwt_token = jwt.encode(payload, private_key, algorithm="RS256")
        url = f"https://api.github.com/app/installations/{INSTALLATION_ID}/access_tokens"
        headers = {"Authorization": f"Bearer {jwt_token}", "Accept": "application/vnd.github+json"}
        resp = requests.post(url, headers=headers, timeout=10)
        if resp.status_code == 201:
            return resp.json()["token"]
        else:
            print(f"❌ Failed to get installation token: HTTP {resp.status_code}")
            return None
    except Exception as e:
        print(f"❌ App auth error: {e}")
        return None

# ---------- GitHub API request ----------
def gh_request(method, url, token, json_data=None, retries=2):
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "Revalidator/1.0"
    }
    for attempt in range(retries + 1):
        try:
            if json_data:
                resp = requests.request(method, url, headers=headers, json=json_data, timeout=15)
            else:
                resp = requests.request(method, url, headers=headers, timeout=15)

            if resp.status_code == 401:
                new_token = get_installation_token() if not PAT_TOKEN else None
                if new_token:
                    token = new_token
                    headers["Authorization"] = f"Bearer {token}"
                    continue
                else:
                    return resp

            if resp.status_code == 429:
                wait = int(resp.headers.get("Retry-After", 60))
                print(f"  ⚠️ Rate limited, waiting {wait}s...")
                time.sleep(wait)
                continue

            return resp
        except requests.exceptions.RequestException as e:
            if attempt == retries:
                raise e
            time.sleep(2 ** attempt)

    return resp

# ---------- Extract source URL from issue body ----------
def extract_source_url(body: str) -> Optional[str]:
    # Table format: "Source URL | https://..."
    match = re.search(r'Source URL\s*\|\s*(https?://[^\s|]+)', body)
    if match:
        url = match.group(1).strip()
        if url.endswith('...'):
            # Try full URL from "Source:" line
            match_full = re.search(r'Source:\s*(https?://[^\s]+)', body)
            if match_full:
                url = match_full.group(1).strip()
        return url
    # Plain "Source:" line
    match = re.search(r'Source:\s*(https?://[^\s]+)', body)
    if match:
        return match.group(1).strip()
    return None

# ---------- Fetch content from source URL ----------
def get_content_from_url(source_url: str, token: str) -> Optional[str]:
    session = requests.Session()
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "Revalidator/1.0"
    }
    try:
        if "/blob/" in source_url:
            parts = source_url.replace("https://github.com/", "").split("/blob/")
            if len(parts) == 2:
                repo_path = parts[0]
                ref_path = parts[1]
                raw_url = f"https://raw.githubusercontent.com/{repo_path}/{ref_path}"
                resp = session.get(raw_url, headers={"User-Agent": "Revalidator/1.0"}, timeout=15)
                if resp.status_code == 200:
                    return resp.text
        elif "/commit/" in source_url:
            parts = source_url.replace("https://github.com/", "").split("/commit/")
            if len(parts) == 2:
                diff_url = f"https://github.com/{parts[0]}/commit/{parts[1]}.diff"
                resp = session.get(diff_url, headers=headers, timeout=15)
                if resp.status_code == 200:
                    return resp.text
        elif "/pull/" in source_url:
            parts = source_url.replace("https://github.com/", "").split("/pull/")
            if len(parts) == 2:
                repo_path = parts[0]
                pr_number = parts[1].split("#")[0]
                diff_url = f"https://api.github.com/repos/{repo_path}/pulls/{pr_number}"
                resp = session.get(diff_url, headers=headers, timeout=15)
                if resp.status_code == 200:
                    pr_data = resp.json()
                    diff_url = pr_data.get("diff_url")
                    if diff_url:
                        diff_resp = session.get(diff_url, headers={"Accept": "application/vnd.github.v3.diff"}, timeout=15)
                        if diff_resp.status_code == 200:
                            return diff_resp.text
        elif "/issues/" in source_url:
            parts = source_url.replace("https://github.com/", "").split("/issues/")
            if len(parts) == 2:
                repo_path = parts[0]
                issue_number = parts[1].split("#")[0]
                api_url = f"https://api.github.com/repos/{repo_path}/issues/{issue_number}"
                resp = session.get(api_url, headers=headers, timeout=15)
                if resp.status_code == 200:
                    issue_data = resp.json()
                    return issue_data.get("body", "")
    except Exception as e:
        print(f"    ⚠️ Error fetching content: {e}")
    return None

# ---------- Verify a single key ----------
def verify_key(service: str, key: str) -> Tuple[bool, float, str]:
    verifier = VERIFIERS.get(service)
    if not verifier:
        return False, 0, "Unknown service"
    try:
        url = verifier["url"](key) if callable(verifier["url"]) else verifier["url"]
        headers = verifier["headers"](key)
        method = verifier.get("method", "GET")
        body = None
        if "body" in verifier:
            body = verifier["body"]()
        if method == "GET":
            resp = requests.get(url, headers=headers, timeout=10)
        else:
            resp = requests.post(url, headers=headers, data=body, timeout=10)
        try:
            data = resp.json()
        except Exception:
            data = None
        return verifier["parse"](resp.status_code, data)
    except Exception as e:
        return False, 0, f"Error: {str(e)[:30]}"

# ---------- Extract keys from text ----------
def extract_keys_from_text(text: str) -> Set[Tuple[str, str]]:
    keys = set()
    for service, pattern in KEY_PATTERNS.items():
        for match in pattern.finditer(text):
            keys.add((service, match.group(0)))
    return keys

# ---------- Main ----------
def main():
    token = PAT_TOKEN
    if not token:
        token = get_installation_token()
    if not token:
        print("❌ No authentication token available.")
        sys.exit(1)

    owner, repo = REPO_NAME.split("/")
    print(f"🔍 Scanning open issues in {REPO_NAME}... (CLOSE_INVALID={CLOSE_INVALID})")

    issues_url = f"https://api.github.com/repos/{owner}/{repo}/issues?state=open&per_page=100"
    page = 1
    total_processed = 0
    total_invalid = 0

    while issues_url:
        print(f"\n📄 Fetching issues page {page}...")
        resp = gh_request("GET", issues_url, token)
        if resp.status_code != 200:
            print(f"❌ Failed to fetch issues: {resp.status_code}")
            break

        issues = resp.json()
        if not issues:
            break

        for issue in issues:
            if "pull_request" in issue:
                continue

            issue_number = issue["number"]
            title = issue["title"]
            body = issue.get("body", "")
            if not body:
                continue

            total_processed += 1
            print(f"\n📝 #{issue_number}: {title}")

            # First try to get keys from source URL content
            source_url = extract_source_url(body)
            found_keys: Set[Tuple[str, str]] = set()

            if source_url:
                print(f"  🔗 Source: {source_url}")
                content = get_content_from_url(source_url, token)
                if content:
                    found_keys = extract_keys_from_text(content)
                else:
                    print("  ⚠️ Could not fetch content from URL, will try extracting from body.")
            else:
                print("  ⏭️ No source URL found, extracting keys from issue body directly.")

            # If no keys found from source, try the body itself
            if not found_keys:
                found_keys = extract_keys_from_text(body)
                # Filter out masked keys (those containing "...") - they can't be verified
                found_keys = {(s, k) for s, k in found_keys if "..." not in k}

            if not found_keys:
                print("  ℹ️ No verifiable keys found, skipping.")
                continue

            # Re-verify each key
            any_valid = False
            for service, key in found_keys:
                print(f"    🔑 Verifying {service}: {key[:25]}...")
                valid, _, info = verify_key(service, key)
                if valid:
                    print(f"      ✅ Still valid: {info}")
                    any_valid = True
                else:
                    print(f"      ❌ Now invalid: {info}")

            # If all keys are invalid
            if not any_valid:
                print(f"  🚨 All keys in this issue are now INVALID.")
                total_invalid += 1

                if DRY_RUN:
                    print("      [DRY RUN] Would add comment and close.")
                    continue

                # Add comment
                comment_body = (
                    "⚠️ **Re-verification result**: All API keys previously reported in this issue "
                    "are now **invalid** (revoked/expired/disabled).\n\n"
                    "This issue has been automatically closed."
                )
                comment_url = f"https://api.github.com/repos/{owner}/{repo}/issues/{issue_number}/comments"
                comment_resp = gh_request("POST", comment_url, token, {"body": comment_body})
                if comment_resp.status_code in (200, 201):
                    print("      💬 Comment added.")
                else:
                    print(f"      ⚠️ Failed to add comment: {comment_resp.status_code}")

                if CLOSE_INVALID:
                    patch_url = f"https://api.github.com/repos/{owner}/{repo}/issues/{issue_number}"
                    patch_resp = gh_request("PATCH", patch_url, token, {"state": "closed"})
                    if patch_resp.status_code == 200:
                        print("      🔒 Issue closed.")
                    else:
                        print(f"      ❌ Failed to close: {patch_resp.status_code}")

            time.sleep(1)

        # Pagination
        links = resp.links
        if "next" in links:
            issues_url = links["next"]["url"]
            page += 1
        else:
            issues_url = None

    print(f"\n✅ Done. Processed {total_processed} issues, {total_invalid} now fully invalid and closed.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n⚠️ Interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        sys.exit(1)