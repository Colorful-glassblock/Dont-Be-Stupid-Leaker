#!/usr/bin/env python3
"""
Close old false-positive issues: Gemini 403 ("Valid but restricted") and
any other issue whose body contains specific HTTP error keywords (e.g. HTTP 401).

Usage:
  # Preview (dry run)
  DRY_RUN=true python close_false_positive_issues.py

  # Actually close
  python close_false_positive_issues.py

  # Custom keywords (comma separated)
  KEYWORDS="Valid but restricted,HTTP 401,Invalid (403)" python close_false_positive_issues.py
"""

import os
import sys
import time
import requests
import jwt
from typing import Optional, List

# ---------- Configuration ----------
REPO_NAME = os.environ.get("GITHUB_REPOSITORY", "Colorful-glassblock/Dont-Be-Stupid-Leaker")
PAT_TOKEN = os.environ.get("PAT_TOKEN")
APP_ID = os.environ.get("APP_ID")
PRIVATE_KEY = os.environ.get("PRIVATE_KEY")
INSTALLATION_ID = os.environ.get("INSTALLATION_ID")
DRY_RUN = os.environ.get("DRY_RUN", "false").lower() == "true"
# Keywords to search for in issue body (comma separated)
KEYWORDS_STR = os.environ.get("KEYWORDS", "Valid but restricted,HTTP 401")
KEYWORDS: List[str] = [kw.strip() for kw in KEYWORDS_STR.split(",") if kw.strip()]

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

# ---------- GitHub API request with retry on 401 / 429 ----------
def gh_request(method, url, token, json_data=None, retries=2):
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "FalsePositiveCleaner/1.0"
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

# ---------- Main ----------
def main():
    token = PAT_TOKEN
    if not token:
        token = get_installation_token()
    if not token:
        print("❌ No authentication token available. Set PAT_TOKEN or App credentials.")
        sys.exit(1)

    print(f"🔍 Keywords to match: {KEYWORDS}")

    # Search for all open issues in the repo
    query = f'repo:{REPO_NAME} is:issue is:open'
    url = f"https://api.github.com/search/issues?q={requests.utils.quote(query)}&per_page=100"

    total_closed = 0
    total_skipped = 0
    page_num = 1

    while url:
        print(f"\n🔍 Fetching page {page_num}...")
        resp = gh_request("GET", url, token)
        if resp.status_code != 200:
            print(f"❌ Search failed after retries: HTTP {resp.status_code}")
            print(resp.text)
            break

        data = resp.json()
        items = data.get("items", [])
        if not items:
            print("No more open issues found.")
            break

        print(f"Found {len(items)} open issues on this page.")

        for item in items:
            body = item.get("body", "")
            # Check if body contains any of the target keywords
            matched_keywords = [kw for kw in KEYWORDS if kw.lower() in body.lower()]
            if not matched_keywords:
                total_skipped += 1
                continue

            issue_number = item["number"]
            title = item["title"]
            print(f"  🎯 #{issue_number}: {title}   (matched: {matched_keywords})")

            if DRY_RUN:
                print("      [DRY RUN] Would close and comment.")
                total_closed += 1
                continue

            # Add explanatory comment
            comment_url = f"https://api.github.com/repos/{REPO_NAME}/issues/{issue_number}/comments"
            comment_body = (
                "⚠️ This issue has been automatically closed because the API key was "
                "incorrectly marked as valid in an older version of the scanner.\n\n"
                f"The original response was: {', '.join(matched_keywords)}.\n"
                "This is now treated as **invalid** by the current scanner.\n"
                "If this is a real leak, it will be re-detected and re-reported correctly."
            )
            comment_resp = gh_request("POST", comment_url, token, {"body": comment_body})
            if comment_resp.status_code not in (200, 201):
                print(f"      ⚠️ Failed to add comment: HTTP {comment_resp.status_code}")

            # Close the issue
            patch_url = f"https://api.github.com/repos/{REPO_NAME}/issues/{issue_number}"
            patch_resp = gh_request("PATCH", patch_url, token, {"state": "closed"})
            if patch_resp.status_code == 200:
                total_closed += 1
                print(f"      ✅ Closed")
            else:
                print(f"      ❌ Failed to close: HTTP {patch_resp.status_code}")

            time.sleep(1)  # respect rate limits

        # Pagination
        if "next" in resp.links:
            url = resp.links["next"]["url"]
            page_num += 1
        else:
            url = None

    print(f"\n✅ Finished. Closed: {total_closed}, Skipped: {total_skipped}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n⚠️ Interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        sys.exit(1)