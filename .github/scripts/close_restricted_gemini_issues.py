#!/usr/bin/env python3
"""
Close Gemini issues previously marked as "Valid but restricted".
Uses GitHub App authentication, matching the main scanner.
"""

import os
import sys
import time
import requests
import jwt

# Configuration
REPO_NAME = os.environ.get("GITHUB_REPOSITORY", "Colorful-glassblock/Dont-Be-Stupid-Leaker")
APP_ID = os.environ.get("APP_ID")
PRIVATE_KEY = os.environ.get("PRIVATE_KEY")
INSTALLATION_ID = os.environ.get("INSTALLATION_ID")
DRY_RUN = os.environ.get("DRY_RUN", "true").lower() == "true"

GITHUB_API = "https://api.github.com"

def get_installation_token():
    """Get GitHub App installation token (same method as main scanner)."""
    private_key = PRIVATE_KEY.replace('\\n', '\n')
    payload = {
        "iat": int(time.time()),
        "exp": int(time.time()) + 600,
        "iss": APP_ID
    }
    jwt_token = jwt.encode(payload, private_key, algorithm="RS256")
    url = f"https://api.github.com/app/installations/{INSTALLATION_ID}/access_tokens"
    headers = {
        "Authorization": f"Bearer {jwt_token}",
        "Accept": "application/vnd.github+json"
    }
    resp = requests.post(url, headers=headers)
    if resp.status_code == 201:
        return resp.json()["token"]
    else:
        print(f"❌ Failed to get installation token: HTTP {resp.status_code}")
        print(resp.text)
        sys.exit(1)

def gh_request(method, url, token, json_data=None):
    """Make a GitHub API request."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json"
    }
    if json_data is not None:
        resp = requests.request(method, url, headers=headers, json=json_data)
    else:
        resp = requests.request(method, url, headers=headers)
    return resp

def main():
    if not APP_ID or not PRIVATE_KEY or not INSTALLATION_ID:
        print("❌ GitHub App credentials not set (APP_ID, PRIVATE_KEY, INSTALLATION_ID)")
        sys.exit(1)
    
    print("🔑 Getting GitHub App installation token...")
    token = get_installation_token()
    print("✅ Authenticated")
    
    # Search for open Gemini issues that mention the restricted keywords
    owner, repo = REPO_NAME.split("/")
    query = f'repo:{REPO_NAME} is:issue is:open Gemini in:title'
    
    # We'll search using the REST API
    search_url = f"{GITHUB_API}/search/issues?q={requests.utils.quote(query)}&per_page=100"
    resp = gh_request("GET", search_url, token)
    
    if resp.status_code != 200:
        print(f"❌ Search failed: HTTP {resp.status_code}")
        print(resp.text)
        sys.exit(1)
    
    data = resp.json()
    items = data.get("items", [])
    
    print(f"🔍 Found {len(items)} open Gemini issues")
    
    if len(items) == 0:
        print("✅ Nothing to clean up")
        return
    
    closed = 0
    skipped = 0
    
    for item in items:
        # Only close issues that were marked as restricted/403
        body = item.get("body", "")
        if "Valid but restricted" not in body and "403" not in body:
            skipped += 1
            print(f"  ⏭️  #{item['number']} - not a restricted Gemini issue, skipping")
            continue
        
        issue_number = item["number"]
        issue_title = item["title"]
        print(f"  📝 #{issue_number}: {issue_title}")
        
        if DRY_RUN:
            print(f"      🔍 [DRY RUN] Would close")
            continue
        
        # Add explanatory comment
        comment_url = f"{GITHUB_API}/repos/{REPO_NAME}/issues/{issue_number}/comments"
        comment_body = (
            "⚠️ This issue has been automatically closed because the Gemini API key "
            "returned HTTP 403, which is now treated as **invalid** (not 'restricted').\n\n"
            "Previous behavior incorrectly marked 403 as 'Valid but restricted'. "
            "If this is a real leak, it will be re-detected and re-reported correctly by the scanner."
        )
        
        comment_resp = gh_request("POST", comment_url, token, {"body": comment_body})
        if comment_resp.status_code not in (201, 200):
            print(f"      ⚠️ Failed to add comment: HTTP {comment_resp.status_code}")
        
        # Close the issue
        patch_url = f"{GITHUB_API}/repos/{REPO_NAME}/issues/{issue_number}"
        patch_resp = gh_request("PATCH", patch_url, token, {"state": "closed"})
        
        if patch_resp.status_code == 200:
            closed += 1
            print(f"      ✅ Closed")
        else:
            print(f"      ❌ Failed to close: HTTP {patch_resp.status_code}")
        
        time.sleep(1)  # Rate limit protection
    
    if DRY_RUN:
        print(f"\n🔍 Dry run complete. Would have closed {len(items) - skipped} issues.")
        print("   Set DRY_RUN=false to actually close them.")
    else:
        print(f"\n✅ Done. Closed {closed} issues, skipped {skipped} non-restricted issues.")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        sys.exit(1)