#!/usr/bin/env python3
"""
Close Gemini issues that were previously marked as "Valid but restricted".
Run this once to clean up old false positives.
"""

import os
import sys
import time
from github import Github, Auth

# Configuration
REPO_NAME = os.environ.get("GITHUB_REPOSITORY", "Colorful-glassblock/Dont-Be-Stupid-Leaker")
PAT_TOKEN = os.environ.get("PAT_TOKEN")
DRY_RUN = os.environ.get("DRY_RUN", "false").lower() == "true"

def main():
    if not PAT_TOKEN:
        print("❌ PAT_TOKEN not set")
        sys.exit(1)
    
    auth = Auth.Token(PAT_TOKEN)
    g = Github(auth=auth)
    repo = g.get_repo(REPO_NAME)
    
    # Search for open Gemini issues that mention "Valid but restricted" or "403"
    query = 'repo:' + REPO_NAME + ' is:issue is:open Gemini "Valid but restricted"'
    issues = g.search_issues(query)
    
    print(f"Found {issues.totalCount} Gemini issues to close")
    
    closed = 0
    for issue in issues:
        print(f"  [#{issue.number}] {issue.title}")
        if not DRY_RUN:
            try:
                # Add a comment explaining why it's being closed
                issue.create_comment(
                    "⚠️ This issue has been automatically closed because the Gemini API key "
                    "returned HTTP 403, which is now treated as **invalid** (not restricted).\n\n"
                    "Previous behavior incorrectly marked 403 as 'Valid but restricted'. "
                    "If this is a real leak, it will be re-detected and re-reported correctly."
                )
                issue.edit(state="closed")
                closed += 1
                print(f"    ✅ Closed")
            except Exception as e:
                print(f"    ❌ Failed: {e}")
        else:
            print(f"    🔍 [DRY RUN] Would close")
        time.sleep(1)  # Rate limit protection
    
    if DRY_RUN:
        print(f"\n🔍 Dry run complete. Would have closed {issues.totalCount} issues.")
    else:
        print(f"\n✅ Closed {closed} issues.")

if __name__ == "__main__":
    main()