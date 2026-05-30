#!/usr/bin/env python3

import os
import re
import sys
import time
import json
import signal
from datetime import datetime
from typing import Tuple
from github import Github, GithubException
import requests

# ========== Timeout Configuration ==========
MAX_RUNTIME_SECONDS = 90 * 60  # 1.5 hours = 5400 seconds
HEARTBEAT_INTERVAL = 300       # 5 minutes

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
PAT_TOKEN = os.environ.get("PAT_TOKEN")
REPO_NAME = os.environ.get("GITHUB_REPOSITORY", "colorful-glassblock/Dont-Be-Stupid-Leaker")
BOT_NAME = "LLMApiCheckBot"
BOT_SIGNATURE = f"*This message was sent by {BOT_NAME} - Repository: {REPO_NAME}*"

ISSUE_QUERY = '"your key leak"'
COMMIT_QUERY = 'sk- OR sk-proj- OR AIza OR sk-ant OR r8_ OR hf_ OR tp-'

STATE_FILE = "replied_state.json"
PROGRESS_FILE = "scan_progress.json"

scan_results = {
    "scan_time": datetime.now().isoformat(),
    "found_keys": [],
    "replied_count": 0,
    "errors": []
}

start_time = time.time()
last_heartbeat = start_time

# ========== Signal Handler for Graceful Shutdown ==========
def signal_handler(sig, frame):
    elapsed = time.time() - start_time
    print(f"\n[!] Received interrupt signal at {elapsed:.0f}s, saving state...")
    save_state()
    save_result()
    print("[!] State saved. Exiting.")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def check_timeout():
    """Check if max runtime exceeded, exit if so"""
    elapsed = time.time() - start_time
    if elapsed >= MAX_RUNTIME_SECONDS:
        print(f"[!] Max runtime ({MAX_RUNTIME_SECONDS}s / 1.5h) reached. Saving and exiting.")
        save_state()
        save_result()
        sys.exit(0)
    return elapsed

def heartbeat():
    """Print heartbeat every HEARTBEAT_INTERVAL seconds"""
    global last_heartbeat
    now = time.time()
    if now - last_heartbeat >= HEARTBEAT_INTERVAL:
        elapsed = now - start_time
        print(f"[❤️] Still alive... elapsed: {elapsed:.0f}s / {MAX_RUNTIME_SECONDS}s ({(elapsed/MAX_RUNTIME_SECONDS)*100:.1f}%)")
        last_heartbeat = now

def load_state():
    try:
        with open(STATE_FILE, "r") as f:
            return json.load(f)
    except:
        return {"replied_commits": [], "replied_issues": []}

def save_state(state=None):
    if state is None:
        state = load_state()
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)

def load_progress():
    try:
        with open(PROGRESS_FILE, "r") as f:
            return json.load(f)
    except:
        return {"last_commit_index": 0, "last_issue_index": 0}

def save_progress(progress):
    with open(PROGRESS_FILE, "w") as f:
        json.dump(progress, f)

KEY_PATTERNS = {
    "OpenAI": re.compile(r"sk-proj-[a-zA-Z0-9]{32,}"),
    "OpenRouter": re.compile(r"sk-or-v1-[a-zA-Z0-9]{50,}"),
    "DeepSeek": re.compile(r"sk-[a-zA-Z0-9]{32,}"),
    "Gemini": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "Anthropic": re.compile(r"sk-ant-api[0-9A-Za-z\-_]{40,}"),
    "Cohere": re.compile(r"[a-zA-Z0-9]{40}"),
    "Replicate": re.compile(r"r8_[a-zA-Z0-9]{32,}"),
    "HuggingFace": re.compile(r"hf_[a-zA-Z0-9]{30,}"),
    "MiMo": re.compile(r"tp-[a-zA-Z0-9]{10,}"),
    "GLM": re.compile(r"sk-[a-zA-Z0-9]{32,}"),
    "ZAI": re.compile(r"[a-zA-Z0-9]{20,}"),
}

def _parse_deepseek(code, data):
    if code != 200 or not isinstance(data, dict) or not data.get("is_available"):
        return False, 0, "Invalid"
    cny = sum(float(i.get("total_balance", 0)) for i in data.get("balance_infos", []) if i.get("currency") == "CNY")
    usd = sum(float(i.get("total_balance", 0)) for i in data.get("balance_infos", []) if i.get("currency") == "USD")
    info = f"Balance: CNY {cny:.2f}, USD {usd:.2f}" if cny or usd else "Valid"
    return True, cny + usd * 7.2, info

def _parse_openrouter(code, data):
    if code == 200 and isinstance(data, dict):
        credits = data.get("credits", 0)
        if credits:
            return True, float(credits), f"Credits: {credits}"
        return True, 0, "Valid"
    return False, 0, "Invalid"

def _parse_mimo(code, data):
    if code == 200 and isinstance(data, dict):
        balance = float(data.get("balance", data.get("credit", 0)))
        return True, balance, f"Balance: {balance}" if balance else "Valid"
    return False, 0, "Invalid"

VERIFIERS = {
    "OpenAI": {"url": "https://api.openai.com/v1/models", "headers": lambda k: {"Authorization": f"Bearer {k}"}, "method": "GET", "parse": lambda c, d: (c == 200, 0, "Valid")},
    "OpenRouter": {"url": "https://openrouter.ai/api/v1/auth/key", "headers": lambda k: {"Authorization": f"Bearer {k}"}, "method": "GET", "parse": _parse_openrouter},
    "DeepSeek": {"url": "https://api.deepseek.com/user/balance", "headers": lambda k: {"Authorization": f"Bearer {k}", "Accept": "application/json"}, "method": "GET", "parse": _parse_deepseek},
    "Gemini": {"url": lambda k: f"https://generativelanguage.googleapis.com/v1/models?key={k}", "headers": lambda k: {}, "method": "GET", "parse": lambda c, d: (c == 200, 0, "Valid")},
    "Anthropic": {"url": "https://api.anthropic.com/v1/messages", "headers": lambda k: {"x-api-key": k, "anthropic-version": "2023-06-01", "Content-Type": "application/json"}, "method": "POST", "body": lambda: json.dumps({"model": "claude-3-haiku-20240307", "max_tokens": 1, "messages": [{"role": "user", "content": "hi"}]}).encode(), "parse": lambda c, d: (c == 200, 0, "Valid")},
    "Cohere": {"url": "https://api.cohere.ai/v1/models", "headers": lambda k: {"Authorization": f"Bearer {k}"}, "method": "GET", "parse": lambda c, d: (c == 200, 0, "Valid")},
    "Replicate": {"url": "https://api.replicate.com/v1/account", "headers": lambda k: {"Authorization": f"Bearer {k}"}, "method": "GET", "parse": lambda c, d: (c == 200, 0, "Valid")},
    "HuggingFace": {"url": "https://huggingface.co/api/whoami", "headers": lambda k: {"Authorization": f"Bearer {k}"}, "method": "GET", "parse": lambda c, d: (c == 200, 0, "Valid")},
    "MiMo": {"url": "https://token-plan-cn.xiaomimimo.com/v1/models", "headers": lambda k: {"Authorization": f"Bearer {k}", "X-Plan-Type": "token-plan"}, "method": "GET", "parse": _parse_mimo},
    "GLM": {"url": "https://open.bigmodel.cn/api/paas/v4/chat/completions", "headers": lambda k: {"Authorization": f"Bearer {k}", "Content-Type": "application/json"}, "method": "POST", "body": lambda: json.dumps({"model": "glm-5.1", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 1}).encode(), "parse": lambda c, d: (c == 200, 0, "Valid")},
    "ZAI": {"url": "https://api.z.ai/api/coding/paas/v4/chat/completions", "headers": lambda k: {"Authorization": f"Bearer {k}", "Content-Type": "application/json"}, "method": "POST", "body": lambda: json.dumps({"model": "glm-5.1", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 1}).encode(), "parse": lambda c, d: (c == 200, 0, "Valid")},
}

def verify_key(service, key):
    v = VERIFIERS.get(service)
    if not v:
        return False, 0, "Unsupported"
    try:
        check_timeout()
        url = v["url"](key) if callable(v["url"]) else v["url"]
        headers = v["headers"](key)
        headers["User-Agent"] = "LLMApiCheckBot"
        body = v.get("body")
        if body:
            body = body()
        if v["method"] == "GET":
            resp = requests.get(url, headers=headers, timeout=10)
        else:
            resp = requests.post(url, headers=headers, data=body, timeout=10)
        return v["parse"](resp.status_code, resp.json() if resp.text else None)
    except Exception as e:
        return False, 0, f"Error: {str(e)[:50]}"

def build_commit_reply(author, service, key, info, commit_url, location_type, line_num, line_content, balance):
    masked = key[:12] + "..." + key[-8:] if len(key) > 24 else key
    loc = f"Location: {location_type}" + (f" (line {line_num})" if line_num else "")
    return f"@{author} Your API key has been exposed in a commit!\n\n# Summary\nThis is a **{service}** API key in commit [{commit_url.split('/')[-1]}]({commit_url}).\n\n{loc}\nKey preview: `{masked}`\n\nVerification result: {info}\n\n---\n\n**What to do:**\n1. Revoke this key from {service} dashboard\n2. Generate a new key\n3. Remove from git history using BFG Repo Cleaner or git filter-branch\n4. Rotate other exposed secrets\n\n**Exposed code:**\n```\n{line_content[:300] if line_content else 'Content too long'}\n```\n\n---\n{BOT_SIGNATURE}"

def build_issue_reply(author, service, key, info, issue_url, location_type, line_num, line_content, balance):
    masked = key[:12] + "..." + key[-8:] if len(key) > 24 else key
    loc = f"Location: {location_type}" + (f" (line {line_num})" if line_num else "")
    return f"@{author} Your API key has been exposed in this issue!\n\n# Summary\nThis is a **{service}** API key in issue [#{issue_url.split('/')[-1]}]({issue_url}).\n\n{loc}\nKey preview: `{masked}`\n\nVerification result: {info}\n\n---\n\n**What to do:**\n1. Revoke this key from {service} dashboard\n2. Generate a new key\n3. Edit or delete the issue/comment containing the key\n4. Rotate other exposed secrets\n\n**Exposed content:**\n```\n{line_content[:300] if line_content else 'Content too long'}\n```\n\n---\n{BOT_SIGNATURE}"

def has_replied_to_commit(commit_sha, state):
    return commit_sha in state.get("replied_commits", [])

def has_replied_to_issue(issue_id, state):
    return str(issue_id) in state.get("replied_issues", [])

def mark_commit_replied(commit_sha, state):
    if "replied_commits" not in state:
        state["replied_commits"] = []
    if commit_sha not in state["replied_commits"]:
        state["replied_commits"].append(commit_sha)

def mark_issue_replied(issue_id, state):
    if "replied_issues" not in state:
        state["replied_issues"] = []
    if str(issue_id) not in state["replied_issues"]:
        state["replied_issues"].append(str(issue_id))

def save_result():
    fname = f"scan_result_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(fname, "w") as f:
        json.dump(scan_results, f, indent=2)
    print(f"Saved to {fname}")

def check_and_reply():
    global last_heartbeat
    
    if not PAT_TOKEN:
        print("Error: PAT_TOKEN not set")
        return
    
    print(f"Starting scan on {REPO_NAME}")
    print(f"Max runtime: {MAX_RUNTIME_SECONDS}s (1.5 hours)")
    
    state = load_state()
    progress = load_progress()
    print(f"Loaded state: {len(state.get('replied_commits', []))} commits, {len(state.get('replied_issues', []))} issues already replied")
    
    g_read = Github(GITHUB_TOKEN)
    g_write = Github(PAT_TOKEN)
    try:
        repo_read = g_read.get_repo(REPO_NAME)
        repo_write = g_write.get_repo(REPO_NAME)
    except Exception as e:
        print(f"Error: {e}")
        return
    processed = set()
    
    # Scan commits
    print("\n--- Scanning commits ---")
    try:
        commits = list(g_read.search_commits(COMMIT_QUERY, sort="committer-date", order="desc"))[:50]
        total_commits = len(commits)
        print(f"Found {total_commits} commits to check")
        
        for idx, commit in enumerate(commits):
            heartbeat()
            check_timeout()
            
            sha = commit.sha
            if has_replied_to_commit(sha, state):
                print(f"Skipping commit {sha[:8]} (already replied)")
                continue
            msg = commit.commit.message
            title = msg.split('\n')[0]
            author = commit.author.login if commit.author else "unknown"
            print(f"[{idx+1}/{total_commits}] Checking commit: {sha[:8]} by {author}")
            
            full_text = title + "\n" + msg
            diff = ""
            try:
                files = repo_read.get_commit(sha).files
                for f in files:
                    if f.patch:
                        diff += f.patch + "\n"
                full_text += "\n" + diff
            except Exception as e:
                print(f"  Error getting diff: {e}")
            
            for service, pattern in KEY_PATTERNS.items():
                for m in pattern.finditer(full_text):
                    key = m.group(0)
                    uid = f"c_{sha}_{key[:16]}"
                    if uid in processed:
                        continue
                    print(f"  Found {service} key: {key[:20]}...")
                    valid, bal, info = verify_key(service, key)
                    if valid:
                        processed.add(uid)
                        loc, line_num, line_content = "code diff", None, ""
                        if key in title:
                            loc, line_num, line_content = "commit title", 1, title[:200]
                        elif key in msg:
                            lines = msg.split('\n')
                            for i, l in enumerate(lines):
                                if key in l:
                                    line_num, line_content = i+1, l.strip()[:200]
                                    break
                            loc = "commit message"
                        elif key in diff:
                            lines = diff.split('\n')
                            for i, l in enumerate(lines):
                                if key in l:
                                    line_num, line_content = i+1, l.strip()[:200]
                                    break
                        reply = build_commit_reply(author, service, key, info, commit.html_url, loc, line_num, line_content, bal)
                        try:
                            repo_write.get_commit(sha).create_comment(reply)
                            mark_commit_replied(sha, state)
                            save_state(state)
                            scan_results["replied_count"] += 1
                            scan_results["found_keys"].append({"type":"commit","sha":sha,"service":service,"key":key,"balance":bal,"info":info})
                            print(f"  Replied to commit {sha[:8]}")
                            time.sleep(1)
                        except Exception as e:
                            scan_results["errors"].append(str(e))
                    else:
                        print(f"  Invalid: {info}")
            time.sleep(0.3)
    except Exception as e:
        scan_results["errors"].append(str(e))
        print(f"Commit scan error: {e}")
    
    # Scan issues
    print("\n--- Scanning issues ---")
    try:
        issues = list(g_read.search_issues(ISSUE_QUERY, sort="created", order="desc"))[:50]
        total_issues = len(issues)
        print(f"Found {total_issues} issues to check")
        
        for idx, issue in enumerate(issues):
            heartbeat()
            check_timeout()
            
            num = issue.number
            if has_replied_to_issue(num, state):
                print(f"Skipping issue #{num} (already replied)")
                continue
            title = issue.title
            body = issue.body or ""
            author = issue.user.login
            print(f"[{idx+1}/{total_issues}] Checking issue #{num} by {author}")
            
            comments = ""
            try:
                for c in issue.get_comments():
                    comments += f"\n[{c.user.login}]: {c.body or ''}"
            except Exception as e:
                print(f"  Error getting comments: {e}")
            
            full_text = f"{title}\n{body}\n{comments}"
            for service, pattern in KEY_PATTERNS.items():
                for m in pattern.finditer(full_text):
                    key = m.group(0)
                    uid = f"i_{num}_{key[:16]}"
                    if uid in processed:
                        continue
                    print(f"  Found {service} key: {key[:20]}...")
                    valid, bal, info = verify_key(service, key)
                    if valid:
                        processed.add(uid)
                        loc, line_num, line_content = "issue body", None, ""
                        if key in title:
                            loc, line_num, line_content = "issue title", 1, title[:200]
                        elif key in body:
                            lines = body.split('\n')
                            for i, l in enumerate(lines):
                                if key in l:
                                    line_num, line_content = i+1, l.strip()[:200]
                                    break
                        elif key in comments:
                            lines = comments.split('\n')
                            for i, l in enumerate(lines):
                                if key in l:
                                    line_num, line_content = i+1, l.strip()[:200]
                                    break
                            loc = "issue comment"
                        reply = build_issue_reply(author, service, key, info, issue.html_url, loc, line_num, line_content, bal)
                        try:
                            repo_write.get_issue(number=num).create_comment(reply)
                            mark_issue_replied(num, state)
                            save_state(state)
                            scan_results["replied_count"] += 1
                            scan_results["found_keys"].append({"type":"issue","number":num,"service":service,"key":key,"balance":bal,"info":info})
                            print(f"  Replied to issue #{num}")
                            time.sleep(1)
                        except Exception as e:
                            scan_results["errors"].append(str(e))
                    else:
                        print(f"  Invalid: {info}")
            time.sleep(0.3)
    except Exception as e:
        scan_results["errors"].append(str(e))
        print(f"Issue scan error: {e}")
    
    elapsed = time.time() - start_time
    print(f"\nScan completed in {elapsed:.0f}s")
    print(f"Found {len(scan_results['found_keys'])} new valid keys, replied to {scan_results['replied_count']} items.")
    save_result()
    save_state(state)

if __name__ == "__main__":
    try:
        check_and_reply()
    except Exception as e:
        print(f"Fatal error: {e}")
        save_state()
        save_result()
        sys.exit(1)