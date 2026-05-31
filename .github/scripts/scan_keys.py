#!/usr/bin/env python3

import os
import re
import sys
import time
import json
import jwt
import signal
import requests
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Tuple, Set, List, Dict
from github import Github, Auth, GithubException

# ========== Configuration ==========
MAX_RUNTIME_SECONDS = 90 * 60
HEARTBEAT_INTERVAL = 300
BATCH_DELAY = 3
BATCH_SIZE = 15
MAX_WORKERS = 10

APP_ID = os.environ.get("APP_ID")
PRIVATE_KEY = os.environ.get("PRIVATE_KEY")
INSTALLATION_ID = int(os.environ.get("INSTALLATION_ID", "0"))

if not APP_ID or not PRIVATE_KEY or not INSTALLATION_ID:
    print("Error: APP_ID, PRIVATE_KEY, INSTALLATION_ID must be set")
    sys.exit(1)

REPO_NAME = os.environ.get("GITHUB_REPOSITORY", "Colorful-glassblock/Dont-Be-Stupid-Leaker")
BOT_NAME = "llmapicheckbot2"
BOT_SIGNATURE = f"*This message was sent by {BOT_NAME} - Repository: {REPO_NAME}*"

USER_AGENTS = ["Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"]

STATE_FILE = "replied_state.json"

scan_results = {
    "scan_time": datetime.now().isoformat(),
    "found_keys": [],
    "replied_count": 0,
    "errors": []
}

start_time = time.time()
last_heartbeat = start_time
stop_scan = False

ISSUE_QUERIES = [
    '"your key leak"',
    '"sk-" OR "sk-proj-" OR "AIza"',
    '"sk-ant-api" OR "r8_" OR "hf_"',
    '"tp-"'
]

COMMIT_QUERIES = [
    '"sk-" OR "sk-proj-" OR "AIza"',
    '"sk-ant-api" OR "r8_" OR "hf_"',
    '"tp-"'
]

def signal_handler(sig, frame):
    global stop_scan
    print(f"\n[!] Interrupted, saving state...")
    stop_scan = True
    time.sleep(2)
    save_state()
    save_result()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def get_jwt():
    payload = {"iat": int(time.time()), "exp": int(time.time()) + 600, "iss": APP_ID}
    return jwt.encode(payload, PRIVATE_KEY, algorithm="RS256")

def get_installation_token():
    jwt_token = get_jwt()
    url = f"https://api.github.com/app/installations/{INSTALLATION_ID}/access_tokens"
    headers = {"Authorization": f"Bearer {jwt_token}", "Accept": "application/vnd.github+json"}
    resp = requests.post(url, headers=headers)
    if resp.status_code != 201:
        print(f"Error getting installation token: {resp.status_code}")
        return None
    return resp.json()["token"]

def get_github_client():
    token = get_installation_token()
    if not token:
        return None
    auth = Auth.Token(token)
    return Github(auth=auth)

def check_timeout():
    elapsed = time.time() - start_time
    if elapsed >= MAX_RUNTIME_SECONDS:
        print(f"[!] Max runtime reached. Exiting.")
        save_state()
        save_result()
        sys.exit(0)
    return elapsed

def heartbeat():
    global last_heartbeat
    now = time.time()
    if now - last_heartbeat >= HEARTBEAT_INTERVAL:
        elapsed = now - start_time
        print(f"[❤️] Alive: {elapsed:.0f}s / {MAX_RUNTIME_SECONDS}s")
        last_heartbeat = now

def load_state():
    try:
        with open(STATE_FILE, "r") as f:
            state = json.load(f)
            if "replied_issues" not in state:
                state["replied_issues"] = []
            if "replied_commits" not in state:
                state["replied_commits"] = []
            return state
    except:
        return {"replied_issues": [], "replied_commits": []}

def save_state(state=None):
    if state is None:
        state = load_state()
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)

KEY_PATTERNS = {
    "OpenAI": re.compile(r"sk-proj-[a-zA-Z0-9]{32,}"),
    "OpenAI_Legacy": re.compile(r"sk-[a-zA-Z0-9]{32,}"),
    "OpenRouter": re.compile(r"sk-or-v1-[a-zA-Z0-9]{50,}"),
    "DeepSeek": re.compile(r"sk-[a-zA-Z0-9]{32,}"),
    "Gemini": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "Anthropic": re.compile(r"sk-ant-api[0-9A-Za-z\-_]{40,}"),
    "Replicate": re.compile(r"r8_[a-zA-Z0-9]{32,}"),
    "HuggingFace": re.compile(r"hf_[a-zA-Z0-9]{30,}"),
    "MiMo": re.compile(r"tp-[a-zA-Z0-9]{10,}"),
}

def _parse_deepseek(code, data):
    if code != 200 or not isinstance(data, dict) or not data.get("is_available"):
        return False, 0, "Invalid"
    cny = sum(float(i.get("total_balance", 0)) for i in data.get("balance_infos", []) if i.get("currency") == "CNY")
    usd = sum(float(i.get("total_balance", 0)) for i in data.get("balance_infos", []) if i.get("currency") == "USD")
    info = f"💰 CNY: {cny:.2f}, USD: {usd:.2f}" if cny or usd else "✅ Valid (no balance)"
    return True, cny + usd * 7.2, info

def _parse_openai(code, data):
    if code != 200 or not isinstance(data, dict):
        return False, 0, f"HTTP {code}"
    models = data.get("data", [])
    if models and len(models) > 0 and models[0].get("id"):
        return True, 0, "✅ Valid"
    return False, 0, "❌ Invalid"

def _parse_openrouter(code, data):
    if code != 200 or not isinstance(data, dict):
        return False, 0, f"HTTP {code}"
    credits = data.get("credits", 0)
    info = f"💰 Credits: {credits}" if credits > 0 else "✅ Valid (no credits)"
    return True, float(credits), info

def _parse_gemini(code, data):
    if code != 200 or not isinstance(data, dict):
        return False, 0, f"HTTP {code}"
    models = data.get("models", [])
    if models and len(models) > 0:
        return True, 0, "✅ Valid"
    return False, 0, "❌ Invalid"

def _parse_anthropic(code, data):
    if code == 200:
        return True, 0, "✅ Valid"
    return False, 0, f"❌ HTTP {code}"

def _parse_replicate(code, data):
    if code == 200:
        return True, 0, "✅ Valid"
    return False, 0, f"❌ HTTP {code}"

def _parse_huggingface(code, data):
    if code == 200:
        return True, 0, "✅ Valid"
    return False, 0, f"❌ HTTP {code}"

def _parse_mimo(code, data):
    if code == 200 and isinstance(data, dict):
        balance = float(data.get("balance", data.get("credit", 0)))
        info = f"💰 Balance: {balance}" if balance > 0 else "✅ Valid (no balance)"
        return True, balance, info
    return False, 0, "❌ Invalid"

VERIFIERS = {
    "OpenAI": {"url": "https://api.openai.com/v1/models", "headers": lambda k: {"Authorization": f"Bearer {k}"}, "method": "GET", "parse": _parse_openai},
    "OpenRouter": {"url": "https://openrouter.ai/api/v1/auth/key", "headers": lambda k: {"Authorization": f"Bearer {k}"}, "method": "GET", "parse": _parse_openrouter},
    "DeepSeek": {"url": "https://api.deepseek.com/user/balance", "headers": lambda k: {"Authorization": f"Bearer {k}", "Accept": "application/json"}, "method": "GET", "parse": _parse_deepseek},
    "Gemini": {"url": lambda k: f"https://generativelanguage.googleapis.com/v1/models?key={k}", "headers": lambda k: {}, "method": "GET", "parse": _parse_gemini},
    "Anthropic": {"url": "https://api.anthropic.com/v1/messages", "headers": lambda k: {"x-api-key": k, "anthropic-version": "2023-06-01", "Content-Type": "application/json"}, "method": "POST", "body": lambda: json.dumps({"model": "claude-3-haiku-20240307", "max_tokens": 1, "messages": [{"role": "user", "content": "hi"}]}).encode(), "parse": _parse_anthropic},
    "Replicate": {"url": "https://api.replicate.com/v1/account", "headers": lambda k: {"Authorization": f"Bearer {k}"}, "method": "GET", "parse": _parse_replicate},
    "HuggingFace": {"url": "https://huggingface.co/api/whoami", "headers": lambda k: {"Authorization": f"Bearer {k}"}, "method": "GET", "parse": _parse_huggingface},
    "MiMo": {"url": "https://token-plan-cn.xiaomimimo.com/v1/models", "headers": lambda k: {"Authorization": f"Bearer {k}", "X-Plan-Type": "token-plan"}, "method": "GET", "parse": _parse_mimo},
}

def verify_key(service, key):
    v = VERIFIERS.get(service)
    if not v:
        return False, 0, "Unsupported"
    try:
        check_timeout()
        url = v["url"](key) if callable(v["url"]) else v["url"]
        headers = v["headers"](key)
        headers["User-Agent"] = USER_AGENTS[0]
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

def build_reply(author, service, key, info, source_url, source_type, location, line_num, line_content, balance):
    masked = key[:12] + "..." + key[-8:] if len(key) > 24 else key
    loc_str = f"Location: {location}" + (f" (line {line_num})" if line_num else "")
    return f"@{author} Your API key has been exposed!\n\n# Summary\nThis is a **{service}** API key found in {source_type}: [{source_url}]({source_url}).\n\n{loc_str}\nKey preview: `{masked}`\n\nVerification result: {info}\n\n---\n\n**What to do:**\n1. Revoke this key from {service} dashboard\n2. Generate a new key\n3. Remove the exposed key\n4. Rotate other exposed secrets\n\n**Exposed content:**\n```\n{line_content[:300] if line_content else 'Content too long'}\n```\n\n---\n{BOT_SIGNATURE}"

def has_replied_to_issue(issue_id, state):
    return str(issue_id) in state.get("replied_issues", [])

def has_replied_to_commit(commit_sha, state):
    return commit_sha in state.get("replied_commits", [])

def mark_replied_issue(issue_id, state):
    if "replied_issues" not in state:
        state["replied_issues"] = []
    if str(issue_id) not in state["replied_issues"]:
        state["replied_issues"].append(str(issue_id))

def mark_replied_commit(commit_sha, state):
    if "replied_commits" not in state:
        state["replied_commits"] = []
    if commit_sha not in state["replied_commits"]:
        state["replied_commits"].append(commit_sha)

def save_result():
    fname = f"scan_result_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(fname, "w") as f:
        json.dump(scan_results, f, indent=2)
    print(f"💾 Saved to {fname}")

def fetch_issues_for_query(g, query, limit=30):
    """获取单个查询的 issues"""
    items = []
    page = 1
    while len(items) < limit and not stop_scan:
        try:
            results = g.search_issues(query, sort="created", order="desc")
            page_items = list(results.get_page(page))
            if not page_items:
                break
            items.extend(page_items)
            page += 1
            time.sleep(0.3)
        except GithubException as e:
            if e.status == 403:
                print(f"    ⚠️ 403 on issues, resetting page 1")
                page = 1
                time.sleep(60)
                continue
            else:
                print(f"    Error: {e}")
                break
        except Exception as e:
            print(f"    Error: {e}")
            break
    return items[:limit]

def fetch_commits_for_query(g, query, limit=30):
    """获取单个查询的 commits"""
    items = []
    page = 1
    while len(items) < limit and not stop_scan:
        try:
            # commits 使用 committer-date 排序
            results = g.search_commits(query, sort="committer-date", order="desc")
            page_items = list(results.get_page(page))
            if not page_items:
                break
            items.extend(page_items)
            page += 1
            time.sleep(0.3)
        except GithubException as e:
            if e.status == 403:
                print(f"    ⚠️ 403 on commits, resetting page 1")
                page = 1
                time.sleep(60)
                continue
            else:
                print(f"    Error: {e}")
                break
        except Exception as e:
            print(f"    Error: {e}")
            break
    return items[:limit]

def process_issue(g, issue, state, processed):
    num = issue.number
    if has_replied_to_issue(num, state):
        return 0
    
    title = issue.title
    body = issue.body or ""
    full_text = f"{title}\n{body}"
    
    try:
        for c in issue.get_comments():
            full_text += f"\n{c.body or ''}"
    except:
        pass
    
    for service, pattern in KEY_PATTERNS.items():
        for m in pattern.finditer(full_text):
            key = m.group(0)
            uid = f"i_{num}_{key[:16]}"
            if uid in processed:
                continue
            
            line_num = None
            line_content = ""
            loc = "issue"
            if key in title:
                line_num = 1
                line_content = title[:200]
            elif key in body:
                lines = body.split('\n')
                for i, l in enumerate(lines):
                    if key in l:
                        line_num = i + 1
                        line_content = l.strip()[:200]
                        break
            else:
                loc = "issue comment"
                line_content = key[:200]
            
            valid, bal, info = verify_key(service, key)
            if valid:
                processed.add(uid)
                reply = build_reply(issue.user.login, service, key, info, issue.html_url, "issue", loc, line_num, line_content, bal)
                try:
                    issue.create_comment(reply)
                    mark_replied_issue(num, state)
                    save_state(state)
                    scan_results["replied_count"] += 1
                    scan_results["found_keys"].append({"type":"issue","number":num,"service":service,"key":key,"balance":bal,"info":info})
                    print(f"      ✅ Replied to issue #{num} - {service} key")
                    time.sleep(1)
                    return 1
                except Exception as e:
                    scan_results["errors"].append(str(e))
    return 0

def process_commit(g, commit, state, processed):
    sha = commit.sha
    if has_replied_to_commit(sha, state):
        return 0
    
    msg = commit.commit.message
    title = msg.split('\n')[0]
    author = commit.author.login if commit.author else "unknown"
    
    full_text = title + "\n" + msg
    diff = ""
    try:
        if commit.repository:
            files = commit.repository.get_commit(sha).files
            for f in files:
                if f.patch:
                    diff += f.patch + "\n"
            full_text += "\n" + diff
    except:
        pass
    
    for service, pattern in KEY_PATTERNS.items():
        for m in pattern.finditer(full_text):
            key = m.group(0)
            uid = f"c_{sha}_{key[:16]}"
            if uid in processed:
                continue
            
            line_num = None
            line_content = ""
            loc = "commit diff"
            
            if key in title:
                line_num = 1
                line_content = title[:200]
                loc = "commit title"
            elif key in msg:
                lines = msg.split('\n')
                for i, l in enumerate(lines):
                    if key in l:
                        line_num = i + 1
                        line_content = l.strip()[:200]
                        break
                loc = "commit message"
            elif key in diff:
                lines = diff.split('\n')
                for i, l in enumerate(lines):
                    if key in l:
                        line_num = i + 1
                        line_content = l.strip()[:200]
                        break
            
            valid, bal, info = verify_key(service, key)
            if valid:
                processed.add(uid)
                reply = build_reply(author, service, key, info, commit.html_url, "commit", loc, line_num, line_content, bal)
                try:
                    commit.create_comment(reply)
                    mark_replied_commit(sha, state)
                    save_state(state)
                    scan_results["replied_count"] += 1
                    scan_results["found_keys"].append({"type":"commit","sha":sha,"service":service,"key":key,"balance":bal,"info":info})
                    print(f"      ✅ Replied to commit {sha[:8]} - {service} key")
                    time.sleep(1)
                    return 1
                except Exception as e:
                    scan_results["errors"].append(str(e))
    return 0

def scan_issues_parallel(g, state, processed):
    print(f"\n  📄 Fetching issues...")
    all_issues = []
    seen_urls = set()
    
    for query in ISSUE_QUERIES:
        if stop_scan:
            break
        print(f"    Query: {query[:40]}...")
        items = fetch_issues_for_query(g, query, limit=20)
        for item in items:
            if item.html_url not in seen_urls:
                seen_urls.add(item.html_url)
                all_issues.append(item)
        time.sleep(1)
    
    if not all_issues:
        print(f"    No issues found")
        return 0
    
    print(f"    Found {len(all_issues)} unique issues")
    
    replied = 0
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(process_issue, g, issue, state, processed): issue 
                   for issue in all_issues[:BATCH_SIZE]}
        for future in as_completed(futures):
            if stop_scan:
                break
            try:
                replied += future.result()
            except Exception as e:
                scan_results["errors"].append(str(e))
    
    return replied

def scan_commits_parallel(g, state, processed):
    print(f"\n  📄 Fetching commits...")
    all_commits = []
    seen_urls = set()
    
    for query in COMMIT_QUERIES:
        if stop_scan:
            break
        print(f"    Query: {query[:40]}...")
        items = fetch_commits_for_query(g, query, limit=20)
        for item in items:
            if item.html_url not in seen_urls:
                seen_urls.add(item.html_url)
                all_commits.append(item)
        time.sleep(1)
    
    if not all_commits:
        print(f"    No commits found")
        return 0
    
    print(f"    Found {len(all_commits)} unique commits")
    
    replied = 0
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(process_commit, g, commit, state, processed): commit 
                   for commit in all_commits[:BATCH_SIZE]}
        for future in as_completed(futures):
            if stop_scan:
                break
            try:
                replied += future.result()
            except Exception as e:
                scan_results["errors"].append(str(e))
    
    return replied

def check_and_reply():
    global last_heartbeat, stop_scan
    
    print(f"\n{'='*60}")
    print(f"🤖 {BOT_NAME} - API Key Leak Scanner (GitHub App)")
    print(f"📁 Self repo: {REPO_NAME}")
    print(f"⏱️  Max runtime: {MAX_RUNTIME_SECONDS}s")
    print(f"⚡ Parallel mode: Issues + Commits running simultaneously")
    print(f"{'='*60}\n")
    
    g = get_github_client()
    if not g:
        print("❌ Failed to get GitHub client")
        return
    
    print("✅ GitHub App client initialized\n")
    
    state = load_state()
    print(f"📍 Loaded state: {len(state.get('replied_issues', []))} issues, {len(state.get('replied_commits', []))} commits replied\n")
    
    processed = set()
    total_replied = 0
    batch_count = 0
    
    while not stop_scan:
        check_timeout()
        batch_count += 1
        
        print(f"\n{'='*50}")
        print(f"Batch #{batch_count} (Parallel)")
        print(f"{'='*50}")
        
        with ThreadPoolExecutor(max_workers=2) as executor:
            issue_future = executor.submit(scan_issues_parallel, g, state, processed)
            commit_future = executor.submit(scan_commits_parallel, g, state, processed)
            
            issue_replied = issue_future.result()
            commit_replied = commit_future.result()
        
        total_replied += issue_replied + commit_replied
        
        save_state(state)
        
        print(f"\n📊 Batch #{batch_count} summary:")
        print(f"   ✅ Issues replied: {issue_replied}")
        print(f"   ✅ Commits replied: {commit_replied}")
        print(f"   📈 Total replied: {total_replied}")
        print(f"   📊 Keys found: {len(scan_results['found_keys'])}")
        
        print(f"\n💤 Waiting {BATCH_DELAY}s...")
        for i in range(BATCH_DELAY):
            if stop_scan:
                break
            check_timeout()
            time.sleep(1)
    
    elapsed = time.time() - start_time
    print(f"\n✅ Scan completed in {elapsed:.0f}s")
    print(f"📊 Found {len(scan_results['found_keys'])} valid keys")
    print(f"📊 Replied to {scan_results['replied_count']} items")
    
    if scan_results['found_keys']:
        print(f"\n🔑 Valid keys found:")
        for i, key_info in enumerate(scan_results['found_keys'], 1):
            print(f"   {i}. [{key_info['service']}] {key_info['key']}")
            print(f"      {key_info['info']}")
    
    save_result()
    save_state(state)

if __name__ == "__main__":
    try:
        check_and_reply()
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        save_state()
        save_result()
        sys.exit(1)