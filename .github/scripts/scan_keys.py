#!/usr/bin/env python3

import os
import re
import sys
import time
import json
import signal
from datetime import datetime
from typing import Tuple
from github import Github, Auth, GithubException
import requests

# ========== Configuration ==========
MAX_RUNTIME_SECONDS = 90 * 60
HEARTBEAT_INTERVAL = 300
BATCH_DELAY = 10

PAT_TOKEN = os.environ.get("PAT_TOKEN")
if not PAT_TOKEN:
    print("Error: PAT_TOKEN not set")
    sys.exit(1)

REPO_NAME = os.environ.get("GITHUB_REPOSITORY", "Colorful-glassblock/Dont-Be-Stupid-Leaker")
BOT_NAME = "LLMApiCheckBot"
BOT_SIGNATURE = f"*This message was sent by {BOT_NAME} - Repository: {REPO_NAME}*"

# 扩大搜索范围
ISSUE_QUERY = '"your key leak" OR "sk-" OR "sk-proj-" OR "AIza" OR "sk-ant-api" OR "r8_" OR "hf_" OR "tp-"'
COMMIT_QUERY = 'sk- OR sk-proj- OR AIza OR sk-ant-api OR r8_ OR hf_ OR tp-'
CODE_QUERY = 'sk- OR sk-proj- OR AIza OR sk-ant-api OR r8_ OR hf_ OR tp-'

STATE_FILE = "replied_state.json"

scan_results = {
    "scan_time": datetime.now().isoformat(),
    "found_keys": [],
    "replied_count": 0,
    "errors": []
}

start_time = time.time()
last_heartbeat = start_time

def signal_handler(sig, frame):
    print(f"\n[!] Interrupted, saving state...")
    save_state()
    save_result()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def check_timeout():
    elapsed = time.time() - start_time
    if elapsed >= MAX_RUNTIME_SECONDS:
        print(f"[!] Max runtime reached ({MAX_RUNTIME_SECONDS}s). Exiting.")
        save_state()
        save_result()
        sys.exit(0)
    return elapsed

def heartbeat():
    global last_heartbeat
    now = time.time()
    if now - last_heartbeat >= HEARTBEAT_INTERVAL:
        elapsed = now - start_time
        remaining = MAX_RUNTIME_SECONDS - elapsed
        print(f"[❤️] Alive: {elapsed:.0f}s / {MAX_RUNTIME_SECONDS}s (remaining: {remaining:.0f}s)")
        last_heartbeat = now

def load_state():
    try:
        with open(STATE_FILE, "r") as f:
            return json.load(f)
    except:
        return {"replied_commits": [], "replied_codes": [], "replied_issues": [], 
                "last_commit_page": 0, "last_code_page": 0, "last_issue_page": 0}

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
    """DeepSeek: is_available=True 就是有效，余额为0也算"""
    if code != 200:
        return False, 0, f"HTTP {code}"
    if not isinstance(data, dict):
        return False, 0, "Invalid response"
    if not data.get("is_available", False):
        return False, 0, "Invalid or expired"
    cny = sum(float(i.get("total_balance", 0)) for i in data.get("balance_infos", []) if i.get("currency") == "CNY")
    usd = sum(float(i.get("total_balance", 0)) for i in data.get("balance_infos", []) if i.get("currency") == "USD")
    info = f"💰 CNY: {cny:.2f}, USD: {usd:.2f}" if cny or usd else "✅ Valid (no balance)"
    return True, cny + usd * 7.2, info

def _parse_openai(code, data):
    """OpenAI: 检查是否返回有效的模型列表"""
    if code != 200:
        return False, 0, f"HTTP {code}"
    if not isinstance(data, dict):
        return False, 0, "Invalid response"
    models = data.get("data", [])
    if models and len(models) > 0 and models[0].get("id"):
        return True, 0, "✅ Valid"
    return False, 0, "❌ Invalid (test key?)"

def _parse_openrouter(code, data):
    """OpenRouter: credits 为0也算有效"""
    if code != 200:
        return False, 0, f"HTTP {code}"
    if not isinstance(data, dict):
        return False, 0, "Invalid response"
    credits = data.get("credits", 0)
    info = f"💰 Credits: {credits}" if credits > 0 else "✅ Valid (no credits)"
    return True, float(credits), info

def _parse_gemini(code, data):
    """Gemini: 检查是否返回模型列表"""
    if code != 200:
        return False, 0, f"HTTP {code}"
    if not isinstance(data, dict):
        return False, 0, "Invalid response"
    models = data.get("models", [])
    if models and len(models) > 0:
        return True, 0, "✅ Valid"
    return False, 0, "❌ Invalid (test key)"

def _parse_anthropic(code, data):
    """Anthropic: 200 即为有效"""
    if code == 200:
        return True, 0, "✅ Valid"
    if code == 401:
        return False, 0, "❌ Invalid key"
    return False, 0, f"❌ HTTP {code}"

def _parse_replicate(code, data):
    """Replicate: 200 即为有效"""
    if code == 200:
        return True, 0, "✅ Valid"
    return False, 0, f"❌ HTTP {code}"

def _parse_huggingface(code, data):
    """HuggingFace: 200 即为有效"""
    if code == 200:
        return True, 0, "✅ Valid"
    return False, 0, f"❌ HTTP {code}"

def _parse_mimo(code, data):
    """MiMo: balance 为0也算有效"""
    if code == 200 and isinstance(data, dict):
        balance = float(data.get("balance", data.get("credit", 0)))
        info = f"💰 Balance: {balance}" if balance > 0 else "✅ Valid (no balance)"
        return True, balance, info
    return False, 0, "❌ Invalid"

VERIFIERS = {
    "OpenAI": {"url": "https://api.openai.com/v1/models", "headers": lambda k: {"Authorization": f"Bearer {k}"}, "method": "GET", "parse": _parse_openai},
    "OpenAI_Legacy": {"url": "https://api.openai.com/v1/models", "headers": lambda k: {"Authorization": f"Bearer {k}"}, "method": "GET", "parse": _parse_openai},
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

def build_code_reply(author, service, key, info, repo_url, file_path, line_num, line_content, balance):
    masked = key[:12] + "..." + key[-8:] if len(key) > 24 else key
    loc = f"File: {file_path}" + (f" (line {line_num})" if line_num else "")
    return f"@{author} Your API key has been exposed in a code file!\n\n# Summary\nThis is a **{service}** API key found in [{repo_url}]({repo_url}).\n\n{loc}\nKey preview: `{masked}`\n\nVerification result: {info}\n\n---\n\n**What to do:**\n1. Revoke this key from {service} dashboard\n2. Generate a new key\n3. Remove the key from the file and force-push\n4. Rotate other exposed secrets\n\n**Exposed code:**\n```\n{line_content[:300] if line_content else 'Content too long'}\n```\n\n---\n{BOT_SIGNATURE}"

def build_issue_reply(author, service, key, info, issue_url, location_type, line_num, line_content, balance):
    masked = key[:12] + "..." + key[-8:] if len(key) > 24 else key
    loc = f"Location: {location_type}" + (f" (line {line_num})" if line_num else "")
    return f"@{author} Your API key has been exposed in this issue!\n\n# Summary\nThis is a **{service}** API key in issue [#{issue_url.split('/')[-1]}]({issue_url}).\n\n{loc}\nKey preview: `{masked}`\n\nVerification result: {info}\n\n---\n\n**What to do:**\n1. Revoke this key from {service} dashboard\n2. Generate a new key\n3. Edit or delete the issue/comment containing the key\n4. Rotate other exposed secrets\n\n**Exposed content:**\n```\n{line_content[:300] if line_content else 'Content too long'}\n```\n\n---\n{BOT_SIGNATURE}"

def has_replied_to_commit(commit_sha, state):
    return commit_sha in state.get("replied_commits", [])

def has_replied_to_code(file_id, state):
    return file_id in state.get("replied_codes", [])

def has_replied_to_issue(issue_id, state):
    return str(issue_id) in state.get("replied_issues", [])

def mark_commit_replied(commit_sha, state):
    if "replied_commits" not in state:
        state["replied_commits"] = []
    if commit_sha not in state["replied_commits"]:
        state["replied_commits"].append(commit_sha)

def mark_code_replied(file_id, state):
    if "replied_codes" not in state:
        state["replied_codes"] = []
    if file_id not in state["replied_codes"]:
        state["replied_codes"].append(file_id)

def mark_issue_replied(issue_id, state):
    if "replied_issues" not in state:
        state["replied_issues"] = []
    if str(issue_id) not in state["replied_issues"]:
        state["replied_issues"].append(str(issue_id))

def save_result():
    fname = f"scan_result_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(fname, "w") as f:
        json.dump(scan_results, f, indent=2)
    print(f"💾 Saved to {fname}")

def get_commit_batch(g, page):
    try:
        results = g.search_commits(COMMIT_QUERY, sort="committer-date", order="desc")
        items = results.get_page(page)
        return items
    except GithubException as e:
        if e.status == 422:
            return []
        print(f"  Commit search error: {e}")
        return []
    except Exception as e:
        print(f"  Commit search error: {e}")
        return []

def get_code_batch(g, page):
    try:
        results = g.search_code(CODE_QUERY)
        items = results.get_page(page)
        return items
    except GithubException as e:
        if e.status == 422:
            return []
        print(f"  Code search error: {e}")
        return []
    except Exception as e:
        print(f"  Code search error: {e}")
        return []

def get_issue_batch(g, page):
    try:
        results = g.search_issues(ISSUE_QUERY, sort="created", order="desc")
        items = results.get_page(page)
        return items
    except GithubException as e:
        if e.status == 422:
            return []
        print(f"  Issue search error: {e}")
        return []
    except Exception as e:
        print(f"  Issue search error: {e}")
        return []

def scan_commit_batch(g, repo, state, processed, page):
    print(f"\n  📦 Fetching commits page {page}...")
    commit_results = get_commit_batch(g, page)
    total = len(commit_results)
    
    if total == 0:
        print(f"  No more commits")
        return 0, page + 1, False
    
    print(f"  Found {total} commits on page {page}")
    replied_this_batch = 0
    
    for idx, commit in enumerate(commit_results):
        heartbeat()
        check_timeout()
        
        sha = commit.sha
        if has_replied_to_commit(sha, state):
            continue
        
        msg = commit.commit.message
        title = msg.split('\n')[0]
        author = commit.author.login if commit.author else "unknown"
        print(f"    [{idx+1}/{total}] Checking commit {sha[:8]} by {author}")
        
        full_text = title + "\n" + msg
        diff = ""
        try:
            files = repo.get_commit(sha).files
            for f in files:
                if f.patch:
                    diff += f.patch + "\n"
            full_text += "\n" + diff
        except Exception as e:
            print(f"      Error getting diff: {e}")
        
        for service, pattern in KEY_PATTERNS.items():
            for m in pattern.finditer(full_text):
                key = m.group(0)
                uid = f"commit_{sha}_{key[:16]}"
                if uid in processed:
                    continue
                print(f"      🔑 Found {service} key: {key[:20]}...")
                
                line_num = None
                line_content = ""
                loc = "code diff"
                
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
                    reply = build_commit_reply(author, service, key, info, commit.html_url, loc, line_num, line_content, bal)
                    try:
                        repo.get_commit(sha).create_comment(reply)
                        mark_commit_replied(sha, state)
                        save_state(state)
                        scan_results["replied_count"] += 1
                        scan_results["found_keys"].append({
                            "type": "commit",
                            "sha": sha,
                            "service": service,
                            "key": key,
                            "balance": bal,
                            "info": info,
                            "url": commit.html_url
                        })
                        replied_this_batch += 1
                        print(f"        ✅ Replied to commit {sha[:8]} - {info}")
                        time.sleep(1)
                    except Exception as e:
                        scan_results["errors"].append(str(e))
                        print(f"        ❌ Failed: {e}")
                else:
                    print(f"        ❌ Invalid: {info}")
        time.sleep(0.3)
    
    return replied_this_batch, page + 1, True

def scan_code_batch(g, repo, state, processed, page):
    print(f"\n  📦 Fetching code page {page}...")
    code_results = get_code_batch(g, page)
    total = len(code_results)
    
    if total == 0:
        print(f"  No more code results")
        return 0, page + 1, False
    
    print(f"  Found {total} code files on page {page}")
    replied_this_batch = 0
    
    for idx, code in enumerate(code_results):
        heartbeat()
        check_timeout()
        
        file_id = f"{code.repository.full_name}_{code.path}"
        if has_replied_to_code(file_id, state):
            continue
        
        repo_name = code.repository.full_name
        file_path = code.path
        file_url = code.html_url
        raw_url = code.download_url
        author = code.repository.owner.login
        
        print(f"    [{idx+1}/{total}] Checking {repo_name}/{file_path}")
        
        content = ""
        try:
            resp = requests.get(raw_url, timeout=10)
            if resp.status_code == 200:
                content = resp.text
            else:
                print(f"      HTTP {resp.status_code}, skipping")
                continue
        except Exception as e:
            print(f"      Error fetching file: {e}")
            continue
        
        for service, pattern in KEY_PATTERNS.items():
            for m in pattern.finditer(content):
                key = m.group(0)
                uid = f"code_{file_id}_{key[:16]}"
                if uid in processed:
                    continue
                print(f"      🔑 Found {service} key: {key[:20]}...")
                
                line_num = None
                line_content = ""
                lines = content.split('\n')
                for i, line in enumerate(lines):
                    if key in line:
                        line_num = i + 1
                        line_content = line.strip()[:300]
                        break
                
                valid, bal, info = verify_key(service, key)
                if valid:
                    processed.add(uid)
                    reply = build_code_reply(author, service, key, info, file_url, file_path, line_num, line_content, bal)
                    try:
                        code_repo = g.get_repo(repo_name)
                        issue_title = f"🚨 API Key Leak Detected in {file_path}"
                        new_issue = code_repo.create_issue(title=issue_title, body=reply, labels=["security"])
                        mark_code_replied(file_id, state)
                        save_state(state)
                        scan_results["replied_count"] += 1
                        scan_results["found_keys"].append({
                            "type": "code",
                            "repo": repo_name,
                            "file": file_path,
                            "service": service,
                            "key": key,
                            "balance": bal,
                            "info": info,
                            "url": file_url
                        })
                        replied_this_batch += 1
                        print(f"        ✅ Created issue #{new_issue.number} in {repo_name} - {info}")
                        time.sleep(1)
                    except Exception as e:
                        scan_results["errors"].append(str(e))
                        print(f"        ❌ Failed: {e}")
                else:
                    print(f"        ❌ Invalid: {info}")
        time.sleep(0.3)
    
    return replied_this_batch, page + 1, True

def scan_issue_batch(g, repo, state, processed, page):
    print(f"\n  📦 Fetching issues page {page}...")
    issue_results = get_issue_batch(g, page)
    total = len(issue_results)
    
    if total == 0:
        print(f"  No more issues")
        return 0, page + 1, False
    
    print(f"  Found {total} issues on page {page}")
    replied_this_batch = 0
    
    for idx, issue in enumerate(issue_results):
        heartbeat()
        check_timeout()
        
        num = issue.number
        if has_replied_to_issue(num, state):
            continue
        
        title = issue.title
        body = issue.body or ""
        author = issue.user.login
        print(f"    [{idx+1}/{total}] Checking issue #{num} by {author}")
        
        full_text = f"{title}\n{body}"
        try:
            for c in issue.get_comments():
                full_text += f"\n{c.body or ''}"
        except Exception as e:
            print(f"      Error getting comments: {e}")
        
        for service, pattern in KEY_PATTERNS.items():
            for m in pattern.finditer(full_text):
                key = m.group(0)
                uid = f"i_{num}_{key[:16]}"
                if uid in processed:
                    continue
                print(f"      🔑 Found {service} key: {key[:20]}...")
                
                line_num = None
                line_content = ""
                loc = "unknown"
                
                if key in title:
                    line_num = 1
                    line_content = title[:200]
                    loc = "issue title"
                elif key in body:
                    lines = body.split('\n')
                    for i, l in enumerate(lines):
                        if key in l:
                            line_num = i + 1
                            line_content = l.strip()[:200]
                            break
                    loc = "issue body"
                else:
                    loc = "issue comment"
                    line_content = key[:200]
                
                valid, bal, info = verify_key(service, key)
                if valid:
                    processed.add(uid)
                    reply = build_issue_reply(author, service, key, info, issue.html_url, loc, line_num, line_content, bal)
                    try:
                        repo.get_issue(number=num).create_comment(reply)
                        mark_issue_replied(num, state)
                        save_state(state)
                        scan_results["replied_count"] += 1
                        scan_results["found_keys"].append({
                            "type": "issue",
                            "number": num,
                            "service": service,
                            "key": key,
                            "balance": bal,
                            "info": info,
                            "url": issue.html_url
                        })
                        replied_this_batch += 1
                        print(f"        ✅ Replied to issue #{num} - {info}")
                        time.sleep(1)
                    except Exception as e:
                        scan_results["errors"].append(str(e))
                        print(f"        ❌ Failed: {e}")
                else:
                    print(f"        ❌ Invalid: {info}")
        time.sleep(0.3)
    
    return replied_this_batch, page + 1, True

def check_and_reply():
    global last_heartbeat
    
    print(f"\n{'='*60}")
    print(f"🤖 LLMApiCheckBot - API Key Leak Scanner")
    print(f"📁 Repository: {REPO_NAME}")
    print(f"⏱️  Max runtime: {MAX_RUNTIME_SECONDS}s (1.5 hours)")
    print(f"⏸️  Delay between batches: {BATCH_DELAY}s")
    print(f"{'='*60}\n")
    
    state = load_state()
    print(f"📊 Loaded state: {len(state.get('replied_commits', []))} commits, {len(state.get('replied_codes', []))} code files, {len(state.get('replied_issues', []))} issues")
    
    commit_page = state.get("last_commit_page", 0)
    code_page = state.get("last_code_page", 0)
    issue_page = state.get("last_issue_page", 0)
    print(f"📍 Starting from commit page {commit_page}, code page {code_page}, issue page {issue_page}\n")
    
    auth = Auth.Token(PAT_TOKEN)
    g = Github(auth=auth)
    
    try:
        user = g.get_user()
        print(f"✅ Authenticated as: {user.login}\n")
    except Exception as e:
        print(f"❌ Auth error: {e}")
        return
    
    try:
        repo = g.get_repo(REPO_NAME)
        print(f"✅ Repository: {repo.full_name}\n")
    except Exception as e:
        print(f"❌ Error accessing repo: {e}")
        return
    
    processed = set()
    batch_count = 0
    total_replied = 0
    
    while True:
        check_timeout()
        batch_count += 1
        
        print(f"\n{'='*50}")
        print(f"📦 Batch #{batch_count}")
        print(f"📍 Commit page {commit_page}, Code page {code_page}, Issue page {issue_page}")
        print(f"{'='*50}")
        
        # Scan commits
        commit_replied, commit_page, commit_has_more = scan_commit_batch(g, repo, state, processed, commit_page)
        total_replied += commit_replied
        check_timeout()
        
        # Scan code
        code_replied, code_page, code_has_more = scan_code_batch(g, repo, state, processed, code_page)
        total_replied += code_replied
        check_timeout()
        
        # Scan issues
        issue_replied, issue_page, issue_has_more = scan_issue_batch(g, repo, state, processed, issue_page)
        total_replied += issue_replied
        
        # Save progress
        state["last_commit_page"] = commit_page
        state["last_code_page"] = code_page
        state["last_issue_page"] = issue_page
        save_state(state)
        
        print(f"\n📊 Batch #{batch_count} summary:")
        print(f"   ✅ Replied to {commit_replied} commits")
        print(f"   ✅ Replied to {code_replied} code files")
        print(f"   ✅ Replied to {issue_replied} issues")
        print(f"   📈 Total replied so far: {total_replied}")
        print(f"   📊 Total keys found: {len(scan_results['found_keys'])}")
        
        # Check if all have no more results
        if not commit_has_more and not code_has_more and not issue_has_more:
            print(f"\n✅ No more results from all searches. Scan complete.")
            break
        
        print(f"\n💤 Waiting {BATCH_DELAY} seconds before next batch...")
        for i in range(BATCH_DELAY):
            check_timeout()
            if i % 5 == 0 and i > 0:
                print(f"   ... {BATCH_DELAY - i} seconds remaining")
            time.sleep(1)
    
    elapsed = time.time() - start_time
    print(f"\n{'='*60}")
    print(f"✅ Scan completed in {elapsed:.0f}s")
    print(f"📊 Found {len(scan_results['found_keys'])} valid keys")
    print(f"📊 Replied to {scan_results['replied_count']} items")
    
    # Print all found keys
    if scan_results['found_keys']:
        print(f"\n🔑 Valid keys found:")
        for i, key_info in enumerate(scan_results['found_keys'], 1):
            print(f"   {i}. [{key_info['service']}] {key_info['key']}")
            print(f"      {key_info['info']}")
            print(f"      {key_info['url']}")
    
    print(f"{'='*60}")
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