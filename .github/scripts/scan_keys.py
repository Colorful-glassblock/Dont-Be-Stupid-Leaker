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
from github import Github, GithubIntegration, GithubException

# ========== Configuration ==========
MAX_RUNTIME_SECONDS = 90 * 60
HEARTBEAT_INTERVAL = 300
PAGE_DELAY = 5
REPO_BATCH_SIZE = 10
MAX_WORKERS = 15

# GitHub App 配置
APP_ID = os.environ.get("APP_ID")
PRIVATE_KEY = os.environ.get("PRIVATE_KEY")
INSTALLATION_ID = int(os.environ.get("INSTALLATION_ID", "0"))

if not APP_ID or not PRIVATE_KEY or not INSTALLATION_ID:
    print("Error: APP_ID, PRIVATE_KEY, INSTALLATION_ID must be set")
    sys.exit(1)

REPO_NAME = os.environ.get("GITHUB_REPOSITORY", "Colorful-glassblock/Dont-Be-Stupid-Leaker")
BOT_NAME = "llmapicheckbot2"
BOT_SIGNATURE = f"*This message was sent by {BOT_NAME} - Repository: {REPO_NAME}*"

USER_AGENTS = [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
]

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
    """生成 JWT Token"""
    private_key = PRIVATE_KEY
    payload = {
        "iat": int(time.time()),
        "exp": int(time.time()) + 600,
        "iss": APP_ID
    }
    return jwt.encode(payload, private_key, algorithm="RS256")

def get_installation_token():
    """获取安装 Token"""
    jwt_token = get_jwt()
    url = f"https://api.github.com/app/installations/{INSTALLATION_ID}/access_tokens"
    headers = {
        "Authorization": f"Bearer {jwt_token}",
        "Accept": "application/vnd.github+json"
    }
    resp = requests.post(url, headers=headers)
    if resp.status_code != 201:
        print(f"Error getting installation token: {resp.status_code}")
        print(resp.text)
        return None
    return resp.json()["token"]

def get_github_client():
    """获取 GitHub 客户端"""
    token = get_installation_token()
    if not token:
        return None
    return Github(token)

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
        remaining = MAX_RUNTIME_SECONDS - elapsed
        print(f"[❤️] Alive: {elapsed:.0f}s / {MAX_RUNTIME_SECONDS}s")
        last_heartbeat = now

def load_state():
    try:
        with open(STATE_FILE, "r") as f:
            state = json.load(f)
            if "processed_repos" not in state:
                state["processed_repos"] = []
            if "current_page" not in state:
                state["current_page"] = 1
            return state
    except:
        return {"replied_commits": [], "replied_codes": [], "replied_issues": [], 
                "processed_repos": [], "current_page": 1}

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

def has_replied_to_commit(commit_sha, state):
    return commit_sha in state.get("replied_commits", [])

def has_replied_to_code(file_id, state):
    return file_id in state.get("replied_codes", [])

def has_replied_to_issue(issue_id, state):
    return str(issue_id) in state.get("replied_issues", [])

def mark_replied_commit(commit_sha, state):
    if "replied_commits" not in state:
        state["replied_commits"] = []
    if commit_sha not in state["replied_commits"]:
        state["replied_commits"].append(commit_sha)

def mark_replied_code(file_id, state):
    if "replied_codes" not in state:
        state["replied_codes"] = []
    if file_id not in state["replied_codes"]:
        state["replied_codes"].append(file_id)

def mark_replied_issue(issue_id, state):
    if "replied_issues" not in state:
        state["replied_issues"] = []
    if str(issue_id) not in state["replied_issues"]:
        state["replied_issues"].append(str(issue_id))

def save_result():
    fname = f"scan_result_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(fname, "w") as f:
        json.dump(scan_results, f, indent=2)
    print(f"💾 Saved to {fname}")

def get_repos_by_page(g, page):
    try:
        results = g.search_repositories("language:python", sort="updated", order="desc")
        items = results.get_page(page)
        return [repo.full_name for repo in items]
    except GithubException as e:
        if e.status == 422:
            try:
                results = g.search_repositories("stars:>0", sort="updated", order="desc")
                items = results.get_page(page)
                return [repo.full_name for repo in items]
            except:
                return []
        return []
    except Exception:
        return []

def scan_single_repo(g, repo_full_name, state, processed):
    print(f"\n  📦 Scanning: {repo_full_name}")
    
    try:
        repo = g.get_repo(repo_full_name)
    except Exception as e:
        print(f"    Cannot access: {e}")
        return 0
    
    replied_total = 0
    
    # Scan code files
    try:
        code_query = f"repo:{repo_full_name} sk- OR sk-proj- OR AIza OR sk-ant-api OR r8_ OR hf_ OR tp-"
        code_results = list(g.search_code(code_query))[:30]
        
        for code in code_results:
            if stop_scan:
                break
            heartbeat()
            check_timeout()
            
            file_path = code.path
            file_url = code.html_url
            file_id = f"{repo_full_name}_{file_path}"
            
            if has_replied_to_code(file_id, state):
                continue
            
            raw_url = f"https://raw.githubusercontent.com/{repo_full_name}/HEAD/{file_path}"
            content = ""
            try:
                resp = requests.get(raw_url, headers={"User-Agent": USER_AGENTS[0]}, timeout=10)
                if resp.status_code == 200:
                    content = resp.text
            except:
                continue
            
            for service, pattern in KEY_PATTERNS.items():
                for m in pattern.finditer(content):
                    key = m.group(0)
                    uid = f"code_{file_id}_{key[:16]}"
                    if uid in processed:
                        continue
                    
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
                        author = repo.owner.login
                        reply = build_reply(author, service, key, info, file_url, "code file", file_path, line_num, line_content, bal)
                        try:
                            new_issue = repo.create_issue(title=f"🚨 API Key Leak in {file_path}", body=reply, labels=["security"])
                            mark_replied_code(file_id, state)
                            save_state(state)
                            scan_results["replied_count"] += 1
                            scan_results["found_keys"].append({"type":"code","repo":repo_full_name,"file":file_path,"service":service,"key":key,"balance":bal,"info":info})
                            replied_total += 1
                            print(f"      ✅ Created issue #{new_issue.number}")
                            time.sleep(1)
                        except Exception as e:
                            scan_results["errors"].append(str(e))
            time.sleep(0.3)
    except Exception as e:
        pass
    
    return replied_total

def check_and_reply():
    global last_heartbeat, stop_scan
    
    print(f"\n{'='*60}")
    print(f"🤖 {BOT_NAME} - API Key Leak Scanner (GitHub App)")
    print(f"📁 Self repo: {REPO_NAME}")
    print(f"⏱️  Max runtime: {MAX_RUNTIME_SECONDS}s")
    print(f"{'='*60}\n")
    
    g = get_github_client()
    if not g:
        print("❌ Failed to get GitHub client")
        return
    
    try:
        user = g.get_user()
        print(f"✅ Authenticated as: {user.login} (App)\n")
    except Exception as e:
        print(f"❌ Auth error: {e}")
        return
    
    state = load_state()
    current_page = state.get("current_page", 1)
    print(f"📍 Starting from page {current_page}")
    print(f"📊 Processed repos: {len(state.get('processed_repos', []))}\n")
    
    processed = set()
    total_replied = 0
    
    while not stop_scan:
        check_timeout()
        
        print(f"\n{'='*50}")
        print(f"📄 Page {current_page}")
        print(f"{'='*50}")
        
        repos = get_repos_by_page(g, current_page)
        
        if not repos:
            print(f"  No repositories, moving to next page")
            state["current_page"] = current_page + 1
            save_state(state)
            time.sleep(PAGE_DELAY)
            continue
        
        repos_to_scan = [r for r in repos[:REPO_BATCH_SIZE] 
                         if r != REPO_NAME and r not in state.get("processed_repos", [])]
        
        print(f"📁 Found {len(repos)} repos, scanning {len(repos_to_scan)} new")
        
        if not repos_to_scan:
            state["current_page"] = current_page + 1
            save_state(state)
            time.sleep(PAGE_DELAY)
            continue
        
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {executor.submit(scan_single_repo, g, repo, state, processed): repo 
                       for repo in repos_to_scan}
            for future in as_completed(futures):
                repo_name = futures[future]
                try:
                    replied = future.result()
                    total_replied += replied
                    if "processed_repos" not in state:
                        state["processed_repos"] = []
                    if repo_name not in state["processed_repos"]:
                        state["processed_repos"].append(repo_name)
                    save_state(state)
                except Exception as e:
                    scan_results["errors"].append(str(e))
        
        print(f"\n📊 Page {current_page} done - Total replied: {total_replied}")
        
        state["current_page"] = current_page + 1
        save_state(state)
        
        print(f"\n💤 Waiting {PAGE_DELAY}s...")
        for i in range(PAGE_DELAY):
            if stop_scan:
                break
            check_timeout()
            time.sleep(1)
    
    elapsed = time.time() - start_time
    print(f"\n✅ Scan completed in {elapsed:.0f}s")
    print(f"📊 Found {len(scan_results['found_keys'])} valid keys")
    print(f"📊 Replied to {scan_results['replied_count']} items")
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