#!/usr/bin/env python3
"""
API Key Leak Scanner - Final Version
- All leaks create issues in Dont-Be-Stupid-Leaker
- 29.5 minute timeout
- Infinite pagination
"""

import os
import re
import sys
import json
import ssl
import jwt
import time
import signal
import requests
import urllib.parse
import urllib.request
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock, Event
from collections import defaultdict
from typing import Optional, List, Tuple, Dict, Any
from github import Github, Auth, GithubException

# ========== Configuration ==========
MAX_RUNTIME_SECONDS = 29.5 * 60  # 29.5 minutes = 1770 seconds
HEARTBEAT_INTERVAL = 60
REQUEST_TIMEOUT = 15
PER_PAGE = 30
SEARCH_WORKERS = 4
VERIFY_WORKERS = 30
BATCH_SIZE = 30

APP_ID = os.environ.get("APP_ID")
PRIVATE_KEY = os.environ.get("PRIVATE_KEY")
INSTALLATION_ID = os.environ.get("INSTALLATION_ID")
PAT_TOKEN = os.environ.get("PAT_TOKEN")

REPO_NAME = os.environ.get("GITHUB_REPOSITORY", "Colorful-glassblock/Dont-Be-Stupid-Leaker")
BOT_NAME = "LLMApiCheckBot"
BOT_SIGNATURE = f"*This message was sent by {BOT_NAME} - Repository: {REPO_NAME}*"

GITHUB_API = "https://api.github.com"

# 搜索条件
ISSUE_QUERY = '"your key leak" OR "sk-" OR "sk-proj-" OR "AIza" OR "sk-ant-api"'
COMMIT_QUERY = 'sk- OR sk-proj- OR AIza OR sk-ant-api'
CODE_QUERY = 'sk- OR sk-proj- OR AIza OR sk-ant-api'

STATE_FILE = "replied_state.json"

start_time = time.time()
last_heartbeat = start_time
stop_event = Event()
found_valid_keys: List[Tuple] = []
valid_lock = Lock()
pending_batches: Dict[int, List[Tuple]] = defaultdict(list)
batch_locks: Dict[int, Lock] = {}
pending_count: Dict[int, int] = defaultdict(int)

# 已处理的记录
processed_sources: set = set()
processed_lock = Lock()

# ========== Key 正则 ==========
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

# ========== 验证函数 ==========
def _parse_deepseek(code, data):
    if code != 200:
        return False, 0, f"HTTP {code}"
    if not isinstance(data, dict):
        return False, 0, "Invalid response"
    if data.get("is_available", False):
        cny = sum(float(i.get("total_balance", 0)) for i in data.get("balance_infos", []) if i.get("currency") == "CNY")
        usd = sum(float(i.get("total_balance", 0)) for i in data.get("balance_infos", []) if i.get("currency") == "USD")
        info = f"💰 CNY: {cny:.2f}, USD: {usd:.2f}" if cny or usd else "Valid (no balance)"
        return True, cny + usd * 7.2, info
    return False, 0, "Invalid"

def _parse_openai(code, data):
    if code == 200:
        return True, 0, "Valid"
    if code == 401:
        return False, 0, "Invalid"
    return False, 0, f"HTTP {code}"

def _parse_openrouter(code, data):
    if code == 200:
        credits = 0
        if isinstance(data, dict):
            credits = data.get("credits", 0)
        info = f"💰 Credits: {credits}" if credits > 0 else "Valid"
        return True, float(credits), info
    return False, 0, f"HTTP {code}"

def _parse_gemini(code, data):
    if code == 200:
        return True, 0, "✅ Valid"
    if code == 403:
        return True, 0, "⚠️ Valid but restricted (IP/region/billing)"
    if code == 400:
        if isinstance(data, dict) and "API key not valid" in str(data):
            return False, 0, "❌ Invalid key"
        return True, 0, "⚠️ Possibly valid (check billing)"
    if code == 404:
        return False, 0, "❌ Invalid (not found)"
    if code == 429:
        return True, 0, "⚠️ Rate limited (key may be valid)"
    return False, 0, f"❌ HTTP {code}"

def _parse_anthropic(code, data):
    if code == 200:
        return True, 0, "Valid"
    return False, 0, f"HTTP {code}"

def _parse_replicate(code, data):
    if code == 200:
        return True, 0, "Valid"
    return False, 0, f"HTTP {code}"

def _parse_huggingface(code, data):
    if code == 200:
        return True, 0, "Valid"
    return False, 0, f"HTTP {code}"

def _parse_mimo(code, data):
    if code == 200:
        balance = 0
        if isinstance(data, dict):
            balance = float(data.get("balance", data.get("credit", 0)))
        info = f"💰 Balance: {balance}" if balance > 0 else "Valid"
        return True, balance, info
    return False, 0, f"HTTP {code}"

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

# ========== GitHub 认证 ==========
def get_github_client():
    token = None
    if APP_ID and PRIVATE_KEY and INSTALLATION_ID:
        try:
            payload = {"iat": int(time.time()), "exp": int(time.time()) + 600, "iss": APP_ID}
            jwt_token = jwt.encode(payload, PRIVATE_KEY, algorithm="RS256")
            url = f"https://api.github.com/app/installations/{INSTALLATION_ID}/access_tokens"
            headers = {"Authorization": f"Bearer {jwt_token}", "Accept": "application/vnd.github+json"}
            resp = requests.post(url, headers=headers)
            if resp.status_code == 201:
                token = resp.json()["token"]
                print("✅ Using GitHub App authentication")
        except Exception as e:
            print(f"⚠️ GitHub App auth failed: {e}")
    if not token and PAT_TOKEN:
        token = PAT_TOKEN
        print("✅ Using PAT authentication")
    if not token:
        print("❌ No authentication method available")
        return None
    auth = Auth.Token(token)
    return Github(auth=auth)

# ========== 工具函数 ==========
def _gh_headers():
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "KeyScanner"}
    if PAT_TOKEN:
        headers["Authorization"] = f"Bearer {PAT_TOKEN}"
    return headers

def _http_request(url, headers, method="GET", body=None, timeout=REQUEST_TIMEOUT):
    try:
        req = urllib.request.Request(url, headers=headers, method=method, data=body)
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            raw = resp.read().decode("utf-8")
            try:
                return resp.status, json.loads(raw)
            except:
                return resp.status, raw
    except urllib.error.HTTPError as e:
        return e.code, str(e)
    except:
        return 0, str(e)

def safe_print(msg):
    with print_lock:
        print(msg, flush=True)

print_lock = Lock()

def check_timeout():
    elapsed = time.time() - start_time
    if elapsed >= MAX_RUNTIME_SECONDS:
        print(f"\n[!] Max runtime reached ({MAX_RUNTIME_SECONDS}s / 29.5 min). Exiting.")
        save_final_results()
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

def signal_handler(sig, frame):
    print("\n\n⚠️ Interrupted, saving results...")
    stop_event.set()
    time.sleep(2)
    save_final_results()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def save_final_results():
    with valid_lock:
        if found_valid_keys:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            with open(f"valid_keys_final_{timestamp}.txt", "w") as f:
                f.write(f"# Scan time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# Total valid keys: {len(found_valid_keys)}\n\n")
                for key, service, balance, info, source_url, source_type, _ in found_valid_keys:
                    f.write(f"{service} | {key} | {info} | {source_url}\n")
            print(f"\n💾 Saved {len(found_valid_keys)} keys to valid_keys_final_{timestamp}.txt")

# ========== 回复模板 ==========
def build_reply(author, service, key, info, source_url, source_type):
    masked = key[:12] + "..." + key[-8:] if len(key) > 24 else key
    return f"""🔴 **API Key Leak Detected!**

@{author} Your API key has been exposed in this {source_type}.

**Service:** `{service}`
**Key preview:** `{masked}`
**Status:** {info}

⚠️ **Immediate Actions Required:**
1. Revoke this key immediately from your {service} dashboard
2. Generate a new key
3. Remove the exposed key from the {source_type}
4. Rotate any other secrets that may be compromised

📍 **Source:** {source_url}

---
{BOT_SIGNATURE}"""

# ========== 创建 Issue 到自己的仓库 ==========
def create_issue_in_my_repo(g, key, service, info, source_url, source_type, author):
    """所有来源都在自己的仓库创建 Issue"""
    message = build_reply(author, service, key, info, source_url, source_type)
    
    with processed_lock:
        if source_url in processed_sources:
            print(f"    ⏭️ Already processed this source, skipping")
            return
        processed_sources.add(source_url)
    
    try:
        my_repo = g.get_repo(REPO_NAME)
        
        # 检查是否已经存在相同来源 URL 的 Issue
        already_exists = False
        existing_issue_num = None
        try:
            issues = my_repo.get_issues(state="all", labels=["leak", "security"])
            for issue in issues:
                if source_url in issue.body:
                    already_exists = True
                    existing_issue_num = issue.number
                    break
        except Exception as e:
            print(f"    ⚠️ Failed to check existing issues: {e}")
        
        if already_exists:
            print(f"    ⏭️ Issue #{existing_issue_num} already exists for this source, skipping")
            return
        
        # 生成简洁的标题
        short_url = source_url.replace("https://github.com/", "")
        if len(short_url) > 60:
            short_url = short_url[:57] + "..."
        
        # 判断是 PR 还是 Issue 还是其他
        if "/pull/" in source_url:
            display_type = "Pull Request"
        elif "/issues/" in source_url:
            display_type = "Issue"
        else:
            display_type = source_type
        
        issue_title = f"🔴 {service} Key Leak in {display_type}: {short_url}"
        issue_body = f"""## API Key Leak Detected

| Field | Value |
|-------|-------|
| **Source Type** | {display_type} |
| **Source URL** | {source_url} |
| **Service** | `{service}` |
| **Key Preview** | `{key[:20]}...` |
| **Status** | {info} |
| **Author** | @{author} |

---

### Details

{message}

---

*Auto-generated by {BOT_NAME}*
"""
        new_issue = my_repo.create_issue(title=issue_title, body=issue_body, labels=["security", "leak"])
        print(f"    📝 Created issue #{new_issue.number} in {REPO_NAME}")
    except Exception as e:
        print(f"    ❌ Failed to create issue: {e}")

# ========== 验证批次 ==========
def verify_batch(worker_id, batch, g):
    if not batch:
        return
    safe_print(f"\n[Worker-{worker_id}] 🔍 Verifying {len(batch)} keys...")
    
    def verify_one(key_info):
        key, service, source_url, source_type, author = key_info
        verifier = VERIFIERS.get(service)
        if not verifier:
            return (key, service, False, 0, "Unsupported", source_url, source_type, author)
        try:
            url = verifier["url"](key) if callable(verifier["url"]) else verifier["url"]
            headers = verifier["headers"](key)
            headers["User-Agent"] = "KeyScanner"
            body = verifier.get("body")
            if body:
                body = body()
            if verifier["method"] == "GET":
                resp = requests.get(url, headers=headers, timeout=8)
            else:
                resp = requests.post(url, headers=headers, data=body, timeout=8)
            valid, balance, info = verifier["parse"](resp.status_code, resp.json() if resp.text else None)
            return (key, service, valid, balance, info, source_url, source_type, author)
        except Exception as e:
            return (key, service, False, 0, f"Error: {str(e)[:30]}", source_url, source_type, author)
    
    with ThreadPoolExecutor(max_workers=VERIFY_WORKERS) as executor:
        futures = [executor.submit(verify_one, ki) for ki in batch]
        for future in as_completed(futures):
            try:
                key, service, valid, balance, info, source_url, source_type, author = future.result(timeout=15)
                if valid:
                    print(f"  ✅ [{service}] {key[:25]}... -> {info}")
                    print(f"     📍 Source: {source_url}")
                    
                    # 保存到本地
                    with valid_lock:
                        found_valid_keys.append((key, service, balance, info, source_url, source_type, datetime.now()))
                    with open("valid_keys_realtime.txt", "a") as f:
                        f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | {service} | {key} | {info} | {source_url}\n")
                    
                    # 创建 Issue 到自己的仓库
                    create_issue_in_my_repo(g, key, service, info, source_url, source_type, author)
                    
                else:
                    print(f"  ❌ [{service}] {key[:25]}... -> {info}")
                    print(f"     📍 Source: {source_url}")
            except Exception as e:
                print(f"  ❌ Exception: {e}")

def add_key_to_pending(worker_id, key, service, source_url, source_type, author, g):
    if worker_id not in batch_locks:
        batch_locks[worker_id] = Lock()
    with batch_locks[worker_id]:
        pending_batches[worker_id].append((key, service, source_url, source_type, author))
        pending_count[worker_id] += 1
        if pending_count[worker_id] >= BATCH_SIZE:
            batch = pending_batches[worker_id].copy()
            pending_batches[worker_id].clear()
            pending_count[worker_id] = 0
            executor = ThreadPoolExecutor(max_workers=1)
            executor.submit(verify_batch, worker_id, batch, g)
            executor.shutdown(wait=False)

def extract_and_queue(text, source_url, source_type, worker_id, author, g):
    for service, pattern in KEY_PATTERNS.items():
        for match in pattern.finditer(text):
            key = match.group(0)
            with valid_lock:
                if any(key == k for k, _, _, _, _, _, _ in found_valid_keys):
                    continue
            print(f"  🔑 Found {service} key in {source_type}: {source_url[:80]}...")
            add_key_to_pending(worker_id, key, service, source_url, source_type, author, g)

# ========== Code 搜索（无限翻页） ==========
def search_code_worker(worker_id, start_page, g):
    safe_print(f"\n[Worker-{worker_id}] 🚀 Starting CODE scan from page {start_page} (infinite)")
    page = start_page
    items_processed = 0
    consecutive_empty = 0
    
    while not stop_event.is_set():
        check_timeout()
        heartbeat()
        
        url = f"{GITHUB_API}/search/code?q={urllib.parse.quote(CODE_QUERY)}&sort=indexed&order=desc&per_page={PER_PAGE}&page={page}"
        try:
            code, data = _http_request(url, headers=_gh_headers(), timeout=REQUEST_TIMEOUT)
            
            if code == 403:
                safe_print(f"[Worker-{worker_id}] CODE page {page}: HTTP 403, waiting 60s...")
                time.sleep(60)
                continue
            
            if code != 200:
                safe_print(f"[Worker-{worker_id}] CODE page {page}: HTTP {code}, continuing")
                page += 1
                time.sleep(2)
                continue
            
            items = data.get("items", []) if isinstance(data, dict) else []
            
            if not items:
                consecutive_empty += 1
                if consecutive_empty >= 3:
                    safe_print(f"[Worker-{worker_id}] CODE: No more results after {page} pages, stopping")
                    break
                page += 1
                time.sleep(1)
                continue
            
            consecutive_empty = 0
            
            safe_print(f"[Worker-{worker_id}] 📄 CODE page {page}: {len(items)} items (total: {items_processed + len(items)})")
            
            for item in items:
                if stop_event.is_set():
                    break
                raw_url = item.get("html_url", "").replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
                author = item.get("repository", {}).get("owner", {}).get("login", "unknown")
                try:
                    resp = requests.get(raw_url, timeout=10)
                    if resp.status_code == 200:
                        extract_and_queue(resp.text, item.get("html_url", ""), "code", worker_id, author, g)
                except:
                    pass
                items_processed += 1
            
            page += 1
            time.sleep(0.5)
        except Exception as e:
            safe_print(f"[Worker-{worker_id}] CODE error: {e}")
            page += 1
            time.sleep(5)
            continue
    
    safe_print(f"[Worker-{worker_id}] CODE scan finished, processed {items_processed} items")

# ========== Issues 搜索（无限翻页） ==========
def search_issues_worker(worker_id, start_page, g):
    safe_print(f"\n[Worker-{worker_id}] 🚀 Starting ISSUE scan from page {start_page} (infinite)")
    query = ISSUE_QUERY
    page = start_page
    items_processed = 0
    consecutive_empty = 0
    
    while not stop_event.is_set():
        check_timeout()
        heartbeat()
        
        url = f"{GITHUB_API}/search/issues?q={urllib.parse.quote(query)}&sort=created&order=desc&per_page={PER_PAGE}&page={page}"
        try:
            code, data = _http_request(url, headers=_gh_headers(), timeout=REQUEST_TIMEOUT)
            
            if code == 403:
                safe_print(f"[Worker-{worker_id}] ISSUE page {page}: HTTP 403, waiting 60s...")
                time.sleep(60)
                continue
            
            if code != 200:
                safe_print(f"[Worker-{worker_id}] ISSUE page {page}: HTTP {code}, continuing")
                page += 1
                time.sleep(2)
                continue
            
            items = data.get("items", []) if isinstance(data, dict) else []
            
            if not items:
                consecutive_empty += 1
                if consecutive_empty >= 3:
                    safe_print(f"[Worker-{worker_id}] ISSUE: No more results after {page} pages, stopping")
                    break
                page += 1
                time.sleep(1)
                continue
            
            consecutive_empty = 0
            
            safe_print(f"[Worker-{worker_id}] 📄 ISSUE page {page}: {len(items)} items (total: {items_processed + len(items)})")
            
            for item in items:
                if stop_event.is_set():
                    break
                title = item.get("title", "")
                body = item.get("body", "") or ""
                author = item.get("user", {}).get("login", "unknown")
                full_text = title + "\n" + body
                # 获取评论
                try:
                    comments_url = item.get("comments_url", "")
                    if comments_url:
                        ccode, cdata = _http_request(comments_url, headers=_gh_headers(), timeout=10)
                        if ccode == 200 and isinstance(cdata, list):
                            for comment in cdata:
                                full_text += f"\n{comment.get('body', '')}"
                except:
                    pass
                extract_and_queue(full_text, item.get("html_url", ""), "issue", worker_id, author, g)
                items_processed += 1
            
            page += 1
            time.sleep(0.5)
        except Exception as e:
            safe_print(f("[Worker-{worker_id}] ISSUE error: {e}")
            page += 1
            time.sleep(5)
            continue
    
    safe_print(f"[Worker-{worker_id}] ISSUE scan finished, processed {items_processed} items")

# ========== Commits 搜索（无限翻页） ==========
def search_commits_worker(worker_id, start_page, g):
    safe_print(f"\n[Worker-{worker_id}] 🚀 Starting COMMIT scan from page {start_page} (infinite)")
    page = start_page
    items_processed = 0
    consecutive_empty = 0
    
    while not stop_event.is_set():
        check_timeout()
        heartbeat()
        
        url = f"{GITHUB_API}/search/commits?q={urllib.parse.quote(COMMIT_QUERY)}&sort=committer-date&order=desc&per_page={PER_PAGE}&page={page}"
        try:
            code, data = _http_request(url, headers=_gh_headers(), timeout=REQUEST_TIMEOUT)
            
            if code == 403:
                safe_print(f"[Worker-{worker_id}] COMMIT page {page}: HTTP 403, waiting 60s...")
                time.sleep(60)
                continue
            
            if code != 200:
                safe_print(f"[Worker-{worker_id}] COMMIT page {page}: HTTP {code}, continuing")
                page += 1
                time.sleep(2)
                continue
            
            items = data.get("items", []) if isinstance(data, dict) else []
            
            if not items:
                consecutive_empty += 1
                if consecutive_empty >= 3:
                    safe_print(f"[Worker-{worker_id}] COMMIT: No more results after {page} pages, stopping")
                    break
                page += 1
                time.sleep(1)
                continue
            
            consecutive_empty = 0
            
            safe_print(f"[Worker-{worker_id}] 📄 COMMIT page {page}: {len(items)} items (total: {items_processed + len(items)})")
            
            for item in items:
                if stop_event.is_set():
                    break
                message = item.get("commit", {}).get("message", "")
                author = item.get("author", {}).get("login", "unknown") if item.get("author") else "unknown"
                full_text = message
                # 获取 diff
                try:
                    diff_url = item.get("html_url", "").replace("github.com", "api.github.com/repos")
                    diff_url = diff_url.replace("/commit/", "/commits/")
                    dcode, ddata = _http_request(diff_url, headers=_gh_headers(), timeout=10)
                    if dcode == 200 and isinstance(ddata, dict):
                        for f in ddata.get("files", []):
                            patch = f.get("patch", "")
                            if patch:
                                full_text += "\n" + patch
                except:
                    pass
                extract_and_queue(full_text, item.get("html_url", ""), "commit", worker_id, author, g)
                items_processed += 1
            
            page += 1
            time.sleep(0.5)
        except Exception as e:
            safe_print(f"[Worker-{worker_id}] COMMIT error: {e}")
            page += 1
            time.sleep(5)
            continue
    
    safe_print(f"[Worker-{worker_id}] COMMIT scan finished, processed {items_processed} items")

# ========== 主函数 ==========
def main():
    print("=" * 70)
    print("🤖 API Key Leak Scanner - Final Version")
    print(f"📁 Target repo: {REPO_NAME}")
    print(f"⏱️  Max runtime: {MAX_RUNTIME_SECONDS}s (29.5 minutes)")
    print("📊 Scanning: CODE + ISSUES + COMMITS (infinite pages)")
    print("📊 All leaks create issues in Dont-Be-Stupid-Leaker")
    print("=" * 70)
    
    g = get_github_client()
    if not g:
        print("❌ Failed to initialize GitHub client")
        return
    
    print("✅ GitHub client initialized\n")
    
    with ThreadPoolExecutor(max_workers=SEARCH_WORKERS) as executor:
        futures = [
            executor.submit(search_code_worker, 1, 1, g),
            executor.submit(search_issues_worker, 2, 1, g),
            executor.submit(search_commits_worker, 3, 1, g),
            executor.submit(search_issues_worker, 4, 6, g),
        ]
        for future in as_completed(futures):
            try:
                future.result()
            except:
                pass
    
    print(f"\n✅ Scan completed. Found {len(found_valid_keys)} valid keys.")
    print(f"📝 All issues created in: https://github.com/{REPO_NAME}/issues")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        save_final_results()
        sys.exit(1)