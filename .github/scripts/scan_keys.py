#!/usr/bin/env python3
"""
API Key Leak Scanner - Full Version with Source Tracking
Supports: Code + Issues + Commits
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
MAX_RUNTIME_SECONDS = 90 * 60
HEARTBEAT_INTERVAL = 300
REQUEST_TIMEOUT = 15
PER_PAGE = 30
MAX_PAGES = 30
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
    """
    Gemini API 验证
    200: 完全有效
    403: Key 有效但受限制（IP/地域/billing），仍视为有效
    400: 可能是格式问题，也可能是 key 无效
    """
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
        print(f"\n[!] Max runtime reached. Exiting.")
        sys.exit(0)
    return elapsed

def heartbeat():
    global last_heartbeat
    now = time.time()
    if now - last_heartbeat >= HEARTBEAT_INTERVAL:
        elapsed = now - start_time
        print(f"[❤️] Alive: {elapsed:.0f}s / {MAX_RUNTIME_SECONDS}s")
        last_heartbeat = now

def signal_handler(sig, frame):
    print("\n\n⚠️ Interrupted, saving results...")
    stop_event.set()
    time.sleep(2)
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# ========== 回复模板 ==========
def build_reply(author, service, key, info, source_url, source_type):
    masked = key[:12] + "..." + key[-8:] if len(key) > 24 else key
    return f"@{author} Your API key has been exposed!\n\n# Summary\nThis is a **{service}** API key found in {source_type}: [{source_url}]({source_url}).\n\nKey preview: `{masked}`\n\nVerification result: {info}\n\n---\n\n**What to do:**\n1. Revoke this key from {service} dashboard\n2. Generate a new key\n3. Remove the exposed key\n4. Rotate other exposed secrets\n\n---\n{BOT_SIGNATURE}"

# ========== 验证批次 ==========
def verify_batch(worker_id, batch):
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
                    with valid_lock:
                        found_valid_keys.append((key, service, balance, info, source_url, source_type, datetime.now()))
                    with open("valid_keys_realtime.txt", "a") as f:
                        f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | {service} | {key} | {info} | {source_url}\n")
                else:
                    print(f"  ❌ [{service}] {key[:25]}... -> {info}")
                    print(f"     📍 Source: {source_url}")
            except Exception as e:
                print(f"  ❌ Exception: {e}")

def add_key_to_pending(worker_id, key, service, source_url, source_type, author):
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
            executor.submit(verify_batch, worker_id, batch)
            executor.shutdown(wait=False)

def extract_and_queue(text, source_url, source_type, worker_id, author):
    for service, pattern in KEY_PATTERNS.items():
        for match in pattern.finditer(text):
            key = match.group(0)
            with valid_lock:
                if any(key == k for k, _, _, _, _, _, _ in found_valid_keys):
                    continue
            # 打印发现的 Key 及其出处
            print(f"  🔑 Found {service} key in {source_type}: {source_url[:80]}...")
            add_key_to_pending(worker_id, key, service, source_url, source_type, author)

# ========== Code 搜索 ==========
def search_code_worker(worker_id, start_page):
    safe_print(f"\n[Worker-{worker_id}] 🚀 Starting CODE scan from page {start_page}")
    page = start_page
    items_processed = 0
    
    while not stop_event.is_set() and page <= MAX_PAGES:
        check_timeout()
        heartbeat()
        
        url = f"{GITHUB_API}/search/code?q={urllib.parse.quote(CODE_QUERY)}&sort=indexed&order=desc&per_page={PER_PAGE}&page={page}"
        try:
            code, data = _http_request(url, headers=_gh_headers(), timeout=REQUEST_TIMEOUT)
            if code != 200:
                safe_print(f"[Worker-{worker_id}] CODE page {page}: HTTP {code}")
                page += 1
                time.sleep(2)
                continue
            items = data.get("items", []) if isinstance(data, dict) else []
            if not items:
                break
            safe_print(f"[Worker-{worker_id}] 📄 CODE page {page}: {len(items)} items")
            for item in items:
                if stop_event.is_set():
                    break
                raw_url = item.get("html_url", "").replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
                author = item.get("repository", {}).get("owner", {}).get("login", "unknown")
                try:
                    resp = requests.get(raw_url, timeout=10)
                    if resp.status_code == 200:
                        extract_and_queue(resp.text, item.get("html_url", ""), "code", worker_id, author)
                except:
                    pass
                items_processed += 1
            page += 1
            time.sleep(0.5)
        except Exception as e:
            safe_print(f"[Worker-{worker_id}] CODE error: {e}")
            page += 1
            time.sleep(5)
    safe_print(f"[Worker-{worker_id}] CODE scan finished, processed {items_processed} files")

# ========== Issues 搜索 ==========
def search_issues_worker(worker_id, start_page):
    safe_print(f"\n[Worker-{worker_id}] 🚀 Starting ISSUE scan from page {start_page}")
    query = ISSUE_QUERY
    page = start_page
    items_processed = 0
    
    while not stop_event.is_set() and page <= MAX_PAGES:
        check_timeout()
        heartbeat()
        
        url = f"{GITHUB_API}/search/issues?q={urllib.parse.quote(query)}&sort=created&order=desc&per_page={PER_PAGE}&page={page}"
        try:
            code, data = _http_request(url, headers=_gh_headers(), timeout=REQUEST_TIMEOUT)
            if code != 200:
                safe_print(f"[Worker-{worker_id}] ISSUE page {page}: HTTP {code}")
                page += 1
                time.sleep(2)
                continue
            items = data.get("items", []) if isinstance(data, dict) else []
            if not items:
                break
            safe_print(f"[Worker-{worker_id}] 📄 ISSUE page {page}: {len(items)} items")
            for item in items:
                if stop_event.is_set():
                    break
                title = item.get("title", "")
                body = item.get("body", "") or ""
                author = item.get("user", {}).get("login", "unknown")
                full_text = title + "\n" + body
                extract_and_queue(full_text, item.get("html_url", ""), "issue", worker_id, author)
                items_processed += 1
            page += 1
            time.sleep(0.5)
        except Exception as e:
            safe_print(f"[Worker-{worker_id}] ISSUE error: {e}")
            page += 1
            time.sleep(5)
    safe_print(f"[Worker-{worker_id}] ISSUE scan finished, processed {items_processed} items")

# ========== Commits 搜索 ==========
def search_commits_worker(worker_id, start_page):
    safe_print(f"\n[Worker-{worker_id}] 🚀 Starting COMMIT scan from page {start_page}")
    page = start_page
    items_processed = 0
    
    while not stop_event.is_set() and page <= MAX_PAGES:
        check_timeout()
        heartbeat()
        
        url = f"{GITHUB_API}/search/commits?q={urllib.parse.quote(COMMIT_QUERY)}&sort=committer-date&order=desc&per_page={PER_PAGE}&page={page}"
        try:
            code, data = _http_request(url, headers=_gh_headers(), timeout=REQUEST_TIMEOUT)
            if code != 200:
                safe_print(f"[Worker-{worker_id}] COMMIT page {page}: HTTP {code}")
                page += 1
                time.sleep(2)
                continue
            items = data.get("items", []) if isinstance(data, dict) else []
            if not items:
                break
            safe_print(f"[Worker-{worker_id}] 📄 COMMIT page {page}: {len(items)} items")
            for item in items:
                if stop_event.is_set():
                    break
                message = item.get("commit", {}).get("message", "")
                author = item.get("author", {}).get("login", "unknown") if item.get("author") else "unknown"
                extract_and_queue(message, item.get("html_url", ""), "commit", worker_id, author)
                items_processed += 1
            page += 1
            time.sleep(0.5)
        except Exception as e:
            safe_print(f"[Worker-{worker_id}] COMMIT error: {e}")
            page += 1
            time.sleep(5)
    safe_print(f"[Worker-{worker_id}] COMMIT scan finished, processed {items_processed} items")

# ========== 主函数 ==========
def main():
    print("=" * 70)
    print("🤖 API Key Leak Scanner - Full Version with Source Tracking")
    print("📊 Scanning: CODE + ISSUES + COMMITS")
    print("📊 Supports: OpenAI(sk-proj-), OpenRouter, DeepSeek, Gemini, Anthropic, Replicate, HuggingFace, MiMo")
    print("=" * 70)
    
    g = get_github_client()
    if not g:
        print("❌ Failed to initialize GitHub client")
        return
    
    with ThreadPoolExecutor(max_workers=SEARCH_WORKERS) as executor:
        futures = [
            executor.submit(search_code_worker, 1, 1),
            executor.submit(search_issues_worker, 2, 1),
            executor.submit(search_commits_worker, 3, 1),
            executor.submit(search_issues_worker, 4, 6),
        ]
        for future in as_completed(futures):
            try:
                future.result()
            except:
                pass
    
    print(f"\n✅ Scan completed. Found {len(found_valid_keys)} valid keys.")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        sys.exit(1)