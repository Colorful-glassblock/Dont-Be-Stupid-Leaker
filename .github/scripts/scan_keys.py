#!/usr/bin/env python3
"""
API Key Leak Scanner - Stable Version
Supports: GitHub App + PAT fallback, OpenRouter, sk-proj-, 1.5h timeout
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
MAX_RUNTIME_SECONDS = 90 * 60  # 1.5 hours
HEARTBEAT_INTERVAL = 300
REQUEST_TIMEOUT = 15
PER_PAGE = 30
MAX_PAGES = 50                # 增加到50页，不会过早停止
SEARCH_WORKERS = 3
VERIFY_WORKERS = 30
BATCH_SIZE = 50

# GitHub App 配置 (从环境变量读取)
APP_ID = os.environ.get("APP_ID")
PRIVATE_KEY = os.environ.get("PRIVATE_KEY")
INSTALLATION_ID = os.environ.get("INSTALLATION_ID")
PAT_TOKEN = os.environ.get("PAT_TOKEN")

REPO_NAME = os.environ.get("GITHUB_REPOSITORY", "Colorful-glassblock/Dont-Be-Stupid-Leaker")
BOT_NAME = "LLMApiCheckBot"
BOT_SIGNATURE = f"*This message was sent by {BOT_NAME} - Repository: {REPO_NAME}*"

GITHUB_API = "https://api.github.com"
ISSUE_QUERY = '"your key leak"'
COMMIT_QUERY = 'sk-'

STATE_FILE = "replied_state.json"

scan_results = {
    "scan_time": datetime.now().isoformat(),
    "found_keys": [],
    "replied_count": 0,
    "errors": []
}

start_time = time.time()
last_heartbeat = start_time
stop_event = Event()
found_valid_keys: List[Tuple] = []
valid_lock = Lock()
pending_batches: Dict[int, List[Tuple]] = defaultdict(list)
batch_locks: Dict[int, Lock] = {}
pending_count: Dict[int, int] = defaultdict(int)

# ========== 多供应商 Key 正则 ==========
KEY_PATTERNS = {
    "OpenAI": re.compile(r"sk-proj-[a-zA-Z0-9]{32,}"),
    "OpenAI_Legacy": re.compile(r"sk-[a-zA-Z0-9]{32,}"),
    "OpenRouter": re.compile(r"sk-or-v1-[a-zA-Z0-9]{50,}"),
    "DeepSeek": re.compile(r"sk-[a-zA-Z0-9]{32,}"),
    "Gemini": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "Anthropic": re.compile(r"sk-ant-api[0-9A-Za-z\-_]{40,}"),
    "Cohere": re.compile(r"[a-zA-Z0-9]{40}"),
    "Replicate": re.compile(r"r8_[a-zA-Z0-9]{32,}"),
    "HuggingFace": re.compile(r"hf_[a-zA-Z0-9]{30,}"),
    "MiMo": re.compile(r"tp-[a-zA-Z0-9]{10,}"),
}

# ========== 增强验证机制 ==========
def _parse_openai(code, data):
    if code != 200:
        return False, 0, f"HTTP {code}"
    if not isinstance(data, dict):
        return False, 0, "Invalid response"
    models = data.get("data", [])
    if models and len(models) > 0:
        return True, 0, "Valid OpenAI key"
    return False, 0, "Invalid (no models)"

def _parse_openrouter(code, data):
    if code == 200:
        if isinstance(data, dict):
            credits = data.get("credits", 0)
            if credits:
                return True, float(credits), f"Credits: {credits}"
        return True, 0, "Valid OpenRouter key"
    elif code == 401:
        return False, 0, "Invalid OpenRouter key"
    else:
        return False, 0, f"HTTP {code}"

def _parse_deepseek(code, data):
    if code != 200 or not isinstance(data, dict) or not data.get("is_available"):
        return False, 0, "Invalid or expired"
    cny = sum(float(i.get("total_balance", 0)) for i in data.get("balance_infos", []) if i.get("currency") == "CNY")
    usd = sum(float(i.get("total_balance", 0)) for i in data.get("balance_infos", []) if i.get("currency") == "USD")
    total = cny + usd * 7.2
    info = f"💰 CNY: {cny:.2f}, USD: {usd:.2f}" if cny or usd else "Valid (no balance)"
    return True, total, info

def _parse_gemini(code, data):
    if code == 200 and isinstance(data, dict):
        models = data.get("models", [])
        if models and len(models) > 0:
            return True, 0, "Valid Gemini key"
    return False, 0, "Invalid"

def _parse_anthropic(code, data):
    if code == 200:
        return True, 0, "Valid Anthropic key"
    return False, 0, f"HTTP {code}"

def _parse_cohere(code, data):
    if code == 200 and isinstance(data, dict):
        models = data.get("models", [])
        if models and len(models) > 0:
            return True, 0, "Valid Cohere key"
    return False, 0, "Invalid"

def _parse_replicate(code, data):
    if code == 200:
        return True, 0, "Valid Replicate key"
    return False, 0, f"HTTP {code}"

def _parse_huggingface(code, data):
    if code == 200:
        return True, 0, "Valid HuggingFace key"
    return False, 0, f"HTTP {code}"

def _parse_mimo(code, data):
    if code == 200 and isinstance(data, dict):
        balance = float(data.get("balance", data.get("credit", 0)))
        info = f"💰 Balance: {balance}" if balance > 0 else "Valid (no balance)"
        return True, balance, info
    return False, 0, "Invalid"

VERIFIERS = {
    "OpenAI": {"url": "https://api.openai.com/v1/models", "headers": lambda k: {"Authorization": f"Bearer {k}"}, "method": "GET", "parse": _parse_openai},
    "OpenAI_Legacy": {"url": "https://api.openai.com/v1/models", "headers": lambda k: {"Authorization": f"Bearer {k}"}, "method": "GET", "parse": _parse_openai},
    "OpenRouter": {"url": "https://openrouter.ai/api/v1/auth/key", "headers": lambda k: {"Authorization": f"Bearer {k}"}, "method": "GET", "parse": _parse_openrouter},
    "DeepSeek": {"url": "https://api.deepseek.com/user/balance", "headers": lambda k: {"Authorization": f"Bearer {k}", "Accept": "application/json"}, "method": "GET", "parse": _parse_deepseek},
    "Gemini": {"url": lambda k: f"https://generativelanguage.googleapis.com/v1/models?key={k}", "headers": lambda k: {}, "method": "GET", "parse": _parse_gemini},
    "Anthropic": {"url": "https://api.anthropic.com/v1/messages", "headers": lambda k: {"x-api-key": k, "anthropic-version": "2023-06-01", "Content-Type": "application/json"}, "method": "POST", "body": lambda: json.dumps({"model": "claude-3-haiku-20240307", "max_tokens": 1, "messages": [{"role": "user", "content": "hi"}]}).encode(), "parse": _parse_anthropic},
    "Cohere": {"url": "https://api.cohere.ai/v1/models", "headers": lambda k: {"Authorization": f"Bearer {k}"}, "method": "GET", "parse": _parse_cohere},
    "Replicate": {"url": "https://api.replicate.com/v1/account", "headers": lambda k: {"Authorization": f"Bearer {k}"}, "method": "GET", "parse": _parse_replicate},
    "HuggingFace": {"url": "https://huggingface.co/api/whoami", "headers": lambda k: {"Authorization": f"Bearer {k}"}, "method": "GET", "parse": _parse_huggingface},
    "MiMo": {"url": "https://token-plan-cn.xiaomimimo.com/v1/models", "headers": lambda k: {"Authorization": f"Bearer {k}", "X-Plan-Type": "token-plan"}, "method": "GET", "parse": _parse_mimo},
}

# ========== GitHub 认证 (App优先，回退到PAT) ==========
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
        print(f"\n[!] Max runtime reached ({MAX_RUNTIME_SECONDS}s). Exiting.")
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

def save_final_results():
    with valid_lock:
        if found_valid_keys:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            with open(f"valid_keys_final_{timestamp}.txt", "w") as f:
                f.write(f"# Scan time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# Total valid keys: {len(found_valid_keys)}\n\n")
                for key, service, balance, info, source_url, _, _ in found_valid_keys:
                    f.write(f"{service} | {key} | {info} | {source_url}\n")
            print(f"\n💾 Saved {len(found_valid_keys)} keys to valid_keys_final_{timestamp}.txt")

def signal_handler(sig, frame):
    print("\n\n⚠️ Interrupted, saving results...")
    stop_event.set()
    time.sleep(2)
    save_final_results()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# ========== 回复模板 ==========
def build_reply(service, key, info, source_url, source_type):
    masked = key[:12] + "..." + key[-8:] if len(key) > 24 else key
    return f"""🔴 **API Key Leak Detected!**

@{source_type.split('_')[0]} Your API key has been exposed in this {source_type}.

**Service:** `{service}`
**Key preview:** `{masked}`
**Status:** {info}

⚠️ **Immediate Actions Required:**
1. Revoke this key immediately from your {service} dashboard
2. Generate a new key
3. Remove the exposed key from git history
4. Rotate any other secrets that may be compromised

📍 **Source:** {source_url}

---
{BOT_SIGNATURE}"""

# ========== 批量验证 ==========
def verify_batch(worker_id, batch):
    if not batch:
        return
    safe_print(f"[Worker-{worker_id}] Verifying batch: {len(batch)} keys")
    
    def verify_one(key_info):
        key, service, source_url, source_type = key_info
        verifier = VERIFIERS.get(service)
        if not verifier:
            return None
        try:
            check_timeout()
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
            if valid:
                return (key, service, balance, info, source_url, source_type, datetime.now())
        except:
            pass
        return None
    
    results = []
    with ThreadPoolExecutor(max_workers=VERIFY_WORKERS) as executor:
        futures = [executor.submit(verify_one, ki) for ki in batch]
        for future in as_completed(futures):
            try:
                result = future.result(timeout=15)
                if result:
                    results.append(result)
                    # 立即处理找到的 Key
                    key, service, balance, info, source_url, source_type, ts = result
                    with valid_lock:
                        found_valid_keys.append(result)
                    print(f"\n{'='*60}")
                    print(f"🎉 VALID KEY FOUND! [{service}]")
                    print(f"   Key: {key}")
                    print(f"   Source: {source_url[:80]}")
                    print(f"   Status: {info}")
                    print(f"{'='*60}\n")
                    with open("valid_keys_realtime.txt", "a") as f:
                        f.write(f"{ts.strftime('%Y-%m-%d %H:%M:%S')} | {service} | {key} | {info} | {source_url}\n")
            except:
                pass
    
    safe_print(f"[Worker-{worker_id}] Batch done: {len(results)} valid keys found")

def add_key_to_pending(worker_id, key, service, source_url, source_type):
    if worker_id not in batch_locks:
        batch_locks[worker_id] = Lock()
    with batch_locks[worker_id]:
        pending_batches[worker_id].append((key, service, source_url, source_type))
        pending_count[worker_id] += 1
        if pending_count[worker_id] >= BATCH_SIZE:
            batch = pending_batches[worker_id].copy()
            pending_batches[worker_id].clear()
            pending_count[worker_id] = 0
            executor = ThreadPoolExecutor(max_workers=1)
            executor.submit(verify_batch, worker_id, batch)
            executor.shutdown(wait=False)

def extract_and_queue(text, source_url, source_type, worker_id):
    for service, pattern in KEY_PATTERNS.items():
        for match in pattern.finditer(text):
            key = match.group(0)
            with valid_lock:
                if any(key == k for k, _, _, _, _, _, _ in found_valid_keys):
                    continue
            add_key_to_pending(worker_id, key, service, source_url, source_type)

def process_item(item, item_type, worker_id):
    if item_type == "issue":
        url = item.get("html_url", "")
        title = item.get("title", "")
        body = item.get("body", "") or ""
        full_text = title + "\n" + body
    else:
        url = item.get("html_url", "")
        message = item.get("commit", {}).get("message", "")
        full_text = message
    key_count = sum(len(pattern.findall(full_text)) for pattern in KEY_PATTERNS.values())
    if key_count > 50:
        return
    extract_and_queue(full_text, url, f"{item_type}_body", worker_id)

# ========== 搜索 Worker（放宽限制版） ==========
def search_worker(worker_id, search_type, start_page):
    safe_print(f"[Worker-{worker_id}] Starting {search_type} scan from page {start_page}")
    query = ISSUE_QUERY if search_type == "issue" else COMMIT_QUERY
    api_path = "issues" if search_type == "issue" else "commits"
    encoded = urllib.parse.quote(query)
    page = start_page
    items_processed = 0
    consecutive_empty = 0
    
    while not stop_event.is_set() and page <= MAX_PAGES:
        check_timeout()
        heartbeat()
        
        url = f"{GITHUB_API}/search/{api_path}?q={encoded}&sort=created&order=desc&per_page={PER_PAGE}&page={page}"
        try:
            code, data = _http_request(url, headers=_gh_headers(), timeout=REQUEST_TIMEOUT)
            
            if code == 403:
                safe_print(f"[Worker-{worker_id}] {search_type} page {page}: HTTP 403, waiting 60s...")
                time.sleep(60)
                continue
            
            if code != 200:
                safe_print(f"[Worker-{worker_id}] {search_type} page {page}: HTTP {code}, continuing")
                page += 1
                time.sleep(2)
                continue
            
            if not isinstance(data, dict):
                page += 1
                continue
            
            items = data.get("items", [])
            
            if not items:
                consecutive_empty += 1
                if consecutive_empty >= 5:
                    safe_print(f"[Worker-{worker_id}] {search_type} no more results (stopping)")
                    break
                page += 1
                time.sleep(1)
                continue
            
            consecutive_empty = 0
            
            safe_print(f"[Worker-{worker_id}] {search_type} page {page}: {len(items)} items (total: {items_processed + len(items)})")
            
            for item in items:
                if stop_event.is_set():
                    break
                process_item(item, search_type, worker_id)
                items_processed += 1
            
            page += 1
            time.sleep(0.5)
            
        except Exception as e:
            safe_print(f"[Worker-{worker_id}] Error on page {page}: {e}")
            page += 1
            time.sleep(5)
            continue
    
    with batch_locks.get(worker_id, Lock()):
        if pending_count.get(worker_id, 0) > 0:
            batch = pending_batches.get(worker_id, []).copy()
            if batch:
                safe_print(f"[Worker-{worker_id}] Processing remaining {len(batch)} keys")
                verify_batch(worker_id, batch)
    
    safe_print(f"[Worker-{worker_id}] Finished, processed {items_processed} items")

# ========== 主函数 ==========
def main():
    print("=" * 70)
    print("API Key Leak Scanner - Stable Version")
    print(f"Supports: OpenAI (sk-proj-), OpenRouter, DeepSeek, Gemini, Anthropic, Cohere, Replicate, HuggingFace, MiMo")
    print(f"Batch size: {BATCH_SIZE} | Max pages: {MAX_PAGES} | Max runtime: {MAX_RUNTIME_SECONDS}s (1.5h)")
    print("=" * 70)
    
    g = get_github_client()
    if not g:
        print("❌ Failed to initialize GitHub client")
        return
    
    with ThreadPoolExecutor(max_workers=SEARCH_WORKERS) as executor:
        futures = [
            executor.submit(search_worker, 1, "issue", 1),
            executor.submit(search_worker, 2, "issue", 6),
            executor.submit(search_worker, 3, "commit", 1)
        ]
        for future in as_completed(futures):
            try:
                future.result()
            except:
                pass
    
    save_final_results()
    print(f"\n✅ Scan completed. Found {len(found_valid_keys)} valid keys.")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        save_final_results()
        sys.exit(1)