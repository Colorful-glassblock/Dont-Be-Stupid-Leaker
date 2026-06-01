#!/usr/bin/env python3
"""
API Key Leak Scanner - Full Content Extraction with Cache Management
- Fetches complete content for all source types (Code/Issues/PRs/Commits/Env files)
- Creates issues without labels if label creation fails
- Random browser User-Agent for all HTTP requests
- Auto-verify on batch size OR 60s timeout
- LRU cache with size and TTL limits to prevent OOM
- Replies to Issues and PRs directly in original repository
- Enhanced deduplication (key + source_url + combo)
- Limited backoff (max 60 seconds)
- Dedicated .env file scanner thread
"""

import os
import re
import sys
import json
import ssl
import jwt
import time
import signal
import random
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
MAX_RUNTIME_SECONDS = 29.5 * 60
HEARTBEAT_INTERVAL = 60
REQUEST_TIMEOUT = 15
PER_PAGE = 30
SEARCH_WORKERS = 5          # 增加到5个worker
VERIFY_WORKERS = 30
BATCH_SIZE = 30
BATCH_TIMEOUT = 60
MAX_BACKOFF = 60

# 缓存配置
MAX_CACHE_SIZE = 200
MAX_CACHE_AGE = 3600

APP_ID = os.environ.get("APP_ID")
PRIVATE_KEY = os.environ.get("PRIVATE_KEY")
INSTALLATION_ID = os.environ.get("INSTALLATION_ID")
PAT_TOKEN = os.environ.get("PAT_TOKEN")

REPO_NAME = os.environ.get("GITHUB_REPOSITORY", "Colorful-glassblock/Dont-Be-Stupid-Leaker")
BOT_NAME = "LLMApiCheckBot"
BOT_SIGNATURE = f"*This message was sent by {BOT_NAME} - Repository: {REPO_NAME}*"

GITHUB_API = "https://api.github.com"

# 搜索条件
ISSUE_QUERY = '"your key leak" OR "sk-" OR "sk-proj-" OR "xai-" OR "AIza" OR "sk-ant-api"'
COMMIT_QUERY = 'sk- OR sk-proj- OR xai- OR AIza OR sk-ant-api'
CODE_QUERY = 'sk- OR sk-proj- OR xai- OR AIza OR sk-ant-api'
ENV_QUERY = 'filename:.env OR filename:.env.example OR filename:.env.local OR filename:.env.production OR filename:.env.staging'

STATE_FILE = "replied_state.json"

start_time = time.time()
last_heartbeat = start_time
stop_event = Event()
found_valid_keys: List[Tuple] = []
valid_lock = Lock()

# pending 批次管理
pending_batches: Dict[int, List[Tuple]] = defaultdict(list)
pending_batch_times: Dict[int, float] = {}
batch_locks: Dict[int, Lock] = {}
pending_count: Dict[int, int] = defaultdict(int)

# 增强去重
processed_keys: set = set()
processed_sources: set = set()
processed_key_source: set = set()
processed_lock = Lock()

# 带时间戳的缓存
file_content_cache: Dict[str, Tuple[str, float]] = {}
issue_content_cache: Dict[str, Tuple[str, float]] = {}
pr_content_cache: Dict[str, Tuple[str, float]] = {}
commit_content_cache: Dict[str, Tuple[str, float]] = {}
env_content_cache: Dict[str, Tuple[str, float]] = {}
cache_lock = Lock()

# 随机 User-Agent 池
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
]

def random_ua():
    return random.choice(USER_AGENTS)

# 缓存管理
def clean_old_cache(cache_dict, max_size=MAX_CACHE_SIZE, max_age=MAX_CACHE_AGE):
    now = time.time()
    expired = [k for k, (_, ts) in cache_dict.items() if now - ts > max_age]
    for k in expired:
        del cache_dict[k]
    if len(cache_dict) > max_size:
        sorted_items = sorted(cache_dict.items(), key=lambda x: x[1][1])
        for k, _ in sorted_items[:len(cache_dict) - max_size]:
            del cache_dict[k]
    return len(cache_dict)

def get_cached(cache_dict, key):
    with cache_lock:
        if key in cache_dict:
            content, timestamp = cache_dict[key]
            if time.time() - timestamp < MAX_CACHE_AGE:
                return content
            else:
                del cache_dict[key]
    return None

def set_cached(cache_dict, key, content):
    with cache_lock:
        cache_dict[key] = (content, time.time())
        if len(cache_dict) > MAX_CACHE_SIZE + 50:
            clean_old_cache(cache_dict)

def print_cache_stats():
    with cache_lock:
        file_count = len(file_content_cache)
        issue_count = len(issue_content_cache)
        pr_count = len(pr_content_cache)
        commit_count = len(commit_content_cache)
        env_count = len(env_content_cache)
        total = file_count + issue_count + pr_count + commit_count + env_count
        print(f"📊 Cache: files={file_count}, issues={issue_count}, PRs={pr_count}, commits={commit_count}, env={env_count}, total={total}")

# Key 正则
KEY_PATTERNS = {
    "OpenAI": re.compile(r"sk-proj-[a-zA-Z0-9_\-]{50,}"),
    "OpenAI_Legacy": re.compile(r"sk-[a-zA-Z0-9]{32,}"),
    "OpenRouter": re.compile(r"sk-or-v1-[a-zA-Z0-9]{50,}"),
    "XAI": re.compile(r"xai-[a-zA-Z0-9]{32,}"),
    "DeepSeek": re.compile(r"sk-[a-zA-Z0-9]{32,}"),
    "Gemini": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "Anthropic": re.compile(r"sk-ant-api[0-9A-Za-z\-_]{40,}"),
    "Replicate": re.compile(r"r8_[a-zA-Z0-9]{32,}"),
    "HuggingFace": re.compile(r"hf_[a-zA-Z0-9]{30,}"),
    "MiMo": re.compile(r"tp-[a-zA-Z0-9]{10,}"),
    "MiniMax": re.compile(r"sk-api-[a-zA-Z0-9]{100,}"),
}

# 验证函数
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
    if code == 429:
        return True, 0, "Rate limited (key may be valid)"
    return False, 0, f"HTTP {code}"

def _parse_openrouter(code, data):
    if code == 200:
        credits = 0
        if isinstance(data, dict):
            credits = data.get("credits", 0)
        info = f"💰 Credits: {credits}" if credits > 0 else "Valid (no credits)"
        return True, float(credits), info
    return False, 0, f"HTTP {code}"

def _parse_xai(code, data):
    if code == 200:
        return True, 0, "Valid"
    if code == 401:
        return False, 0, "Invalid"
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

def _parse_minimax(code, data):
    if code == 200:
        return True, 0, "Valid"
    if code == 401:
        return False, 0, "Invalid"
    return False, 0, f"HTTP {code}"

VERIFIERS = {
    "OpenAI": {"url": "https://api.openai.com/v1/models", "headers": lambda k: {"Authorization": f"Bearer {k}"}, "method": "GET", "parse": _parse_openai},
    "OpenAI_Legacy": {"url": "https://api.openai.com/v1/models", "headers": lambda k: {"Authorization": f"Bearer {k}"}, "method": "GET", "parse": _parse_openai},
    "OpenRouter": {"url": "https://openrouter.ai/api/v1/auth/key", "headers": lambda k: {"Authorization": f"Bearer {k}"}, "method": "GET", "parse": _parse_openrouter},
    "XAI": {"url": "https://api.x.ai/v1/models", "headers": lambda k: {"Authorization": f"Bearer {k}"}, "method": "GET", "parse": _parse_xai},
    "DeepSeek": {"url": "https://api.deepseek.com/user/balance", "headers": lambda k: {"Authorization": f"Bearer {k}", "Accept": "application/json"}, "method": "GET", "parse": _parse_deepseek},
    "Gemini": {"url": lambda k: f"https://generativelanguage.googleapis.com/v1/models?key={k}", "headers": lambda k: {}, "method": "GET", "parse": _parse_gemini},
    "Anthropic": {"url": "https://api.anthropic.com/v1/messages", "headers": lambda k: {"x-api-key": k, "anthropic-version": "2023-06-01", "Content-Type": "application/json"}, "method": "POST", "body": lambda: json.dumps({"model": "claude-3-haiku-20240307", "max_tokens": 1, "messages": [{"role": "user", "content": "hi"}]}).encode(), "parse": _parse_anthropic},
    "Replicate": {"url": "https://api.replicate.com/v1/account", "headers": lambda k: {"Authorization": f"Bearer {k}"}, "method": "GET", "parse": _parse_replicate},
    "HuggingFace": {"url": "https://huggingface.co/api/whoami", "headers": lambda k: {"Authorization": f"Bearer {k}"}, "method": "GET", "parse": _parse_huggingface},
    "MiMo": {"url": "https://token-plan-cn.xiaomimimo.com/v1/models", "headers": lambda k: {"Authorization": f"Bearer {k}", "X-Plan-Type": "token-plan"}, "method": "GET", "parse": _parse_mimo},
    "MiniMax": {"url": "https://api.minimax.io/v1/models", "headers": lambda k: {"Authorization": f"Bearer {k}"}, "method": "GET", "parse": _parse_minimax},
}

# GitHub 认证
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
    return Github(auth=auth, retry=0)

# 工具函数
def _gh_headers():
    headers = {"Accept": "application/vnd.github+json", "User-Agent": random_ua()}
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

def safe_sleep(seconds):
    actual_sleep = min(seconds, MAX_BACKOFF)
    elapsed = 0
    while elapsed < actual_sleep and not stop_event.is_set():
        check_timeout()
        time.sleep(min(0.5, actual_sleep - elapsed))
        elapsed += 0.5

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
        print_cache_stats()
        last_heartbeat = now

def signal_handler(sig, frame):
    print("\n\n⚠️ Interrupted, saving results...")
    stop_event.set()
    safe_sleep(2)
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

# 回复模板
def build_reply(author, service, key, info, source_url, source_type, balance=None, is_fallback=False):
    masked = key[:12] + "..." + key[-8:] if len(key) > 24 else key
    balance_text = f" (Balance: {balance})" if balance is not None and balance > 0 else ""
    
    install_note = ""
    if is_fallback:
        install_note = f"""
---
📌 **To receive notifications directly in your repository, install this bot:**
https://github.com/apps/llmapicheckbot2
"""
    
    return f"""🔴 **API Key Leak Detected!**

@{author} Your API key has been exposed in this {source_type}{balance_text}.

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
{BOT_SIGNATURE}{install_note}"""

# 获取完整内容函数
def get_full_file_content(source_url):
    cache_key = source_url.split("/blob/")[0] + source_url.split("/blob/")[1] if "/blob/" in source_url else source_url
    
    cached = get_cached(file_content_cache, cache_key)
    if cached is not None:
        return cached
    
    raw_url = source_url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
    try:
        headers = {"User-Agent": random_ua()}
        resp = requests.get(raw_url, headers=headers, timeout=10)
        if resp.status_code == 200:
            content = resp.text
            set_cached(file_content_cache, cache_key, content)
            print(f"    📄 Fetched full file: {source_url[:80]}...")
            return content
    except Exception as e:
        print(f"    ⚠️ Failed to fetch file: {e}")
    return None

def get_full_env_content(source_url):
    """专门获取 .env 文件内容"""
    cache_key = source_url
    
    cached = get_cached(env_content_cache, cache_key)
    if cached is not None:
        return cached
    
    raw_url = source_url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
    try:
        headers = {"User-Agent": random_ua()}
        resp = requests.get(raw_url, headers=headers, timeout=10)
        if resp.status_code == 200:
            content = resp.text
            set_cached(env_content_cache, cache_key, content)
            print(f"    📄 Fetched .env file: {source_url[:80]}...")
            return content
    except Exception as e:
        print(f"    ⚠️ Failed to fetch .env file: {e}")
    return None

def get_full_issue_content(g, source_url):
    cached = get_cached(issue_content_cache, source_url)
    if cached is not None:
        return cached
    
    try:
        parts = source_url.replace("https://github.com/", "").split("/issues/")
        if len(parts) != 2:
            return None
        repo_path = parts[0]
        issue_num = int(parts[1])
        
        repo = g.get_repo(repo_path)
        issue = repo.get_issue(number=issue_num)
        
        content = f"# {issue.title}\n\n{issue.body or ''}\n\n"
        
        comments = issue.get_comments()
        for i, comment in enumerate(comments):
            content += f"\n## Comment by {comment.user.login}\n{comment.body or ''}\n"
        
        set_cached(issue_content_cache, source_url, content)
        print(f"    📄 Fetched full issue #{issue_num} with {comments.totalCount} comments")
        return content
    except Exception as e:
        print(f"    ⚠️ Failed to fetch issue: {e}")
        return None

def get_full_pr_content(g, source_url):
    cached = get_cached(pr_content_cache, source_url)
    if cached is not None:
        return cached
    
    try:
        parts = source_url.replace("https://github.com/", "").split("/pull/")
        if len(parts) != 2:
            return None
        repo_path = parts[0]
        pr_num = int(parts[1])
        
        repo = g.get_repo(repo_path)
        pr = repo.get_pull(number=pr_num)
        
        content = f"# {pr.title}\n\n{pr.body or ''}\n\n"
        
        comments = pr.get_issue_comments()
        for comment in comments:
            content += f"\n## Comment by {comment.user.login}\n{comment.body or ''}\n"
        
        review_comments = pr.get_review_comments()
        for rc in review_comments:
            content += f"\n## Review Comment by {rc.user.login}\n{rc.body or ''}\n"
        
        diff_url = f"https://patch-diff.githubusercontent.com/raw/{repo_path}/pull/{pr_num}.diff"
        headers = {"User-Agent": random_ua()}
        try:
            resp = requests.get(diff_url, headers=headers, timeout=10)
            if resp.status_code == 200:
                content += f"\n## Diff\n{resp.text}\n"
        except:
            pass
        
        set_cached(pr_content_cache, source_url, content)
        print(f"    📄 Fetched full PR #{pr_num}")
        return content
    except Exception as e:
        print(f"    ⚠️ Failed to fetch PR: {e}")
        return None

def get_full_commit_content(g, source_url):
    cached = get_cached(commit_content_cache, source_url)
    if cached is not None:
        return cached
    
    try:
        parts = source_url.replace("https://github.com/", "").split("/commit/")
        if len(parts) != 2:
            return None
        repo_path = parts[0]
        commit_sha = parts[1]
        
        repo = g.get_repo(repo_path)
        commit = repo.get_commit(sha=commit_sha)
        
        content = f"# {commit.commit.message}\n\n"
        
        files = commit.files
        for f in files:
            content += f"\n## {f.filename}\n"
            if f.patch:
                content += f"{f.patch}\n"
        
        set_cached(commit_content_cache, source_url, content)
        print(f"    📄 Fetched full commit {commit_sha[:8]}")
        return content
    except Exception as e:
        print(f"    ⚠️ Failed to fetch commit: {e}")
        return None

# 去重函数
def is_duplicate(key, source_url):
    with processed_lock:
        if key in processed_keys:
            print(f"    ⏭️ Duplicate key (already processed globally): {key[:20]}...")
            return True
        if source_url in processed_sources:
            print(f"    ⏭️ Duplicate source (already processed): {source_url[:60]}...")
            return True
        combo = f"{key}|{source_url}"
        if combo in processed_key_source:
            print(f"    ⏭️ Duplicate key-source combo")
            return True
    return False

def mark_processed(key, source_url):
    with processed_lock:
        processed_keys.add(key)
        processed_sources.add(source_url)
        processed_key_source.add(f"{key}|{source_url}")

# 回复函数
def reply_to_original_issue_or_pr(g, source_url, author, service, key, info, balance):
    try:
        if "/issues/" in source_url:
            parts = source_url.replace("https://github.com/", "").split("/issues/")
            is_pr = False
        elif "/pull/" in source_url:
            parts = source_url.replace("https://github.com/", "").split("/pull/")
            is_pr = True
        else:
            return False
        
        if len(parts) != 2:
            return False
        
        repo_path = parts[0]
        item_num = int(parts[1])
        repo = g.get_repo(repo_path)
        
        if is_pr:
            item = repo.get_pull(number=item_num)
            comment_func = item.create_issue_comment
            item_type = "PR"
        else:
            item = repo.get_issue(number=item_num)
            comment_func = item.create_comment
            item_type = "Issue"
        
        bot_login = g.get_user().login
        if is_pr:
            comments = item.get_issue_comments()
        else:
            comments = item.get_comments()
        
        for comment in comments:
            if comment.user.login == bot_login and "API Key Leak Detected" in comment.body:
                print(f"    ⏭️ Already replied to {item_type} #{item_num} in {repo_path}")
                return True
        
        message = build_reply(author, service, key, info, source_url, item_type.lower(), balance, is_fallback=False)
        comment_func(message)
        print(f"    📝 Replied to {item_type} #{item_num} in {repo_path}")
        return True
        
    except Exception as e:
        print(f"    ❌ Failed to reply: {e}")
        return False

def create_issue_in_original_repo(g, source_url, author, service, key, info, balance):
    if "/blob/" not in source_url:
        return False
    try:
        parts = source_url.replace("https://github.com/", "").split("/blob/")
        if len(parts) != 2:
            return False
        repo_path = parts[0]
        file_path = parts[1]
        repo = g.get_repo(repo_path)

        already_exists = False
        try:
            issues = repo.get_issues(state="all")
            if issues is not None:
                for issue in issues:
                    if file_path in issue.title or source_url in issue.body:
                        already_exists = True
                        print(f"    ⏭️ Issue already exists for {file_path} in {repo_path}")
                        break
        except Exception as e:
            print(f"    ⚠️ Could not check existing issues: {e}")

        if already_exists:
            return True

        message = build_reply(author, service, key, info, source_url, "code file", balance, is_fallback=False)
        issue_title = f"🔴 API Key Leak Detected in {file_path}"
        issue_body = message + f"\n\n**File:** `{file_path}`"
        
        try:
            new_issue = repo.create_issue(title=issue_title, body=issue_body, labels=["security"])
            print(f"    📝 Created issue in {repo_path} for file {file_path} (with labels)")
            return True
        except Exception as e:
            if "labels" in str(e).lower() or "permission" in str(e).lower():
                print(f"    ⚠️ Cannot create labels in {repo_path}, retrying without labels...")
                try:
                    new_issue = repo.create_issue(title=issue_title, body=issue_body)
                    print(f"    📝 Created issue in {repo_path} for file {file_path} (without labels)")
                    return True
                except Exception as e2:
                    print(f"    ❌ Failed to create issue even without labels: {e2}")
                    return False
            else:
                print(f"    ❌ Failed to create issue: {e}")
                return False
    except Exception as e:
        print(f"    ❌ Failed to create issue in original repo: {e}")
        return False

def create_issue_in_my_repo(g, key, service, info, source_url, source_type, author, balance, is_fallback=False):
    message = build_reply(author, service, key, info, source_url, source_type, balance, is_fallback=is_fallback)

    try:
        my_repo = g.get_repo(REPO_NAME)

        already_exists = False
        existing_issue_num = None
        try:
            issues = my_repo.get_issues(state="all")
            if issues is not None:
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

        short_url = source_url.replace("https://github.com/", "")
        if len(short_url) > 60:
            short_url = short_url[:57] + "..."

        if "/pull/" in source_url:
            display_type = "Pull Request"
        elif "/issues/" in source_url:
            display_type = "Issue"
        elif "/commit/" in source_url:
            display_type = "Commit"
        else:
            display_type = source_type

        fallback_note = " (fallback because original notification failed)" if is_fallback else ""
        issue_title = f"🔴 {service} Key Leak in {display_type}: {short_url}"
        issue_body = f"""## API Key Leak Detected{fallback_note}

| Field | Value |
|-------|-------|
| **Source Type** | {display_type} |
| **Source URL** | {source_url} |
| **Service** | `{service}` |
| **Key Preview** | `{key[:20]}...` |
| **Status** | {info} |
| **Author** | @{author} |
| **Balance** | {balance if balance else 'N/A'} |

---

### Details

{message}

---

*Auto-generated by {BOT_NAME}*
"""
        try:
            new_issue = my_repo.create_issue(title=issue_title, body=issue_body, labels=["security", "leak"])
            print(f"    📝 Created issue #{new_issue.number} in {REPO_NAME} (with labels)")
        except Exception as e:
            if "labels" in str(e).lower() or "permission" in str(e).lower():
                print(f"    ⚠️ Cannot create labels in {REPO_NAME}, retrying without labels...")
                new_issue = my_repo.create_issue(title=issue_title, body=issue_body)
                print(f"    📝 Created issue #{new_issue.number} in {REPO_NAME} (without labels)")
            else:
                raise
    except Exception as e:
        print(f"    ❌ Failed to create issue in my repo: {e}")

def handle_leak(g, key, service, info, source_url, source_type, author, balance):
    if is_duplicate(key, source_url):
        print(f"    ⏭️ Skipping duplicate in handle_leak")
        return
    
    mark_processed(key, source_url)
    
    if "/issues/" in source_url or "/pull/" in source_url:
        original_success = reply_to_original_issue_or_pr(g, source_url, author, service, key, info, balance)
        create_issue_in_my_repo(g, key, service, info, source_url, source_type, author, balance, is_fallback=not original_success)
    
    elif "/blob/" in source_url:
        original_success = create_issue_in_original_repo(g, source_url, author, service, key, info, balance)
        create_issue_in_my_repo(g, key, service, info, source_url, source_type, author, balance, is_fallback=not original_success)
    
    elif "/commit/" in source_url:
        create_issue_in_my_repo(g, key, service, info, source_url, source_type, author, balance, is_fallback=False)
        print(f"    ℹ️ Commit source, only created issue in fallback repo")
    
    else:
        create_issue_in_my_repo(g, key, service, info, source_url, source_type, author, balance, is_fallback=False)
        print(f"    ⚠️ Unknown source type, only created issue in fallback repo")

def verify_batch(worker_id, batch, g):
    if not batch:
        return
    
    is_timeout_trigger = len(batch) < BATCH_SIZE
    if is_timeout_trigger:
        safe_print(f"\n[Worker-{worker_id}] ⏰ Verifying timeout batch: {len(batch)} keys (triggered by {BATCH_TIMEOUT}s timeout)")
    else:
        safe_print(f"\n[Worker-{worker_id}] 🔍 Verifying full batch: {len(batch)} keys")

    def verify_one(key_info):
        key, service, source_url, source_type, author = key_info
        verifier = VERIFIERS.get(service)
        if not verifier:
            return (key, service, False, 0, "Unsupported", source_url, source_type, author)
        try:
            url = verifier["url"](key) if callable(verifier["url"]) else verifier["url"]
            headers = verifier["headers"](key)
            headers["User-Agent"] = random_ua()
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
        valid_count = 0
        invalid_count = 0
        for future in as_completed(futures):
            try:
                key, service, valid, balance, info, source_url, source_type, author = future.result(timeout=15)
                if valid:
                    valid_count += 1
                    print(f"  ✅ [{service}] {key[:25]}... -> {info}")
                    print(f"     📍 Source: {source_url}")

                    with valid_lock:
                        found_valid_keys.append((key, service, balance, info, source_url, source_type, datetime.now()))
                    with open("valid_keys_realtime.txt", "a") as f:
                        f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | {service} | {key} | {info} | {source_url}\n")

                    handle_leak(g, key, service, info, source_url, source_type, author, balance)
                else:
                    invalid_count += 1
                    print(f"  ❌ [{service}] {key[:25]}... -> {info}")
                    print(f"     📍 Source: {source_url}")
            except Exception as e:
                invalid_count += 1
                print(f"  ❌ Exception: {e}")
        
        if is_timeout_trigger:
            safe_print(f"[Worker-{worker_id}] 📊 Timeout batch completed: {valid_count} valid, {invalid_count} invalid (total {len(batch)})")
        else:
            safe_print(f"[Worker-{worker_id}] 📊 Batch completed: {valid_count}/{len(batch)} valid keys")

def check_pending_timeout(worker_id, g):
    with batch_locks.get(worker_id, Lock()):
        if pending_count.get(worker_id, 0) > 0:
            elapsed = time.time() - pending_batch_times.get(worker_id, start_time)
            if elapsed >= BATCH_TIMEOUT:
                batch = pending_batches[worker_id].copy()
                pending_batches[worker_id].clear()
                count = pending_count[worker_id]
                pending_count[worker_id] = 0
                if worker_id in pending_batch_times:
                    del pending_batch_times[worker_id]
                
                safe_print(f"[Worker-{worker_id}] ⏰ Triggering verification by timeout ({elapsed:.0f}s, {count} keys)")
                executor = ThreadPoolExecutor(max_workers=1)
                executor.submit(verify_batch, worker_id, batch, g)
                executor.shutdown(wait=False)
                return True
    return False

def add_key_to_pending(worker_id, key, service, source_url, source_type, author, g):
    if is_duplicate(key, source_url):
        return
    
    mark_processed(key, source_url)
    
    if worker_id not in batch_locks:
        batch_locks[worker_id] = Lock()
    with batch_locks[worker_id]:
        if pending_count[worker_id] == 0:
            pending_batch_times[worker_id] = time.time()
        
        pending_batches[worker_id].append((key, service, source_url, source_type, author))
        pending_count[worker_id] += 1
        
        if pending_count[worker_id] >= BATCH_SIZE:
            batch = pending_batches[worker_id].copy()
            pending_batches[worker_id].clear()
            count = pending_count[worker_id]
            pending_count[worker_id] = 0
            if worker_id in pending_batch_times:
                del pending_batch_times[worker_id]
            
            safe_print(f"[Worker-{worker_id}] 📦 Triggering verification by batch size ({count} keys)")
            executor = ThreadPoolExecutor(max_workers=1)
            executor.submit(verify_batch, worker_id, batch, g)
            executor.shutdown(wait=False)

def extract_and_queue(text, source_url, source_type, worker_id, author, g):
    full_text = text
    
    if source_type == "code" and "/blob/" in source_url:
        file_content = get_full_file_content(source_url)
        if file_content:
            full_text = file_content
            print(f"    📄 Using full file content for code (all keys from this file)")
    
    elif source_type == "env" and "/blob/" in source_url:
        env_content = get_full_env_content(source_url)
        if env_content:
            full_text = env_content
            print(f"    📄 Using full .env file content (all keys from this file)")
    
    elif source_type == "issue" and "/issues/" in source_url:
        issue_content = get_full_issue_content(g, source_url)
        if issue_content:
            full_text = issue_content
            print(f"    📄 Using full issue content (title + body + comments)")
    
    elif "/pull/" in source_url:
        pr_content = get_full_pr_content(g, source_url)
        if pr_content:
            full_text = pr_content
            print(f"    📄 Using full PR content (description + comments + diff)")
    
    elif source_type == "commit" and "/commit/" in source_url:
        commit_content = get_full_commit_content(g, source_url)
        if commit_content:
            full_text = commit_content
            print(f"    📄 Using full commit diff")
    
    for service, pattern in KEY_PATTERNS.items():
        for match in pattern.finditer(full_text):
            key = match.group(0)
            print(f"  🔑 Found {service} key in {source_type}: {source_url[:80]}...")
            add_key_to_pending(worker_id, key, service, source_url, source_type, author, g)
    
    check_pending_timeout(worker_id, g)

# ========== 搜索 Workers ==========
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
                safe_sleep(60)
                continue

            if code != 200:
                safe_print(f"[Worker-{worker_id}] CODE page {page}: HTTP {code}, continuing")
                page += 1
                safe_sleep(2)
                continue

            items = data.get("items", []) if isinstance(data, dict) else []

            if not items:
                consecutive_empty += 1
                if consecutive_empty >= 3:
                    safe_print(f"[Worker-{worker_id}] CODE: No more results after {page} pages, stopping")
                    break
                page += 1
                safe_sleep(1)
                continue

            consecutive_empty = 0

            safe_print(f"[Worker-{worker_id}] 📄 CODE page {page}: {len(items)} items (total: {items_processed + len(items)})")

            for item in items:
                if stop_event.is_set():
                    break
                html_url = item.get("html_url", "")
                author = item.get("repository", {}).get("owner", {}).get("login", "unknown")
                
                extract_and_queue("", html_url, "code", worker_id, author, g)
                items_processed += 1

            page += 1
            safe_sleep(0.5)
        except Exception as e:
            safe_print(f"[Worker-{worker_id}] CODE error: {e}")
            page += 1
            safe_sleep(5)
            continue

    safe_print(f"[Worker-{worker_id}] CODE scan finished, processed {items_processed} items")

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
                safe_sleep(60)
                continue

            if code != 200:
                safe_print(f"[Worker-{worker_id}] ISSUE page {page}: HTTP {code}, continuing")
                page += 1
                safe_sleep(2)
                continue

            items = data.get("items", []) if isinstance(data, dict) else []

            if not items:
                consecutive_empty += 1
                if consecutive_empty >= 3:
                    safe_print(f"[Worker-{worker_id}] ISSUE: No more results after {page} pages, stopping")
                    break
                page += 1
                safe_sleep(1)
                continue

            consecutive_empty = 0

            safe_print(f"[Worker-{worker_id}] 📄 ISSUE page {page}: {len(items)} items (total: {items_processed + len(items)})")

            for item in items:
                if stop_event.is_set():
                    break
                html_url = item.get("html_url", "")
                author = item.get("user", {}).get("login", "unknown")
                
                extract_and_queue("", html_url, "issue", worker_id, author, g)
                items_processed += 1

            page += 1
            safe_sleep(0.5)
        except Exception as e:
            safe_print(f"[Worker-{worker_id}] ISSUE error: {e}")
            page += 1
            safe_sleep(5)
            continue

    safe_print(f("[Worker-{worker_id}] ISSUE scan finished, processed {items_processed} items")

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
                safe_sleep(60)
                continue

            if code != 200:
                safe_print(f"[Worker-{worker_id}] COMMIT page {page}: HTTP {code}, continuing")
                page += 1
                safe_sleep(2)
                continue

            items = data.get("items", []) if isinstance(data, dict) else []

            if not items:
                consecutive_empty += 1
                if consecutive_empty >= 3:
                    safe_print(f"[Worker-{worker_id}] COMMIT: No more results after {page} pages, stopping")
                    break
                page += 1
                safe_sleep(1)
                continue

            consecutive_empty = 0

            safe_print(f"[Worker-{worker_id}] 📄 COMMIT page {page}: {len(items)} items (total: {items_processed + len(items)})")

            for item in items:
                if stop_event.is_set():
                    break
                html_url = item.get("html_url", "")
                author = item.get("author", {}).get("login", "unknown") if item.get("author") else "unknown"
                
                extract_and_queue("", html_url, "commit", worker_id, author, g)
                items_processed += 1

            page += 1
            safe_sleep(0.5)
        except Exception as e:
            safe_print(f"[Worker-{worker_id}] COMMIT error: {e}")
            page += 1
            safe_sleep(5)
            continue

    safe_print(f"[Worker-{worker_id}] COMMIT scan finished, processed {items_processed} items")

# ========== .env 专用搜索线程 ==========
def search_env_worker(worker_id, start_page, g):
    safe_print(f"\n[Worker-{worker_id}] 🚀 Starting ENV file scan (page {start_page})")
    page = start_page
    items_processed = 0
    consecutive_empty = 0

    while not stop_event.is_set():
        check_timeout()
        heartbeat()

        url = f"{GITHUB_API}/search/code?q={urllib.parse.quote(ENV_QUERY)}&sort=indexed&order=desc&per_page={PER_PAGE}&page={page}"
        try:
            code, data = _http_request(url, headers=_gh_headers(), timeout=REQUEST_TIMEOUT)

            if code == 403:
                safe_print(f"[Worker-{worker_id}] ENV page {page}: HTTP 403, waiting 60s...")
                safe_sleep(60)
                continue

            if code != 200:
                safe_print(f"[Worker-{worker_id}] ENV page {page}: HTTP {code}, continuing")
                page += 1
                safe_sleep(2)
                continue

            items = data.get("items", []) if isinstance(data, dict) else []

            if not items:
                consecutive_empty += 1
                if consecutive_empty >= 3:
                    safe_print(f"[Worker-{worker_id}] ENV: No more results after {page} pages, stopping")
                    break
                page += 1
                safe_sleep(1)
                continue

            consecutive_empty = 0

            safe_print(f"[Worker-{worker_id}] 📄 ENV page {page}: {len(items)} items (total: {items_processed + len(items)})")

            for item in items:
                if stop_event.is_set():
                    break
                html_url = item.get("html_url", "")
                author = item.get("repository", {}).get("owner", {}).get("login", "unknown")
                
                extract_and_queue("", html_url, "env", worker_id, author, g)
                items_processed += 1

            page += 1
            safe_sleep(0.5)
        except Exception as e:
            safe_print(f"[Worker-{worker_id}] ENV error: {e}")
            page += 1
            safe_sleep(5)
            continue

    safe_print(f"[Worker-{worker_id}] ENV scan finished, processed {items_processed} files")

def main():
    print("=" * 70)
    print("🤖 API Key Leak Scanner - Full Content Extraction with Enhanced Deduplication")
    print(f"📁 Fallback repo: {REPO_NAME}")
    print(f"⏱️  Max runtime: {MAX_RUNTIME_SECONDS}s (29.5 minutes)")
    print(f"📦 Batch size: {BATCH_SIZE} keys OR {BATCH_TIMEOUT}s timeout")
    print(f"💾 Cache: max {MAX_CACHE_SIZE} items, TTL {MAX_CACHE_AGE}s")
    print(f"⏲️  Max backoff: {MAX_BACKOFF}s")
    print("📊 Scanning: CODE + ISSUES + COMMITS + ENV (infinite pages)")
    print("📊 Feature: Full content extraction for all sources (no key left behind)")
    print("📊 Notification: Issues/PRs get direct replies; Code files get issues; Commits logged only")
    print("📊 Deduplication: Key + Source URL + Combo")
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
            executor.submit(search_env_worker, 5, 1, g),
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
        save_final_results()
        sys.exit(1)