#!/usr/bin/env python3
"""
API Key Leak Scanner - Production Ready v3.1.8
- Fixed NameError: github_session now initialized at module level
- Graceful shutdown guards against uninitialized github_session
- Retained all v3.1.7 features (Gemini 403 invalid, issue dedup, etc.)
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
import urllib.parse
import urllib.request
import math
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from threading import Lock, Event, RLock, local
from collections import defaultdict, Counter, OrderedDict
from typing import Optional, List, Tuple, Dict, Any, Set
from dataclasses import dataclass, field
from contextlib import closing

import requests
from github import Github, Auth
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ========== Configuration ==========
MAX_RUNTIME_SECONDS = 50 * 60
HEARTBEAT_INTERVAL = 60
REQUEST_TIMEOUT = 15
PER_PAGE = 30
SEARCH_WORKERS = 4
VERIFY_WORKERS = 20
BATCH_SIZE = 30
BATCH_TIMEOUT = 60
DEEP_SCAN_MAX_FILES = 200
DEEP_SCAN_WORKER_ID = 99
MAX_FILE_SIZE_BYTES = 500 * 1024
MAX_COMMIT_DIFF_BYTES = 2 * 1024 * 1024
MAX_COMMENTS_PER_ISSUE = 50
MAX_CACHE_SIZE = 500
MAX_CACHE_AGE = 3600
FAKE_KEY_ENTROPY_THRESHOLD = 2.5
MAX_CONSECUTIVE_ERRORS = 5
MAX_PAGE_RETRIES = 5
MAX_PROCESSED_EXACT = 200_000
BLOOM_FILTER_SIZE = 1_000_000
BLOOM_FILTER_HASHES = 5

APP_ID = os.environ.get("APP_ID")
PRIVATE_KEY = os.environ.get("PRIVATE_KEY")
INSTALLATION_ID = os.environ.get("INSTALLATION_ID")
PAT_TOKEN = os.environ.get("PAT_TOKEN")

REPO_NAME = os.environ.get("GITHUB_REPOSITORY", "Colorful-glassblock/Dont-Be-Stupid-Leaker")
BOT_NAME = "LLMApiCheckBot"
BOT_SIGNATURE = f"*This message was sent by {BOT_NAME} - Repository: {REPO_NAME}*"

GITHUB_API = "https://api.github.com"

CODE_QUERY = 'sk-proj- OR xai- OR AIza OR sk-ant-api OR r8_ OR hf_ OR tp-'
ISSUE_QUERY = '"your key leak" OR "sk-proj-" OR "xai-" OR "AIza" OR "sk-ant-api"'
COMMIT_QUERY = 'sk-proj- OR xai- OR AIza OR sk-ant-api'
ENV_QUERY = 'filename:.env OR filename:.env.example OR filename:.env.local OR filename:.env.production OR filename:.env.staging OR filename:.env.dev OR filename:.env.test'

start_time = time.time()
last_heartbeat = start_time
stop_event = Event()
shutdown_requested = False

auth_token: Optional[str] = None
github_session = None  # Fix NameError: initialize global variable

deep_scan_threads: List[threading.Thread] = []
deep_scan_threads_lock = Lock()

download_warned_urls: Set[str] = set()
download_warned_lock = Lock()

# ========== Thread-local HTTP session ==========
_session_local = local()

def get_http_session() -> requests.Session:
    if not hasattr(_session_local, 'session'):
        _session_local.session = create_session()
    return _session_local.session

# ========== LRU Cache with TTL ==========
class LRUCache:
    def __init__(self, max_size: int = MAX_CACHE_SIZE, ttl: int = MAX_CACHE_AGE):
        self.max_size = max_size
        self.ttl = ttl
        self.cache: Dict[str, Tuple[Any, float]] = {}
        self.lock = RLock()
    
    def get(self, key: str) -> Optional[Any]:
        with self.lock:
            if key in self.cache:
                value, timestamp = self.cache[key]
                if time.time() - timestamp < self.ttl:
                    del self.cache[key]
                    self.cache[key] = (value, timestamp)
                    return value
                else:
                    del self.cache[key]
            return None
    
    def put(self, key: str, value: Any) -> None:
        with self.lock:
            if key in self.cache:
                del self.cache[key]
            elif len(self.cache) >= self.max_size:
                oldest = next(iter(self.cache))
                del self.cache[oldest]
            self.cache[key] = (value, time.time())
    
    def clear(self) -> None:
        with self.lock:
            self.cache.clear()

file_cache = LRUCache()
issue_cache = LRUCache()
pr_cache = LRUCache()
commit_cache = LRUCache()

# ========== Deduplication ==========
class BloomFilter:
    def __init__(self, size: int = BLOOM_FILTER_SIZE, hash_count: int = BLOOM_FILTER_HASHES):
        self.size = size
        self.hash_count = hash_count
        self.bits = bytearray(size // 8 + 1)
        self.lock = Lock()
    
    def _hashes(self, item: str) -> List[int]:
        result = []
        for i in range(self.hash_count):
            h = hash(f"{item}_{i}")
            result.append(h % self.size)
        return result
    
    def add(self, item: str) -> None:
        with self.lock:
            for pos in self._hashes(item):
                byte_idx = pos // 8
                bit_idx = pos % 8
                self.bits[byte_idx] |= (1 << bit_idx)
    
    def contains(self, item: str) -> bool:
        with self.lock:
            for pos in self._hashes(item):
                byte_idx = pos // 8
                bit_idx = pos % 8
                if not (self.bits[byte_idx] & (1 << bit_idx)):
                    return False
        return True

processed_exact: "OrderedDict[str, bool]" = OrderedDict()
processed_exact_lock = Lock()
bloom_filter = BloomFilter()
scanned_repos: Set[str] = set()
scanned_repos_lock = Lock()

def is_duplicate(key: str, source_url: str) -> bool:
    combo = f"{key}|{source_url}"
    with processed_exact_lock:
        if combo in processed_exact:
            return True
        while len(processed_exact) >= MAX_PROCESSED_EXACT:
            oldest = next(iter(processed_exact))
            del processed_exact[oldest]
        if bloom_filter.contains(combo):
            return True
        processed_exact[combo] = True
    bloom_filter.add(combo)
    return False

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counter = Counter(s)
    length = len(s)
    entropy = 0.0
    for count in counter.values():
        prob = count / length
        entropy -= prob * math.log2(prob)
    return entropy

def is_fake_key(key: str) -> bool:
    body = re.sub(
        r'^(sk-proj-|sk-or-v1-|xai-|AIza|sk-ant-api|r8_|hf_|tp-|sk-api-|pplx-|github_pat_|ghp_|sk_live_|sk_test_|sk-)',
        '', key
    )
    if len(body) < 8:
        return True
    return shannon_entropy(body) < FAKE_KEY_ENTROPY_THRESHOLD

# ========== Batch Manager ==========
@dataclass
class BatchQueue:
    items: List[Tuple] = field(default_factory=list)
    count: int = 0
    start_time: float = 0
    lock: Lock = field(default_factory=Lock)

class BatchManager:
    def __init__(self, verify_func, batch_size: int = BATCH_SIZE, timeout: int = BATCH_TIMEOUT):
        self.queues: Dict[int, BatchQueue] = defaultdict(BatchQueue)
        self.verify_func = verify_func
        self.batch_size = batch_size
        self.timeout = timeout
        self.global_lock = Lock()
        self._executor = ThreadPoolExecutor(max_workers=VERIFY_WORKERS, thread_name_prefix="verify")
        self._futures: List = []
        self._futures_lock = Lock()
    
    def _get_queue(self, worker_id: int) -> BatchQueue:
        with self.global_lock:
            return self.queues[worker_id]
    
    def add(self, worker_id, key, service, source_url, source_type, author, g):
        queue = self._get_queue(worker_id)
        with queue.lock:
            if queue.count == 0:
                queue.start_time = time.time()
            queue.items.append((key, service, source_url, source_type, author))
            queue.count += 1
            should_verify = (queue.count >= self.batch_size) or (time.time() - queue.start_time >= self.timeout)
            if should_verify:
                batch = queue.items.copy()
                queue.items.clear()
                count = queue.count
                queue.count = 0
                self._submit_verify(worker_id, batch, g, count)
    
    def _submit_verify(self, worker_id, batch, g, batch_size):
        future = self._executor.submit(self.verify_func, worker_id, batch, g, batch_size)
        with self._futures_lock:
            self._futures.append(future)
    
    def flush_all(self, g):
        with self.global_lock:
            for worker_id, queue in list(self.queues.items()):
                with queue.lock:
                    if queue.count > 0:
                        self._submit_verify(worker_id, queue.items.copy(), g, queue.count)
                        queue.items.clear()
                        queue.count = 0
    
    def shutdown(self, wait=True):
        self._executor.shutdown(wait=wait)

# ========== Key Patterns ==========
KEY_PATTERNS = {
    "OpenAI": re.compile(r"sk-proj-[a-zA-Z0-9_\-]{50,}"),
    "OpenRouter": re.compile(r"sk-or-v1-[a-zA-Z0-9]{50,}"),
    "XAI": re.compile(r"xai-[a-zA-Z0-9]{32,}"),
    "DeepSeek": re.compile(r"sk-[a-zA-Z0-9]{32,}"),
    "Gemini": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "Anthropic": re.compile(r"sk-ant-api[0-9A-Za-z\-_]{40,}"),
    "Replicate": re.compile(r"r8_[a-zA-Z0-9]{32,}"),
    "HuggingFace": re.compile(r"hf_[a-zA-Z0-9]{30,}"),
    "MiMo": re.compile(r"tp-[a-zA-Z0-9]{10,}"),
    "MiniMax": re.compile(r"sk-api-[a-zA-Z0-9]{100,}"),
    "Perplexity": re.compile(r"pplx-[a-zA-Z0-9]{32,}"),
    "GitHub_PAT": re.compile(r"github_pat_[a-zA-Z0-9_]{50,}"),
    "GitHub_Token": re.compile(r"ghp_[a-zA-Z0-9]{36}"),
    "Stripe_Live": re.compile(r"sk_live_[a-zA-Z0-9]{24,}"),
    "Stripe_Test": re.compile(r"sk_test_[a-zA-Z0-9]{24,}"),
}

# ========== Verifiers ==========
def _parse_stripe(code, data):
    return (code == 200, 0, "Valid") if code == 200 else (False, 0, "Invalid") if code == 401 else (False, 0, f"HTTP {code}")

def _parse_deepseek(code, data):
    if code != 200 or not isinstance(data, dict) or not data.get("is_available"):
        return False, 0, f"HTTP {code}" if code != 200 else "Invalid"
    cny = sum(float(i.get("total_balance", 0)) for i in data.get("balance_infos", []) if i.get("currency") == "CNY")
    usd = sum(float(i.get("total_balance", 0)) for i in data.get("balance_infos", []) if i.get("currency") == "USD")
    info = f"CNY: {cny:.2f}, USD: {usd:.2f}" if cny or usd else "Valid (no balance)"
    return True, cny + usd * 7.2, info

def _parse_openai(code, data):
    return (True, 0, "Valid") if code == 200 else (False, 0, "Invalid") if code == 401 else (False, 0, f"HTTP {code}")

def _parse_openrouter(code, data):
    if code == 200 and isinstance(data, dict):
        credits = data.get("credits", 0)
        info = f"Credits: {credits}" if credits > 0 else "Valid"
        return True, float(credits), info
    return False, 0, f"HTTP {code}"

def _parse_xai(code, data):
    return (True, 0, "Valid") if code == 200 else (False, 0, f"HTTP {code}")

def _parse_gemini(code, data):
    # 403 means key is disabled/revoked, treat as invalid
    if code == 200:
        return True, 0, "Valid"
    if code == 403:
        return False, 0, "Invalid (403)"
    return False, 0, f"HTTP {code}"

def _parse_anthropic(code, data):
    return (True, 0, "Valid") if code == 200 else (False, 0, f"HTTP {code}")

def _parse_github_token(code, data):
    return (True, 0, "Valid") if code == 200 else (False, 0, "Invalid")

def _parse_generic_token(code, data):
    return (True, 0, "Valid") if code == 200 else (False, 0, f"HTTP {code}")

VERIFIERS = {
    "OpenAI": {"url": "https://api.openai.com/v1/models", "headers": lambda k: {"Authorization": f"Bearer {k}"}, "method": "GET", "parse": _parse_openai},
    "OpenRouter": {"url": "https://openrouter.ai/api/v1/auth/key", "headers": lambda k: {"Authorization": f"Bearer {k}"}, "method": "GET", "parse": _parse_openrouter},
    "XAI": {"url": "https://api.x.ai/v1/models", "headers": lambda k: {"Authorization": f"Bearer {k}"}, "method": "GET", "parse": _parse_xai},
    "DeepSeek": {"url": "https://api.deepseek.com/user/balance", "headers": lambda k: {"Authorization": f"Bearer {k}", "Accept": "application/json"}, "method": "GET", "parse": _parse_deepseek},
    "Gemini": {"url": lambda k: f"https://generativelanguage.googleapis.com/v1/models?key={k}", "headers": lambda k: {}, "method": "GET", "parse": _parse_gemini},
    "Anthropic": {"url": "https://api.anthropic.com/v1/messages", "headers": lambda k: {"x-api-key": k, "anthropic-version": "2023-06-01", "Content-Type": "application/json"}, "method": "POST", "body": lambda: json.dumps({"model": "claude-3-haiku-20240307", "max_tokens": 1, "messages": [{"role": "user", "content": "hi"}]}).encode(), "parse": _parse_anthropic},
    "Replicate": {"url": "https://api.replicate.com/v1/account", "headers": lambda k: {"Authorization": f"Bearer {k}"}, "method": "GET", "parse": _parse_generic_token},
    "HuggingFace": {"url": "https://huggingface.co/api/whoami", "headers": lambda k: {"Authorization": f"Bearer {k}"}, "method": "GET", "parse": _parse_generic_token},
    "MiMo": {"url": "https://token-plan-cn.xiaomimimo.com/v1/models", "headers": lambda k: {"Authorization": f"Bearer {k}", "X-Plan-Type": "token-plan"}, "method": "GET", "parse": _parse_generic_token},
    "MiniMax": {"url": "https://api.minimax.io/v1/models", "headers": lambda k: {"Authorization": f"Bearer {k}"}, "method": "GET", "parse": _parse_generic_token},
    "Perplexity": {"url": "https://api.perplexity.ai/chat/completions", "headers": lambda k: {"Authorization": f"Bearer {k}", "Content-Type": "application/json"}, "method": "POST", "body": lambda: json.dumps({"model": "llama-3.1-sonar-small-128k-online", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 1}).encode(), "parse": _parse_generic_token},
    "GitHub_PAT": {"url": "https://api.github.com/user", "headers": lambda k: {"Authorization": f"Bearer {k}"}, "method": "GET", "parse": _parse_github_token},
    "GitHub_Token": {"url": "https://api.github.com/user", "headers": lambda k: {"Authorization": f"Bearer {k}"}, "method": "GET", "parse": _parse_github_token},
    "Stripe_Live": {"url": "https://api.stripe.com/v1/account", "headers": lambda k: {"Authorization": f"Bearer {k}"}, "method": "GET", "parse": _parse_stripe},
    "Stripe_Test": {"url": "https://api.stripe.com/v1/account", "headers": lambda k: {"Authorization": f"Bearer {k}"}, "method": "GET", "parse": _parse_stripe},
}

# ========== HTTP Session ==========
def create_session() -> requests.Session:
    session = requests.Session()
    retry = Retry(total=2, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=10)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session

found_valid_keys: List[Tuple] = []
valid_lock = Lock()
realtime_lock = Lock()
batch_manager: Optional[BatchManager] = None

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
]

def random_ua():
    return random.choice(USER_AGENTS)

def check_timeout_and_exit():
    if time.time() - start_time >= MAX_RUNTIME_SECONDS:
        if not shutdown_requested:
            print(f"\nMax runtime reached ({MAX_RUNTIME_SECONDS}s). Shutting down...")
            graceful_shutdown()

def graceful_shutdown():
    global shutdown_requested
    if shutdown_requested:
        return
    shutdown_requested = True
    print("\n[!] Graceful shutdown initiated...")
    stop_event.set()
    with deep_scan_threads_lock:
        for t in deep_scan_threads:
            if t.is_alive():
                t.join(timeout=30)
    if batch_manager:
        print("[!] Flushing pending batches...")
        # Safely check if github_session exists
        if 'github_session' in globals() and github_session:
            batch_manager.flush_all(github_session)
        else:
            print("[!] No GitHub session, skipping flush")
        print("[!] Shutting down verification executor...")
        batch_manager.shutdown(wait=True)
    print("[!] Saving results...")
    save_final_results()
    print("[!] Shutdown complete.")

def signal_handler(sig, frame):
    graceful_shutdown()

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def get_github_client():
    global github_session, auth_token
    if github_session:
        return github_session
    token = None
    if APP_ID and PRIVATE_KEY and INSTALLATION_ID:
        try:
            private_key = PRIVATE_KEY.replace('\\n', '\n')
            payload = {"iat": int(time.time()), "exp": int(time.time()) + 600, "iss": APP_ID}
            jwt_token = jwt.encode(payload, private_key, algorithm="RS256")
            url = f"https://api.github.com/app/installations/{INSTALLATION_ID}/access_tokens"
            headers = {"Authorization": f"Bearer {jwt_token}", "Accept": "application/vnd.github+json"}
            resp = requests.post(url, headers=headers)
            if resp.status_code == 201:
                token = resp.json()["token"]
                print("Using GitHub App authentication")
        except Exception as e:
            print(f"GitHub App auth failed: {e}")
    if not token and PAT_TOKEN:
        token = PAT_TOKEN
        print("Using PAT authentication")
    if not token:
        print("No authentication method available")
        return None
    auth_token = token
    auth = Auth.Token(token)
    github_session = Github(auth=auth, retry=0)
    return github_session

def save_final_results():
    with valid_lock:
        if found_valid_keys:
            unique = {}
            for entry in found_valid_keys:
                key, service, balance, info, source_url, source_type, timestamp = entry
                unique[(key, source_url)] = entry
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            with open(f"valid_keys_final_{timestamp}.txt", "w") as f:
                f.write(f"# Scan time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# Total valid keys (unique): {len(unique)}\n\n")
                for entry in unique.values():
                    key, service, balance, info, source_url, source_type, _ = entry
                    f.write(f"{service} | {key} | {info} | {source_url}\n")
            print(f"\nSaved {len(unique)} unique keys to valid_keys_final_{timestamp}.txt")
            return True
    return False

def build_reply(author, service, key, info, source_url, source_type, balance=None, is_fallback=False):
    if len(key) > 24:
        masked = key[:12] + "..." + key[-8:]
    elif len(key) > 16:
        masked = key[:8] + "..." + key[-6:]
    else:
        masked = key[:4] + "..." + key[-4:]
    balance_text = f" (Balance: {balance})" if balance is not None else ""
    install_note = "\n\n---\n📌 To receive notifications directly, install: https://github.com/apps/llmapicheckbot2" if is_fallback else ""
    return f"""🔴 API Key Leak Detected!

@{author} Your API key has been exposed in this {source_type}{balance_text}.

Service: {service}
Key preview: {masked}
Status: {info}

Source: {source_url}

---
{BOT_SIGNATURE}{install_note}"""

def get_full_file_content(source_url):
    cached = file_cache.get(source_url)
    if cached:
        return cached
    try:
        parts = source_url.replace("https://github.com/", "").split("/blob/")
        if len(parts) != 2:
            return None
        repo_path = parts[0]
        ref_path = parts[1]
        encoded_ref_path = urllib.parse.quote(ref_path, safe='/')
        raw_url = f"https://raw.githubusercontent.com/{repo_path}/{encoded_ref_path}"
    except Exception:
        return None
    session = get_http_session()
    try:
        resp = session.get(raw_url, timeout=10, stream=True)
        if resp.status_code == 200:
            with closing(resp):
                chunks = []
                size = 0
                for chunk in resp.iter_content(chunk_size=16384):
                    chunks.append(chunk.decode('utf-8', errors='replace'))
                    size += len(chunks[-1])
                    if size > MAX_FILE_SIZE_BYTES:
                        chunks.append("\n...[File truncated]")
                        break
                content = "".join(chunks)
            file_cache.put(source_url, content)
            return content
        else:
            resp.close()
            with download_warned_lock:
                if source_url not in download_warned_urls:
                    print(f"  ⚠️ Failed to download {source_url} (HTTP {resp.status_code})")
                    download_warned_urls.add(source_url)
    except Exception as e:
        with download_warned_lock:
            if source_url not in download_warned_urls:
                print(f"  ⚠️ Error downloading {source_url}: {e}")
                download_warned_urls.add(source_url)
    return None

def get_issue_or_pr_content(source_url, g):
    cache = issue_cache if "/issues/" in source_url else pr_cache
    cached = cache.get(source_url)
    if cached:
        return cached
    try:
        if "/issues/" in source_url:
            parts = source_url.replace("https://github.com/", "").split("/issues/")
        else:
            parts = source_url.replace("https://github.com/", "").split("/pull/")
        if len(parts) != 2:
            return ""
        repo_path = parts[0]
        number = int(parts[1].split("#")[0])
        repo = g.get_repo(repo_path)
        item = repo.get_issue(number=number)
        content = f"{item.title}\n{item.body or ''}"
        cache.put(source_url, content)
        return content
    except Exception as e:
        print(f"  ⚠️ Error fetching issue/PR content: {e}")
        return ""

def get_pr_diff_content(source_url, g):
    cached = pr_cache.get(source_url)
    if cached:
        return cached
    try:
        parts = source_url.replace("https://github.com/", "").split("/pull/")
        if len(parts) != 2:
            return ""
        repo_path = parts[0]
        pr_number = int(parts[1].split("#")[0])
        repo = g.get_repo(repo_path)
        pr = repo.get_pull(pr_number)
        diff_url = pr.diff_url
        headers = _gh_headers()
        session = get_http_session()
        resp = session.get(diff_url, headers=headers, timeout=10, stream=True)
        if resp.status_code == 200:
            chunks = []
            size = 0
            for chunk in resp.iter_content(chunk_size=16384):
                chunks.append(chunk.decode('utf-8', errors='replace'))
                size += len(chunks[-1])
                if size > MAX_FILE_SIZE_BYTES:
                    chunks.append("\n...[Diff truncated]")
                    break
            content = "".join(chunks)
            pr_cache.put(source_url, content)
            return content
        else:
            resp.close()
            print(f"  ⚠️ Could not fetch PR diff (HTTP {resp.status_code}) for {source_url}")
            return ""
    except Exception as e:
        print(f"  ⚠️ Error fetching PR diff: {e}")
        return ""

def get_commit_content(source_url, g):
    cached = commit_cache.get(source_url)
    if cached:
        return cached
    try:
        parts = source_url.replace("https://github.com/", "").split("/commit/")
        if len(parts) != 2:
            return ""
        sha = parts[1].split("#")[0]
        diff_url = f"https://github.com/{parts[0]}/commit/{sha}.diff"
        headers = _gh_headers()
        session = get_http_session()
        resp = session.get(diff_url, headers=headers, timeout=10, stream=True)
        if resp.status_code == 200:
            chunks = []
            size = 0
            for chunk in resp.iter_content(chunk_size=16384):
                chunks.append(chunk.decode('utf-8', errors='replace'))
                size += len(chunks[-1])
                if size > MAX_COMMIT_DIFF_BYTES:
                    chunks.append("\n...[Diff truncated]")
                    break
            content = "".join(chunks)
            commit_cache.put(source_url, content)
            return content
        else:
            resp.close()
            print(f"  ⚠️ Could not fetch diff (HTTP {resp.status_code}) for {source_url}")
            return ""
    except Exception as e:
        print(f"  ⚠️ Error fetching commit diff: {e}")
        return ""

def extract_and_queue(text, source_url, source_type, worker_id, author, g):
    full_text = text
    if source_type in ("code", "env") and "/blob/" in source_url:
        content = get_full_file_content(source_url)
        if content:
            full_text = content
    elif source_type == "pr":
        full_text = get_pr_diff_content(source_url, g)
    elif source_type == "issue":
        full_text = get_issue_or_pr_content(source_url, g)
    elif source_type == "commit":
        full_text = get_commit_content(source_url, g)
    else:
        return
    if not full_text:
        return
    for service, pattern in KEY_PATTERNS.items():
        for match in pattern.finditer(full_text):
            key = match.group(0)
            if is_fake_key(key):
                continue
            if is_duplicate(key, source_url):
                continue
            print(f"  🔑 Found {service} key: {source_url[:80]}...")
            batch_manager.add(worker_id, key, service, source_url, source_type, author, g)

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
        try:
            issues = repo.get_issues(state="all", sort="created", direction="desc")[:50]
            for issue in issues:
                if file_path in (issue.title or "") or source_url in (issue.body or ""):
                    return True
        except:
            pass
        message = build_reply(author, service, key, info, source_url, "code file", balance)
        issue_title = f"API Key Leak Detected in {file_path}"
        issue_body = message + f"\n\nFile: {file_path}"
        try:
            repo.create_issue(title=issue_title, body=issue_body, labels=["security"])
            print(f"    📝 Created issue in {repo_path}")
            return True
        except Exception as e:
            if "labels" in str(e).lower():
                try:
                    repo.create_issue(title=issue_title, body=issue_body)
                    print(f"    📝 Created issue in {repo_path} (no labels)")
                    return True
                except Exception:
                    return False
            return False
    except Exception:
        return False

def _issue_already_exists_in_my_repo(g, issue_title, key_preview):
    try:
        my_repo = g.get_repo(REPO_NAME)
        for issue in my_repo.get_issues(state="all", sort="created", direction="desc")[:50]:
            if issue.title == issue_title:
                return True
            if key_preview and key_preview in (issue.body or ""):
                return True
    except Exception:
        pass
    return False

def create_issue_in_my_repo(g, key, service, info, source_url, source_type, author, balance, is_fallback=False):
    message = build_reply(author, service, key, info, source_url, source_type, balance, is_fallback)
    try:
        my_repo = g.get_repo(REPO_NAME)
        short_raw = source_url.replace("https://github.com/", "")
        short_url = short_raw[:57] + "..." if len(short_raw) > 57 else short_raw
        display_type = "Pull Request" if "/pull/" in source_url else "Issue" if "/issues/" in source_url else "Commit" if "/commit/" in source_url else source_type
        issue_title = f"{service} Key Leak in {display_type}: {short_url}"
        key_preview = key[:20] + "..." if len(key) > 20 else key
        if _issue_already_exists_in_my_repo(g, issue_title, key_preview):
            print(f"    📝 Issue already exists for this key, skipping")
            return
        issue_body = f"""## API Key Leak Detected{' (fallback)' if is_fallback else ''}

| Field | Value |
|-------|-------|
| Source Type | {display_type} |
| Source URL | {source_url} |
| Service | {service} |
| Key Preview | {key_preview} |
| Status | {info} |
| Author | @{author} |
| Balance | {balance if balance else 'N/A'} |

---

{message}

---
Auto-generated by {BOT_NAME}
"""
        try:
            new_issue = my_repo.create_issue(title=issue_title, body=issue_body, labels=["security", "leak"])
            print(f"    📝 Created issue #{new_issue.number}")
        except Exception:
            try:
                new_issue = my_repo.create_issue(title=issue_title, body=issue_body)
                print(f"    📝 Created issue #{new_issue.number} (no labels)")
            except Exception as e:
                print(f"    ❌ Failed to create issue: {e}")
                return
    except Exception as e:
        print(f"    ❌ Failed: {e}")

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
        item_num = int(parts[1].split("#")[0])
        repo = g.get_repo(repo_path)
        if is_pr:
            item = repo.get_pull(number=item_num)
            comment_func = item.create_issue_comment
            item_type = "PR"
            comments = item.get_issue_comments()[:MAX_COMMENTS_PER_ISSUE]
        else:
            item = repo.get_issue(number=item_num)
            comment_func = item.create_comment
            item_type = "Issue"
            comments = item.get_comments()[:MAX_COMMENTS_PER_ISSUE]
        bot_login = g.get_user().login
        for comment in comments:
            if comment.user.login == bot_login and "API Key Leak Detected" in comment.body:
                print(f"    Already replied to {item_type} #{item_num}")
                return True
        message = build_reply(author, service, key, info, source_url, item_type.lower(), balance)
        comment_func(message)
        print(f"    📝 Replied to {item_type} #{item_num}")
        return True
    except Exception as e:
        print(f"    ❌ Failed: {e}")
        return False

def handle_leak(g, key, service, info, source_url, source_type, author, balance):
    if "/issues/" in source_url or "/pull/" in source_url:
        success = reply_to_original_issue_or_pr(g, source_url, author, service, key, info, balance)
        create_issue_in_my_repo(g, key, service, info, source_url, source_type, author, balance, is_fallback=not success)
    elif "/blob/" in source_url:
        success = create_issue_in_original_repo(g, source_url, author, service, key, info, balance)
        create_issue_in_my_repo(g, key, service, info, source_url, source_type, author, balance, is_fallback=not success)
        try:
            repo_full_name = source_url.replace("https://github.com/", "").split("/blob/")[0]
            if repo_full_name not in scanned_repos:
                t = threading.Thread(target=deep_scan_repository, args=(g, repo_full_name), daemon=True)
                with deep_scan_threads_lock:
                    deep_scan_threads.append(t)
                t.start()
        except Exception:
            pass
    else:
        create_issue_in_my_repo(g, key, service, info, source_url, source_type, author, balance, is_fallback=False)

def verify_batch(worker_id, batch, g, batch_size):
    if not batch:
        return
    print(f"\n[Worker-{worker_id}] 🔍 Verifying {len(batch)} keys{' (timeout)' if batch_size < BATCH_SIZE else ''}")
    results = []
    session = get_http_session()
    for key, service, source_url, source_type, author in batch:
        verifier = VERIFIERS.get(service)
        if not verifier:
            continue
        try:
            url = verifier["url"](key) if callable(verifier["url"]) else verifier["url"]
            headers = verifier["headers"](key)
            headers["User-Agent"] = random_ua()
            body = verifier.get("body")
            if body:
                body = body()
            if verifier["method"] == "GET":
                resp = session.get(url, headers=headers, timeout=8)
            else:
                resp = session.post(url, headers=headers, data=body, timeout=8)
            try:
                resp_data = resp.json() if resp.text else None
            except Exception:
                resp_data = None
            valid, balance, info = verifier["parse"](resp.status_code, resp_data)
            if valid:
                results.append((key, service, valid, balance, info, source_url, source_type, author))
                print(f"  ✅ [{service}] {key[:25]}... -> {info}")
                print(f"     📍 Source: {source_url}")
            else:
                print(f"  ❌ [{service}] {key[:25]}... -> {info}")
        except Exception as e:
            print(f"  ❌ [{service}] {key[:25]}... -> Error: {str(e)[:30]}")
    for key, service, valid, balance, info, source_url, source_type, author in results:
        with valid_lock:
            found_valid_keys.append((key, service, balance, info, source_url, source_type, datetime.now()))
        with realtime_lock:
            with open("valid_keys_realtime.txt", "a") as f:
                f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | {service} | {key} | {info} | {source_url}\n")
        try:
            handle_leak(g, key, service, info, source_url, source_type, author, balance)
        except Exception as e:
            print(f"    ❌ Failed to handle leak notification: {e}")

def deep_scan_repository(g, repo_full_name):
    with scanned_repos_lock:
        if repo_full_name in scanned_repos:
            return 0
        scanned_repos.add(repo_full_name)
    print(f"\n🔍 Deep scanning: {repo_full_name}")
    try:
        repo = g.get_repo(repo_full_name)
    except Exception as e:
        print(f"  ❌ Cannot access: {e}")
        return 0
    found_count = 0
    branch = repo.default_branch
    author = getattr(repo.owner, 'login', None) or "unknown"
    try:
        commit = repo.get_commit(sha=branch)
        tree = commit.get_tree(recursive=True)
        if hasattr(tree, 'truncated') and tree.truncated:
            print(f"  ⚠️ Tree truncated (repo too large), results may be incomplete")
        files_scanned = 0
        for item in tree.tree:
            if files_scanned >= DEEP_SCAN_MAX_FILES:
                break
            if item.type != "blob":
                continue
            file_path = item.path
            extensions = ['.env', '.json', '.yaml', '.yml', '.toml', '.txt', '.md', '.cfg', '.conf',
                          '.config', '.ini', '.properties', '.py', '.js', '.ts', '.java', '.go', '.rs', '.rb', '.php']
            if not any(file_path.lower().endswith(ext) for ext in extensions):
                continue
            files_scanned += 1
            print(f"    📄 Scanning: {file_path}")
            try:
                encoded_branch = urllib.parse.quote(branch, safe='/')
                encoded_path = urllib.parse.quote(file_path, safe='/')
                raw_url = f"https://raw.githubusercontent.com/{repo_full_name}/{encoded_branch}/{encoded_path}"
                session = get_http_session()
                resp = session.get(raw_url, timeout=10, stream=True)
                if resp.status_code == 200:
                    with closing(resp):
                        chunks = []
                        size = 0
                        for chunk in resp.iter_content(chunk_size=16384):
                            chunks.append(chunk.decode('utf-8', errors='replace'))
                            size += len(chunks[-1])
                            if size > MAX_FILE_SIZE_BYTES:
                                chunks.append("\n...[File truncated]")
                                break
                        content = "".join(chunks)
                    for service, pattern in KEY_PATTERNS.items():
                        for match in pattern.finditer(content):
                            key = match.group(0)
                            if is_fake_key(key):
                                continue
                            if is_duplicate(key, raw_url):
                                continue
                            print(f"      🔑 Found {service} key")
                            batch_manager.add(DEEP_SCAN_WORKER_ID, key, service, raw_url, "deep_scan", author, g)
                            found_count += 1
                else:
                    resp.close()
                    with download_warned_lock:
                        if raw_url not in download_warned_urls:
                            print(f"      ⚠️ Failed to download {raw_url} (HTTP {resp.status_code})")
                            download_warned_urls.add(raw_url)
            except Exception as e:
                with download_warned_lock:
                    if raw_url not in download_warned_urls:
                        print(f"      ⚠️ Error: {e}")
                        download_warned_urls.add(raw_url)
    except Exception as e:
        print(f"  ❌ Deep scan failed: {e}")
    print(f"  ✅ Deep scan completed: found {found_count} keys")
    return found_count

# ========== Search Workers ==========
def _gh_headers():
    headers = {"Accept": "application/vnd.github+json", "User-Agent": random_ua()}
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"
    elif PAT_TOKEN:
        headers["Authorization"] = f"Bearer {PAT_TOKEN}"
    return headers

def _http_request(url, headers, retries=2):
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers=headers)
            ctx = ssl.create_default_context()
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT, context=ctx) as resp:
                raw = resp.read().decode("utf-8")
                try:
                    return resp.status, json.loads(raw)
                except:
                    return resp.status, raw
        except urllib.error.HTTPError as e:
            if e.code in (429, 403):
                wait = min(60, (2 ** attempt) * 5)
                print(f"  ⚠️ HTTP {e.code} - backing off {wait}s")
                time.sleep(wait)
                if attempt == retries:
                    return e.code, str(e)
            elif e.code >= 500:
                if attempt < retries:
                    time.sleep(2)
                    continue
                return e.code, str(e)
            else:
                return e.code, str(e)
        except Exception as e:
            if attempt == retries:
                return 0, str(e)
            time.sleep(2)
    return 0, "max retries exceeded"

def safe_sleep(seconds):
    elapsed = 0
    while elapsed < seconds and not stop_event.is_set():
        check_timeout_and_exit()
        time.sleep(min(0.5, seconds - elapsed))
        elapsed += 0.5

def heartbeat():
    global last_heartbeat
    now = time.time()
    if now - last_heartbeat >= HEARTBEAT_INTERVAL:
        elapsed = now - start_time
        remaining = MAX_RUNTIME_SECONDS - elapsed
        print(f"❤️ Alive: {elapsed:.0f}s / {MAX_RUNTIME_SECONDS}s (remaining: {remaining:.0f}s)")
        print(f"📊 Cache: files={len(file_cache.cache)}, issues={len(issue_cache.cache)}, "
              f"prs={len(pr_cache.cache)}, commits={len(commit_cache.cache)}")
        last_heartbeat = now

def search_code_worker(worker_id, start_page, g):
    print(f"\n[Worker-{worker_id}] Starting CODE scan")
    page = start_page
    consecutive_empty = 0
    error_count = 0
    page_retries = 0
    while not stop_event.is_set():
        check_timeout_and_exit()
        url = f"{GITHUB_API}/search/code?q={urllib.parse.quote(CODE_QUERY)}&sort=indexed&order=desc&per_page={PER_PAGE}&page={page}"
        code, data = _http_request(url, _gh_headers())
        if code in (429, 403):
            error_count += 1
            if error_count >= MAX_CONSECUTIVE_ERRORS:
                if page_retries < MAX_PAGE_RETRIES:
                    page_retries += 1
                    error_count = 0
                    print(f"[Worker-{worker_id}] Rate limited on page {page}, retrying after 30s (attempt {page_retries}/{MAX_PAGE_RETRIES})")
                    safe_sleep(30)
                    continue
                else:
                    print(f"[Worker-{worker_id}] Skipping page {page} after {MAX_PAGE_RETRIES} retries")
                    page += 1
                    page_retries = 0
                    error_count = 0
                    continue
            safe_sleep(10)
            continue
        if code != 200:
            page += 1
            page_retries = 0
            safe_sleep(2)
            continue
        error_count = 0
        page_retries = 0
        items = data.get("items", []) if isinstance(data, dict) else []
        if not items:
            consecutive_empty += 1
            if consecutive_empty >= 3:
                break
            page += 1
            safe_sleep(1)
            continue
        consecutive_empty = 0
        print(f"[Worker-{worker_id}] CODE page {page}: {len(items)} items")
        for item in items:
            if stop_event.is_set():
                break
            html_url = item.get("html_url", "")
            author = item.get("repository", {}).get("owner", {}).get("login", "unknown")
            extract_and_queue("", html_url, "code", worker_id, author, g)
        page += 1
        safe_sleep(0.5)
    print(f"[Worker-{worker_id}] CODE scan finished")

def search_issues_worker(worker_id, start_page, g):
    print(f"\n[Worker-{worker_id}] Starting ISSUE/PR scan")
    page = start_page
    consecutive_empty = 0
    error_count = 0
    page_retries = 0
    while not stop_event.is_set():
        check_timeout_and_exit()
        url = f"{GITHUB_API}/search/issues?q={urllib.parse.quote(ISSUE_QUERY)}&sort=created&order=desc&per_page={PER_PAGE}&page={page}"
        code, data = _http_request(url, _gh_headers())
        if code in (429, 403):
            error_count += 1
            if error_count >= MAX_CONSECUTIVE_ERRORS:
                if page_retries < MAX_PAGE_RETRIES:
                    page_retries += 1
                    error_count = 0
                    print(f"[Worker-{worker_id}] Rate limited on page {page}, retrying after 30s (attempt {page_retries}/{MAX_PAGE_RETRIES})")
                    safe_sleep(30)
                    continue
                else:
                    print(f"[Worker-{worker_id}] Skipping page {page} after {MAX_PAGE_RETRIES} retries")
                    page += 1
                    page_retries = 0
                    error_count = 0
                    continue
            safe_sleep(10)
            continue
        if code != 200:
            page += 1
            page_retries = 0
            safe_sleep(2)
            continue
        error_count = 0
        page_retries = 0
        items = data.get("items", []) if isinstance(data, dict) else []
        if not items:
            consecutive_empty += 1
            if consecutive_empty >= 3:
                break
            page += 1
            safe_sleep(1)
            continue
        consecutive_empty = 0
        print(f"[Worker-{worker_id}] ISSUE page {page}: {len(items)} items")
        for item in items:
            if stop_event.is_set():
                break
            html_url = item.get("html_url", "")
            author = item.get("user", {}).get("login", "unknown")
            source_type = "pr" if "/pull/" in html_url else "issue"
            extract_and_queue("", html_url, source_type, worker_id, author, g)
        page += 1
        safe_sleep(0.5)
    print(f"[Worker-{worker_id}] ISSUE scan finished")

def search_commits_worker(worker_id, start_page, g):
    print(f"\n[Worker-{worker_id}] Starting COMMIT scan")
    page = start_page
    consecutive_empty = 0
    error_count = 0
    page_retries = 0
    while not stop_event.is_set():
        check_timeout_and_exit()
        url = f"{GITHUB_API}/search/commits?q={urllib.parse.quote(COMMIT_QUERY)}&sort=committer-date&order=desc&per_page={PER_PAGE}&page={page}"
        code, data = _http_request(url, _gh_headers())
        if code in (429, 403):
            error_count += 1
            if error_count >= MAX_CONSECUTIVE_ERRORS:
                if page_retries < MAX_PAGE_RETRIES:
                    page_retries += 1
                    error_count = 0
                    print(f"[Worker-{worker_id}] Rate limited on page {page}, retrying after 30s (attempt {page_retries}/{MAX_PAGE_RETRIES})")
                    safe_sleep(30)
                    continue
                else:
                    print(f"[Worker-{worker_id}] Skipping page {page} after {MAX_PAGE_RETRIES} retries")
                    page += 1
                    page_retries = 0
                    error_count = 0
                    continue
            safe_sleep(10)
            continue
        if code != 200:
            page += 1
            page_retries = 0
            safe_sleep(2)
            continue
        error_count = 0
        page_retries = 0
        items = data.get("items", []) if isinstance(data, dict) else []
        if not items:
            consecutive_empty += 1
            if consecutive_empty >= 3:
                break
            page += 1
            safe_sleep(1)
            continue
        consecutive_empty = 0
        print(f"[Worker-{worker_id}] COMMIT page {page}: {len(items)} items")
        for item in items:
            if stop_event.is_set():
                break
            html_url = item.get("html_url", "")
            author = item.get("author", {}).get("login", "unknown") if item.get("author") else "unknown"
            extract_and_queue("", html_url, "commit", worker_id, author, g)
        page += 1
        safe_sleep(0.5)
    print(f"[Worker-{worker_id}] COMMIT scan finished")

def search_env_worker(worker_id, start_page, g):
    print(f"\n[Worker-{worker_id}] Starting ENV scan")
    page = start_page
    consecutive_empty = 0
    error_count = 0
    page_retries = 0
    while not stop_event.is_set():
        check_timeout_and_exit()
        url = f"{GITHUB_API}/search/code?q={urllib.parse.quote(ENV_QUERY)}&sort=indexed&order=desc&per_page={PER_PAGE}&page={page}"
        code, data = _http_request(url, _gh_headers())
        if code in (429, 403):
            error_count += 1
            if error_count >= MAX_CONSECUTIVE_ERRORS:
                if page_retries < MAX_PAGE_RETRIES:
                    page_retries += 1
                    error_count = 0
                    print(f"[Worker-{worker_id}] Rate limited on page {page}, retrying after 30s (attempt {page_retries}/{MAX_PAGE_RETRIES})")
                    safe_sleep(30)
                    continue
                else:
                    print(f"[Worker-{worker_id}] Skipping page {page} after {MAX_PAGE_RETRIES} retries")
                    page += 1
                    page_retries = 0
                    error_count = 0
                    continue
            safe_sleep(10)
            continue
        if code != 200:
            page += 1
            page_retries = 0
            safe_sleep(2)
            continue
        error_count = 0
        page_retries = 0
        items = data.get("items", []) if isinstance(data, dict) else []
        if not items:
            consecutive_empty += 1
            if consecutive_empty >= 3:
                break
            page += 1
            safe_sleep(1)
            continue
        consecutive_empty = 0
        print(f"[Worker-{worker_id}] ENV page {page}: {len(items)} items")
        for item in items:
            if stop_event.is_set():
                break
            html_url = item.get("html_url", "")
            author = item.get("repository", {}).get("owner", {}).get("login", "unknown")
            extract_and_queue("", html_url, "env", worker_id, author, g)
        page += 1
        safe_sleep(0.5)
    print(f"[Worker-{worker_id}] ENV scan finished")

def main():
    global batch_manager, github_session
    print("=" * 70)
    print("🤖 API Key Leak Scanner - Production Ready v3.1.8")
    print(f"📁 Fallback repo: {REPO_NAME}")
    print(f"⏱️  Max runtime: {MAX_RUNTIME_SECONDS}s (50 minutes)")
    print(f"📦 Batch size: {BATCH_SIZE} keys OR {BATCH_TIMEOUT}s timeout")
    print(f"🔍 Scanning: CODE + ISSUES/PRs (incl. diffs) + COMMITS + ENV")
    print(f"🧠 Fake key filter: entropy < {FAKE_KEY_ENTROPY_THRESHOLD} (body only)")
    print("=" * 70)

    g = get_github_client()
    if not g:
        print("❌ Failed to initialize GitHub client")
        return
    github_session = g
    print("✅ GitHub client initialized")

    batch_manager = BatchManager(verify_batch, BATCH_SIZE, BATCH_TIMEOUT)

    with ThreadPoolExecutor(max_workers=SEARCH_WORKERS) as executor:
        futures = [
            executor.submit(search_code_worker, 1, 1, g),
            executor.submit(search_issues_worker, 2, 1, g),
            executor.submit(search_commits_worker, 3, 1, g),
            executor.submit(search_issues_worker, 4, 6, g),
            executor.submit(search_env_worker, 5, 1, g),
        ]
        while not stop_event.is_set():
            time.sleep(1)
            check_timeout_and_exit()
            heartbeat()
            if all(f.done() for f in futures):
                break
        stop_event.set()
        for future in futures:
            try:
                future.result(timeout=5)
            except:
                pass

    graceful_shutdown()
    print(f"\n✅ Scan completed. Found {len(found_valid_keys)} valid keys.")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        graceful_shutdown()
        sys.exit(1)