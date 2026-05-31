#!/usr/bin/env python3

import os
import re
import sys
import time
import json
import signal
import random
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Tuple, Set, List, Dict
from github import Github, Auth, GithubException
import requests

# ========== Configuration ==========
MAX_RUNTIME_SECONDS = 90 * 60
HEARTBEAT_INTERVAL = 300
PAGE_DELAY = 5           # 翻页后等待时间
REPO_BATCH_SIZE = 10     # 每页取多少个仓库
MAX_WORKERS = 15         # 并发线程数

PAT_TOKEN = os.environ.get("PAT_TOKEN")
if not PAT_TOKEN:
    print("Error: PAT_TOKEN not set")
    sys.exit(1)

REPO_NAME = os.environ.get("GITHUB_REPOSITORY", "Colorful-glassblock/Dont-Be-Stupid-Leaker")
BOT_NAME = "LLMApiCheckBot"
BOT_SIGNATURE = f"*This message was sent by {BOT_NAME} - Repository: {REPO_NAME}*"

# UA 伪装
USER_AGENTS = [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
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
            state = json.load(f)
            if "processed_repos" not in state:
                state["processed_repos"] = []
            if "current_page" not in state:
                state["current_page"] = 1
            if "replied_commits" not in state:
                state["replied_commits"] = []
            if "replied_codes" not in state:
                state["replied_codes"] = []
            if "replied_issues" not in state:
                state["replied_issues"] = []
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
        headers["User-Agent"] = random.choice(USER_AGENTS)
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
    """获取指定页的仓库"""
    try:
        # 使用有意义的搜索条件，按更新时间排序
        results = g.search_repositories("language:python", sort="updated", order="desc")
        items = results.get_page(page)
        return [repo.full_name for repo in items]
    except GithubException as e:
        if e.status == 422:
            # 如果还失败，用更宽泛的搜索
            try:
                results = g.search_repositories("stars:>0", sort="updated", order="desc")
                items = results.get_page(page)
                return [repo.full_name for repo in items]
            except:
                return []
        print(f"  Repo search error on page {page}: {e}")
        return []
    except Exception as e:
        print(f"  Repo search error on page {page}: {e}")
        return []

def scan_repo_code(repo, repo_full_name, state, processed):
    """扫描单个仓库的代码文件"""
    replied = 0
    try:
        code_query = f"repo:{repo_full_name} sk- OR sk-proj- OR AIza OR sk-ant-api OR r8_ OR hf_ OR tp-"
        code_results = list(repo._requester.requestJsonAndCheck("GET", f"/search/code?q={code_query}")[1].get("items", []))[:30]
        
        for code_item in code_results:
            if stop_scan:
                break
            heartbeat()
            check_timeout()
            
            file_path = code_item.get("path", "")
            file_url = code_item.get("html_url", "")
            file_id = f"{repo_full_name}_{file_path}"
            
            if has_replied_to_code(file_id, state):
                continue
            
            # 获取文件内容
            raw_url = f"https://raw.githubusercontent.com/{repo_full_name}/HEAD/{file_path}"
            content = ""
            try:
                headers = {"User-Agent": random.choice(USER_AGENTS)}
                resp = requests.get(raw_url, headers=headers, timeout=10)
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
                            new_issue = repo.create_issue(title=f"🚨 API Key Leak Detected in {file_path}", body=reply, labels=["security"])
                            mark_replied_code(file_id, state)
                            save_state(state)
                            scan_results["replied_count"] += 1
                            scan_results["found_keys"].append({"type":"code","repo":repo_full_name,"file":file_path,"service":service,"key":key,"balance":bal,"info":info})
                            replied += 1
                            print(f"      ✅ Created issue #{new_issue.number} - {service} key")
                            time.sleep(1)
                        except Exception as e:
                            scan_results["errors"].append(str(e))
    except Exception as e:
        print(f"    Code scan error: {e}")
    return replied

def scan_repo_issues(repo, repo_full_name, state, processed):
    """扫描单个仓库的 Issues"""
    replied = 0
    try:
        issues = repo.get_issues(state="all", sort="created", direction="desc")
        issue_count = 0
        for issue in issues:
            if stop_scan or issue_count >= 30:
                break
            issue_count += 1
            heartbeat()
            check_timeout()
            
            num = issue.number
            if has_replied_to_issue(num, state):
                continue
            
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
                            scan_results["found_keys"].append({"type":"issue","repo":repo_full_name,"number":num,"service":service,"key":key,"balance":bal,"info":info})
                            replied += 1
                            print(f"      ✅ Replied to issue #{num} - {service} key")
                            time.sleep(1)
                        except Exception as e:
                            scan_results["errors"].append(str(e))
    except Exception as e:
        print(f"    Issue scan error: {e}")
    return replied

def scan_repo_commits(repo, repo_full_name, state, processed):
    """扫描单个仓库的 Commits"""
    replied = 0
    try:
        commits = repo.get_commits()
        commit_count = 0
        for commit in commits:
            if stop_scan or commit_count >= 30:
                break
            commit_count += 1
            heartbeat()
            check_timeout()
            
            sha = commit.sha
            if has_replied_to_commit(sha, state):
                continue
            
            msg = commit.commit.message
            title = msg.split('\n')[0]
            author = commit.author.login if commit.author else "unknown"
            
            full_text = title + "\n" + msg
            diff = ""
            try:
                files = repo.get_commit(sha).files
                for f in files:
                    if f.patch:
                        diff += f.patch + "\n"
                full_text += "\n" + diff
            except:
                pass
            
            for service, pattern in KEY_PATTERNS.items():
                for m in pattern.finditer(full_text):
                    key = m.group(0)
                    uid = f"commit_{sha}_{key[:16]}"
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
                            repo.get_commit(sha).create_comment(reply)
                            mark_replied_commit(sha, state)
                            save_state(state)
                            scan_results["replied_count"] += 1
                            scan_results["found_keys"].append({"type":"commit","repo":repo_full_name,"sha":sha,"service":service,"key":key,"balance":bal,"info":info})
                            replied += 1
                            print(f"      ✅ Replied to commit {sha[:8]} - {service} key")
                            time.sleep(1)
                        except Exception as e:
                            scan_results["errors"].append(str(e))
    except Exception as e:
        print(f"    Commit scan error: {e}")
    return replied

def scan_single_repo_parallel(g, repo_full_name, state, processed):
    """并行扫描单个仓库的 Code + Issues + Commits"""
    print(f"\n  📦 Scanning: {repo_full_name}")
    
    try:
        repo = g.get_repo(repo_full_name)
    except Exception as e:
        print(f"    Cannot access: {e}")
        return 0
    
    total_replied = 0
    
    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = {
            executor.submit(scan_repo_code, repo, repo_full_name, state, processed): "code",
            executor.submit(scan_repo_issues, repo, repo_full_name, state, processed): "issues",
            executor.submit(scan_repo_commits, repo, repo_full_name, state, processed): "commits",
        }
        
        for future in as_completed(futures):
            try:
                replied = future.result()
                total_replied += replied
            except Exception as e:
                scan_results["errors"].append(str(e))
    
    return total_replied

def check_and_reply():
    global last_heartbeat, stop_scan
    
    print(f"\n{'='*60}")
    print(f"🤖 LLMApiCheckBot - API Key Leak Scanner")
    print(f"📁 Self repo: {REPO_NAME}")
    print(f"⏱️  Max runtime: {MAX_RUNTIME_SECONDS}s (1.5 hours)")
    print(f"🔄 Scanning: Public repositories (infinite pages)")
    print(f"⚡ Parallel workers: {MAX_WORKERS}")
    print(f"{'='*60}\n")
    
    state = load_state()
    current_page = state.get("current_page", 1)
    print(f"📍 Starting from page {current_page}")
    print(f"📊 Processed repos: {len(state.get('processed_repos', []))}\n")
    
    auth = Auth.Token(PAT_TOKEN)
    g = Github(auth=auth)
    
    try:
        user = g.get_user()
        print(f"✅ Authenticated as: {user.login}\n")
    except Exception as e:
        print(f"❌ Auth error: {e}")
        return
    
    processed = set()
    page_replied_total = 0
    page_count = 0
    
    while not stop_scan:
        check_timeout()
        page_count += 1
        current_page = state.get("current_page", 1)
        
        print(f"\n{'='*50}")
        print(f"📄 Page {current_page}")
        print(f"{'='*50}")
        
        # 获取当前页的仓库
        repos = get_repos_by_page(g, current_page)
        
        if not repos:
            print(f"  No repositories on page {current_page}, moving to next page")
            state["current_page"] = current_page + 1
            save_state(state)
            time.sleep(PAGE_DELAY)
            continue
        
        # 取前 REPO_BATCH_SIZE 个仓库
        repos_to_scan = [r for r in repos[:REPO_BATCH_SIZE] 
                         if r != REPO_NAME and r not in state.get("processed_repos", [])]
        
        print(f"📁 Found {len(repos)} repos, scanning {len(repos_to_scan)} new ones")
        
        if not repos_to_scan:
            print(f"  No new repos on page {current_page}, moving to next page")
            state["current_page"] = current_page + 1
            save_state(state)
            time.sleep(PAGE_DELAY)
            continue
        
        page_replied = 0
        
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {executor.submit(scan_single_repo_parallel, g, repo, state, processed): repo 
                       for repo in repos_to_scan}
            
            for future in as_completed(futures):
                repo_name = futures[future]
                try:
                    replied = future.result()
                    page_replied += replied
                    page_replied_total += replied
                    
                    # 标记已处理
                    if "processed_repos" not in state:
                        state["processed_repos"] = []
                    if repo_name not in state["processed_repos"]:
                        state["processed_repos"].append(repo_name)
                    save_state(state)
                    
                except Exception as e:
                    scan_results["errors"].append(str(e))
        
        print(f"\n📊 Page {current_page} summary:")
        print(f"   ✅ Replied: {page_replied}")
        print(f"   📈 Total: {page_replied_total}")
        print(f"   📊 Keys found: {len(scan_results['found_keys'])}")
        
        # 翻到下一页
        state["current_page"] = current_page + 1
        save_state(state)
        
        print(f"\n💤 Waiting {PAGE_DELAY} seconds before next page...")
        for i in range(PAGE_DELAY):
            if stop_scan:
                break
            check_timeout()
            time.sleep(1)
    
    elapsed = time.time() - start_time
    print(f"\n{'='*60}")
    print(f"✅ Scan completed in {elapsed:.0f}s")
    print(f"📊 Processed {page_count} pages")
    print(f"📊 Found {len(scan_results['found_keys'])} valid keys")
    print(f"📊 Replied to {scan_results['replied_count']} items")
    
    if scan_results['found_keys']:
        print(f"\n🔑 Valid keys found:")
        for i, key_info in enumerate(scan_results['found_keys'], 1):
            print(f"   {i}. [{key_info['service']}] {key_info['key']}")
            print(f"      {key_info['info']}")
    
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