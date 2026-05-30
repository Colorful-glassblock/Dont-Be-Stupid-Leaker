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

PAT_TOKEN = os.environ.get("PAT_TOKEN")
if not PAT_TOKEN:
    print("Error: PAT_TOKEN not set")
    sys.exit(1)

REPO_NAME = os.environ.get("GITHUB_REPOSITORY", "Colorful-glassblock/Dont-Be-Stupid-Leaker")
BOT_NAME = "LLMApiCheckBot"
BOT_SIGNATURE = f"*This message was sent by {BOT_NAME} - Repository: {REPO_NAME}*"

ISSUE_QUERY = '"your key leak"'
CODE_QUERY = 'sk- OR sk-proj- OR AIza OR sk-ant-api OR r8_ OR hf_ OR tp- extension:json OR extension:env OR extension:yaml OR extension:txt OR extension:md'

MAX_ISSUE_PAGES = 5   # 最多5页，避免403
MAX_CODE_PAGES = 5    # 最多5页
PER_PAGE = 30

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
            return json.load(f)
    except:
        return {"replied_codes": [], "replied_issues": []}

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
    "Cohere": re.compile(r"[a-zA-Z0-9]{40}"),
    "Replicate": re.compile(r"r8_[a-zA-Z0-9]{32,}"),
    "HuggingFace": re.compile(r"hf_[a-zA-Z0-9]{30,}"),
    "MiMo": re.compile(r"tp-[a-zA-Z0-9]{10,}"),
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

def build_code_reply(author, service, key, info, repo_url, file_path, line_num, line_content, balance):
    masked = key[:12] + "..." + key[-8:] if len(key) > 24 else key
    loc = f"File: {file_path}" + (f" (line {line_num})" if line_num else "")
    return f"@{author} Your API key has been exposed in a code file!\n\n# Summary\nThis is a **{service}** API key found in [{repo_url}]({repo_url}).\n\n{loc}\nKey preview: `{masked}`\n\nVerification result: {info}\n\n---\n\n**What to do:**\n1. Revoke this key from {service} dashboard\n2. Generate a new key\n3. Remove the key from the file and force-push\n4. Rotate other exposed secrets\n\n**Exposed code:**\n```\n{line_content[:300] if line_content else 'Content too long'}\n```\n\n---\n{BOT_SIGNATURE}"

def build_issue_reply(author, service, key, info, issue_url, location_type, line_num, line_content, balance):
    masked = key[:12] + "..." + key[-8:] if len(key) > 24 else key
    loc = f"Location: {location_type}" + (f" (line {line_num})" if line_num else "")
    return f"@{author} Your API key has been exposed in this issue!\n\n# Summary\nThis is a **{service}** API key in issue [#{issue_url.split('/')[-1]}]({issue_url}).\n\n{loc}\nKey preview: `{masked}`\n\nVerification result: {info}\n\n---\n\n**What to do:**\n1. Revoke this key from {service} dashboard\n2. Generate a new key\n3. Edit or delete the issue/comment containing the key\n4. Rotate other exposed secrets\n\n**Exposed content:**\n```\n{line_content[:300] if line_content else 'Content too long'}\n```\n\n---\n{BOT_SIGNATURE}"

def has_replied_to_code(file_id, state):
    return file_id in state.get("replied_codes", [])

def has_replied_to_issue(issue_id, state):
    return str(issue_id) in state.get("replied_issues", [])

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
    print(f"Saved to {fname}")

def search_issues_paginated(g, query, max_pages=MAX_ISSUE_PAGES):
    """Paginate issues to avoid 403"""
    all_items = []
    for page in range(1, max_pages + 1):
        try:
            items = list(g.search_issues(query, sort="created", order="desc")[PER_PAGE*(page-1):PER_PAGE*page])
            if not items:
                break
            all_items.extend(items)
            print(f"  Issues page {page}: {len(items)} items")
            time.sleep(0.5)
        except GithubException as e:
            if e.status == 403:
                print(f"  Rate limited, stopping issues search at page {page}")
                break
            else:
                raise
        except Exception as e:
            print(f"  Error on page {page}: {e}")
            break
    return all_items[:50]

def search_code_paginated(g, query, max_pages=MAX_CODE_PAGES):
    """Paginate code search"""
    all_items = []
    for page in range(1, max_pages + 1):
        try:
            items = list(g.search_code(query)[PER_PAGE*(page-1):PER_PAGE*page])
            if not items:
                break
            all_items.extend(items)
            print(f"  Code page {page}: {len(items)} items")
            time.sleep(0.5)
        except GithubException as e:
            if e.status == 403:
                print(f"  Rate limited, stopping code search at page {page}")
                break
            else:
                raise
        except Exception as e:
            print(f"  Error on page {page}: {e}")
            break
    return all_items[:50]

def check_and_reply():
    global last_heartbeat
    
    print(f"Starting scan on {REPO_NAME}")
    print(f"Max runtime: {MAX_RUNTIME_SECONDS}s (1.5 hours)")
    
    state = load_state()
    print(f"Loaded state: {len(state.get('replied_codes', []))} code files, {len(state.get('replied_issues', []))} issues already replied")
    
    auth = Auth.Token(PAT_TOKEN)
    g = Github(auth=auth)
    
    try:
        user = g.get_user()
        print(f"Authenticated as: {user.login}")
    except Exception as e:
        print(f"Auth error: {e}")
        return
    
    try:
        repo = g.get_repo(REPO_NAME)
        print(f"Repository: {repo.full_name}")
    except Exception as e:
        print(f"Error accessing repo: {e}")
        return
    
    processed = set()
    
    # ========== Code Search ==========
    print("\n--- Scanning code files ---")
    try:
        code_results = search_code_paginated(g, CODE_QUERY)
        total = len(code_results)
        print(f"Found {total} code files to check")
        
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
            
            print(f"[{idx+1}/{total}] Checking {repo_name}/{file_path}")
            
            content = ""
            try:
                resp = requests.get(raw_url, timeout=10)
                if resp.status_code == 200:
                    content = resp.text
            except Exception as e:
                print(f"  Error fetching file: {e}")
                continue
            
            for service, pattern in KEY_PATTERNS.items():
                for m in pattern.finditer(content):
                    key = m.group(0)
                    uid = f"code_{file_id}_{key[:16]}"
                    if uid in processed:
                        continue
                    print(f"  Found {service} key: {key[:20]}...")
                    
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
                            issue_title = f"API Key Leak Detected in {file_path}"
                            new_issue = code_repo.create_issue(title=issue_title, body=reply, labels=["security"])
                            mark_code_replied(file_id, state)
                            save_state(state)
                            scan_results["replied_count"] += 1
                            scan_results["found_keys"].append({"type":"code","repo":repo_name,"file":file_path,"service":service,"key":key,"balance":bal,"info":info})
                            print(f"  Created issue #{new_issue.number} for {repo_name}")
                            time.sleep(1)
                        except Exception as e:
                            scan_results["errors"].append(str(e))
                            print(f"  Failed: {e}")
                    else:
                        print(f"  Invalid: {info}")
            time.sleep(0.3)
    except Exception as e:
        scan_results["errors"].append(str(e))
        print(f"Code scan error: {e}")
    
    # ========== Scan Issues ==========
    print("\n--- Scanning issues ---")
    try:
        issues = search_issues_paginated(g, ISSUE_QUERY)
        total = len(issues)
        print(f"Found {total} issues to check")
        
        for idx, issue in enumerate(issues):
            heartbeat()
            check_timeout()
            
            num = issue.number
            if has_replied_to_issue(num, state):
                continue
            
            title = issue.title
            body = issue.body or ""
            author = issue.user.login
            print(f"[{idx+1}/{total}] Checking issue #{num} by {author}")
            
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
                    elif key in comments:
                        lines = comments.split('\n')
                        for i, l in enumerate(lines):
                            if key in l:
                                line_num = i + 1
                                line_content = l.strip()[:200]
                                break
                        loc = "issue comment"
                    
                    valid, bal, info = verify_key(service, key)
                    if valid:
                        processed.add(uid)
                        reply = build_issue_reply(author, service, key, info, issue.html_url, loc, line_num, line_content, bal)
                        try:
                            repo.get_issue(number=num).create_comment(reply)
                            mark_issue_replied(num, state)
                            save_state(state)
                            scan_results["replied_count"] += 1
                            scan_results["found_keys"].append({"type":"issue","number":num,"service":service,"key":key,"balance":bal,"info":info})
                            print(f"  Replied to issue #{num}")
                            time.sleep(1)
                        except Exception as e:
                            scan_results["errors"].append(str(e))
                            print(f"  Failed: {e}")
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