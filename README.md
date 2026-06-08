<!-- Language selector -->
<p align="right">
  <a href="/readmel10n/readme-zh-CN.md">中文</a> |
  <a href="/readmel10n/readme-ja-JP.md">日本語</a>
</p>

<p align="center">
  <a href="https://github.com/Colorful-glassblock/Dont-Be-Stupid-Leaker/tree/experiment/ts-rewrite">
    <img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&size=28&pause=800&color=3178C6&center=true&vCenter=true&width=600&lines=LLMApiCheckBot+%F0%9F%94%8D+TS;Rewritten+in+TypeScript+because+Python+was+too+slow;Your+key+is+still+more+public+than+your+ex"/>
  </a>
</p>

<p align="center">
  <img width="20%" src="https://count.getloli.com/@Dont-Be-Stupid-Leaker?name=Dont-Be-Stupid-Leaker&theme=random&padding=7&offset=0&align=top&scale=1&pixelated=1&darkmode=auto" alt="victim counter" />
</p>

---

![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/Colorful-glassblock/Dont-Be-Stupid-Leaker/ci.yml?branch=experiment/ts-rewrite&label=CI&color=3178C6)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/Colorful-glassblock/Dont-Be-Stupid-Leaker/scan_ts.yml?branch=experiment/ts-rewrite&label=scan%20status)
![TypeScript](https://img.shields.io/badge/TypeScript-6.0-3178C6?logo=typescript&logoColor=white)
![Node.js](https://img.shields.io/badge/Node.js-%3E%3D22-339933?logo=node.js&logoColor=white)
![pnpm](https://img.shields.io/badge/pnpm-11.x-F69220?logo=pnpm&logoColor=white)

> ⚡ **Proud supporter of Ban Comic Sans** ⚡  
> This README uses JetBrains Mono exclusively. Comic Sans is forbidden.

> [!IMPORTANT]
> 🚨 **This is the TypeScript rewrite branch**
>
> If you're looking for the original Python version, switch to `main`.
> If you're here to complain about breaking changes, skill issue.

> [!IMPORTANT]
> 🚨 **To Certain "Genius" Fork Users**
> 
> Two types of galaxy-brain behavior have been observed:
> 
> **Type A**: Detached fork + never sync upstream  
> Running ancient code, generating false positives everywhere, and somehow feeling proud of it. Don't come crying when your issues explode.
> 
> **Type B**: Private repo + unchanged `REPO_NAME`  
> All your scan results get dumped into *my* repo, flooding me with garbage notifications. If you're so smart, why not point the webhook at your own repo while you're at it?
> 
> **To both types: your actions are disrupting upstream. Fix your shit or delete your repo.**
> 
> I will not provide any technical support for your stupidity.  
> — The original author, not your babysitter QwQ

## 🤔 What is This

A GitHub Actions bot that roasts you when you accidentally leak API keys.  
Like your mom, but for tokens. It finds your exposed keys, verifies them (including balance!), then publicly shames you with a comment and an issue.

**Now rewritten in TypeScript** because Python's GIL couldn't handle the sheer volume of stupidity we need to process concurrently.

**Casual version**: Your key now belongs to everyone, including the guy who's training GPT-6 on your dime.

**Philosophical version**: When you stare into `git push`, `git push` stares into your wallet.

---

## 🧠 Detected Patterns

| Service | Prefix | Roast angle |
|---------|--------|-------------|
| OpenAI | `sk-proj-...` / `sk-...` | Balance enough for a party |
| OpenRouter | `sk-or-v1-...` | Middleman won't save you |
| DeepSeek | `sk-...` | Chinese glory, leak glory |
| Gemini | `AIza...` | Google's free tier, now everyone's |
| Anthropic | `sk-ant-api...` | Claude shakes its head |
| XAI | `xai-...` | Grok can't fix stupid |
| HuggingFace | `hf_...` | From hugging face to slapping face |
| Replicate | `r8_...` | Replicate models, replicate keys |
| MiMo | `tp-...` | Xiaomi: I'm calling the police |
| MiniMax | `sk-api-...` | Your balance, everyone's benefit |
| Perplexity | `pplx-...` | The perplexed one is you, not AI |
| GitHub | `ghp_...` / `github_pat_...` | Leaking yourself, perfect loop |
| Stripe | `sk_live_...` / `sk_test_...` | Money directly to my account, thanks |

> Twilio was fired — verification always fails, not worth the roast.

---

## 🎭 Meme Gallery

**Classic opener**
```
Leaker: "I committed my API key but it's private repo"
Bot:    "w 114514"
Leaker: "what?"
Bot:    "your key is now on the blockchain QwQ"
```

**Daily annihilation**
```
Bot:    "Skill Issue detected"
Bot:    "Generating roast..."
Bot:    "Roast generated QwQ"
Bot:    "skill issue + ratio + you leak keys + L + bozo + no maidens?"
```

**Classic excuse**
```
Leaker: "It's just a test key"
Bot:    "Okay, let me test the balance for you — wow, $420, let's all use it!"
```

**Most hopeless comfort**
```
Leaker: "I'll delete it now!"
Bot:    "Someone already forked it, good luck."
```

---

## ⚙️ How It Works

1. **Hourly patrol** — more diligent than your landlord.
2. **Global search** — scans commits, issues, PRs, code files, .env files.
3. **Key verification** — actually calls the API to check if the key is live (and reads the balance for extra pain).
4. **Bloom filter dedup** — won't waste time on keys it's already seen. O(1) memory, infinite shame.
5. **Shannon entropy filter** — `sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx` doesn't even get verified. Fake keys get filtered before they waste our API calls.
6. **LRU cache** — hot keys stay hot, cold keys get evicted. Just like your social life after leaking keys.
7. **Precision roast** — posts a comment on the original repo and archives an issue in our repo for eternal shame.

---

## 📦 Deployment

### English
1. Fork this repo (or create a new one, irony max).
2. Add secrets in Settings → Secrets and variables → Actions:
   - `PAT_TOKEN` — GitHub PAT with `repo` and `issues:write` (use an alt account, don't be stupid)
   - Or `APP_ID` + `PRIVATE_KEY` + `INSTALLATION_ID` for GitHub App auth
3. Push to `experiment/ts-rewrite`. CI runs lint + typecheck + tests. Scanner runs hourly.

### 中文
1. Fork 或新建仓库，名字越嘲讽越好。
2. 添加 Secrets：
   - `PAT_TOKEN` — 小号 Token，别用大号，万一被反杀
   - 或者 `APP_ID` + `PRIVATE_KEY` + `INSTALLATION_ID`（GitHub App 认证）
3. 推送到 `experiment/ts-rewrite`，CI 跑 lint + 类型检查 + 测试，扫描器每小时巡逻。

---

## 📂 File Structure

```
src/
├── config.ts                 # 环境变量 + 默认配置
├── index.ts                  # 入口
├── scanner.ts                # 主编排器：搜索 → 验证 → 通知 → 深扫
├── github/
│   ├── client.ts             # Octokit 封装（PAT / App 认证）
│   ├── search.ts             # Code / Issue / Commit 搜索 worker
│   └── content.ts            # 文件内容 / Issue / PR diff 获取
├── patterns/
│   └── key-patterns.ts       # 14 种 API key 正则
├── verify/
│   └── batch-manager.ts      # 批量验证队列
├── verifiers/
│   ├── verify.ts             # 验证调度
│   └── http-verifiers.ts     # 各厂商 API 验证器
├── notify/
│   ├── notifier.ts           # Issue / Comment 通知
│   └── results.ts            # 实时结果写入
├── scan/
│   ├── deep-scan.ts          # 仓库深度扫描（默认分支全文件）
│   └── shutdown.ts           # 优雅关停
├── types/
│   └── index.ts              # 类型定义
└── utils/
    ├── dedup.ts              # 去重器
    ├── entropy.ts            # Shannon 熵过滤假 key
    ├── bloom-filter.ts       # 布隆过滤器
    └── lru-cache.ts          # LRU 缓存
```

---

## 📋 Dependencies

| 包 | 用途 |
|----|------|
| `@octokit/rest` | GitHub API 客户端 |
| `@octokit/auth-app` | GitHub App 认证 |
| `dotenv` | 环境变量加载 |
| `p-limit` | 并发控制 |
| `pino` | 结构化日志 |
| `vitest` | 测试框架 |
| `typescript` | 类型系统（你正在看的语言） |
| `eslint` + `typescript-eslint` | 代码质量 |

---

## 🛡️ Disclaimer

```
This bot is for educational purposes only.
Don't leak API keys. Use environment variables.
If you get roasted by this bot, that's a skill issue.
If you get mad, that's a you problem.
If you laugh, you're one of us.
The TypeScript rewrite is not an endorsement of Microsoft.
(We just needed async/await that actually works concurrently.)
```

---

## ⭐ Star History

<p align="center">
  <img src="https://api.star-history.com/svg?repos=Colorful-glassblock/Dont-Be-Stupid-Leaker&type=Date" alt="stars are all from memers" />
</p>

---

## 💡 Trivia / FAQ

**Q: Why rewrite in TypeScript?**  
A: Python's `asyncio` is a lie. Node.js event loop goes brrrrr.

**Q: Why pnpm?**  
A: Because npm is slow and yarn is... yarn. pnpm supremacy.

**Q: Why vitest and not jest?**  
A: Because we're not savages. Also, it's faster.

**Q: What's with the bloom filter?**  
A: We process millions of search results. A bloom filter lets us say "definitely not seen" in O(1) memory. The 0.01% false positive rate just means we skip a roast we already delivered. The universe balances itself.

**Q: Shannon entropy for fake keys?**  
A: `sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx` has an entropy of 0. Real keys have entropy > 2.5. Math doesn't lie, unlike your commit messages.

**Q: 114514?**  
A: If you know, you know. If you don't, you haven't been roasted enough.

**Q: 0721?**  
A: はいはいわかりました草

**Q: QwQ?**  
A: Emotionally stable (big lie).

**Q: Will the bot roast itself?**  
A: No. We added dedup. Infinite self-roasting would be too beautiful for this world.

---

<p align="center">
  <img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&size=20&pause=1000&color=3178C6&center=true&vCenter=true&width=600&lines=Stop+Leaking+Keys+QwQ;Rewritten+in+TypeScript+because+skill+issue;async+await+%3E+asyncio;w+114514;0721...;Skill+Issue+%2B+You+Leak+Keys+%2B+L+%2B+Bozo" alt="final roast" />
</p>

---

<p align="center">
  <sub>Made with 💀, ☕, 114514% sarcasm, TypeScript 6.0, and absolutely zero Comic Sans</sub>
</p>
