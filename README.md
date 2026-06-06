<!-- Language selector -->
<p align="right">
  <a href="/readmel10n/readme-zh-CN.md">中文</a> |
  <a href="/readmel10n/readme-ja-JP.md">日本語</a>
</p>

<p align="center">
  <a href="https://github.com/Colorful-glassblock/Dont-Be-Stupid-Leaker">
    <img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&size=28&pause=800&color=FF4444&center=true&vCenter=true&width=600&lines=LLMApiCheckBot+%F0%9F%94%8D;Your+key+is+more+public+than+your+ex;Stop+being+a+stupid+leaker+QwQ"/>
  </a>
</p>

<p align="center">
  <img width="20%" src="https://count.getloli.com/@Dont-Be-Stupid-Leaker?name=Dont-Be-Stupid-Leaker&theme=random&padding=7&offset=0&align=top&scale=1&pixelated=1&darkmode=auto" alt="victim counter" />
</p>

---

![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/Colorful-glassblock/Dont-Be-Stupid-Leaker/scan.yml?label=scan%20status)
![GitHub Issues](https://img.shields.io/github/issues/Colorful-glassblock/Dont-Be-Stupid-Leaker?label=leaks%20archived)
![GitHub last commit](https://img.shields.io/github/last-commit/Colorful-glassblock/Dont-Be-Stupid-Leaker?label=last%20roast)

> ⚡ **Proud supporter of Ban Comic Sans** ⚡  
> This README uses JetBrains Mono exclusively. Comic Sans is forbidden.

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
4. **Precision roast** — posts a comment on the original repo and archives an issue in our repo for eternal shame.
5. **Never twice** — won't roast the same key again (jokes get old).

---

## 📦 Deployment

### English
1. Create a new repo (suggested name: `Dont-Be-Stupid-Leaker`, irony max).
2. Copy `.github/workflows/scan.yml` and `.github/scripts/scan_keys.py` into it.
3. Add `PAT_TOKEN` in Settings → Secrets and variables → Actions (use an alt account token with `repo` and `issues:write`).
4. Push. The bot runs every hour.

### 中文
1. Fork 或新建仓库，名字越嘲讽越好。
2. 复制进 workflow 和脚本文件。
3. 添加 `PAT_TOKEN` 到 Secrets（小号 Token，别用大号，万一被反杀）。
4. 推送，等着看别人社死。

---

## 📂 File Structure

```
.github/
├── workflows/
│   └── scan.yml          # GitHub Actions schedule
└── scripts/
    └── scan_keys.py      # The roasting engine
```

---

## 📋 Dependencies

- `PyGithub` — sweet talks GitHub API
- `requests` — knocks on APIs asking "yo this key still good?"
- `PyJWT` — for GitHub App auth
- `urllib3` — rock-solid HTTP pooling

---

## 🛡️ Disclaimer

```
This bot is for educational purposes only.
Don't leak API keys. Use environment variables.
If you get roasted by this bot, that's a skill issue.
If you get mad, that's a you problem.
If you laugh, you're one of us.
```

---

## ⭐ Star History

<p align="center">
  <img src="https://api.star-history.com/svg?repos=Colorful-glassblock/Dont-Be-Stupid-Leaker&type=Date" alt="stars are all from memers" />
</p>

---

## 💡 Trivia / FAQ

**Q: Why "Dont-Be-Stupid-Leaker"?**  
A: Because the people who leak keys are exactly the ones who need to see this name. Targeted therapy.

**Q: 114514?**  
A: If you know, you know. If you don't, you haven't been roasted enough.

**Q: 0721?**  
A: はいはいわかりました草

**Q: QwQ?**  
A: Emotionally stable (big lie).

**Q: Why use Shannon entropy to filter fake keys?**  
A: `sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx` doesn't deserve verification, not even a roast.

**Q: What's deep scan?**  
A: Full-file scan on a repo's default branch, for manual checks of a specific victim.

**Q: Will the bot roast itself?**  
A: No. We added dedup. Infinite self-roasting would be too beautiful for this world.

---

<p align="center">
  <img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&size=20&pause=1000&color=FF69B4&center=true&vCenter=true&width=600&lines=Stop+Leaking+Keys+QwQ;w+114514;0721...;Skill+Issue+%2B+You+Leak+Keys+%2B+L+%2B+Bozo" alt="final roast" />
</p>

---

<p align="center">
  <sub>Made with 💀, ☕, 114514% sarcasm, and absolutely zero Comic Sans</sub>
</p>