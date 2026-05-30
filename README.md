Dont-Be-Stupid-Leaker

https://readme-typing-svg.demolab.com?font=JetBrains+Mono&size=33&pause=1000&color=FF0000&center=true&vCenter=true&width=750&lines=Your+API+Key%3F+More+Like+Your+AP-I+CHEAP!;%E4%BD%A0%E7%9A%84Key%3F%E8%A2%AB%E8%96%85%E5%85%89%E4%BA%86QwQ;w+114514;0721...;Skill+Issue+%2B+You+Leak+Keys

<p align="center">
  <a href="https://github.com/Colorful-glassblock/Dont-Be-Stupid-Leaker">
    <img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&size=32&pause=1000&color=FF4444&center=true&vCenter=true&width=500&lines=LLMApiCheckBot;%E5%88%AB%E5%BD%93%E5%82%BB%E9%80%BC%E6%B3%84%E9%9C%B2%E8%80%85"/>
  </a>
</p>

<p align="center">
  <img width="20%" src="https://count.getloli.com/@Dont-Be-Stupid-Leaker?name=Dont-Be-Stupid-Leaker&theme=random&padding=7&offset=0&align=top&scale=1&pixelated=1&darkmode=auto" alt="Visitor Count" />
</p>

---

What is This / 这是什么

```
ENG: A GitHub Actions bot that scans commits and issues for leaked API keys,
     then replies with a ~~rude~~ polite warning.
     
ZH : 一个 GitHub Actions 机器人，扫描 commits 和 issues 里泄露的 API Key，
     然后回复一条~~阴阳怪气~~友好的提醒。
```

Detected patterns / 检测格式:

· sk-proj-* / sk-* (OpenAI, DeepSeek, GLM)
· sk-or-v1-* (OpenRouter)
· AIza* (Gemini)
· sk-ant-api* (Anthropic)
· tp-* (MiMo)
· r8_* (Replicate)
· hf_* (HuggingFace)

---

Meme / 梗

```
Leaker: "I committed my API key but it's private"
Bot:    "w 114514"
Leaker: "what?"
Bot:    "your key is now on the blockchain QwQ"
Leaker: "0721..."
Bot:    "skill issue + ratio + you leak keys + L + bozo"

Bot:    "检测到 Skill Issue"
Bot:    "正在生成嘲讽..."
Bot:    "嘲讽生成完毕 QwQ"
```

---

How It Works / 工作原理

```yaml
Schedule:
  - cron: '0 * * * *'  # every hour / 每小时

Workflow:
  1. Search recent commits with key patterns
  2. Search recent issues with "your key leak"
  3. Verify each key via provider API
  4. If valid -> reply with warning
  5. Save state -> never reply twice
```

---

Deployment / 部署

ENG

1. Create a new GitHub repository (name it whatever, maybe Dont-Be-Stupid-Leaker for max irony)
2. Copy .github/workflows/scan.yml and .github/scripts/scan_keys.py to your repo
3. Add PAT_TOKEN to Secrets (Settings → Secrets and variables → Actions)
   · Use an alt account's PAT with repo and issues:write permissions
4. Push. The bot will run every hour.

中文

1. 新建一个 GitHub 仓库（建议就叫 Dont-Be-Stupid-Leaker，讽刺拉满）
2. 把 .github/workflows/scan.yml 和 .github/scripts/scan_keys.py 复制进去
3. 在 Secrets 里添加 PAT_TOKEN（Settings → Secrets and variables → Actions）
   · 用小号的 PAT，需要 repo 和 issues:write 权限
4. 推送。机器人每小时自动运行。

---

Example Reply / 回复示例

ENG

```
@someone Your API key has been exposed in a commit!

# Summary
This is a **DeepSeek** API key in commit [abc1234](https://github.com/...).

Location: code diff (line 42)
Key preview: `sk-abc123...xyz789`

Verification result: Balance: CNY 6.66, USD 0.00

---

**What to do:**
1. Revoke this key from DeepSeek dashboard
2. Generate a new key
3. Remove from git history using BFG Repo Cleaner
4. Rotate other exposed secrets

**Exposed code:**
`Authorization: Bearer sk-abc123def456...`

---
*This message was sent by LLMApiCheckBot - Repository: Dont-Be-Stupid-Leaker*
```

中文

```
@大佬 你的 API Key 在 commit 里泄露了！

# 摘要
这是一个 **DeepSeek** API key，出现在 commit [abc1234](https://github.com/...)。

位置: 代码 diff (第 42 行)
Key 预览: `sk-abc123...xyz789`

验证结果: 余额 CNY 6.66, USD 0.00

---

**建议操作:**
1. 立即在 DeepSeek 控制台吊销这个 Key
2. 生成新的 Key
3. 用 BFG Repo Cleaner 从 git 历史中删除
4. 轮换其他可能泄露的密钥

**泄露的代码:**
`Authorization: Bearer sk-abc123def456...`

---
*本消息由 LLMApiCheckBot 发送 - 仓库: Dont-Be-Stupid-Leaker*
```

---

File Structure / 文件结构

```
.github/
├── workflows/
│   └── scan.yml          # GitHub Actions workflow
└── scripts/
    └── scan_keys.py      # The bot itself / 机器人本体
```

---

Requirements / 依赖

· GitHub Token (GITHUB_TOKEN) - auto provided by Actions
· PAT_TOKEN (your alt account's token) - for replying

---

Disclaimer / 免责声明

```
ENG: This bot is for educational purposes only.
     Don't leak API keys. Use environment variables.
     If you get roasted by this bot, that's a skill issue.

ZH : 本机器人仅供学习交流。
     别泄露 API Key，用环境变量。
     如果你被这个机器人嘲讽了，那是你菜。
```

---

Star History / 星星历史

https://api.star-history.com/svg?repos=Colorful-glassblock/Dont-Be-Stupid-Leaker&type=Date

---

Trivia / 冷知识

```
Q: Why "Dont-Be-Stupid-Leaker"?
A: Because the people who leak keys are exactly the ones who need to see this name.

Q: 114514?
A: If you know, you know.

Q: 0721?
A: はいはいわかりました草

Q: QwQ?
A: 情绪稳定（大嘘）
```

---

<p align="center">
  <img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&size=20&pause=1000&color=00AAFF&center=true&vCenter=true&width=600&lines=Stop+Leaking+Keys+QwQ;%E5%88%AB%E6%B3%84%E9%9C%B2%E4%BA%86%E5%95%A6%E8%90%8C%E7%99%BE;w+114514;0721...;Skill+Issue+%2B+You+Leak+Keys"/>
</p>

---

Made with 💀, ☕, and 114514% sarcasm