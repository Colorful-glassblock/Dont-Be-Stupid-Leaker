<p align="center">
  <a href="https://github.com/Colorful-glassblock/Dont-Be-Stupid-Leaker">
    <img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&size=28&pause=800&color=FF4444&center=true&vCenter=true&width=600&lines=LLMApiCheckBot+%F0%9F%94%8D;%E4%BD%A0%E7%9A%84Key%E6%AF%94%E4%BD%A0%E7%9A%84%E5%89%8D%E7%94%B7%E5%8F%8B%E8%BF%98%E5%85%AC%E5%BC%80;%E5%88%AB%E5%BD%93%E5%82%BB%E9%80%BC%E6%B3%84%E9%9C%B2%E8%80%85+QwQ"/>
  </a>
</p>

<p align="center">
  <img width="20%" src="https://count.getloli.com/@Dont-Be-Stupid-Leaker?name=Dont-Be-Stupid-Leaker&theme=random&padding=7&offset=0&align=top&scale=1&pixelated=1&darkmode=auto" alt="受害者计数" />
</p>

---

![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/Colorful-glassblock/Dont-Be-Stupid-Leaker/scan.yml?label=扫描状态)
![GitHub Issues](https://img.shields.io/github/issues/Colorful-glassblock/Dont-Be-Stupid-Leaker?label=泄露记录)
![GitHub last commit](https://img.shields.io/github/last-commit/Colorful-glassblock/Dont-Be-Stupid-Leaker?label=最后犯病)

> ⚡ **Ban Comic Sans 忠实支持者** ⚡  
> 本 README 仅使用 JetBrains Mono，拒绝 Comic Sans，保护开发者视力从我做起。

> [!IMPORTANT]
> 🚨 **致某些“天才” Fork 用户**
> 
> 最近观察到两类神人操作：
> 
> **类型 A**：脱离 Fork 网络 + 不同步上游  
> 拿着远古版本的代码到处制造误报，还觉得自己挺聪明。等你 issue 炸了别来找我哭。
> 
> **类型 B**：设为私有仓库 + 不改 `REPO_NAME`  
> 扫描结果全发回到我的仓库，给我刷了一堆垃圾通知。这么牛逼怎么不顺便把回调地址改成自己的？
> 
> **以上两位，你们的行为已经对 upstream 造成了干扰。请自行修复，或直接删库。**
> 
> 我不会再为你们的愚蠢提供任何技术支持。  
> — 原作者，不伺候巨婴 QwQ

## 🤔 这是什么

一个会嘲讽你的 GitHub Actions 机器人。你把 API Key 丢到公网，它就用阴阳怪气给你捡回来，顺便贴一张余额明细供大家传阅。

**通俗版**：你的 Key 现在是公共财产，包括那个用你余额跑 GPT-6 训练的老哥。

**哲学版**：当你凝视 `git push`，`git push` 也在凝视你的钱包。

---

## 🧠 检测格式

| 服务 | 前缀示例 | 嘲讽方向 |
|------|----------|----------|
| OpenAI | `sk-proj-...` / `sk-...` | 余额够大家用一整天 |
| OpenRouter | `sk-or-v1-...` | 中转站也逃不掉 |
| DeepSeek | `sk-...` | 国产之光，泄露之光 |
| Gemini | `AIza...` | Google 给的羊毛，大家薅 |
| Anthropic | `sk-ant-api...` | Claude 看了都摇头 |
| XAI | `xai-...` | Grok 也挽救不了你的智商 |
| HuggingFace | `hf_...` | 抱抱脸 → 打打脸 |
| Replicate | `r8_...` | 复制模型，顺便复制你的 Key |
| MiMo | `tp-...` | 小米：我报警了 |
| MiniMax | `sk-api-...` | 你的余额，大家的福利 |
| Perplexity | `pplx-...` | 困惑的不是 AI，是你 |
| GitHub | `ghp_...` / `github_pat_...` | 自己泄露自己，完美闭环 |
| Stripe | `sk_live_...` / `sk_test_...` | 钱直接打到我卡上谢谢 |

> Twilio 已被开除——验证永远失败，属于无效嘲讽，不配出现在这里。

---

## 🎭 嘲讽文案精选

**场景一：经典开局**
```
Leaker: "I committed my API key but it's private repo"
Bot:    "w 114514"
Leaker: "what?"
Bot:    "your key is now on the blockchain QwQ"
```

**场景二：日常破防**
```
Bot:    "检测到 Skill Issue"
Bot:    "正在生成嘲讽..."
Bot:    "嘲讽生成完毕 QwQ"
Bot:    "skill issue + ratio + you leak keys + L + bozo + no maidens?"
```

**场景三：经典借口**
```
Leaker: "这只是测试 Key"
Bot:    "好的，那我帮您测试一下余额——哇，还有 $420，大家快来用！"
```

**场景四：最绝望的安慰**
```
Leaker: "我马上删！"
Bot:    "已经有人 fork 了，祝你好运。"
```

---

## ⚙️ 工作原理

1. **定时巡逻**：每小时一次，比你家物业还勤快
2. **全网搜索**：扫描 GitHub 上的 commits、issues、PRs、代码文件、.env 文件
3. **密钥验证**：用各服务商 API 验证 Key 是否有效（余额也帮你查了，不客气）
4. **精准嘲讽**：有效 Key → 在原仓库评论嘲讽，并在中央仓库存档，确保社死永久化
5. **永不重复**：已嘲讽过的 Key 不会嘲讽第二次，毕竟同一件事笑两次不太好

---

## 📦 部署指南

### 英文版
1. 新建一个 GitHub 仓库（建议命名：`Dont-Be-Stupid-Leaker`，讽刺拉满）
2. 把 `.github/workflows/scan.yml` 和 `.github/scripts/scan_keys.py` 丢进去
3. 在 Settings → Secrets and variables → Actions 添加 `PAT_TOKEN`
   - 用小号的 Personal Access Token，需要 `repo` 和 `issues:write` 权限
4. Push 上去，机器人每小时自动巡逻

### 中文版
1. Fork 或新建仓库，名字越嘲讽越好
2. 复制进 workflow 和脚本文件
3. 添加 `PAT_TOKEN` 到 Secrets（小号 Token，别用大号，万一被反杀）
4. 推送，等着看别人社死

---

## 📂 文件结构

```
.github/
├── workflows/
│   └── scan.yml          # GitHub Actions 定时任务
└── scripts/
    └── scan_keys.py      # 嘲讽引擎本体
```

---

## 📋 依赖

- `PyGithub`：和 GitHub API 谈情说爱
- `requests`：HTTP 请求，敲门问 "这 Key 还好使不？"
- `PyJWT`：GitHub App 认证用的
- `urllib3`：稳如老狗的 HTTP 连接池

---

## 🛡️ 免责声明

```
本机器人仅供学习交流。
别泄露 API Key，用环境变量。
如果你被这个机器人嘲讽了，那是你菜。
如果你生气了，那是你破防了。
如果你笑了，那说明你也是乐子人。
```

---

## ⭐ 星标历史

<p align="center">
  <img src="https://api.star-history.com/svg?repos=Colorful-glassblock/Dont-Be-Stupid-Leaker&type=Date" alt="星星全是乐子人点的" />
</p>

---

## 💡 冷知识 / 常见问题

**Q: 为什么叫 Dont-Be-Stupid-Leaker？**  
A: 因为泄露 Key 的人最需要看见这行字。属于靶向治疗。

**Q: 114514？**  
A: 懂的都懂，不懂的说明你还没被嘲讽够。

**Q: 0721？**  
A: はいはいわかりました草。

**Q: QwQ？**  
A: 情绪稳定（大嘘）。

**Q: 为什么要用香农熵过滤假 Key？**  
A: 因为 `sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx` 不配被验证，连嘲讽的机会都不给。

**Q: 深度扫描是什么？**  
A: 对指定仓库的默认分支进行全文件扫描，适合手动抽查某个倒霉蛋。

**Q: 机器人会嘲讽自己吗？**  
A: 不会。我们加了去重，不然它会陷入自嘲的无限循环，那画面太美我不敢看。

---

<p align="center">
  <img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&size=20&pause=1000&color=FF69B4&center=true&vCenter=true&width=600&lines=Stop+Leaking+Keys+QwQ;%E5%88%AB%E6%B3%84%E9%9C%B2%E4%BA%86%E5%95%A6%E8%90%8C%E7%99%BE;w+114514;0721...;Skill+Issue+%2B+You+Leak+Keys+%2B+L+%2B+Bozo" alt="最后的嘲讽" />
</p>

---

<p align="center">
  <sub>Made with 💀, ☕, 114514% sarcasm, and absolutely zero Comic Sans</sub>
</p>