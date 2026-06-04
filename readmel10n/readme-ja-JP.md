<p align="center">
  <a href="https://github.com/Colorful-glassblock/Dont-Be-Stupid-Leaker">
    <img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&size=28&pause=800&color=FF4444&center=true&vCenter=true&width=600&lines=LLMApiCheckBot+%F0%9F%94%8D;%E3%81%8A%E5%89%8D%E3%81%AE%E3%82%AD%E3%83%BC%E3%80%81%E5%85%83%E3%82%AB%E3%83%8E%E3%81%AB%E3%82%88%E3%82%8A%E5%85%AC%E9%96%8B%E3%81%95%E3%82%8C%E3%81%A6%E3%81%BE%E3%81%99;%E3%83%90%E3%82%AB%E3%83%AA%E3%83%BC%E3%82%AB%E3%83%BC%E3%81%AB%E3%81%AA%E3%82%8B%E3%81%AA+QwQ"/>
  </a>
</p>

<p align="center">
  <img width="20%" src="https://count.getloli.com/@Dont-Be-Stupid-Leaker?name=Dont-Be-Stupid-Leaker&theme=random&padding=7&offset=0&align=top&scale=1&pixelated=1&darkmode=auto" alt="被害者数" />
</p>

---

![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/Colorful-glassblock/Dont-Be-Stupid-Leaker/scan.yml?label=スキャン状態)
![GitHub Issues](https://img.shields.io/github/issues/Colorful-glassblock/Dont-Be-Stupid-Leaker?label=リーク記録)
![GitHub last commit](https://img.shields.io/github/last-commit/Colorful-glassblock/Dont-Be-Stupid-Leaker?label=最後の煽り)

> ⚡ **Ban Comic Sans 賛同者** ⚡  
> このREADMEはJetBrains Monoのみ使用。Comic Sansは絶対禁止。

## 🤔 これは何？

APIキーをうっかり公開しちゃった人を煽るGitHub Actionsボットです。  
まるでお母さんみたいに、あなたのキーがネットの海に流れてるのを見つけては、残高までチェックして晒し上げます。

**ざっくり言うと**：あなたのキーはもうみんなのもの。GPT-6のトレーニングに使われてるかもね。

**哲学的に言うと**：`git push`をのぞくとき、`git push`もまたあなたの財布をのぞいている。

---

## 🧠 検出パターン

| サービス | プレフィックス | 煽りポイント |
|----------|----------------|--------------|
| OpenAI | `sk-proj-...` / `sk-...` | 残高パーティー開催中 |
| OpenRouter | `sk-or-v1-...` | 中継業者も救えない |
| DeepSeek | `sk-...` | 中国の光、リークの光 |
| Gemini | `AIza...` | Googleの無料枠、みんなで分け合おう |
| Anthropic | `sk-ant-api...` | Claudeもドン引き |
| XAI | `xai-...` | Grokでもあなたのバカは治せない |
| HuggingFace | `hf_...` | 抱きしめる顔→ぶたれる顔 |
| Replicate | `r8_...` | モデルもキーも複製し放題 |
| MiMo | `tp-...` | Xiaomi「通報しますね」 |
| MiniMax | `sk-api-...` | あなたの残高、みんなの福利厚生 |
| Perplexity | `pplx-...` | 困惑してるのはAIじゃなくてあなた |
| GitHub | `ghp_...` / `github_pat_...` | 自分で自分をリーク、完全なる循環 |
| Stripe | `sk_live_...` / `sk_test_...` | 私の口座に直接送金ありがとう |

> Twilioはクビ——検証が常に失敗するので煽り損。

---

## 🎭 煽り文例集

**基本の煽り**
```
Leaker: "I committed my API key but it's private repo"
Bot:    "w 114514"
Leaker: "what?"
Bot:    "your key is now on the blockchain QwQ"
```

**日替わりフルボッコ**
```
Bot:    "スキル不足を検出"
Bot:    "煽り生成中..."
Bot:    "煽り生成完了 QwQ"
Bot:    "skill issue + ratio + you leak keys + L + bozo + no maidens?"
```

**言い訳あるある**
```
Leaker: "これはテスト用のキーです"
Bot:    "では残高をテストしますね——おや、$420も残ってますよ、みんなで使いましょう！"
```

**最後のトドメ**
```
Leaker: "今すぐ削除します！"
Bot:    "もうforkされました。ご武運を。"
```

---

## ⚙️ 動作の仕組み

1. **毎時パトロール** — 大家さんより勤勉
2. **全世界検索** — コミット、Issue、PR、コード、.envファイルをスキャン
3. **キー検証** — 実際にAPIを叩いて有効性チェック（残高も見ちゃう）
4. **精密煽り** — 元のリポジトリにコメントで煽り、中央リポジトリに永久保存
5. **二度殴らない** — 同じキーは二度煽らない（笑いの賞味期限）

---

## 📦 デプロイ方法

1. 新しいリポジトリを作成（推奨名：`Dont-Be-Stupid-Leaker`、皮肉満載）
2. `.github/workflows/scan.yml` と `.github/scripts/scan_keys.py` をコピー
3. Settings → Secrets and variables → Actions で `PAT_TOKEN` を追加（サブ垢のトークン、`repo`と`issues:write`権限）
4. プッシュ。1時間ごとに自動運行。

---

## 📂 ファイル構成

```
.github/
├── workflows/
│   └── scan.yml          # GitHub Actionsの定期実行
└── scripts/
    └── scan_keys.py      # 煽りエンジン
```

---

## 📋 依存関係

- `PyGithub` — GitHub APIとイチャイチャ
- `requests` — 「そのキーまだ使える？」とAPIに聞く
- `PyJWT` — GitHub App認証用
- `urllib3` — 安定のHTTPコネクションプール

---

## 🛡️ 免責事項

```
このボットは教育目的です。
APIキーを漏らさないで。環境変数を使いましょう。
煽られてムカついても自己責任です。
笑ったらあなたも仲間です。
```

---

## ⭐ スター履歴

<p align="center">
  <img src="https://api.star-history.com/svg?repos=Colorful-glassblock/Dont-Be-Stupid-Leaker&type=Date" alt="星は全部ネタ好き" />
</p>

---

## 💡 トリビア / よくある質問

**Q: なぜ Dont-Be-Stupid-Leaker？**  
A: リークする人にこそ見せたい名前だから。ピンポイント療法。

**Q: 114514？**  
A: わかる人にはわかる。わからなければまだ煽りが足りない。

**Q: 0721？**  
A: はいはいわかりました草

**Q: QwQ？**  
A: 感情は安定しています（大嘘）

**Q: 偽キーをシャノンエントロピーで弾く理由は？**  
A: `sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`は検証すら値しない。煽りの機会すら与えない。

**Q: ディープスキャンとは？**  
A: 特定リポジトリのデフォルトブランチを全ファイル検査する、個別指導向け機能。

**Q: ボットは自分自身を煽る？**  
A: いいえ。重複排除があるので無限自虐は起きません。その光景は美しすぎてこの世には無理。

---

<p align="center">
  <img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&size=20&pause=1000&color=FF69B4&center=true&vCenter=true&width=600&lines=Stop+Leaking+Keys+QwQ;%E3%83%AA%E3%83%BC%E3%82%AF%E3%81%99%E3%82%8B%E3%81%AA%E3%83%90%E3%82%AB;w+114514;0721...;Skill+Issue+%2B+You+Leak+Keys+%2B+L+%2B+Bozo" alt="最後の煽り" />
</p>

---

<p align="center">
  <sub>Made with 💀, ☕, 114514% sarcasm, and absolutely zero Comic Sans</sub>
</p>