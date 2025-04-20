# 🧠 sAils AI Agent
![sAils Logo](sAils_small.png)
## Overview
`sAils` is a self-contained AI assistant for end-to-end smart contract and documentation analysis. It integrates two internal tools:

- **VectorEyes** – vectorizes vulnerability reports and builds reusable detection patterns
- **DeepCurrent** – performs LLM-powered analysis of smart contracts and protocol documentation

Together, they provide a pipeline for:
- Smart contract analysis
- Protocol documentation interpretation
- Vulnerability pattern extraction
- Automated detection and alerting

All components are **single-file scripts** compatible with **[Astral](https://astral.sh) `uv run`** — no installation or package management needed.

---

## 🚀 How to Use

### 🔹 Analyze a Folder of Contracts
```bash
uv run sAils.py --contracts ./contracts --vuln-scan
```

### 🔹 Add Documents and Reports
```bash
uv run sAils.py \
  --contracts ./contracts \
  --docs ./docs/spec.pdf ./docs/whitepaper.md \
  --reports https://raw.githubusercontent.com/.../audit.md \
  --vuln-scan
```

### 🔹 Watch Mode: Auto-Trigger on New Folders
```bash
uv run sAils.py --watch
```
> Watches paths like `~/Documents/web3/*` and runs analysis when new folders are created.

---

## 🧠 LLM Support
Supports two options:

- `ollama` (default): local model (e.g. `deepseek-r1:32b`)
- `openrouter`: remote models like `google/gemini-2.5-pro` (requires API key)

Set via CLI:
```bash
--llm-provider ollama --ollama-model deepseek-r1:32b
# or
--llm-provider openrouter --openrouter-key sk-... --openrouter-model google/gemini-2.5-pro
```

---

## 📂 Directory Structure
All output is saved to a timestamped `analysis_YYYYMMDD_HHMMSS` folder.

```text
analysis_20250419_152302/
├── contract_A.sol/
│   ├── functions_report.md
│   ├── journey_diagram.mmd
│   └── call_diagram.mmd
├── docs_whitepaper.md/
│   ├── summary.md
│   ├── key_highlights.md
│   └── mechanics_diagram.mmd
├── vulnerability_report.md
└── smart_contracts_analysis.db
```

---

## 🔧 Options
| Flag | Description |
|------|-------------|
| `--contracts` | Path to contract dir or file |
| `--docs` | PDFs, markdowns, or URLs |
| `--reports` | GitHub/Markdown audit reports |
| `--session` | Output folder name |
| `--vuln-scan` | Run vulnerability detection scan |
| `--watch` | Watch mode for folder monitoring |
| `--llm-provider` | `ollama` or `openrouter` |
| `--ollama-model` | Ollama model name |
| `--openrouter-key` | OpenRouter API key |
| `--openrouter-model` | OpenRouter model to use |

---

## 🛠️ Project Structure

### `sAils.py` — Main AI Agent
- Manages pipeline execution
- Watches directories if enabled
- Triggers VectorEyes and DeepCurrent

### `VectorEyes.py`
- Processes GitHub audit reports
- Extracts CWE, code, questions, patterns
- Stores patterns in SQLite (`vectorisation.db`)

### `DeepCurrent.py`
- Parses and analyzes:
  - Smart contracts: Solidity, Vyper, Move, Rust
  - Docs: PDF, Markdown, Web
- Generates:
  - Journey diagrams (Mermaid)
  - Call graphs
  - Protocol summaries and contract/function breakdowns

---

## 🧬 Fully Self-Contained
Each script includes:
```python
# /// script
# requires-python = ">=3.8"
# dependencies = [ ... ]
# ///
```
Just use:
```bash
uv run sAils.py [...args]
```
No need for pip, poetry, or manual installs.

---

## 📡 Make sAils Globally Available
```bash
chmod +x sAils.py
sudo mv sAils.py /usr/local/bin/sails
```
Then run it anywhere:
```bash
sails --contracts ./contracts --vuln-scan
```

---

## 🧱 SQLite Storage
| File | Purpose |
|------|---------|
| `smart_contracts_analysis.db` | All session data, contract + doc analysis |
| `vectorisation.db` | Vectorized audit reports + detection patterns |

---

## 📜 License
MIT License © 2025 pxng0lin/ThΞ CxgΞ
