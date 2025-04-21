# 🧠 sAils AI Agent
![sAils Logo](sAils_logo_small.png)
## Overview
`sAils` is a self-contained AI assistant for end-to-end smart contract and documentation analysis. It integrates two powerful internal tools:

- **VectorEyes** – vectorizes vulnerability reports and builds reusable detection patterns with CWE mapping, attack vectors, severity ratings, and detection signatures
- **DeepCurrent** – performs in-depth LLM-powered smart contract and protocol documentation analysis, including Mermaid diagrams and advanced Q&A with context

Together, they form a pipeline for:
- Smart contract auditing and call graph generation
- Protocol documentation interpretation and diagramming
- Vulnerability report digestion and clustering
- Automated detection, scanning, and insight generation using LLMs

All components are **single-file scripts** compatible with **[Astral](https://astral.sh) `uv run`** — no package management needed.

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
Supports two providers:

- `ollama` (default): local models (e.g. `deepseek-r1:32b`)
- `openrouter`: remote models (e.g. `google/gemini-2.5-pro`) — requires API key

```bash
--llm-provider ollama --ollama-model deepseek-r1:32b
# or
--llm-provider openrouter --openrouter-key sk-... --openrouter-model google/gemini-2.5-pro
```

---

## 📂 Output Structure
Results are saved in a timestamped folder like `analysis_YYYYMMDD_HHMMSS/`:

```
analysis_20250421_181800/
├── contract_A.sol/
│   ├── functions_report.md
│   ├── journey_diagram.mmd
│   ├── call_diagram.mmd
│   └── vulnerabilities.md
├── docs_whitepaper.md/
│   ├── summary.md
│   ├── key_highlights.md
│   ├── contract_breakdown.md
│   ├── function_breakdown.md
│   └── mechanics_diagram.mmd
├── vulnerability_report.md
├── smart_contracts_analysis.db
├── vectorisation.db
```

---

## 🔧 CLI Options
| Flag | Description |
|------|-------------|
| `--contracts` | Path to contract dir or file |
| `--docs` | PDFs, markdowns, or URLs |
| `--reports` | GitHub/Markdown audit reports |
| `--session` | Output folder name |
| `--vuln-scan` | Run vulnerability detection scan |
| `--vuln-scan-only` | Run detection scan on existing folder only |
| `--watch` | Watch mode for folder monitoring |
| `--llm-provider` | `ollama` or `openrouter` |
| `--ollama-model` | Ollama model name |
| `--openrouter-key` | OpenRouter API key |
| `--openrouter-model` | OpenRouter model to use |

---

## 🛠️ Project Structure

### `sAils.py` — Main AI Agent
- Coordinates the analysis pipeline
- Supports watch mode
- Orchestrates ingestion, scanning, document and contract analysis
- Automatically asks critical security questions using LLMs

### `VectorEyes.py` — Report Vectorization
- Ingests markdown reports and GitHub audit directories
- Extracts:
  - CWE and vulnerability types
  - Security research questions
  - Code examples (vulnerable & fixed)
  - Severity, attack vectors, detection signatures
- Generates and clusters detection templates via LLM
- Stores into `vectorisation.db`

### `DeepCurrent.py` — Contract & Doc Analysis
- Analyzes:
  - Smart contracts: Solidity, Vyper, Rust, Move
  - Docs: PDFs, Markdown, Web URLs
- Generates:
  - Mermaid diagrams (journey, call, mechanics)
  - Structured summaries
  - Contract/function breakdowns
  - Multi-format Q&A and session exports
- Provides vulnerability scanning and enhancement via detection library
- Stores all analysis in `smart_contracts_analysis.db`

---

## 📝 Self-Contained Scripts
Every file is ready-to-run via Astral:
```python
# /// script
# requires-python = ">=3.8"
# dependencies = [ ... ]
# ///
```
Run without installs:
```bash
uv run sAils.py --contracts ./path --vuln-scan
```

---

## 📡 Global Access
Make the agent available globally:
```bash
chmod +x sAils.py
sudo mv sAils.py /usr/local/bin/sails
```
Then run from anywhere:
```bash
sails --contracts ./contracts --vuln-scan
```

---

## 🧱 SQLite Storage
| File | Purpose |
|------|---------|
| `smart_contracts_analysis.db` | Session output, document + contract results, Q&A |
| `vectorisation.db` | Ingested audit reports and detection patterns |

---

## 📄 License
MIT License © 2025 pxng0lin / ThΞ CxgΞ
