# 📄 README.md — Updated with LLM-Enhanced Vulnerability Detection

# 🧠 sAils AI Agent

## Overview
`sAils` is a self-contained AI assistant for end-to-end smart contract and documentation analysis. It integrates two internal tools:

- **VectorEyes** – vectorizes vulnerability reports and builds reusable detection patterns with LLM-enhanced capabilities
- **DeepCurrent** – performs LLM-powered analysis of smart contracts and protocol documentation

Together, they provide a pipeline for:
- Smart contract analysis
- Protocol documentation interpretation
- Vulnerability pattern extraction and semantic search
- LLM-optimized detection templates and prompts
- Automated detection and alerting
- Post-analysis Q&A (interactive and automated)

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
> ✅ Prompts you to enter a glob path like `~/Documents/web3/*`
> ✅ Watches recursively for new folders
> ✅ Triggers full analysis, vuln scan, interactive Q&A, and invasive LLM probing

### 🔹 Recategorize Vulnerabilities
```bash
uv run sAils.py --recategorize-other-vulns
```
> ✅ Uses LLM to analyze and recategorize vulnerabilities labeled as 'Other'
> ✅ Assigns specific vulnerability types and CWE numbers when possible
> ✅ Merges duplicate entries and handles conflicts automatically
> ✅ Provides detailed statistics on recategorization results

### 🔹 Fix Unknown Reports
```bash
uv run sAils.py --fix-unknown-reports
```
> ✅ Identifies reports with unknown vulnerability types
> ✅ Uses LLM to analyze report content and determine appropriate categories
> ✅ Creates automatic database backups before making changes
> ✅ Works with the same reports identified by --clean-reports

---

## 🔬 Post-Analysis Intelligence

`sAils` now includes **interactive and automated audit Q&A**:

- 🔹 `ask_questions_about_analysis()` launches an interactive session
- 🔹 Auto-generated probing questions like:
  - "What does this contract rely on that it doesn’t control?"
  - "How would it behave under denial-of-service attempts?"
  - "Are any assumptions unjustified?"
- ✅ Answers are saved to `automated_insights.md` in the session folder
- ✅ Q&A runs after each session (watch mode or CLI mode)

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
All output is saved to a timestamped `analysis_YYYYMMDD_HHMMSS` folder within a centralized `sessions` directory in your sAils installation. This ensures that all session data is stored in one location regardless of where you run sAils from.

```text
sAils/sessions/
└── analysis_20250419_152302/
    ├── contract_A.sol/
    │   ├── functions_report.md
    │   ├── journey_diagram.mmd
    │   └── call_diagram.mmd
    ├── docs_whitepaper.md/
    │   ├── summary.md
    │   ├── key_highlights.md
    │   └── mechanics_diagram.mmd
    ├── automated_insights.md
    ├── vulnerability_report.md
    └── smart_contracts_analysis.db
```

> ✅ Sessions are always stored in a central location
> ✅ Accessible from any working directory
> ✅ Easy to manage and reference across projects

---

## 🔧 Options

### Core Options
| Flag | Description |
|------|-------------|
| `--contracts` | Path to contract dir or file |
| `--docs` | PDFs, markdowns, or URLs |
| `--reports` | GitHub/Markdown audit reports |
| `--session` | Output folder name |
| `--vuln-scan` | Run vulnerability detection scan |
| `--watch` | Watch mode for folder monitoring |

### LLM Provider Options
| Flag | Description |
|------|-------------|
| `--llm-provider` | `ollama` or `openrouter` |
| `--ollama-model` | Ollama model name |
| `--openrouter-key` | OpenRouter API key |
| `--openrouter-model` | OpenRouter model to use |
| `--analysis-model` | Specific model for analysis tasks |
| `--query-model` | Specific model for query tasks |
| `--test-llm-connection` | Test connection to LLM provider and show available models |

### Vulnerability Library Management
| Flag | Description |
|------|-------------|
| `--view-vuln-library` | View the vulnerability detection library |
| `--vuln-detail` | Show detailed information for a specific vulnerability type |
| `--export-vuln-library` | Export the vulnerability library to a markdown file |
| `--build-vuln-library` | Rebuild the vulnerability detection library using LLM analysis |
| `--recategorize-other-vulns` | Recategorize vulnerabilities labeled as 'Other' into specific types using LLM analysis |
| `--fix-unknown-reports` | Fix reports with unknown vulnerability types and assign proper categories |
| `--clean-reports` | Clean reports with unknown vulnerability types |

### LLM Enhancement Options
| Flag | Description |
|------|-------------|
| `--enhance-library` | Enhance the vulnerability library with LLM-optimized features |
| `--semantic-search` | Search vulnerabilities semantically using natural language |
| `--llm-prompt` | Generate an LLM detection prompt for a specific vulnerability type |
| `--llm-model` | Specify target LLM model for prompt generation (affects context size) |
| `--openai-compatible` | Make generated prompts compatible with OpenAI API format |

---

## 🦹 LLM-Enhanced Vulnerability Library

The sAils vulnerability detection library has been enhanced with advanced LLM capabilities to provide more robust and effective analysis:

### Using OpenAI-Compatible Format with OpenRouter

The `--openai-compatible` flag formats vulnerability detection prompts to work with OpenAI API structure, which is also compatible with OpenRouter. Here are some examples:

#### Example 1: Generate an OpenRouter-compatible prompt

```bash
# Generate a prompt for detecting reentrancy vulnerabilities that works with OpenRouter
uv run sAils.py --llm-prompt "Reentrancy (CWE-841)" --openai-compatible --llm-model claude-3-opus
```

This will output a formatted JSON prompt structure compatible with OpenRouter's API.

#### Example 2: Run a vulnerability scan using OpenRouter

```bash
# Run a vulnerability scan on contract files using OpenRouter
uv run sAils.py --contracts ./my_contracts/ --llm-provider openrouter --openrouter-key "your_key_here" --openrouter-model "anthropic/claude-3-opus-20240229"
```

#### Example 3: Generate and save a prompt for later use

```bash
# Generate and save a prompt for integer overflow detection
uv run sAils.py --llm-prompt "Integer Overflow/Underflow (CWE-190)" --openai-compatible --llm-model gpt-4-turbo --export-prompt ./prompts/integer_overflow.json
```

### Key Features
- **Vector Embeddings** for semantic similarity search
- **LLM-optimized prompt templates** for each vulnerability type
- **Batch processing** for handling large datasets efficiently
- **OpenRouter integration** for using powerful hosted models
- **Semantic search** for finding vulnerabilities by description

### Usage Examples

#### Semantic Vulnerability Search
```bash
uv run sAils.py --semantic-search "reentrancy vulnerabilities in token transfers"
```

#### Generate LLM Detection Prompt
```bash
uv run sAils.py --llm-prompt "Reentrancy (CWE-841)" --llm-model "gpt-4"
```

#### Export Vulnerability Library
```bash
uv run sAils.py --export-vuln-library "vulnerability_library.md"
```

#### View Detailed Vulnerability Information
```bash
uv run sAils.py --vuln-detail "Integer Overflow"
```

## 🔧 Integrated Vulnerability Tools

All specialized vulnerability management tools are now integrated directly in the main sAils.py application:

### Library Rebuilding
Rebuild the vulnerability library using powerful LLM clustering:
```bash
# Using the built-in rebuild functionality
uv run sAils.py --build-vuln-library

# Using dedicated LLM-powered rebuild process (better for complex libraries)
uv run sAils.py --rebuild-with-llm --api openrouter --openrouter-key YOUR_KEY --openrouter-model MODEL_NAME
```

### Library Diagnostics
Automatically diagnose and fix issues in the vulnerability library:
```bash
uv run sAils.py --diagnose-library
```
This tool performs:
- Schema validation and updates
- Validation of vulnerability details
- Error fixing for malformed entries
- Library status reporting
- Comprehensive report generation

### LLM Enhancements
Use LLM-specific enhancements directly from the main application:
```bash
# Enhance the library with LLM features
uv run sAils.py --enhance-library

# Semantic search for vulnerabilities
uv run sAils.py --semantic-search "privilege escalation"

# Generate detection prompt for a specific vulnerability
uv run sAils.py --llm-prompt "Reentrancy" --llm-model "gpt-4"
```

### Advanced Options
Additional options for library management:
```bash
# View vulnerabilities in the library
uv run sAils.py --view-vuln-library

# View details about a specific vulnerability
uv run sAils.py --vuln-detail "Integer Overflow"

# Export the full library to markdown
uv run sAils.py --export-vuln-library "vulnerability_library.md"

# Build templates directly from reports with minimal clustering
uv run sAils.py --build-direct-templates

# Build direct templates with a specific minimum example count
uv run sAils.py --build-direct-templates --min-examples 3
```

## 📛 SQLite Storage & Management
| File | Purpose |
|------|--------|
| `smart_contracts_analysis.db` | All session data, contract + doc analysis |
| `vectorisation.db` | Vectorized audit reports + detection patterns |

### Database Merging
Merge databases from another sAils installation into your current one:

```bash
# Merge databases from another directory
uv run sAils.py --merge-databases /path/to/other/sails/installation

# Merge without using LLM for similarity detection (faster but less accurate)
uv run sAils.py --merge-databases /path/to/other/installation --no-llm-merge
```

This feature lets you consolidate data from multiple sAils installations, automatically handling:
- Deduplication of reports, templates, contracts, and documents
- Intelligent merging of vulnerability descriptions using LLM
- Preservation of unique code examples and detectors
- Smart conflict resolution

---

## 📜 License
MIT License © 2025 pxng0lin/ThΞ CxgΞ