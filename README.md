# 📄 README.md

<p align="center">
  <img src="sAils_logo_small.png" alt="sAils Logo" width="200"/>
</p>

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
> ✅ Performs full contract analysis followed by vulnerability scanning
> ✅ Creates a timestamped session folder with all analysis artifacts
> ✅ Generates detailed reports and diagrams for each contract

### 🔹 Vulnerability Scan Only
```bash
uv run sAils.py --contracts ./contracts --vuln-scan-only
```
> ✅ Skips the time-consuming analysis step
> ✅ Directly performs vulnerability scanning on the contracts
> ✅ Significantly faster than full analysis + scan
> ✅ Useful when you only need vulnerability detection

### 🔹 Add Documents and Reports
```bash
uv run sAils.py \
  --contracts ./contracts \
  --docs ./docs/spec.pdf ./docs/whitepaper.md \
  --reports https://raw.githubusercontent.com/.../audit.md \
  --vuln-scan
```
> ✅ Analyzes contracts, documentation, and ingests vulnerability reports
> ✅ Creates connections between all sources for comprehensive understanding
> ✅ Enhances vulnerability detection with knowledge from reports

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

### 🔹 Analyze Specific Reports by ID
```bash
uv run sAils.py --analyze-specific-reports report_id1 report_id2 --llm-provider openrouter --openrouter-key YOUR_API_KEY
```
> ✅ Analyzes only the specified reports by their IDs
> ✅ Works with both local Ollama models and OpenRouter cloud models
> ✅ Saves analysis summaries directly to the database
> ✅ Useful for targeting specific reports that need reanalysis

### 🔹 Fix Unknown Reports
```bash
uv run sAils.py --fix-unknown-reports
```
> ✅ Identifies reports with unknown vulnerability types
> ✅ Uses LLM to analyze report content and determine appropriate categories
> ✅ Creates automatic database backups before making changes
> ✅ Works with the same reports identified by --clean-reports

---

## 🔍 Vulnerability Scanning Options

sAils offers two approaches to vulnerability scanning:

### Full Analysis + Vulnerability Scan (`--vuln-scan`)

The standard approach performs a complete analysis of the contracts before running vulnerability detection:

```bash
uv run sAils.py --contracts ./contracts --vuln-scan
```

- ✅ Performs deep semantic analysis of contract code
- ✅ Generates comprehensive reports, diagrams, and insights
- ✅ Identifies complex vulnerability patterns
- ✅ Takes longer to complete but provides more context

### Vulnerability Scan Only (`--vuln-scan-only`)

The optimized approach skips the analysis step and directly performs vulnerability scanning:

```bash
uv run sAils.py --contracts ./contracts --vuln-scan-only
```

- ✅ Significantly faster than full analysis + scan
- ✅ Focuses exclusively on vulnerability detection
- ✅ Uses the same detection library and patterns
- ✅ Ideal for quick security checks or when you've already analyzed the contracts
- ✅ Perfect for CI/CD pipelines where speed is important

#### When to use `--vuln-scan-only`:

- When you need quick vulnerability detection without full analysis
- For regular security checks during development
- When you've already analyzed the contracts and only want to check for vulnerabilities
- In automated testing pipelines where speed is critical

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

### Advanced JSON Extraction

Both LLM providers now feature robust JSON extraction capabilities:

- Multiple extraction strategies for handling various response formats
- Code block extraction for JSON wrapped in markdown code blocks
- Brace matching to find complete JSON objects
- Incremental substring parsing for partially valid JSON
- Fallback to structured markdown extraction when JSON parsing fails
- Automatic field validation and default value handling

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
| Flag | Description | Example |
|------|-------------|--------|
| `--contracts` | Path to contract directory or file | `--contracts ./contracts` |
| `--docs` | PDFs, markdowns, or URLs to analyze | `--docs ./docs/spec.pdf ./whitepaper.md` |
| `--reports` | GitHub/Markdown audit reports to ingest | `--reports https://github.com/user/repo/audit.md` |
| `--session` | Custom output folder name | `--session my_analysis_session` |
| `--vuln-scan` | Run vulnerability detection scan after analysis | `--vuln-scan` |
| `--vuln-scan-only` | Skip analysis and run only vulnerability scan | `--vuln-scan-only --contracts ./contracts` |
| `--watch` | Watch mode for folder monitoring | `--watch` |
| `--qa-mode` | Run in Q&A mode for analyzed contracts | `--qa-mode --session my_session` |
| `--analyze-reports` | Analyze ingested reports with LLM | `--analyze-reports` |
| `--analyze-specific-reports` | Analyze specific reports by their IDs | `--analyze-specific-reports report_id1 report_id2` |
| `--web-portfolio` | URL to a web portfolio for report ingestion | `--web-portfolio https://cantina.xyz/portfolio` |
| `--site-type` | Type of site to scrape (auto, cantina, generic) | `--site-type cantina` |

### LLM Provider Options
| Flag | Description | Example |
|------|-------------|--------|
| `--llm-provider` | Choose LLM backend: 'ollama' or 'openrouter' | `--llm-provider ollama` |
| `--ollama-model` | Local Ollama model name | `--ollama-model deepseek-r1:32b` |
| `--openrouter-key` | OpenRouter API key for cloud LLM usage | `--openrouter-key sk-...` |
| `--openrouter-model` | OpenRouter model to use | `--openrouter-model google/gemini-2.5-pro` |
| `--analysis-model` | Specific model for analysis tasks | `--analysis-model deepseek-r1:32b` |
| `--query-model` | Specific model for query tasks | `--query-model deepseek-r1:32b` |
| `--test-llm-connection` | Test connection to LLM provider | `--test-llm-connection` |

### Vulnerability Library Management
| Flag | Description | Example |
|------|-------------|--------|
| `--view-vuln-library` | View the vulnerability detection library | `--view-vuln-library` |
| `--vuln-detail` | Show detailed info for a vulnerability type | `--vuln-detail "Reentrancy"` |
| `--export-vuln-library` | Export the vulnerability library to markdown | `--export-vuln-library vuln_lib.md` |
| `--build-vuln-library` | Rebuild the vulnerability detection library | `--build-vuln-library` |
| `--build-direct-templates` | Build templates directly from reports | `--build-direct-templates --min-examples 3` |
| `--min-examples` | Minimum code examples for template building | `--min-examples 2` |
| `--recategorize-other-vulns` | Recategorize 'Other' vulnerabilities | `--recategorize-other-vulns` |
| `--fix-unknown-reports` | Fix reports with unknown vulnerability types | `--fix-unknown-reports` |
| `--clean-reports` | Clean reports with unknown vulnerability types | `--clean-reports` |
| `--diagnose-library` | Run diagnostic tests on the vulnerability library | `--diagnose-library` |
| `--rebuild-with-llm` | Use LLM to rebuild the vulnerability library | `--rebuild-with-llm --api ollama` |
| `--api` | API to use for the rebuild process | `--api openrouter` |

### LLM Enhancement Options
| Flag | Description | Example |
|------|-------------|--------|
| `--enhance-library` | Enhance library with LLM-optimized features | `--enhance-library` |
| `--semantic-search` | Search vulnerabilities semantically | `--semantic-search "price manipulation"` |
| `--llm-prompt` | Generate LLM detection prompt | `--llm-prompt "Reentrancy"` |
| `--llm-model` | Target LLM model for prompt generation | `--llm-model gpt-4` |
| `--openai-compatible` | Make prompts OpenAI API compatible | `--openai-compatible` |

### Database Management
| Flag | Description | Example |
|------|-------------|--------|
| `--merge-databases` | Merge databases from another sAils directory | `--merge-databases /path/to/other/sAils` |
| `--no-llm-merge` | Disable LLM for similarity detection during merge | `--no-llm-merge` |

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