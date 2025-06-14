#!/usr/bin/env python
# VectorEyes.py
# /// script
# requires-python = ">=3.8"
# dependencies = [
#     "requests",
#     "tqdm",
#     "sentence-transformers",
#     "regex",
#     "rich",
#     "numpy",
#     "ollama>=0.1.6"
# ]
# ///

"""
VectorEyes - Vulnerability Report Vectorisation & Detection Library Builder

Features:
1. Accept a URL (Markdown file or GitHub repo) for a vulnerability report.
2. Download, embed, and call a local LLM to extract:
   • Vulnerability type (with CWE if available)
   • Three key security research questions
   • Dual code snippets (vulnerable/fixed)
   • Researcher insights
3. Save the report data (and a detection pattern) in a SQLite DB.
4. Build a comprehensive detection library by aggregating reports per vulnerability category.
5. Use the LLM to generate robust aggregated detection templates.
6. Save the aggregated library and robust detection templates to a new table in the database.
7. View the detection library.
8. Delete one or all detection library entries.
"""

import os, sys, time, json, sqlite3, hashlib, threading, requests, re, numpy as np
from datetime import datetime
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import ollama  # Import the ollama-python client
from bs4 import BeautifulSoup  # For parsing HTML content
import json

# Simplified API key management (session-only, not saved to disk)
# No longer using external api_keys module for more secure API key handling
print("Using secure session-based API key management")
# Removing SentenceTransformer dependency to avoid compatibility issues
# from sentence_transformers import SentenceTransformer
from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table
from rich.layout import Layout
from rich.panel import Panel
from rich.align import Align
from rich.box import SIMPLE

# ---------------------- Global & Console Setup ----------------------
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
VECTOR_DB_PATH = os.path.join(SCRIPT_DIR, "vectorisation.db")
DEEP_DB_PATH = os.path.join(SCRIPT_DIR, "smart_contracts_analysis.db")


DB_PATH = VECTOR_DB_PATH
console = Console()
task_status = {}    # For background task statuses
task_lock = threading.Lock()

# ---------------------- Database Functions ----------------------
def init_db():
    """Initialize database tables for vectorized report storage and detection library."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Create or update the main reports table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS reports (
            id TEXT PRIMARY KEY,
            source TEXT,
            content TEXT,
            overall_embedding TEXT,
            section_embeddings TEXT,
            analysis_summary TEXT,
            metadata TEXT
        )
    ''')
    
    # Create or update patterns table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS patterns (
            report_id TEXT PRIMARY KEY,
            pattern TEXT
        )
    ''')
    
    # Create or update detection library table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS detection_library (
            vuln_type TEXT PRIMARY KEY,
            details TEXT,
            template TEXT
        )
    ''')
    
    conn.commit()
    conn.close()
    
    # Create cache directory for API responses
    CACHE_DIR = os.path.join(SCRIPT_DIR, "cache")
    if not os.path.exists(CACHE_DIR):
        os.makedirs(CACHE_DIR, exist_ok=True)

def save_report(report_id, source, content, overall_embedding, section_embeddings, analysis_summary, metadata):
    """Save a processed report into the reports table."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        INSERT OR REPLACE INTO reports 
        (id, source, content, overall_embedding, section_embeddings, analysis_summary, metadata)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (
        report_id,
        source,
        content,
        json.dumps(overall_embedding),
        json.dumps(section_embeddings),
        json.dumps(analysis_summary),
        json.dumps(metadata)
    ))
    conn.commit()
    conn.close()

def save_pattern(report_id, pattern):
    """Save a detection pattern (extracted from analysis) to the patterns table."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        INSERT OR REPLACE INTO patterns
        (report_id, pattern)
        VALUES (?, ?)
    ''', (report_id, pattern))
    conn.commit()
    conn.close()

def view_reports():
    """Display all processed reports in a table."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, source, metadata FROM reports")
    rows = c.fetchall()
    conn.close()
    if not rows:
        console.print("[yellow]No reports found.[/yellow]")
        return
    table = Table(title="Vectorized Reports", show_lines=True)
    table.add_column("Report ID", style="cyan")
    table.add_column("Source", style="magenta")
    table.add_column("Downloaded At", style="green")
    for row in rows:
        try:
            metadata = json.loads(row[2])
            downloaded_at = metadata.get("downloaded_at", "N/A")
        except Exception:
            downloaded_at = "N/A"
        table.add_row(row[0], row[1], downloaded_at)
    console.print(table)

def delete_report(report_id: str):
    """Delete a single report and its associated pattern."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM reports WHERE id=?", (report_id,))
    c.execute("DELETE FROM patterns WHERE report_id=?", (report_id,))
    conn.commit()
    conn.close()

def delete_all_reports():
    """Delete all reports and associated patterns."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM reports")
    c.execute("DELETE FROM patterns")
    conn.commit()
    conn.close()

def delete_reports():
    """Prompt to delete a single report or all reports."""
    choice = console.input("Delete a single report or all reports? (single/all): ").strip().lower()
    if choice == "single":
        report_id = console.input("Enter the Report ID to delete: ").strip()
        delete_report(report_id)
        console.print(f"[green]Deleted report {report_id}.[/green]")
    elif choice == "all":
        confirm = console.input("Are you sure you want to delete ALL reports? (Y/N): ").strip().lower()
        if confirm == "y":
            delete_all_reports()
            console.print("[green]All reports deleted.[/green]")
        else:
            console.print("[yellow]Deletion cancelled.[/yellow]")
    else:
        console.print("[red]Invalid choice. No reports deleted.[/red]")

# ---------------------- Utility Functions ----------------------
def download_markdown(url: str) -> str:
    """Download a Markdown file from a URL; adjust URL if GitHub blob."""
    if "github.com" in url and "/blob/" in url:
        url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
    try:
        r = requests.get(url)
        return r.text if r.status_code == 200 else None
    except Exception:
        return None

def compute_embedding(text: str, model_instance=None) -> list:
    """Compute a simple hash-based embedding for text (fallback method)
    
    This is a simplified embedding that hashes the text and converts to vector.
    It's not as good as a proper embedding model but works without dependencies.
    """
    # Create a simpler representation based on hashing
    # This won't have the semantic properties of a real embedding, but can work for basic similarity
    if not text:
        return [0.0] * 64  # Return a zero vector if text is empty
    
    # Get a stable hash from the text
    h = hashlib.sha256(text.encode('utf-8')).digest()
    
    # Convert the 32-byte hash to 64 float values between -1 and 1
    # by treating each byte as two 4-bit values
    result = []
    for byte in h:
        # Extract the high 4 bits and low 4 bits
        high = (byte >> 4) & 0xF
        low = byte & 0xF
        # Convert to values between -1 and 1
        result.append((high / 7.5) - 1.0)  # -1.0 to 1.0
        result.append((low / 7.5) - 1.0)   # -1.0 to 1.0
    
    return result

def split_into_sections(text: str) -> list:
    """Split Markdown text into sections based on headings."""
    sections = text.split("\n#")
    results = []
    for sec in sections:
        if sec.strip():
            if sec.startswith("#"):
                sec = sec[1:]
            lines = sec.splitlines()
            title = lines[0].strip() if lines else "Introduction"
            content = "\n".join(lines[1:]).strip() if len(lines) > 1 else ""
            results.append({"title": title, "content": content})
    return results

def should_ignore_file(url: str) -> bool:
    """Ignore files with 'readme' in the URL."""
    return "readme" in url.lower()

def report_already_exists(report_id: str) -> bool:
    """Check if a report with the given ID already exists."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT 1 FROM reports WHERE id=?", (report_id,))
    exists = c.fetchone() is not None
    conn.close()
    return exists

# ---------------------- LLM Analysis Functions ----------------------
# Ollama API settings
LLM_API_BASE = os.getenv("LLM_API_BASE", "http://localhost:11434")
# The ollama-python client handles these URLs internally
LLM_API_GENERATE = os.getenv("LLM_API_GENERATE", f"{LLM_API_BASE}/api/generate")
LLM_API_URL = os.getenv("LLM_API_URL", f"{LLM_API_BASE}/v1/completions")

# Configure Ollama client to use the right base URL
try:
    # Set the host for the ollama client
    ollama.host = LLM_API_BASE
except Exception as e:
    console.print(f"[yellow]Warning: Failed to configure Ollama client: {e}[/yellow]")

# Use API key management system if available
# Session-based API key management
# Initialize from environment variables or use defaults
USE_API = os.environ.get("USE_API", "auto")  # auto, ollama, openrouter
OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY", "")
OPENROUTER_DATA_USAGE = os.environ.get("OPENROUTER_DATA_USAGE", "opt-out-from-training")
DEFAULT_MODEL = os.environ.get("DEFAULT_MODEL", "anthropic/claude-3-haiku")
DEFAULT_OLLAMA_MODEL = os.environ.get("DEFAULT_OLLAMA_MODEL", "deepseek-r1:32b")
BACKUP_MODELS = ["deepseek/deepseek-v3-base:free", "meta-llama/llama-3-8b-instruct:free", "mistralai/mistral-7b-instruct-v0.2:free"]

# Helper functions to set API configuration
def set_openrouter_api_key(api_key):
    """Set the OpenRouter API key globally."""
    global OPENROUTER_API_KEY
    OPENROUTER_API_KEY = api_key
    os.environ["OPENROUTER_API_KEY"] = api_key
    
def set_api_preference(preference):
    """Set the API preference globally (auto, ollama, or openrouter)."""
    global USE_API
    if preference in ["auto", "ollama", "openrouter"]:
        USE_API = preference
        os.environ["USE_API"] = preference
    else:
        console.print(f"[yellow]Invalid API preference: {preference}. Using 'auto'.[/yellow]")
        USE_API = "auto"
        os.environ["USE_API"] = "auto"
        
def set_default_model(model_name):
    """Set the default model globally."""
    global DEFAULT_MODEL
    DEFAULT_MODEL = model_name
    os.environ["DEFAULT_MODEL"] = model_name

# OpenRouter API URL and data policy setting
OPENROUTER_API_URL = "https://openrouter.ai/api/v1/chat/completions"
OPENROUTER_DATA_USAGE = "null"  # Set to 'null' to use models without sharing data

# Backup models for OpenRouter - matching DeepCurrent_v3.1.py model selection
BACKUP_MODELS = [
    "deepseek/deepseek-v3-base:free",
    "google/gemini-2.5-pro-exp-03-25:free",
    "mistralai/mistral-small-3.1-24b-instruct:free",
    "open-r1/olympiccoder-32b:free"
]

# Cache directory for responses
CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "response_cache")

def generate_structured_analysis(report: str, model: str = DEFAULT_OLLAMA_MODEL) -> dict:
    """
    Call the LLM to extract structured vulnerability data from the report using an enhanced prompt
    that handles modern audit report formats better.
    
    Enhanced extraction includes:
      - 'vuln_type': The vulnerability type, with CWE and severity
      - 'questions': Security research questions that led to discovering the vulnerability
      - 'vulnerable_code': Code snippet demonstrating the vulnerability
      - 'fixed_code': Code showing how the vulnerability was fixed
      - 'researcher_insights': Summary of researcher insights and impact analysis
      - 'severity_rating': High/Medium/Low/Informational rating
      - 'attack_vectors': Possible attack vectors or exploitation methods
      - 'detection_signatures': Code patterns or indicators that can help detect similar issues
      
    Returns a comprehensive JSON object with these keys.
    
    Args:
        report: The vulnerability report text to analyze
        model: For OpenRouter, use an OpenRouter model ID. For Ollama, use a local model name.
    """
    # Truncate report if too long to avoid token limits
    max_report_length = 20000  # Character limit
    truncated_report = report[:max_report_length] if len(report) > max_report_length else report
    
    # Enhanced extraction prompt
    extraction_prompt = """
    Analyze this smart contract vulnerability report and extract the following information in JSON format:

    1. 'vuln_type': The precise vulnerability type, including CWE classification if available 
       (e.g., 'Reentrancy (CWE-841)'). Include sub-categories if present.

    2. 'severity_rating': The severity rating (Critical/High/Medium/Low/Informational).

    3. 'questions': 3-5 key questions that security researchers would ask when investigating this vulnerability.

    4. 'vulnerable_code': The most representative code snippet showing the vulnerability. 
       Include full function context when possible.

    5. 'fixed_code': The code snippet showing how the vulnerability was fixed.

    6. 'researcher_insights': A detailed summary of the security researcher's analysis, including:
       - Root cause of the vulnerability
       - Exploitation conditions
       - Potential impact

    7. 'attack_vectors': Specific methods an attacker could use to exploit this vulnerability.

    8. 'detection_signatures': Code patterns, function signatures, or indicators that could help
       detect similar vulnerabilities in other contracts.

    9. 'pattern': A regular expression or code pattern that could help identify this vulnerability in other code.

    If you cannot find information for a specific field, use an empty string or list as appropriate.
    Format your answer as a valid JSON object with the keys listed above.
    Do not include any explanatory text outside the JSON object.
    """
    
    # Generate a cache key based on the report content and prompt
    hasher = hashlib.md5()
    hasher.update((extraction_prompt + truncated_report).encode('utf-8'))
    cache_key = hasher.hexdigest()
    
    # Check if we have a cached response
    cache_file = os.path.join(CACHE_DIR, f"{cache_key}.json")
    if os.path.exists(cache_file):
        try:
            with open(cache_file, 'r') as f:
                cached_data = json.load(f)
            console.print("[dim]Using cached analysis result[/dim]")
            return cached_data
        except (json.JSONDecodeError, IOError) as e:
            console.print(f"[yellow]Cache read error: {e}, generating new analysis[/yellow]")
    
    # Determine which API to use based on configuration and availability
    use_openrouter = False
    
    if USE_API == "auto" or USE_API == "openrouter":
        if OPENROUTER_API_KEY:
            use_openrouter = True
            # If in auto mode and OpenRouter fails, we'll fall back to Ollama
            use_fallback = (USE_API == "auto")
        else:
            if USE_API == "openrouter":
                console.print("[yellow]OPENROUTER_API_KEY not found but USE_API=openrouter, please set the API key[/yellow]")
            console.print("[dim]Falling back to local Ollama API[/dim]")
    
    if use_openrouter:
        try:
            console.print(f"[cyan]Attempting OpenRouter API with model: {DEFAULT_MODEL}[/cyan]")
            result = _generate_with_openrouter(extraction_prompt, truncated_report, DEFAULT_MODEL, cache_key)
            return result
        except Exception as e:
            if use_fallback:
                console.print(f"[yellow]OpenRouter API failed: {str(e)}[/yellow]")
                console.print(f"[cyan]Falling back to local Ollama API with model: {model}[/cyan]")
            else:
                console.print(f"[red]OpenRouter API error: {str(e)} and no fallback is enabled[/red]")
                raise
    
    # If we get here, either OpenRouter failed with fallback enabled, or we're using Ollama directly
    return _generate_with_ollama(extraction_prompt, truncated_report, model, cache_key)

def _generate_with_openrouter(extraction_prompt, report, model, cache_key):
    """Generate structured analysis using OpenRouter API"""
    # Create cache directory if it doesn't exist
    if not os.path.exists(CACHE_DIR):
        os.makedirs(CACHE_DIR, exist_ok=True)
        
    # Define cache file path
    cache_file = os.path.join(CACHE_DIR, f"{cache_key}.json")
    
    # Check if we have a cached result
    if os.path.exists(cache_file):
        try:
            with open(cache_file, 'r') as f:
                cached_result = json.load(f)
            console.print(f"[green]Using cached analysis result[/green]")
            return cached_result
        except Exception as e:
            console.print(f"[yellow]Error reading cache: {e}. Will regenerate.[/yellow]")
    
    # Standard headers for OpenRouter API exactly as in DeepCurrent_v3.1.py
    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/pxng0lin/DeepCurrent",  # Required for data policies
        "X-Title": "DeepCurrent Security Analysis",  # Name of your app
        "X-Data-Usage": OPENROUTER_DATA_USAGE  # Control data usage policy
    }
    
    # Prepare messages array for OpenRouter API with enhanced system prompt
    messages = [
        {"role": "system", "content": "You are an expert in smart contract security analysis. Respond with properly formatted JSON that matches the requested schema exactly."}, 
        {"role": "user", "content": extraction_prompt + "\n" + report}
    ]
    
    # Include all models to try in order of preference
    models_to_try = [model] + [m for m in BACKUP_MODELS if m != model]
    console.print(f"[cyan]Using OpenRouter API with model: {model}[/cyan]")
    
    # Try up to 3 times with different models
    max_retries = 3
    base_wait = 2  # seconds
    
    for attempt in range(max_retries):
        # Rotate through models if needed
        current_model = models_to_try[min(attempt, len(models_to_try) - 1)]
        
        try:
            console.print(f"[dim]Attempt {attempt+1}/{max_retries} with model {current_model}...[/dim]")
            
            # Request format for OpenRouter API
            payload = {
                "model": current_model,
                "messages": messages,
                "temperature": 0.2,  # Lower temperature for more deterministic output
                "max_tokens": 20000
            }
            
            # Make the API request
            response = requests.post(
                OPENROUTER_API_URL,
                headers=headers,
                json=payload,
                timeout=120
            )
            
            # Check if we hit rate limits
            if response.status_code == 429:
                console.print(f"[yellow]OpenRouter rate limit exceeded on attempt {attempt+1}[/yellow]")
                # If this isn't the last attempt and we still have models to try, continue
                if attempt < max_retries - 1 and attempt < len(models_to_try) - 1:
                    wait_time = base_wait * (2 ** attempt)
                    console.print(f"[yellow]Trying alternate model in {wait_time} seconds...[/yellow]")
                    time.sleep(wait_time)
                    continue
                else:
                    raise Exception("Rate limit exceeded for all available models")
            
            # Handle HTTP errors
            elif response.status_code != 200:
                console.print(f"[yellow]HTTP error {response.status_code} on attempt {attempt+1}[/yellow]")
                if attempt < max_retries - 1:
                    wait_time = base_wait * (2 ** attempt)
                    console.print(f"[yellow]Retrying in {wait_time} seconds...[/yellow]")
                    time.sleep(wait_time)
                    continue
                else:
                    response.raise_for_status()
            
            # Parse the response
            response_data = response.json()
            console.print(f"Using model: {current_model}")
            
            # Extract the response text
            try:
                response_text = response_data['choices'][0]['message']['content']
                console.print(f"Response received ({len(response_text)} chars)")
                
                # Try to parse the JSON response
                try:
                    # Find JSON content in the response using multiple strategies
                    # Strategy 1: Look for JSON in code blocks
                    json_match = re.search(r'```(?:json)?\s*({[\s\S]*?})\s*```', response_text)
                    if json_match:
                        json_str = json_match.group(1)
                        try:
                            result = json.loads(json_str)
                            console.print(f"[green]Successfully extracted JSON from code block[/green]")
                        except json.JSONDecodeError:
                            console.print(f"[yellow]Failed to parse JSON from code block, trying other methods[/yellow]")
                            json_match = None
                    
                    # Strategy 2: Look for JSON between curly braces
                    if not json_match:
                        # Find the first { and the last } that might form a complete JSON object
                        start_idx = response_text.find('{')
                        end_idx = response_text.rfind('}')
                        
                        if start_idx != -1 and end_idx != -1 and start_idx < end_idx:
                            json_str = response_text[start_idx:end_idx+1]
                            try:
                                result = json.loads(json_str)
                                console.print(f"[green]Successfully extracted JSON using brace matching[/green]")
                            except json.JSONDecodeError:
                                # Try to find the largest valid JSON object
                                console.print(f"[yellow]Failed with simple brace matching, trying advanced extraction[/yellow]")
                                
                                # Try to find valid JSON by incrementally parsing
                                valid_json = None
                                for i in range(end_idx, start_idx, -1):
                                    try:
                                        test_str = response_text[start_idx:i+1]
                                        valid_json = json.loads(test_str)
                                        console.print(f"[green]Found valid JSON substring[/green]")
                                        break
                                    except json.JSONDecodeError:
                                        continue
                                
                                if valid_json:
                                    result = valid_json
                                else:
                                    # Last resort: try to parse the entire response
                                    try:
                                        result = json.loads(response_text)
                                    except json.JSONDecodeError as e:
                                        raise json.JSONDecodeError(f"Could not extract valid JSON using any method: {e}", e.doc, e.pos)
                    
                    # Validate that we have the expected fields
                    expected_fields = ["vuln_type", "severity_rating", "pattern"]
                    if all(field in result for field in expected_fields):
                        # Write the result to cache
                        with open(cache_file, 'w') as f:
                            json.dump(result, f)
                        
                        console.print(f"[green]Successfully parsed JSON response with all required fields[/green]")
                        return result
                    else:
                        missing_fields = [field for field in expected_fields if field not in result]
                        console.print(f"[yellow]Response missing required fields: {missing_fields}[/yellow]")
                        
                        if attempt < max_retries - 1:
                            wait_time = base_wait * (2 ** attempt)
                            console.print(f"[yellow]Retrying with different model in {wait_time} seconds...[/yellow]")
                            time.sleep(wait_time)
                            continue
                        else:
                            # Last attempt, add missing fields with default values
                            for field in missing_fields:
                                result[field] = "Unknown" if field != "pattern" else ""
                            
                            # Write the result to cache
                            with open(cache_file, 'w') as f:
                                json.dump(result, f)
                            
                            console.print(f"[yellow]Using partial result with added default values for missing fields[/yellow]")
                            return result
                except (json.JSONDecodeError, TypeError) as e:
                    console.print(f"[yellow]Failed to parse JSON response: {e}[/yellow]")
                    if attempt < max_retries - 1:
                        wait_time = base_wait * (2 ** attempt)
                        console.print(f"[yellow]Retrying with different model in {wait_time} seconds...[/yellow]")
                        time.sleep(wait_time)
                        continue
                    else:
                        # Last attempt, create a basic structure with the raw text
                        console.print(f"[yellow]Creating fallback result structure with raw text[/yellow]")
                        result = {
                            "vuln_type": "Unknown",
                            "severity_rating": "Unknown",
                            "questions": [],
                            "vulnerable_code": "",
                            "fixed_code": "",
                            "researcher_insights": response_text[:500],
                            "attack_vectors": [],
                            "detection_signatures": [],
                            "pattern": ""
                        }
                        with open(cache_file, 'w') as f:
                            json.dump(result, f)
                        return result
            except (KeyError, IndexError) as e:
                console.print(f"[yellow]Failed to extract response text: {e}[/yellow]")
                if attempt < max_retries - 1:
                    wait_time = base_wait * (2 ** attempt)
                    console.print(f"[yellow]Retrying with different model in {wait_time} seconds...[/yellow]")
                    time.sleep(wait_time)
                    continue
                else:
                    raise Exception(f"Failed to extract response text after {max_retries} attempts")
                    
        except requests.RequestException as e:
            console.print(f"[yellow]Request error on attempt {attempt+1}: {e}[/yellow]")
            if attempt < max_retries - 1:
                wait_time = base_wait * (2 ** attempt)
                console.print(f"[yellow]Retrying in {wait_time} seconds...[/yellow]")
                time.sleep(wait_time)
                continue
        except json.JSONDecodeError as e:
            console.print(f"[yellow]JSON decode error on attempt {attempt+1}: {e}[/yellow]")
            if attempt < max_retries - 1:
                wait_time = base_wait * (2 ** attempt)
                console.print(f"[yellow]Retrying in {wait_time} seconds...[/yellow]")
                time.sleep(wait_time)
                continue
        except ValueError as e:
            console.print(f"[yellow]Value error on attempt {attempt+1}: {e}[/yellow]")
            if attempt < max_retries - 1:
                wait_time = base_wait * (2 ** attempt)
                console.print(f"[yellow]Retrying in {wait_time} seconds...[/yellow]")
                time.sleep(wait_time)
                continue
        except Exception as e:
            console.print(f"[red]Unexpected error on attempt {attempt+1}: {e}[/red]")
            if attempt < max_retries - 1:
                wait_time = base_wait * (2 ** attempt)
                console.print(f"[yellow]Retrying in {wait_time} seconds...[/yellow]")
                time.sleep(wait_time)
                continue
    
    # If we get here, all attempts failed
    raise Exception("Failed to get a valid response from OpenRouter after multiple attempts")

def _generate_with_ollama(extraction_prompt, report, model, cache_key):
    """Generate structured analysis using local Ollama API with ollama-python client"""
    console.print(f"[cyan]Using local Ollama API with model: {model}[/cyan]")
    
    # Create cache directory if it doesn't exist
    if not os.path.exists(CACHE_DIR):
        os.makedirs(CACHE_DIR, exist_ok=True)
        
    # Define cache file path
    cache_file = os.path.join(CACHE_DIR, f"{cache_key}.json")
    
    # Check if we have a cached result
    if os.path.exists(cache_file):
        try:
            with open(cache_file, 'r') as f:
                cached_result = json.load(f)
            console.print(f"[green]Using cached analysis result[/green]")
            return cached_result
        except Exception as e:
            console.print(f"[yellow]Error reading cache: {e}. Will regenerate.[/yellow]")
    
    # Try up to 3 times with exponential backoff
    max_retries = 3
    base_wait = 2  # seconds
    
    full_prompt = extraction_prompt + "\n\n" + report
    
    for attempt in range(max_retries):
        try:
            # Use the ollama-python client with chat API
            console.print(f"[dim]Attempt {attempt+1}/{max_retries} with model {model}...[/dim]")
            
            try:
                response = ollama.chat(
                    model=model,
                    messages=[
                        {
                            'role': 'system',
                            'content': 'You are a smart contract vulnerability analysis expert.'
                        },
                        {
                            'role': 'user',
                            'content': full_prompt
                        }
                    ],
                    options={
                        "temperature": 0.2,  # Lower temperature for more deterministic output
                    }
                )
                
                # Extract content from response
                if isinstance(response, dict) and 'message' in response:
                    # Dictionary format response
                    if 'content' in response['message']:
                        text = response['message']['content']
                    else:
                        raise ValueError("No content in response message")
                elif hasattr(response, 'message') and hasattr(response.message, 'content'):
                    # Object format response
                    text = response.message.content
                else:
                    raise ValueError("Unexpected response format from Ollama API")
                    
                console.print(f"[dim]Response received ({len(text)} chars)[/dim]")
                
                if not text:
                    raise ValueError("Empty response from Ollama API")
            except Exception as e:
                console.print(f"[yellow]Error with Ollama response: {str(e)}[/yellow]")
                raise
            
            # Try to extract JSON from text using multiple strategies
            try:
                # Strategy 1: Direct JSON parsing if response starts with {
                if text.startswith("{"):
                    try:
                        parsed_data = json.loads(text)
                        console.print("[green]Successfully parsed direct JSON response[/green]")
                    except json.JSONDecodeError:
                        console.print("[yellow]Response starts with { but is not valid JSON, trying other methods[/yellow]")
                        raise
                else:
                    # Strategy 2: Look for JSON in code blocks
                    json_match = re.search(r'```(?:json)?\s*({[\s\S]*?})\s*```', text)
                    if json_match:
                        json_str = json_match.group(1)
                        try:
                            parsed_data = json.loads(json_str)
                            console.print("[green]Successfully extracted JSON from code block[/green]")
                        except json.JSONDecodeError:
                            console.print("[yellow]Failed to parse JSON from code block, trying other methods[/yellow]")
                            json_match = None
                    
                    # Strategy 3: Look for JSON between curly braces
                    if not json_match:
                        # Find the first { and the last } that might form a complete JSON object
                        start_idx = text.find('{')
                        end_idx = text.rfind('}')
                        
                        if start_idx != -1 and end_idx != -1 and start_idx < end_idx:
                            json_str = text[start_idx:end_idx+1]
                            try:
                                parsed_data = json.loads(json_str)
                                console.print("[green]Successfully extracted JSON using brace matching[/green]")
                            except json.JSONDecodeError:
                                # Try to find the largest valid JSON object
                                console.print("[yellow]Failed with simple brace matching, trying advanced extraction[/yellow]")
                                
                                # Try to find valid JSON by incrementally parsing
                                valid_json = None
                                for i in range(end_idx, start_idx, -1):
                                    try:
                                        test_str = text[start_idx:i+1]
                                        valid_json = json.loads(test_str)
                                        console.print("[green]Found valid JSON substring[/green]")
                                        break
                                    except json.JSONDecodeError:
                                        continue
                                
                                if valid_json:
                                    parsed_data = valid_json
                                else:
                                    # Strategy 4: Try to find JSON with vuln_type field
                                    json_match = re.search(r'\{[^{]*"vuln_type".*\}', text, re.DOTALL)
                                    if json_match:
                                        try:
                                            parsed_data = json.loads(json_match.group(0))
                                            console.print("[green]Found JSON with vuln_type field[/green]")
                                        except json.JSONDecodeError:
                                            # Try markdown extraction as a last resort
                                            console.print("[yellow]No valid JSON found, attempting to extract structured information from markdown...[/yellow]")
                                            extracted_info = extract_structured_info_from_markdown(text)
                                            if extracted_info and extracted_info["vuln_type"] != "Unknown":
                                                console.print("[green]Successfully extracted structured information from markdown[/green]")
                                                parsed_data = extracted_info
                                            else:
                                                raise ValueError("Failed to extract structured data from response")
                                    else:
                                        # Try markdown extraction as a last resort
                                        console.print("[yellow]No JSON found, attempting to extract structured information from markdown...[/yellow]")
                                        extracted_info = extract_structured_info_from_markdown(text)
                                        if extracted_info and extracted_info["vuln_type"] != "Unknown":
                                            console.print("[green]Successfully extracted structured information from markdown[/green]")
                                            parsed_data = extracted_info
                                        else:
                                            raise ValueError("Failed to extract structured data from response")
                        else:
                            # Try markdown extraction as a last resort
                            console.print("[yellow]No JSON found, attempting to extract structured information from markdown...[/yellow]")
                            extracted_info = extract_structured_info_from_markdown(text)
                            if extracted_info and extracted_info["vuln_type"] != "Unknown":
                                console.print("[green]Successfully extracted structured information from markdown[/green]")
                                parsed_data = extracted_info
                            else:
                                raise ValueError("Failed to extract structured data from response")
                
                # Ensure all expected fields exist with default values if missing
                expected_fields = [
                    "vuln_type", "severity_rating", "questions", "vulnerable_code", 
                    "fixed_code", "researcher_insights", "attack_vectors", 
                    "detection_signatures", "pattern"
                ]
                
                for field in expected_fields:
                    if field not in parsed_data:
                        if field in ["questions", "attack_vectors", "detection_signatures"]:
                            parsed_data[field] = []
                        else:
                            parsed_data[field] = ""
                
                # Ensure list fields are actually lists
                list_fields = ["questions", "attack_vectors", "detection_signatures"]
                for field in list_fields:
                    if not isinstance(parsed_data[field], list):
                        if parsed_data[field]:  # If it has a value but isn't a list
                            parsed_data[field] = [parsed_data[field]]
                        else:
                            parsed_data[field] = []
                
                # Cache the result
                with open(cache_file, 'w') as f:
                    json.dump(parsed_data, f)
                
                return parsed_data
            
            except (ValueError, json.JSONDecodeError) as e:
                console.print(f"[yellow]Failed to parse response (attempt {attempt+1}/{max_retries}): {e}[/yellow]")
        
        except requests.exceptions.RequestException as e:
            console.print(f"[yellow]API request failed (attempt {attempt+1}/{max_retries}): {e}[/yellow]")
        except Exception as e:
            console.print(f"[red]Unexpected error (attempt {attempt+1}/{max_retries}): {e}[/red]")
        
        # Don't sleep after the last attempt
        if attempt < max_retries - 1:
            wait_time = base_wait * (2 ** attempt)  # Exponential backoff
            console.print(f"[yellow]Retrying in {wait_time} seconds...[/yellow]")
            time.sleep(wait_time)
    
    # If we get here, all attempts failed
    return {
        "vuln_type": "Unknown",
        "severity_rating": "",
        "questions": [],
        "vulnerable_code": "",
        "fixed_code": "",
        "researcher_insights": "Analysis failed due to LLM service issues.",
        "attack_vectors": [],
        "detection_signatures": [],
        "pattern": "",
        "raw_analysis": "LLM analysis failed after multiple attempts."
    }

# ---------------------- Web Portfolio Functions ----------------------
def process_web_portfolio(url="https://cantina.xyz/portfolio", model_instance=None, skip_analysis=False, max_reports=None, site_type="auto"):
    """
    Scrape and process vulnerability reports from the Cantina portfolio page.
    
    Args:
        url: URL of the Cantina portfolio page (default: https://cantina.xyz/portfolio)
        model_instance: Optional embedding model instance
        skip_analysis: If True, skip LLM analysis and only vectorize the report
        max_reports: Maximum number of reports to process (None for all)
    """
    # Determine site type if auto
    if site_type == "auto":
        if "cantina.xyz" in url:
            site_type = "cantina"
        else:
            site_type = "generic"
            
    console.print(f"[bold blue]Scraping portfolio reports from {url} (site type: {site_type})[/bold blue]")
    
    try:
        # Get the portfolio page content
        response = requests.get(url)
        response.raise_for_status()
        
        # Extract all report URLs
        report_urls = []
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Look for links that match the portfolio item pattern based on site type
        if site_type == "cantina":
            # Cantina-specific pattern
            for link in soup.find_all('a', href=True):
                href = link['href']
                if '/portfolio/' in href and not href.endswith('/portfolio/'):
                    if not href.startswith('http'):
                        href = 'https://cantina.xyz' + href
                    report_urls.append(href)
        else:
            # Generic approach - look for links that might be report URLs
            # This is a heuristic approach that looks for links that might contain reports
            base_url = url.split('//')[0] + '//' + url.split('//')[1].split('/')[0]
            for link in soup.find_all('a', href=True):
                href = link['href']
                # Look for links that might be reports (contain keywords or have UUID-like patterns)
                if any(term in href.lower() for term in ['report', 'audit', 'finding', 'vulnerability', 'security']):
                    if not href.startswith('http'):
                        if href.startswith('/'):
                            href = base_url + href
                        else:
                            href = base_url + '/' + href
                    report_urls.append(href)
        
        # Remove duplicates while preserving order
        report_urls = list(dict.fromkeys(report_urls))
        
        if max_reports:
            report_urls = report_urls[:max_reports]
            
        console.print(f"[green]Found {len(report_urls)} Cantina reports to process[/green]")
        
        # Process each report
        processed_count = 0
        for report_url in report_urls:
            try:
                # Extract report ID from URL
                report_id = report_url.split('/')[-1]
                
                # Check if report already exists in database
                if report_already_exists(report_id):
                    console.print(f"[yellow]Report {report_id} already exists in database, skipping...[/yellow]")
                    continue
                
                console.print(f"[bold cyan]Processing report: {report_url}[/bold cyan]")
                
                # Get the report page content
                report_response = requests.get(report_url)
                report_response.raise_for_status()
                
                # Extract the report content based on site type
                if site_type == "cantina":
                    report_content = extract_cantina_report_content(report_response.text, report_url)
                else:
                    report_content = extract_generic_report_content(report_response.text, report_url)
                
                if not report_content:
                    console.print(f"[yellow]No findings extracted from {report_url}, skipping...[/yellow]")
                    continue
                
                # Process the report content as markdown
                report_md = format_report_content_as_markdown(report_content)
                
                # Generate a unique report ID based on URL if not already available
                if not report_id:
                    report_id = hashlib.md5(report_url.encode()).hexdigest()
                
                # Split the report into sections
                sections = split_into_sections(report_md)
                
                # Compute embeddings
                overall_embedding = compute_embedding(report_md, model_instance)
                section_embeddings = {}
                for section_title, section_content in sections.items():
                    section_embeddings[section_title] = compute_embedding(section_content, model_instance)
                
                # Generate metadata
                metadata = {
                    "source": site_type,
                    "url": report_url,
                    "date_processed": datetime.now().isoformat(),
                    "sections": list(sections.keys())
                }
                
                # Perform LLM analysis if not skipped
                analysis_summary = {}
                pattern = "N/A"
                if not skip_analysis:
                    try:
                        analysis_summary = generate_structured_analysis(report_md, model="deepseek-r1:32b")
                        pattern = analysis_summary.get("pattern", "N/A")
                    except Exception as e:
                        console.print(f"[red]Error during LLM analysis: {e}[/red]")
                        analysis_summary = {"error": str(e)}
                
                # Save the report to the database
                save_report(report_id, report_url, report_md, overall_embedding, section_embeddings, analysis_summary, metadata)
                
                # Save the pattern if analysis was performed
                if not skip_analysis and pattern != "N/A":
                    save_pattern(report_id, pattern)
                
                processed_count += 1
                console.print(f"[green]Successfully processed report: {report_url}[/green]")
                
            except Exception as e:
                console.print(f"[red]Error processing report {report_url}: {e}[/red]")
        
        console.print(f"[bold green]Completed processing {processed_count} reports from {site_type} site[/bold green]")
        return processed_count
        
    except Exception as e:
        console.print(f"[red]Error scraping portfolio from {url}: {e}[/red]")
        return 0

def extract_cantina_report_content(html_content, report_url):
    """
    Extract the findings content from a Cantina report page.
    
    Args:
        html_content: HTML content of the report page
        report_url: URL of the report page for pagination handling
    
    Returns:
        Dictionary containing the extracted findings content
    """
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Extract report title
        title_element = soup.find('h1')
        title = title_element.text.strip() if title_element else "Unknown Report"
        
        # Extract project name and date if available
        project_name = ""
        date_range = ""
        metadata_div = soup.find('div', class_=lambda c: c and 'metadata' in c)
        if metadata_div:
            project_element = metadata_div.find('p', class_=lambda c: c and 'project' in c)
            if project_element:
                project_name = project_element.text.strip()
            
            date_element = metadata_div.find('p', class_=lambda c: c and 'date' in c)
            if date_element:
                date_range = date_element.text.strip()
        
        # Extract findings
        findings = []
        
        # Look for findings sections which are typically under h3 headings like "Medium Risk", "High Risk", etc.
        risk_headings = soup.find_all(['h3', 'h2'], string=lambda s: s and any(risk in s.lower() for risk in ['risk', 'severity', 'finding', 'vulnerability']))
        
        for heading in risk_headings:
            risk_level = heading.text.strip()
            
            # Find all finding elements after this heading until the next heading
            finding_elements = []
            current = heading.next_sibling
            
            while current and current.name not in ['h2', 'h3']:
                if current.name:
                    finding_elements.append(current)
                current = current.next_sibling
            
            # Process each finding
            for element in finding_elements:
                if element.name in ['div', 'section'] and element.text.strip():
                    # Extract finding details
                    finding_title = ""
                    title_el = element.find(['h4', 'h5', 'strong', 'b'])
                    if title_el:
                        finding_title = title_el.text.strip()
                    
                    # Extract the full content
                    content = element.text.strip()
                    
                    # Only add if we have actual content
                    if content and len(content) > 50:  # Minimum content length check
                        findings.append({
                            "risk_level": risk_level,
                            "title": finding_title,
                            "content": content
                        })
        
        # If no findings were found using the structured approach, try a more general extraction
        if not findings:
            # Look for content divs that might contain findings
            content_divs = soup.find_all('div', class_=lambda c: c and any(term in c.lower() for term in ['content', 'finding', 'vulnerability', 'report']))
            
            for div in content_divs:
                content = div.text.strip()
                if content and len(content) > 100:  # Minimum content length check
                    findings.append({
                        "risk_level": "Unknown",
                        "title": "",
                        "content": content
                    })
        
        # Compile the report data
        report_data = {
            "title": title,
            "project": project_name,
            "date": date_range,
            "url": report_url,
            "findings": findings
        }
        
        return report_data
        
    except Exception as e:
        console.print(f"[red]Error extracting content from Cantina report: {e}[/red]")
        return None

def extract_generic_report_content(html_content, report_url):
    """
    Extract the findings content from a generic report page.
    This is a more general approach that tries to identify common patterns in security reports.
    
    Args:
        html_content: HTML content of the report page
        report_url: URL of the report page
    
    Returns:
        Dictionary containing the extracted findings content
    """
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Extract report title - look for the most prominent heading
        title_element = soup.find(['h1', 'h2', 'title'])
        title = title_element.text.strip() if title_element else "Unknown Report"
        
        # Extract project name and date if available - look for metadata sections
        project_name = ""
        date_range = ""
        
        # Look for project name in common patterns
        project_elements = soup.find_all(['h2', 'h3', 'div', 'span', 'p'], 
                                       string=lambda s: s and any(term in s.lower() for term in ['project', 'client', 'protocol', 'contract']))
        if project_elements:
            for element in project_elements:
                text = element.text.strip()
                if len(text) < 100:  # Avoid capturing large blocks of text
                    project_name = text
                    break
        
        # Look for date in common patterns
        date_elements = soup.find_all(['div', 'span', 'p', 'time'], 
                                    string=lambda s: s and any(term in s.lower() for term in ['date', 'period', 'time', 'duration']))
        if date_elements:
            for element in date_elements:
                text = element.text.strip()
                if len(text) < 100:  # Avoid capturing large blocks of text
                    date_range = text
                    break
        
        # Extract findings - look for common security report sections
        findings = []
        
        # Look for findings sections with common headings
        finding_headings = soup.find_all(['h2', 'h3', 'h4'], 
                                       string=lambda s: s and any(term in s.lower() for term in 
                                                               ['finding', 'issue', 'vulnerability', 'bug', 'risk', 
                                                                'critical', 'high', 'medium', 'low', 'informational', 
                                                                'severity', 'impact', 'exploit']))
        
        for heading in finding_headings:
            risk_level = "Unknown"
            
            # Try to determine risk level from the heading
            heading_text = heading.text.lower()
            if 'critical' in heading_text:
                risk_level = "Critical"
            elif 'high' in heading_text:
                risk_level = "High"
            elif 'medium' in heading_text:
                risk_level = "Medium"
            elif 'low' in heading_text:
                risk_level = "Low"
            elif 'informational' in heading_text or 'info' in heading_text:
                risk_level = "Informational"
            
            # Extract the finding content - get all content until the next heading of same or higher level
            finding_content = []
            current = heading.next_sibling
            
            while current:
                if current.name and current.name in ['h2', 'h3', 'h4'] and current.name <= heading.name:
                    break
                if current.name:
                    finding_content.append(current.text.strip())
                current = current.next_sibling
            
            # Join the content and add to findings
            content = "\n".join([c for c in finding_content if c])
            if content and len(content) > 50:  # Minimum content length check
                findings.append({
                    "risk_level": risk_level,
                    "title": heading.text.strip(),
                    "content": content
                })
        
        # If no findings were found using the structured approach, try a more general extraction
        if not findings:
            # Look for content divs that might contain findings
            content_divs = soup.find_all(['div', 'section', 'article'], 
                                        class_=lambda c: c and any(term in (c.lower() if c else "") 
                                                                for term in ['content', 'finding', 'vulnerability', 'report', 'issue']))
            
            for div in content_divs:
                content = div.text.strip()
                if content and len(content) > 100:  # Minimum content length check
                    findings.append({
                        "risk_level": "Unknown",
                        "title": "",
                        "content": content
                    })
        
        # Compile the report data
        report_data = {
            "title": title,
            "project": project_name,
            "date": date_range,
            "url": report_url,
            "findings": findings
        }
        
        return report_data
        
    except Exception as e:
        console.print(f"[red]Error extracting content from generic report: {e}[/red]")
        return None

def format_report_content_as_markdown(report_data):
    """
    Format the extracted Cantina report content as Markdown.
    
    Args:
        report_data: Dictionary containing the extracted report data
    
    Returns:
        Markdown formatted string of the report content
    """
    if not report_data or not report_data.get("findings"):
        return ""
    
    md_lines = []
    
    # Add report title and metadata
    md_lines.append(f"# {report_data['title']}\n")
    
    if report_data.get("project"):
        md_lines.append(f"**Project:** {report_data['project']}\n")
    
    if report_data.get("date"):
        md_lines.append(f"**Date:** {report_data['date']}\n")
    
    md_lines.append(f"**Source:** {report_data['url']}\n")
    
    # Group findings by risk level
    findings_by_risk = {}
    for finding in report_data["findings"]:
        risk_level = finding.get("risk_level", "Unknown")
        if risk_level not in findings_by_risk:
            findings_by_risk[risk_level] = []
        findings_by_risk[risk_level].append(finding)
    
    # Add findings organized by risk level
    md_lines.append("## Findings Summary\n")
    
    for risk_level, findings in findings_by_risk.items():
        md_lines.append(f"### {risk_level}\n")
        md_lines.append(f"*Number of findings: {len(findings)}*\n")
    
    # Add detailed findings
    md_lines.append("## Detailed Findings\n")
    
    for risk_level, findings in findings_by_risk.items():
        md_lines.append(f"### {risk_level}\n")
        
        for i, finding in enumerate(findings, 1):
            # Add finding title if available
            if finding.get("title"):
                md_lines.append(f"#### {i}. {finding['title']}\n")
            else:
                md_lines.append(f"#### Finding {i}\n")
            
            # Add finding content
            md_lines.append(f"{finding['content']}\n\n")
    
    return "\n".join(md_lines)

# ---------------------- Vectorisation Functions ----------------------
def process_markdown_file(file_url: str, source: str, model_instance=None, skip_analysis=False):
    """Download, embed, extract structured data via LLM, and save the report.
    
    Args:
        file_url: URL of the markdown file to process
        source: Source identifier for the report
        model_instance: Optional embedding model instance
        skip_analysis: If True, skip LLM analysis and only vectorize the report
    """
    console.print(f"[bold blue]🔄 Starting vectorization for: {file_url}[/bold blue]")
    report_id = hashlib.sha256(file_url.encode("utf-8")).hexdigest()
    console.print(f"[bold yellow]🛠 Calculated Report ID: {report_id}[/bold yellow]")
    console.print(f"[bold blue]🔄 Downloading report from: {file_url}[/bold blue]")
    content = download_markdown(file_url)
    if content is None:
        console.print("[red]❌ Failed to download report. Check the URL and try again.[/red]")
        return
    console.print("[bold yellow]🔍 Extracting key information...[/bold yellow]")
    overall_embedding = compute_embedding(content, model_instance)
    sections = split_into_sections(content)
    console.print(f"[bold blue]📄 Found {len(sections)} sections in report[/bold blue]")
    section_embeddings = [
        {"title": sec["title"], "content": sec["content"], "embedding": compute_embedding(sec["content"], model_instance)}
        for sec in sections if sec["content"]
    ]
    
    # Initialize analysis_summary as empty if skipping analysis
    analysis_summary = {}
    pattern = "N/A"
    
    if not skip_analysis:
        console.print("[bold yellow]🔍 Generating structured analysis via LLM...[/bold yellow]")
        analysis_summary = generate_structured_analysis(content, model="deepseek-r1:32b")
        pattern = analysis_summary.get("pattern", "N/A")
    else:
        console.print("[bold yellow]🔍 Skipping LLM analysis as requested...[/bold yellow]")
    
    metadata = {
        "downloaded_at": datetime.utcnow().isoformat() + "Z",
        "report_length": len(content),
        "word_count": len(content.split()),
        "embedding_model": "all-MiniLM-L6-v2",
        "llm_model": "deepseek-r1:32b" if not skip_analysis else "skipped",
        "script_version": "3.2"
    }
    console.print("[bold cyan]💾 Saving data to the database...[/bold cyan]")
    save_report(report_id, source, content, overall_embedding, section_embeddings, analysis_summary, metadata)
    
    # Save the basic pattern extracted (if any)
    if not skip_analysis:
        save_pattern(report_id, pattern)
    
    console.print("[bold green]✅ Report successfully vectorized" + (" and analyzed" if not skip_analysis else "") + " and saved to database![/bold green]")

def process_single_file(url: str, model_instance=None, skip_analysis=False):
    """Process a single Markdown file or all .md files in a GitHub directory.
    
    Args:
        url: URL of the file or directory to process
        model_instance: Optional embedding model instance
        skip_analysis: If True, skip LLM analysis and only vectorize the report
    """
    # Handle GitHub directory URLs (tree, blob, or trailing /md/)
    if (
        "github.com" in url and (
            "/tree/" in url or "/blob/" in url or url.endswith("/md") or url.endswith("/md/")
        )
    ):
        try:
            # Extract owner, repo, branch, and directory
            parts = url.split("github.com/")[-1].split("/")
            debug_info = f"[debug] URL parts: {parts}"
            if "tree" in parts:
                idx = parts.index("tree")
                owner = parts[0]
                repo = parts[1]
                branch = parts[idx+1]
            else:
                console.print(f"[red]Failed to fetch directory listing from GitHub API (HTTP {resp.status_code})[/red]")
                console.print(f"[red]GitHub API response: {resp.text}[/red]")
                return
        except Exception as e:
            console.print(f"[red]Error processing GitHub directory: {e}[/red]")
            return
    # Default: single file
    if should_ignore_file(url):
        report_id = hashlib.sha256(url.encode("utf-8")).hexdigest()
        with task_lock:
            task_status[report_id] = "Skipped (ignored file)"
        return
    process_markdown_file(url, url, model_instance, skip_analysis=skip_analysis)

def process_repo(url: str, model_instance=None, skip_analysis=False):
    """Process all Markdown files in a GitHub repository.
    
    Args:
        url: URL of the repository to process
        model_instance: Optional embedding model instance
        skip_analysis: If True, skip LLM analysis and only vectorize the report
    """
    if "github.com" not in url:
        with task_lock:
            task_status[url] = "Error: Not a GitHub URL"
        return
    
    console.print(f"[bold cyan]Processing GitHub repository: {url}[/bold cyan]")
    
    # Parse GitHub URL to extract owner, repo, branch, and path
    try:
        # Remove any trailing slashes
        url = url.rstrip('/')
        
        # Extract the part after github.com/
        github_path = url.split('github.com/')[-1]
        
        # Split the path into components
        parts = github_path.split('/')
        
        # First two parts are always owner and repo
        if len(parts) < 2:
            console.print(f"[red]Invalid GitHub URL format: {url}[/red]")
            return
            
        owner = parts[0]
        repo = parts[1]
        
        # Default branch and path
        branch = "main"  # Default to main
        dir_path = ""
        
        # Check if URL contains tree or blob to determine branch and path
        if len(parts) > 3 and parts[2] in ["tree", "blob"]:
            branch = parts[3]
            dir_path = "/".join(parts[4:]) if len(parts) > 4 else ""
        
        console.print(f"[dim]Parsed GitHub URL - Owner: {owner}, Repo: {repo}, Branch: {branch}, Path: {dir_path}[/dim]")
    except Exception as e:
        console.print(f"[red]Error parsing GitHub URL: {e}[/red]")
        return
    
    # Set up headers for GitHub API
    headers = {"User-Agent": "DeepCurrent-VectorEyes/1.0"}
    
    # If URL points to a specific directory, use contents API
    if dir_path:
        api_url = f"https://api.github.com/repos/{owner}/{repo}/contents/{dir_path}?ref={branch}"
        console.print(f"[bold yellow]Fetching GitHub API URL: {api_url}[/bold yellow]")
        
        try:
            resp = requests.get(api_url, headers=headers)
            
            if resp.status_code == 404 and branch == "main":
                # Try with master branch if main fails
                branch = "master"
                api_url = f"https://api.github.com/repos/{owner}/{repo}/contents/{dir_path}?ref={branch}"
                console.print(f"[yellow]Main branch not found, trying master branch: {api_url}[/yellow]")
                resp = requests.get(api_url, headers=headers)
            
            if resp.status_code == 200:
                files = resp.json()
                
                # Handle both single file and directory responses
                if isinstance(files, dict):  # Single file
                    files = [files]
                
                # Include all Markdown files, even if they have 'readme' in their name
                md_files = [f for f in files if f['name'].endswith('.md')]
                
                if not md_files:
                    console.print(f"[yellow]No Markdown files found in directory: {url}[/yellow]")
                    return
                
                console.print(f"[green]Found {len(md_files)} Markdown files to process[/green]")
                for f in md_files:
                    raw_url = f['download_url']
                    console.print(f"[dim]Processing: {f['name']}[/dim]")
                    process_markdown_file(raw_url, raw_url, model_instance, skip_analysis=skip_analysis)
                return
            else:
                console.print(f"[red]Failed to fetch directory listing from GitHub API (HTTP {resp.status_code})[/red]")
                console.print(f"[red]GitHub API response: {resp.text}[/red]")
                return
        except Exception as e:
            console.print(f"[red]Error accessing GitHub API: {e}[/red]")
            return
    
    # Otherwise, get all files in the repo
    repo_api = f"https://api.github.com/repos/{owner}/{repo}/git/trees/{branch}?recursive=1"
    console.print(f"[bold yellow]Fetching GitHub API URL: {repo_api}[/bold yellow]")
    
    try:
        r = requests.get(repo_api, headers=headers)
        if r.status_code != 200:
            with task_lock:
                task_status[url] = f"Error: Repo fetch failed (HTTP {r.status_code})"
            console.print(f"[red]GitHub API response: {r.text}[/red]")
            return
        
        # Process all Markdown files in the repo
        tree = r.json().get('tree', [])
        # Include all Markdown files, even if they have 'readme' in their name
        md_files = [f for f in tree if f['path'].endswith('.md')]
        
        if not md_files:
            with task_lock:
                task_status[url] = "No Markdown files found"
            return
        
        console.print(f"[green]Found {len(md_files)} Markdown files to process in repository[/green]")
        for f in md_files:
            raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{f['path']}"
            console.print(f"[dim]Processing: {f['path']}[/dim]")
            process_markdown_file(raw_url, raw_url, model_instance, skip_analysis=skip_analysis)
    except Exception as e:
        console.print(f"[red]Error processing repository: {e}[/red]")
        with task_lock:
            task_status[url] = f"Error: {str(e)}"
        return

# ---------------------- Detection Library Functions ----------------------
def init_detection_library_table():
    """
    Create the detection_library table if it doesn't exist.
    Schema:
      - vuln_type (TEXT PRIMARY KEY)
      - details (JSON string with aggregated questions, examples, insights)
      - template (Robust detection template as TEXT)
      - vector_embedding (BLOB for vectorized embeddings)
      - llm_template (TEXT for LLM-friendly template)
      - schema_version (INTEGER for tracking schema changes)
      - last_updated (TEXT for tracking last update timestamp)
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS detection_library (
            vuln_type TEXT PRIMARY KEY,
            details TEXT,
            template TEXT,
            vector_embedding BLOB,
            llm_template TEXT,
            schema_version INTEGER DEFAULT 1,
            last_updated TEXT
        )
    ''')
    conn.commit()
    conn.close()

def extract_structured_info_from_markdown(text):
    """Extract structured vulnerability info from a markdown-formatted response."""
    # Initialize our structured result
    result = {
        "vuln_type": "Unknown",
        "severity_rating": "Unknown",
        "vulnerability_description": "",
        "questions": [],
        "vulnerable_code": "",
        "fixed_code": "",
        "researcher_insights": "",
        "attack_vectors": [],
        "detection_signatures": [],
        "pattern": ""
    }
    
    # Extract vulnerability type from header
    title_match = re.search(r'^\s*#{1,6}\s+(.+)$', text, re.MULTILINE)
    if title_match:
        result["vuln_type"] = title_match.group(1).strip()
    
    # Extract severity rating
    severity_match = re.search(r'\*\*severity\*\*\s*:\s*([^\n]+)', text, re.IGNORECASE)
    if severity_match:
        result["severity_rating"] = severity_match.group(1).strip()
    
    # Extract description (everything between severity and recommendation)
    desc_pattern = r'\*\*severity\*\*\s*:[^\n]+\n\s*([\s\S]*?)(?:\*\*recommendation|$)'    
    desc_match = re.search(desc_pattern, text, re.IGNORECASE)
    if desc_match:
        result["researcher_insights"] = desc_match.group(1).strip()
        result["vulnerability_description"] = desc_match.group(1).strip()
    else:
        # If no recommendation section, try to grab everything after severity
        desc_pattern = r'\*\*severity\*\*\s*:[^\n]+\n\s*([\s\S]*)'    
        desc_match = re.search(desc_pattern, text, re.IGNORECASE)
        if desc_match:
            result["researcher_insights"] = desc_match.group(1).strip()
            result["vulnerability_description"] = desc_match.group(1).strip()
    
    # Extract attack vectors based on context clues
    if "allowing" in result["vulnerability_description"].lower():
        attack_pattern = r'allowing ([^\.,]+)'
        attack_match = re.search(attack_pattern, result["vulnerability_description"], re.IGNORECASE)
        if attack_match:
            result["attack_vectors"].append(attack_match.group(1).strip())
    
    # Look for potential detection signatures
    if "before" in result["vulnerability_description"].lower():
        signature_pattern = r'([^\.,]+) before ([^\.,]+)'
        sig_match = re.search(signature_pattern, result["vulnerability_description"], re.IGNORECASE)
        if sig_match:
            result["detection_signatures"].append(f"Check if {sig_match.group(1).strip()} occurs before {sig_match.group(2).strip()}")
    
    # Extract recommendation as a detection signature
    rec_pattern = r'\*\*recommendation\*\*\s*:?\s*([\s\S]*)'
    rec_match = re.search(rec_pattern, text, re.IGNORECASE)
    if rec_match:
        recommendation = rec_match.group(1).strip()
        if recommendation:
            result["detection_signatures"].append(recommendation)
    
    # Add simple questions based on vulnerability type
    if result["vuln_type"] != "Unknown":
        result["questions"] = [
            f"How can the {result['vuln_type']} vulnerability be exploited?",
            f"What are the conditions needed for a {result['vuln_type']} attack?",
            f"How can the {result['vuln_type']} vulnerability be prevented?"
        ]
    
    return result

def cluster_vulnerabilities(vuln_details_list, model=DEFAULT_OLLAMA_MODEL):
    """Enhanced vulnerability clustering using advanced LLM analysis techniques"""
    if not vuln_details_list:
        return {}
    
    console.print("[bold cyan]🔍 Starting enhanced vulnerability clustering...[/bold cyan]")
    console.print(f"[bold blue]Found {len(vuln_details_list)} vulnerability reports to analyze[/bold blue]")
    
    # For OpenRouter, check if we need batch processing (for datasets > 100 reports)
    if (USE_API == "openrouter" and len(vuln_details_list) > 100):
        console.print("[yellow]Large dataset detected with OpenRouter. Using batch processing.[/yellow]")
        # Split into manageable batches of 50 reports each
        return _batch_process_vulnerabilities(vuln_details_list, model)
    
    # Extract richer vulnerability data to improve clustering accuracy
    vuln_data = []
    for i, details in enumerate(vuln_details_list):
        if not details.get("vuln_type"):
            continue
            
        vuln_entry = {
            "index": i,
            "vuln_type": details.get("vuln_type", "Unknown"),
            "severity": details.get("severity_rating", ""),
        }
        
        # Add detection signatures if available
        if "detection_signatures" in details and details["detection_signatures"]:
            if isinstance(details["detection_signatures"], list):
                vuln_entry["signatures"] = details["detection_signatures"][:2]
            else:
                vuln_entry["signatures"] = [str(details["detection_signatures"])]
        
        # Add attack vectors if available
        if "attack_vectors" in details and details["attack_vectors"]:
            if isinstance(details["attack_vectors"], list):
                vuln_entry["attack_vectors"] = details["attack_vectors"][:2]
            else:
                vuln_entry["attack_vectors"] = [str(details["attack_vectors"])]
                
        # Include code snippet info (just presence, not full content to save tokens)
        vuln_entry["has_code_examples"] = bool(details.get("vulnerable_code") or details.get("fixed_code"))
        
        vuln_data.append(vuln_entry)
    
    # If we have very few vulnerabilities, skip complex clustering
    if len(vuln_data) < 3:
        console.print("[yellow]Few vulnerabilities found. Using simple categorization.[/yellow]")
        library = {}
        for details in vuln_details_list:
            vuln_type = details.get("vuln_type", "Unknown")
            if not vuln_type or vuln_type == "Unknown":
                continue
                
            if vuln_type not in library:
                library[vuln_type] = {
                    "questions": [], 
                    "vulnerable_examples": [], 
                    "fixed_examples": [],
                    "insights": [], 
                    "patterns": [], 
                    "attack_vectors": [], 
                    "severity_ratings": [],
                    "detection_signatures": []
                }
            
            # Add all details to the library
            _update_library_with_details(library[vuln_type], details)
            
        return library
    
    # Enhanced clustering prompt that aligns with DeepCurrent's detection system
    prompt = """
    You are a smart contract security expert. Analyze these vulnerability types and organize them into a comprehensive detection library.
    Examine each vulnerability carefully and determine the logical categories that would be most useful for detection and scanning purposes.
    
    CLUSTERING RULES:
    1. Use precise, actionable categories (e.g., "Reentrancy (CWE-841)" instead of just "Logic Error")
    2. Include CWE identifiers when applicable
    3. Merge near-identical vulnerabilities even if they have different names
    4. Keep truly distinct vulnerabilities separate, even if they fall in the same general area
    5. Prioritize categories that will be most useful for automated vulnerability detection
    6. Consider severity levels when creating categories
    
    VULNERABILITY DATA:
    {}
    
    OUTPUT INSTRUCTIONS:
    Return a JSON object where:
    - Each key is a standardized, precise vulnerability category name (with CWE if possible)
    - Each value is an array of indices from the input list that belong to this category
    
    Example format:
    {{
      "Reentrancy (CWE-841)": [0, 3, 7],
      "Integer Overflow (CWE-190)": [1, 4],
      "Access Control Issues (CWE-284)": [2, 5, 6]
    }}
    
    Only provide the JSON with no additional explanation.
    """.format(json.dumps(vuln_data, indent=2))
    
    # Use multiple attempts with exponential backoff
    max_retries = 3
    base_wait = 2  # seconds
    
    for attempt in range(max_retries):
        try:
            # Create a cache directory if it doesn't exist
            if not os.path.exists(CACHE_DIR):
                os.makedirs(CACHE_DIR, exist_ok=True)
                
            # Generate cache key for this clustering operation
            hasher = hashlib.md5()
            hasher.update(prompt.encode('utf-8'))
            cache_key = hasher.hexdigest()
            cache_file = os.path.join(CACHE_DIR, f"cluster_{cache_key}.json")
            
            # Check if we have a cached result
            if os.path.exists(cache_file):
                try:
                    with open(cache_file, 'r') as f:
                        cached_result = json.load(f)
                    console.print(f"[green]Using cached clustering result[/green]")
                    return cached_result
                except Exception as e:
                    console.print(f"[yellow]Error reading cache: {e}. Will regenerate.[/yellow]")
            
            # Determine which API to use based on configuration
            use_openrouter = False
            if USE_API == "auto" or USE_API == "openrouter":
                if OPENROUTER_API_KEY:
                    use_openrouter = True
            
            if use_openrouter:
                # Use OpenRouter API
                console.print(f"[cyan]Attempt {attempt+1}/{max_retries}: Clustering vulnerabilities using OpenRouter...[/cyan]")
                try:
                    headers = {
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                        "HTTP-Referer": "https://github.com/pxng0lin/DeepCurrent",
                        "X-Title": "DeepCurrent Security Analysis"
                    }
                    
                    messages = [
                        {"role": "system", "content": "You are a smart contract security expert. Analyze vulnerability types and organize them into comprehensive categories."}, 
                        {"role": "user", "content": prompt}
                    ]
                    
                    payload = {
                        "model": DEFAULT_MODEL,
                        "messages": messages,
                        "temperature": 0.2,
                        "max_tokens": 20000
                    }
                    
                    response = requests.post(
                        "https://openrouter.ai/api/v1/chat/completions",
                        headers=headers,
                        json=payload,
                        timeout=180
                    )
                except Exception as e:
                    console.print(f"[yellow]OpenRouter API error: {e}. Falling back to Ollama...[/yellow]")
                    use_openrouter = False
            
            if not use_openrouter:
                # Use Ollama API
                console.print(f"[cyan]Attempt {attempt+1}/{max_retries}: Clustering vulnerabilities using Ollama...[/cyan]")
                headers = {"Content-Type": "application/json"}
                payload = {
                    "model": model,
                    "prompt": prompt,
                    "temperature": 0.2,  # Lower temperature for more consistent results
                    "max_tokens": 20000
                }
                
                response = requests.post(LLM_API_URL, json=payload, headers=headers, timeout=120)
            
            if response.status_code != 200:
                console.print(f"[yellow]HTTP error {response.status_code}. Retrying...[/yellow]")
                if attempt < max_retries - 1:
                    wait_time = base_wait * (2 ** attempt)
                    time.sleep(wait_time)
                continue
                
            result = response.json()
            
            # Handle different response formats based on API used
            if use_openrouter:
                try:
                    # Debug the response structure
                    console.print(f"[cyan]OpenRouter response keys: {list(result.keys())}[/cyan]")
                    
                    # Standard OpenRouter response format
                    if "choices" in result and result["choices"] and len(result["choices"]) > 0:
                        # Check and print what's in the first choice
                        choice = result["choices"][0]
                        console.print(f"[cyan]OpenRouter choice keys: {list(choice.keys())}[/cyan]")
                        
                        if "message" in choice and "content" in choice["message"]:
                            result_text = choice["message"]["content"].strip()
                        elif "text" in choice:
                            # Some models might return text directly
                            result_text = choice["text"].strip()
                        else:
                            # Try to extract content from other possible locations
                            for possible_key in ["finish_reason", "logprobs", "usage"]:
                                if possible_key in choice and isinstance(choice[possible_key], str):
                                    result_text = choice[possible_key].strip()
                                    break
                            else:
                                # If we can't find content in expected places, dump full response for debugging
                                console.print(f"[yellow]OpenRouter response structure: {json.dumps(result, indent=2)}[/yellow]")
                                raise ValueError("Cannot find content in OpenRouter response")
                    # Handle alternative response formats
                    elif "object" in result and result["object"] == "chat.completion":
                        if "choices" in result and len(result["choices"]) > 0:
                            # Try to extract from alternative structure
                            if "delta" in result["choices"][0] and "content" in result["choices"][0]["delta"]:
                                result_text = result["choices"][0]["delta"]["content"].strip()
                            elif "content" in result["choices"][0]:
                                # Direct content field
                                result_text = result["choices"][0]["content"].strip()
                            else:
                                # Dump structure for debugging
                                console.print(f"[yellow]OpenRouter chat.completion structure: {json.dumps(result, indent=2)}[/yellow]")
                                raise ValueError("Cannot find content in chat.completion")
                    # Direct text response
                    elif "text" in result:
                        result_text = result["text"].strip()
                    # Complete fallback - try to find any text field recursively
                    else:
                        # Dump full response for debugging
                        console.print(f"[yellow]Full OpenRouter response: {json.dumps(result, indent=2)}[/yellow]")
                        raise ValueError("Unrecognized OpenRouter response format")
                except Exception as e:
                    console.print(f"[yellow]OpenRouter response processing error: {e}. Retrying...[/yellow]")
                    if attempt < max_retries - 1:
                        wait_time = base_wait * (2 ** attempt)
                        time.sleep(wait_time)
                    continue
            else:  # Ollama response format
                if "choices" in result and result["choices"]:
                    result_text = result["choices"][0].get("text", "").strip()
                elif "response" in result:
                    result_text = result["response"].strip()
                else:
                    console.print("[yellow]Invalid Ollama response structure. Retrying...[/yellow]")
                    if attempt < max_retries - 1:
                        wait_time = base_wait * (2 ** attempt)
                        time.sleep(wait_time)
                    continue
            if not result_text:
                console.print("[yellow]Empty response. Retrying...[/yellow]")
                if attempt < max_retries - 1:
                    wait_time = base_wait * (2 ** attempt)
                    time.sleep(wait_time)
                continue
            
            # Process and clean the response
            # Remove code fences if present
            if result_text.startswith("```") and result_text.endswith("```"):
                result_text = "\n".join(result_text.split("\n")[1:-1])
            elif result_text.startswith("```"):
                result_text = "\n".join(result_text.split("\n")[1:])
                
            # Remove any JSON syntax identifier
            if result_text.startswith("json"):
                result_text = result_text[4:].lstrip()
                
            # Clean up any trailing commas before closing brackets
            result_text = re.sub(r",\s*([\]}])", r"\1", result_text)
            
            # Extract JSON if embedded in other text
            if not result_text.startswith("{"):
                json_match = re.search(r'\{.*\}', result_text, re.DOTALL)
                if json_match:
                    result_text = json_match.group(0)
            
            # Parse the clustering result
            try:
                # Use raw_decode to handle potential trailing data
                decoder = json.JSONDecoder()
                clustering, idx = decoder.raw_decode(result_text)
                
                if not isinstance(clustering, dict):
                    raise ValueError("Clustering result is not a dictionary")
                    
                # Success - create the library based on clustering
                library = {}
                
                # Initialize categories with extended fields
                for category in clustering.keys():
                    library[category] = {
                        "questions": [], 
                        "vulnerable_examples": [], 
                        "fixed_examples": [],
                        "insights": [], 
                        "patterns": [], 
                        "attack_vectors": [], 
                        "severity_ratings": [],
                        "detection_signatures": []
                    }
                
                # Populate library based on clustering
                for category, indices in clustering.items():
                    for idx in indices:
                        if isinstance(idx, int) and 0 <= idx < len(vuln_details_list):
                            details = vuln_details_list[idx]
                            _update_library_with_details(library[category], details)
                
                # Remove duplicates and limit entries
                for category_data in library.values():
                    _deduplicate_library_category(category_data)
                
                console.print(f"[green]✅ Successfully clustered into {len(library)} vulnerability categories[/green]")
                
                # Cache the successful result
                try:
                    with open(cache_file, 'w') as f:
                        json.dump(library, f)
                except Exception as e:
                    console.print(f"[yellow]Failed to cache result: {e}[/yellow]")
                    
                return library
                
            except (ValueError, json.JSONDecodeError) as e:
                console.print(f"[yellow]Failed to parse clustering result: {e}[/yellow]")
                if attempt < max_retries - 1:
                    wait_time = base_wait * (2 ** attempt)
                    time.sleep(wait_time)
                continue
                
        except requests.exceptions.RequestException as e:
            console.print(f"[yellow]Request error: {e}[/yellow]")
        except Exception as e:
            console.print(f"[red]Unexpected error: {e}[/red]")
        
        if attempt < max_retries - 1:
            wait_time = base_wait * (2 ** attempt)
            console.print(f"[yellow]Retrying in {wait_time} seconds...[/yellow]")
            time.sleep(wait_time)
    
    # If all attempts failed, fall back to simple categorization
    console.print("[yellow]Clustering failed. Falling back to simple categorization by vulnerability type.[/yellow]")
    library = {}
    for details in vuln_details_list:
        vuln_type = details.get("vuln_type", "Unknown")
        if not vuln_type or vuln_type == "Unknown":
            continue
            
        if vuln_type not in library:
            library[vuln_type] = {
                "questions": [], 
                "vulnerable_examples": [], 
                "fixed_examples": [],
                "insights": [], 
                "patterns": [], 
                "attack_vectors": [], 
                "severity_ratings": [],
                "detection_signatures": []
            }
        
        # Add all details to the library
        _update_library_with_details(library[vuln_type], details)
    
    # Deduplicate the simple categorization results
    for category_data in library.values():
        _deduplicate_library_category(category_data)
        
    return library

def _update_library_with_details(category_data, details):
    """Helper function to update a category with vulnerability details"""
    # Add standard fields
    if details.get("questions"):
        if isinstance(details["questions"], list):
            category_data["questions"].extend(details["questions"])
        else:
            category_data["questions"].append(str(details["questions"]))
    
    if details.get("vulnerable_code"):
        category_data["vulnerable_examples"].append(details["vulnerable_code"])
    
    if details.get("fixed_code"):
        category_data["fixed_examples"].append(details["fixed_code"])
    
    if details.get("researcher_insights"):
        category_data["insights"].append(details["researcher_insights"])
    
    if details.get("pattern"):
        category_data["patterns"].append(details["pattern"])
    
    # Add enhanced fields
    if details.get("attack_vectors"):
        if isinstance(details["attack_vectors"], list):
            category_data["attack_vectors"].extend(details["attack_vectors"])
        else:
            category_data["attack_vectors"].append(str(details["attack_vectors"]))
    
    if details.get("severity_rating"):
        category_data["severity_ratings"].append(details["severity_rating"])
    
    if details.get("detection_signatures"):
        if isinstance(details["detection_signatures"], list):
            category_data["detection_signatures"].extend(details["detection_signatures"])
        else:
            category_data["detection_signatures"].append(str(details["detection_signatures"]))

def _deduplicate_library_category(category_data):
    """Helper function to deduplicate entries in a category and limit their number"""
    # Safe deduplication function that works with any data type
    def safe_deduplicate(items, limit=5):
        if not items:
            return []
            
        # For string items, we can use set for efficient deduplication
        if all(isinstance(item, str) for item in items):
            return list(set(items))[:limit]
            
        # For mixed or non-hashable types, use a slower but safer approach
        unique_items = []
        for item in items:
            # Convert complex items to strings for comparison
            item_str = str(item)
            if not any(str(existing) == item_str for existing in unique_items):
                unique_items.append(item)
                if len(unique_items) >= limit:
                    break
        return unique_items
    
    # Apply safe deduplication to all list fields
    category_data["questions"] = safe_deduplicate(category_data["questions"], 5)
    category_data["attack_vectors"] = safe_deduplicate(category_data["attack_vectors"], 5)
    category_data["detection_signatures"] = safe_deduplicate(category_data["detection_signatures"], 5)
    category_data["patterns"] = safe_deduplicate(category_data["patterns"], 5)
        
    # Limit examples and insights
    category_data["vulnerable_examples"] = category_data["vulnerable_examples"][:3]  # Limit to 3
    category_data["fixed_examples"] = category_data["fixed_examples"][:3]  # Limit to 3
    category_data["insights"] = category_data["insights"][:3]  # Limit to 3
  
def _batch_process_vulnerabilities(vuln_details_list, model):
    """Process a large dataset by splitting it into manageable batches and then combining the results using LLM-based analysis"""
    # Determine batch size based on provider
    batch_size = 40  # For OpenRouter, we'll use smaller batches to stay well under the token limit
    
    # Split the data into batches
    batches = []
    for i in range(0, len(vuln_details_list), batch_size):
        batches.append(vuln_details_list[i:i+batch_size])
    
    console.print(f"[cyan]Processing {len(batches)} batches of ~{batch_size} reports each using LLM analysis[/cyan]")
    
    # Process each batch separately using the LLM
    library = {}
    for i, batch in enumerate(batches):
        console.print(f"\n[bold]Processing batch {i+1}/{len(batches)} with LLM...[/bold]")
        
        try:
            # Use the same LLM clustering logic, but on the smaller batch
            # This avoids the token limit issues while still leveraging LLM capabilities
            batch_start_time = time.time()
            
            # Extract vulnerability data for this batch (similar to cluster_vulnerabilities)
            vuln_data = []
            for j, details in enumerate(batch):
                if not details.get("vuln_type"):
                    continue
                    
                vuln_entry = {
                    "index": j,  # Local index within this batch
                    "vuln_type": details.get("vuln_type", "Unknown"),
                    "severity": details.get("severity_rating", ""),
                }
                
                # Add detection signatures if available
                if "detection_signatures" in details and details["detection_signatures"]:
                    if isinstance(details["detection_signatures"], list):
                        vuln_entry["signatures"] = details["detection_signatures"][:2]
                    else:
                        vuln_entry["signatures"] = [str(details["detection_signatures"])]
                
                # Add attack vectors if available
                if "attack_vectors" in details and details["attack_vectors"]:
                    if isinstance(details["attack_vectors"], list):
                        vuln_entry["attack_vectors"] = details["attack_vectors"][:2]
                    else:
                        vuln_entry["attack_vectors"] = [str(details["attack_vectors"])]
                        
                # Include code snippet info (just presence, not full content to save tokens)
                vuln_entry["has_code_examples"] = bool(details.get("vulnerable_code") or details.get("fixed_code"))
                
                vuln_data.append(vuln_entry)
            
            # Enhanced clustering prompt - similar to the main function but optimized for smaller batches
            prompt = """
            You are a smart contract security expert. Analyze these vulnerability types and organize them into a comprehensive detection library.
            Examine each vulnerability carefully and determine the logical categories.
            
            CLUSTERING RULES:
            1. Use precise, actionable categories (e.g., "Reentrancy (CWE-841)" instead of just "Logic Error")
            2. Include CWE identifiers when applicable
            3. Merge near-identical vulnerabilities even if they have different names
            4. Keep truly distinct vulnerabilities separate, even if they fall in the same general area
            5. Prioritize categories that will be most useful for automated vulnerability detection
            
            VULNERABILITY DATA:
            {}
            
            OUTPUT INSTRUCTIONS:
            Return a JSON object where:
            - Each key is a standardized, precise vulnerability category name (with CWE if possible)
            - Each value is an array of indices from the input list that belong to this category
            
            Example format:
            {{
              "Reentrancy (CWE-841)": [0, 3, 7],
              "Integer Overflow (CWE-190)": [1, 4],
              "Access Control Issues (CWE-284)": [2, 5, 6]
            }}
            
            Only provide the JSON with no additional explanation.
            """.format(json.dumps(vuln_data, indent=2))
            
            # Note the cached response check is inside the main clustering function
            
            # Use OpenRouter for all batches since that's what the user specified
            use_openrouter = (USE_API == "openrouter")
            
            # Generate the clustering response
            max_retries = 3
            base_wait = 2  # seconds
            
            # Similar to the main clustering logic but simplified
            for attempt in range(max_retries):
                try:
                    if use_openrouter:
                        # Use OpenRouter API
                        console.print(f"[cyan]Batch {i+1}: Attempt {attempt+1}/{max_retries} using OpenRouter...[/cyan]")
                        headers = {
                            "Content-Type": "application/json",
                            "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                            "HTTP-Referer": "https://github.com/pxng0lin/DeepCurrent",
                            "X-Title": "DeepCurrent Security Analysis"
                        }
                        
                        messages = [
                            {"role": "system", "content": "You are a smart contract security expert."}, 
                            {"role": "user", "content": prompt}
                        ]
                        
                        payload = {
                            "model": DEFAULT_MODEL,
                            "messages": messages,
                            "temperature": 0.2,
                            "max_tokens": 4000  # Reduced max tokens since we're dealing with smaller batches
                        }
                        
                        response = requests.post(
                            "https://openrouter.ai/api/v1/chat/completions",
                            headers=headers,
                            json=payload,
                            timeout=120
                        )
                    else:
                        # Use Ollama API
                        console.print(f"[cyan]Batch {i+1}: Attempt {attempt+1}/{max_retries} using Ollama...[/cyan]")
                        headers = {"Content-Type": "application/json"}
                        payload = {
                            "model": model,
                            "prompt": prompt,
                            "temperature": 0.2,
                            "max_tokens": 4000
                        }
                        
                        response = requests.post(LLM_API_URL, json=payload, headers=headers, timeout=120)
                    
                    if response.status_code != 200:
                        console.print(f"[yellow]HTTP error {response.status_code}. Retrying...[/yellow]")
                        if attempt < max_retries - 1:
                            wait_time = base_wait * (2 ** attempt)
                            time.sleep(wait_time)
                        continue
                    
                    result = response.json()
                    
                    # Debug output to help understand the response structure
                    if use_openrouter:
                        console.print(f"[dim]OpenRouter response keys: {list(result.keys())}[/dim]")
                    
                    # Handle different response formats
                    if use_openrouter:
                        try:
                            # Extract text from OpenRouter response
                            if "choices" in result and result["choices"] and len(result["choices"]) > 0:
                                choice = result["choices"][0]
                                if "message" in choice and "content" in choice["message"]:
                                    result_text = choice["message"]["content"].strip()
                                else:
                                    raise ValueError("Cannot find content in OpenRouter response")
                            elif "error" in result:
                                error_msg = result["error"].get("message", "Unknown error")
                                console.print(f"[red]OpenRouter error: {error_msg}[/red]")
                                raise ValueError(f"OpenRouter API error: {error_msg}")
                            else:
                                raise ValueError("Unrecognized OpenRouter response format") 
                        except Exception as e:
                            console.print(f"[yellow]OpenRouter processing error: {e}. Retrying...[/yellow]")
                            if attempt < max_retries - 1:
                                wait_time = base_wait * (2 ** attempt)
                                time.sleep(wait_time)
                            continue
                    else:  # Ollama response
                        if "response" in result:
                            result_text = result["response"].strip()
                        else:
                            console.print("[yellow]Invalid Ollama response structure. Retrying...[/yellow]")
                            if attempt < max_retries - 1:
                                wait_time = base_wait * (2 ** attempt)
                                time.sleep(wait_time)
                            continue
                    
                    # Process and clean the response
                    # Remove code fences
                    if result_text.startswith("```") and result_text.endswith("```"):
                        result_text = "\n".join(result_text.split("\n")[1:-1])
                    elif result_text.startswith("```"):
                        result_text = "\n".join(result_text.split("\n")[1:])
                    
                    # Remove JSON syntax identifier
                    if result_text.startswith("json"):
                        result_text = result_text[4:].lstrip()
                    
                    # Extract JSON
                    if not result_text.startswith("{"):
                        json_match = re.search(r'\{.*\}', result_text, re.DOTALL)
                        if json_match:
                            result_text = json_match.group(0)
                    
                    # Parse the clustering
                    try:
                        # Use raw_decode to handle potential trailing data
                        decoder = json.JSONDecoder()
                        clustering, _ = decoder.raw_decode(result_text)
                        
                        if not isinstance(clustering, dict):
                            raise ValueError("Clustering result is not a dictionary")
                        
                        # Process the clustering results for this batch
                        batch_library = {}
                        for category in clustering.keys():
                            batch_library[category] = {
                                "questions": [], 
                                "vulnerable_examples": [], 
                                "fixed_examples": [],
                                "insights": [], 
                                "patterns": [], 
                                "attack_vectors": [], 
                                "severity_ratings": [],
                                "detection_signatures": []
                            }
                        
                        # Populate library based on clustering
                        for category, indices in clustering.items():
                            for idx in indices:
                                if isinstance(idx, int) and 0 <= idx < len(batch):
                                    details = batch[idx]
                                    _update_library_with_details(batch_library[category], details)
                        
                        # Merge this batch's library into the main library
                        for vuln_type, data in batch_library.items():
                            if vuln_type not in library:
                                library[vuln_type] = data
                            else:
                                # Merge the data
                                for key in data:
                                    library[vuln_type][key].extend(data[key])
                        
                        batch_duration = time.time() - batch_start_time
                        console.print(f"[green]✅ Batch {i+1}/{len(batches)} categorized into {len(batch_library)} vulnerability types in {batch_duration:.1f}s[/green]")
                        
                        # Successfully processed this batch
                        break
                    except (ValueError, json.JSONDecodeError) as e:
                        console.print(f"[yellow]Failed to parse batch {i+1} clustering: {e}[/yellow]")
                        console.print(f"[dim]Result text: {result_text[:100]}...[/dim]")
                        if attempt < max_retries - 1:
                            wait_time = base_wait * (2 ** attempt)
                            time.sleep(wait_time)
                        continue
                except Exception as e:
                    console.print(f"[red]Batch {i+1} processing error: {e}[/red]")
                    if attempt < max_retries - 1:
                        wait_time = base_wait * (2 ** attempt)
                        time.sleep(wait_time)
                    continue
            
            # If we got here and exhausted all retries, use simple categorization for this batch
            if attempt >= max_retries - 1:
                console.print(f"[yellow]Could not process batch {i+1} with LLM. Using simple categorization.[/yellow]")
                # Simple categorization fallback
                batch_library = {}
                for details in batch:
                    vuln_type = details.get("vuln_type", "Unknown")
                    if not vuln_type or vuln_type == "Unknown":
                        continue
                    
                    if vuln_type not in batch_library:
                        batch_library[vuln_type] = {
                            "questions": [], 
                            "vulnerable_examples": [], 
                            "fixed_examples": [],
                            "insights": [], 
                            "patterns": [], 
                            "attack_vectors": [], 
                            "severity_ratings": [],
                            "detection_signatures": []
                        }
                    
                    # Add all details to the library
                    _update_library_with_details(batch_library[vuln_type], details)
                
                # Merge this batch's library into the main library
                for vuln_type, data in batch_library.items():
                    if vuln_type not in library:
                        library[vuln_type] = data
                    else:
                        # Merge the data
                        for key in data:
                            library[vuln_type][key].extend(data[key])
        except KeyboardInterrupt:
            console.print("\n[yellow]Batch processing interrupted. Using partial results.[/yellow]")
            break
        except Exception as e:
            console.print(f"\n[red]Error processing batch {i+1}: {e}[/red]")
            # Continue with next batch
    
    # Final deduplication and cleanup
    for category_data in library.values():
        _deduplicate_library_category(category_data)
    
    console.print(f"\n[green]✅ Successfully processed {len(vuln_details_list)} reports into {len(library)} vulnerability categories using LLM-powered batch processing[/green]")
    return library

def format_examples(examples):
    """Convert a list of examples (which may be dicts) into a formatted string."""
    if not examples:
        return ""
        
    formatted = []
    for i, ex in enumerate(examples):
        if isinstance(ex, dict):
            formatted.append(f"Example {i+1}: {json.dumps(ex, indent=2)}")
        else:
            formatted.append(f"Example {i+1}: {ex}")
    return "\n".join(formatted)

def display_detection_library(library):
    """
    Display a summary table of the detection pattern library (the aggregated in-memory structure).
    If the aggregated details for a vulnerability type is a list, use the first element.
    Convert dict entries into formatted strings.
    """
    table = Table(title="Detection Pattern Library (Aggregated in Memory)")
    table.add_column("Vulnerability Type", style="cyan")
    table.add_column("Questions", style="magenta")
    table.add_column("Vulnerable Examples", style="red")
    table.add_column("Fixed Examples", style="green")
    
    for vuln_type, details in library.items():
        # If details is a list, use the first element (if available)
        if isinstance(details, list):
            details = details[0] if details else {}
        questions = "\n".join(details.get("questions", []))
        vuln_examples = format_examples(details.get("vulnerable_examples", []))
        fixed_examples = format_examples(details.get("fixed_examples", []))
        table.add_row(vuln_type, questions, vuln_examples, fixed_examples)
    console.print(table)

def build_detection_library(db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("SELECT analysis_summary FROM reports")
    rows = c.fetchall()
    conn.close()
    
    vuln_details_list = []
    for (analysis_summary,) in rows:
        try:
            details = json.loads(analysis_summary)
            vuln_details_list.append(details)
        except Exception:
            continue

    # Use LLM to cluster the vulnerabilities into categories.
    library = cluster_vulnerabilities(vuln_details_list)
    # If library is a string, try to parse it
    if isinstance(library, str):
        try:
            library = json.loads(library)
        except Exception as e:
            console.print(f"[red]Failed to parse detection library string: {e}[/red]")
            library = {}
    return library

def generate_robust_detection_template(vuln_type, details, model=DEFAULT_OLLAMA_MODEL):
    """
    Generate a detailed, actionable detection template for a vulnerability type
    using the enhanced library structure with severity, attack vectors, and detection signatures.
    
    Args:
        vuln_type: The type of vulnerability to generate a template for
        details: Dictionary containing vulnerability details
        model: For OpenRouter, use an OpenRouter model ID. For Ollama, use a local model name.
    """
    # Extract key components that could help improve the template
    questions = details.get("questions", [])
    vulnerabilities = details.get("vulnerable_examples", [])
    fixes = details.get("fixed_examples", [])
    insights = details.get("insights", [])
    patterns = details.get("patterns", [])
    attack_vectors = details.get("attack_vectors", [])
    severity_ratings = details.get("severity_ratings", [])
    detection_signatures = details.get("detection_signatures", [])
    
    # Determine overall severity if available
    severity = "Unknown"
    if severity_ratings:
        # Try to extract numerical values
        numeric_values = []
        for rating in severity_ratings:
            # Try to extract a number like "7.5" or "8/10"
            matches = re.findall(r'\b(\d+(?:\.\d+)?)(?:/10)?\b', rating.lower())
            if matches:
                try:
                    numeric_values.append(float(matches[0]))
                except ValueError:
                    pass
            # Look for common severity terms
            elif "critical" in rating.lower() or "high" in rating.lower():
                numeric_values.append(8.0)
            elif "medium" in rating.lower():
                numeric_values.append(5.0)
            elif "low" in rating.lower():
                numeric_values.append(3.0)
        
        # Calculate average severity if we found numeric values
        if numeric_values:
            avg_severity = sum(numeric_values) / len(numeric_values)
            # Map to severity category
            if avg_severity >= 7.0:
                severity = "Critical"
            elif avg_severity >= 5.0:
                severity = "High"
            elif avg_severity >= 3.0:
                severity = "Medium"
            else:
                severity = "Low"
    
    # Build a prompt that directs the LLM to generate a comprehensive template
    prompt = f"""
    You are a smart contract security expert creating a detection template for '{vuln_type}'.
    
    VULNERABILITY INFORMATION:
    - Overall Severity: {severity}
    - Attack Vectors: {', '.join(attack_vectors) if attack_vectors else 'Not specified'}
    
    DETECTION CRITERIA:
    Questions: {json.dumps(questions)}
    Detection Signatures: {json.dumps(detection_signatures)}
    Patterns: {json.dumps(patterns)}
    
    CODE EXAMPLES:
    Vulnerable Code: {json.dumps(vulnerabilities[:1]) if vulnerabilities else 'Not available'}
    Fixed Code: {json.dumps(fixes[:1]) if fixes else 'Not available'}
    
    RESEARCHER INSIGHTS:
    {json.dumps(insights) if insights else 'Not available'}
    
    INSTRUCTIONS:
    Create a comprehensive detection template that includes:
    1. Clear title and description of the vulnerability
    2. Severity rating and impact assessment
    3. Technical detection methodology with specific code patterns to look for
    4. Required security checks and questions to ask
    5. Example vulnerable and fixed code (if available)
    6. Prevention strategies
    
    Format the template as a structured document with clear sections.
    Use Markdown formatting for better readability.
    """
    
    # Generate a cache key based on the content and prompt
    hasher = hashlib.md5()
    hasher.update((prompt + str(vuln_type)).encode('utf-8'))
    cache_key = hasher.hexdigest()
    
    # Check if we have a cached response
    cache_file = os.path.join(CACHE_DIR, f"template_{cache_key}.md")
    if os.path.exists(cache_file):
        try:
            with open(cache_file, 'r') as f:
                cached_template = f.read()
            console.print("[dim]Using cached template[/dim]")
            return cached_template
        except IOError as e:
            console.print(f"[yellow]Cache read error: {e}, generating new template[/yellow]")
    
    # Determine which API to use based on configuration and availability
    use_openrouter = False
    
    if USE_API == "auto" or USE_API == "openrouter":
        if OPENROUTER_API_KEY:
            use_openrouter = True
            # If in auto mode and OpenRouter fails, we'll fall back to Ollama
            use_fallback = (USE_API == "auto")
        else:
            if USE_API == "openrouter":
                console.print("[yellow]OPENROUTER_API_KEY not found but USE_API=openrouter, please set the API key[/yellow]")
            console.print("[dim]Falling back to local Ollama API[/dim]")
    
    template = None
    
    if use_openrouter:
        try:
            template = _generate_template_with_openrouter(prompt, vuln_type, DEFAULT_MODEL)
        except Exception as e:
            if use_fallback:
                console.print(f"[yellow]OpenRouter API failed: {e}, falling back to Ollama[/yellow]")
            else:
                raise
    
    # If template is None, either OpenRouter failed with fallback enabled, or we're using Ollama directly
    if template is None:
        template = _generate_template_with_ollama(prompt, vuln_type, model)
    
    # Cache the result
    try:
        with open(cache_file, 'w') as f:
            f.write(template)
    except IOError as e:
        console.print(f"[yellow]Failed to cache template: {e}[/yellow]")
    
    return template

def _generate_template_with_openrouter(prompt, vuln_type, model):
    """Generate template using OpenRouter API"""
    global OPENROUTER_API_KEY
    
    # Create cache directory if it doesn't exist
    if not os.path.exists(CACHE_DIR):
        os.makedirs(CACHE_DIR, exist_ok=True)
    
    # Generate a unique cache key for this template request
    hasher = hashlib.md5()
    hasher.update((prompt + vuln_type + model).encode('utf-8'))
    cache_key = hasher.hexdigest()
    cache_file = os.path.join(CACHE_DIR, f"or_template_{cache_key}.md")
    
    # Check if we have a cached result
    if os.path.exists(cache_file):
        try:
            with open(cache_file, 'r') as f:
                cached_template = f.read()
            console.print(f"[green]Using cached template for {vuln_type}[/green]")
            return cached_template
        except Exception as e:
            console.print(f"[yellow]Error reading cache: {e}. Will regenerate.[/yellow]")
    
    # Standard headers for OpenRouter API exactly as in DeepCurrent_v3.1.py
    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/pxng0lin/DeepCurrent",  # Required for data policies
        "X-Title": "DeepCurrent Security Analysis",  # Name of your app
        "X-Data-Usage": OPENROUTER_DATA_USAGE  # Control data usage policy
    }
    
    # Prepare messages array for OpenRouter API
    messages = [
        {"role": "system", "content": "You are an expert in smart contract security analysis specializing in creating detailed vulnerability detection templates."},
        {"role": "user", "content": prompt}
    ]
    
    # Include all models to try in order of preference
    models_to_try = [model] + [m for m in BACKUP_MODELS if m != model]
    console.print(f"[cyan]Using OpenRouter API with model: {model}[/cyan]")
    
    # Try up to 3 times with different models
    max_retries = 3
    base_wait = 2  # seconds
    
    for attempt in range(max_retries):
        # Rotate through models if needed
        current_model = models_to_try[min(attempt, len(models_to_try) - 1)]
        
        try:
            console.print(f"[dim]Attempt {attempt+1}/{max_retries} with model {current_model}...[/dim]")
            
            payload = {
                "model": current_model,
                "messages": messages,
                "temperature": 0.3,  # Lower temperature for consistent template output
                "max_tokens": 20000
            }
            
            # Make the API request
            response = requests.post(
                OPENROUTER_API_URL,
                headers=headers,
                json=payload,
                timeout=120
            )
            
            # Handle rate limits and other HTTP errors
            if response.status_code == 429:
                console.print(f"[yellow]OpenRouter rate limit exceeded on attempt {attempt+1}[/yellow]")
                
                # Try rotating API key if available
                # Session-based implementation doesn't support key rotation
                console.print(f"[yellow]Rate limit reached. You may need to update your API key.[/yellow]")
                
                # If we can try another model instead
                if attempt < max_retries - 1 and attempt < len(models_to_try) - 1:
                    wait_time = base_wait * (2 ** attempt)
                    console.print(f"[yellow]Trying alternate model in {wait_time} seconds...[/yellow]")
                    time.sleep(wait_time)
                    continue
                else:
                    raise Exception("Rate limit exceeded for all available models/keys")
            elif response.status_code != 200:
                console.print(f"[yellow]HTTP error {response.status_code} on attempt {attempt+1}[/yellow]")
                if attempt < max_retries - 1:
                    wait_time = base_wait * (2 ** attempt)
                    console.print(f"[yellow]Retrying in {wait_time} seconds...[/yellow]")
                    time.sleep(wait_time)
                    continue
                else:
                    response.raise_for_status()
            
            # Process successful response
            try:
                result = response.json()
                
                # Log model information if available
                if "model" in result:
                    console.print(f"[dim]Using model: {result['model']}[/dim]")
                
                # Validate response structure
                if not isinstance(result, dict):
                    console.print(f"[yellow]Unexpected response type: {type(result)}[/yellow]")
                    raise ValueError(f"Unexpected response type: {type(result)}")
                    
                if "choices" not in result or not result["choices"] or not isinstance(result["choices"], list):
                    console.print(f"[yellow]Invalid response format - missing choices: {result}[/yellow]")
                    raise ValueError("Invalid API response format - missing choices")
                    
                # Extract the content from the response
                choice = result["choices"][0]
                if "message" not in choice:
                    console.print(f"[yellow]No 'message' in response choice: {choice}[/yellow]")
                    raise ValueError("No 'message' in API response")
                    
                message = choice["message"]
                if "content" not in message:
                    console.print(f"[yellow]No 'content' in message: {message}[/yellow]")
                    raise ValueError("No 'content' in API response message")
                    
                template = message["content"].strip()
                console.print(f"[dim]Template received ({len(template)} chars)[/dim]")
                
                if not template:
                    raise ValueError("Empty template from API")
                
                # Cache the successful response
                try:
                    with open(cache_file, 'w') as f:
                        f.write(template)
                    console.print(f"[dim]Cached template to {cache_file}[/dim]")
                except Exception as e:
                    console.print(f"[yellow]Failed to cache template: {e}[/yellow]")
                
                return template
            except Exception as e:
                console.print(f"[yellow]Failed to parse template response: {str(e)}[/yellow]")
                raise ValueError(f"Invalid template API response format: {str(e)}")
            
        except Exception as e:
            console.print(f"[yellow]Error on attempt {attempt+1}: {e}[/yellow]")
        
        # Don't wait after the last attempt
        if attempt < max_retries - 1:
            wait_time = base_wait * (2 ** attempt)
            console.print(f"[yellow]Retrying in {wait_time} seconds...[/yellow]")
            time.sleep(wait_time)
    
    # All attempts failed
    return None

def _generate_template_with_ollama(prompt, vuln_type, model):
    """Generate template using local Ollama API with ollama-python client"""
    console.print(f"[cyan]Using local Ollama API with model: {model}[/cyan]")
    
    # Create cache directory if it doesn't exist
    if not os.path.exists(CACHE_DIR):
        os.makedirs(CACHE_DIR, exist_ok=True)
        
    # Generate a unique cache key for this template request
    hasher = hashlib.md5()
    hasher.update((prompt + vuln_type + model).encode('utf-8'))
    cache_key = hasher.hexdigest()
    cache_file = os.path.join(CACHE_DIR, f"ollama_template_{cache_key}.md")
    
    # Check if we have a cached result
    if os.path.exists(cache_file):
        try:
            with open(cache_file, 'r') as f:
                cached_template = f.read()
            console.print(f"[green]Using cached template for {vuln_type}[/green]")
            return cached_template
        except Exception as e:
            console.print(f"[yellow]Error reading cache: {e}. Will regenerate.[/yellow]")
            
    # Try up to 3 times with exponential backoff
    max_retries = 3
    base_wait = 2  # seconds
    
    for attempt in range(max_retries):
        try:
            # Use the ollama-python client with chat API
            console.print(f"[dim]Attempt {attempt+1}/{max_retries} with model {model}...[/dim]")
            
            response = ollama.chat(
                model=model,
                messages=[
                    {
                        'role': 'system',
                        'content': 'You are a smart contract security expert specializing in creating detailed vulnerability detection templates.'
                    },
                    {
                        'role': 'user',
                        'content': prompt
                    }
                ],
                options={
                    "temperature": 0.3,  # Lower temperature for more consistent, focused results
                }
            )
            
            # Extract content from response
            template = ""
            if isinstance(response, dict) and 'message' in response:
                # Dictionary format response
                if 'content' in response['message']:
                    template = response['message']['content']
                else:
                    raise ValueError("No content in response message")
            elif hasattr(response, 'message') and hasattr(response.message, 'content'):
                # Object format response
                template = response.message.content
            else:
                raise ValueError("Unexpected response format from Ollama API")
                
            console.print(f"[dim]Template received ({len(template)} chars)[/dim]")
            
            if not template:
                raise ValueError("Empty template response")
                
            # Cache the successful result
            try:
                with open(cache_file, 'w') as f:
                    f.write(template)
            except Exception as e:
                console.print(f"[yellow]Failed to cache template: {e}[/yellow]")
                
            return template
                
        except requests.exceptions.RequestException as e:
            console.print(f"[yellow]Request error on attempt {attempt+1}: {e}[/yellow]")
        except ValueError as e:
            console.print(f"[yellow]Value error on attempt {attempt+1}: {e}[/yellow]")
        except Exception as e:
            console.print(f"[red]Unexpected error on attempt {attempt+1}: {e}[/red]")
            
        # Don't wait after the last attempt
        if attempt < max_retries - 1:
            wait_time = base_wait * (2 ** attempt)
            console.print(f"[yellow]Retrying in {wait_time} seconds...[/yellow]")
            time.sleep(wait_time)
    
    # Fallback template if all attempts fail
    return f"""
    # {vuln_type} - Detection Template
    
    ## Description
    This vulnerability represents a security issue in smart contracts. Due to technical issues, 
    a complete template could not be generated. Please refer to the vulnerability details for more information.
    
    ## Available Information
    - Questions to ask: {len(questions) if 'questions' in details else 0} questions available
    - Code examples: {len(vulnerabilities)} vulnerable examples, {len(fixes)} fixed examples
    - Known patterns: {len(patterns)} patterns identified
    
    ## Manual Review Required
    Please conduct a manual review of this vulnerability type using the provided details.
    """

def save_detection_library_to_db(library, db_path=DB_PATH):
    """
    Save the aggregated detection library and robust detection templates into the detection_library table.
    For each vulnerability category, call the LLM to generate a robust template.
    """
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    for vuln_type, details in library.items():
        robust_template = generate_robust_detection_template(vuln_type, details)
        details_json = json.dumps(details, indent=4)
        c.execute('''
            INSERT OR REPLACE INTO detection_library (vuln_type, details, template)
            VALUES (?, ?, ?)
        ''', (vuln_type, details_json, robust_template))
    conn.commit()
    conn.close()
    console.print("[green]Detection library and robust templates have been saved to the database.[/green]")

def view_detection_library():
    """
    Query the detection_library table and display its contents in a table.
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT vuln_type, template FROM detection_library")
    rows = c.fetchall()
    conn.close()
    if not rows:
        console.print("[yellow]No detection library entries found.[/yellow]")
        return
    table = Table(title="Detection Library Contents", show_lines=True)
    table.add_column("Vulnerability Type", style="cyan")
    table.add_column("Robust Detection Template", style="white")
    for row in rows:
        vuln_type, template = row
        # Truncate template display if needed
        template_display = template if len(template) <= 300 else template[:300] + "..."
        table.add_row(vuln_type, template_display)
    console.print(table)

def display_detection_library(library):
    """Display an enhanced view of the detection library with all available fields"""
    # If library is a string, attempt to convert it
    if isinstance(library, str):
        try:
            library = json.loads(library)
        except Exception as e:
            console.print(f"[red]Failed to convert library string: {e}[/red]")
            return
    
    # Check if library is empty
    if not library:
        console.print("[yellow]Detection library is empty. No vulnerability patterns to display.[/yellow]")
        return
        
    # Print a summary header
    console.print(f"\n[bold cyan]📚 Detection Library Summary[/bold cyan]")
    console.print(f"[blue]Found {len(library)} vulnerability categories in the library[/blue]")
    
    # Create an expanded table with all the enhanced fields
    table = Table(title="Enhanced Detection Pattern Library", show_lines=True, box=box.ROUNDED)
    
    # Add all columns including new ones
    table.add_column("Vulnerability Type", style="cyan", no_wrap=True)
    table.add_column("Severity", style="yellow", justify="center")
    table.add_column("Detection Signatures", style="bright_magenta", max_width=30)
    table.add_column("Attack Vectors", style="red", max_width=30)
    table.add_column("Examples", style="green", max_width=30)
    
    # Process each vulnerability type
    for vuln_type, details in library.items():
        # Ensure details is a dictionary
        if not isinstance(details, dict):
            try:
                details = dict(details) if details else {}
            except Exception:
                details = {}
        
        # Calculate severity
        severity_ratings = details.get("severity_ratings", [])
        severity = "Unknown"
        
        if severity_ratings:
            # Extract severity values using similar logic as the template generator
            severity_values = []
            for rating in severity_ratings:
                rating_str = str(rating).lower()
                if "critical" in rating_str:
                    severity_values.append("Critical")
                elif "high" in rating_str:
                    severity_values.append("High")
                elif "medium" in rating_str:
                    severity_values.append("Medium")
                elif "low" in rating_str:
                    severity_values.append("Low")
            
            # Use most common severity if available
            if severity_values:
                from collections import Counter
                severity_counter = Counter(severity_values)
                severity = severity_counter.most_common(1)[0][0]
        
        # Format detection signatures
        detection_signatures = details.get("detection_signatures", [])
        signatures_text = "\n".join([f"• {sig[:100]}..." if len(sig) > 100 else f"• {sig}" for sig in detection_signatures[:3]]) if detection_signatures else "None specified"
        
        # Format attack vectors
        attack_vectors = details.get("attack_vectors", [])
        vectors_text = "\n".join([f"• {vec[:100]}..." if len(vec) > 100 else f"• {vec}" for vec in attack_vectors[:3]]) if attack_vectors else "None specified"
        
        # Format code examples (combine vulnerable and fixed)
        vuln_examples = details.get("vulnerable_examples", [])
        fixed_examples = details.get("fixed_examples", [])
        
        if vuln_examples or fixed_examples:
            examples_text = f"[bold]Found:[/bold] {len(vuln_examples)} vulnerable examples\n[bold]Fixed:[/bold] {len(fixed_examples)} fixed examples"
            
            # Add snippet of first example if available
            if vuln_examples:
                first_example = str(vuln_examples[0])
                if len(first_example) > 100:
                    examples_text += f"\n\n[dim]Sample: {first_example[:100]}...[/dim]"
        else:
            examples_text = "No code examples available"
        
        # Add the row to the table
        table.add_row(
            vuln_type,
            severity,
            signatures_text,
            vectors_text,
            examples_text
        )
    
    # Print the table
    console.print(table)
    console.print("\n[italic]Use the view_detection_library() function to see the full detection templates.[/italic]")

def format_examples(examples):
    """Convert a list of examples (which may be dicts) into a formatted string."""
    formatted = []
    for ex in examples:
        if isinstance(ex, dict):
            # Convert dict to a pretty JSON string
            formatted.append(json.dumps(ex, indent=2))
        else:
            formatted.append(str(ex))
    return "\n".join(formatted)

def display_detection_library(library):
    # If library is a string, attempt to convert it.
    if isinstance(library, str):
        try:
            library = json.loads(library)
        except Exception as e:
            console.print(f"[red]Failed to convert library string: {e}[/red]")
            return

    table = Table(title="Detection Pattern Library (Aggregated in Memory)")
    table.add_column("Vulnerability Type", style="cyan")
    table.add_column("Questions", style="magenta")
    table.add_column("Vulnerable Examples", style="red")
    table.add_column("Fixed Examples", style="green")
    
    for vuln_type, details in library.items():
        # If details is a string, try to parse it into a dictionary.
        if isinstance(details, str):
            try:
                details = json.loads(details)
            except Exception as e:
                console.print(f"[red]Failed to parse details for {vuln_type}: {e}[/red]")
                details = {}
        # If details is a list, use the first element (if available)
        if isinstance(details, list):
            details = details[0] if details else {}
        questions = "\n".join(details.get("questions", []))
        vuln_examples = format_examples(details.get("vulnerable_examples", []))
        fixed_examples = format_examples(details.get("fixed_examples", []))
        table.add_row(vuln_type, questions, vuln_examples, fixed_examples)
    console.print(table)

# ---------------------- UI Layout & Main Loop ----------------------
def render_layout() -> Panel:
    header = Panel("[bold magenta]VectorEyes[/bold magenta]", padding=(1,2), style="on blue")
    menu_table = Table.grid(padding=1)
    menu_table.add_column(justify="left")
    menu_table.add_row("[bold blue]1.[/bold blue] Vectorize Report")
    menu_table.add_row("[bold blue]2.[/bold blue] View Reports")
    menu_table.add_row("[bold blue]3.[/bold blue] Delete Reports")
    menu_table.add_row("[bold blue]4.[/bold blue] Build & Save Detection Library")
    menu_table.add_row("[bold blue]5.[/bold blue] View Detection Library")
    menu_table.add_row("[bold blue]6.[/bold blue] Delete Detection Library Entries")
    menu_table.add_row("[bold blue]7.[/bold blue] Clean Unknown Reports")
    menu_table.add_row("[bold blue]8.[/bold blue] Import Cached Templates")
    menu_table.add_row("[bold blue]9.[/bold blue] Update API Keys")
    menu_table.add_row("[bold blue]10.[/bold blue] Exit")
    menu = Panel(menu_table, title="Main Menu", border_style="bright_green", padding=(1,2))
    tasks_table = Table(show_header=False, box=None, padding=(0,1))
    with task_lock:
        for key, status in task_status.items():
            tasks_table.add_row(key, status)
    body = Panel(tasks_table, title="Background Tasks", padding=(0,1), border_style="yellow")
    layout = Table.grid(expand=True)
    layout.add_row(header)
    layout.add_row(menu)
    layout.add_row(body)
    outer = Panel(layout, padding=(2, 6), border_style="magenta")
    return outer

def clean_unknown_reports():
    """Clean reports with unknown vuln_type from the database - either by removing or fixing them"""
    console.clear()
    console.print(Panel.fit(
        "[bold]Clean Unknown Reports[/bold]\n\n"
        "This utility will identify reports with 'Unknown' vulnerability types\n"
        "and offers options to either remove them or attempt to fix them using LLM analysis.",
        title="Database Cleanup Utility",
        border_style="blue"
    ))
    
    # Count and categorize reports
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    c.execute("SELECT analysis_summary FROM reports WHERE analysis_summary IS NOT NULL")
    
    types = {}
    unknown_count = 0
    valid_count = 0
    error_count = 0
    
    for (analysis_summary,) in c.fetchall():
        try:
            analysis = json.loads(analysis_summary)
            vuln_type = analysis.get('vuln_type', 'Unknown')
            
            if vuln_type == 'Unknown' or 'unknown' in vuln_type.lower():
                unknown_count += 1
            else:
                valid_count += 1
                if vuln_type in types:
                    types[vuln_type] += 1
                else:
                    types[vuln_type] = 1
        except (json.JSONDecodeError, KeyError, TypeError):
            error_count += 1
    
    conn.close()
    
    console.print(f"[bold]Database statistics:[/bold]")
    console.print(f"- Valid reports: {valid_count}")
    console.print(f"- Reports with unknown vulnerability type: {unknown_count}")
    console.print(f"- Reports with parsing errors: {error_count}")
    
    if unknown_count == 0 and error_count == 0:
        console.print("[green]No unknown reports to fix![/green]")
        return
    
    # Create a backup
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = f"{DB_PATH}_backup_{timestamp}"
    
    try:
        import shutil
        shutil.copy2(DB_PATH, backup_path)
        console.print(f"[green]Created database backup at {backup_path}[/green]")
    except Exception as e:
        console.print(f"[red]Error creating backup: {e}[/red]")
        confirm = Prompt.ask("Continue without backup?", choices=["yes", "no"], default="no")
        if confirm.lower() != "yes":
            return
    
    # Offer options for handling unknown reports
    if unknown_count > 0 or error_count > 0:
        total_problematic = unknown_count + error_count
        action = Prompt.ask(
            f"What would you like to do with the {total_problematic} reports with unknown vuln_type or parsing errors?", 
            choices=["fix", "remove", "cancel"], 
            default="fix"
        )
        
        if action.lower() == "remove":
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            
            try:
                # First identify all unknown report IDs
                c.execute("SELECT id, analysis_summary FROM reports WHERE analysis_summary IS NOT NULL")
                unknown_ids = []
                
                for row in c.fetchall():
                    report_id, analysis_summary = row
                    try:
                        analysis = json.loads(analysis_summary)
                        vuln_type = analysis.get('vuln_type', 'Unknown')
                        if vuln_type == 'Unknown' or 'unknown' in vuln_type.lower():
                            unknown_ids.append(report_id)
                    except (json.JSONDecodeError, KeyError, TypeError):
                        unknown_ids.append(report_id)
                
                # Now remove them
                for report_id in unknown_ids:
                    c.execute("DELETE FROM reports WHERE id = ?", (report_id,))
                    c.execute("DELETE FROM patterns WHERE report_id = ?", (report_id,))
                
                conn.commit()
                console.print(f"[green]Removed {len(unknown_ids)} reports with unknown vuln_type[/green]")
                
                # Offer to clear detection library so it can be rebuilt
                rebuild = Prompt.ask(
                    "Clear detection_library table so it can be rebuilt with clean data?", 
                    choices=["yes", "no"], 
                    default="no"
                )
                
                if rebuild.lower() == "yes":
                    c.execute("DELETE FROM detection_library")
                    conn.commit()
                    console.print("[green]Cleared detection_library table - you'll need to rebuild it[/green]")
            
            except Exception as e:
                console.print(f"[red]Error removing unknown reports: {e}[/red]")
                conn.rollback()
            
            finally:
                conn.close()
        
        elif action.lower() == "fix":
            try:
                # Import the UnknownReportFixer class
                from fix_unknown_reports import UnknownReportFixer
                console.print("[green]Launching the LLM-based report fixer...[/green]")
                fixer = UnknownReportFixer()
                fixer.fix_unknown_reports()
                console.print("[green]Completed fixing unknown reports with LLM analysis[/green]")
            except Exception as e:
                console.print(f"[red]Error fixing unknown reports: {e}[/red]")
                console.print("[yellow]Make sure the fix_unknown_reports.py module is available and properly configured.[/yellow]")
        
        else:  # cancel
            console.print("[yellow]Operation cancelled. No changes were made to the database.[/yellow]")
    
    # Show final advice
    console.print("\n[bold]Next steps:[/bold]")
    if action.lower() == "fix":
        console.print("1. Check if any reports still have unknown vulnerability types")
        console.print("2. Select option 4 to rebuild the detection library")
        console.print("3. Then use copy_templates.py to transfer templates to DeepCurrent")
    else:
        console.print("1. Select option 4 to rebuild the detection library")
        console.print("2. Then use copy_templates.py to transfer templates to DeepCurrent")

def import_cached_templates():
    """Import templates from the cache directory into the vectorisation.db database"""
    console.clear()
    console.print(Panel.fit(
        "[bold]Import Cached Templates[/bold]\n\n"
        "This utility will import templates from the response_cache directory\n"
        "into the vectorisation.db database for use in vulnerability detection.",
        title="Template Import Utility",
        border_style="blue"
    ))
    
    cache_dir = CACHE_DIR
    db_path = DB_PATH
    
    console.print(f"Starting import of cached templates from {cache_dir} to {db_path}...")
    
    if not os.path.exists(cache_dir):
        console.print(f"[red]Error: Cache directory {cache_dir} not found.[/red]")
        return
    
    # Connect to database
    try:
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        
        # Ensure the detection_library table exists
        c.execute('''
            CREATE TABLE IF NOT EXISTS detection_library (
                vuln_type TEXT PRIMARY KEY,
                details TEXT,
                template TEXT
            )
        ''')
        
        # Get existing vulnerability types
        c.execute("SELECT vuln_type FROM detection_library")
        existing_vuln_types = set(row[0] for row in c.fetchall())
        console.print(f"Found {len(existing_vuln_types)} existing templates in database.")
        
        # Find all template files in the cache directory
        template_files = []
        for filename in os.listdir(cache_dir):
            if filename.endswith('.md') and ('template_' in filename or 'or_template_' in filename):
                template_files.append(os.path.join(cache_dir, filename))
        
        console.print(f"Found {len(template_files)} template files in cache directory.")
        
        # Import each template
        count = 0
        for template_file in template_files:
            try:
                with open(template_file, 'r') as f:
                    template_content = f.read()
                
                # Extract vulnerability type from template content
                # Try to find a title in the format "# Detection Template: [Vuln Type]"
                title_match = re.search(r'# Detection Template: (.*?)(?:\n|$)', template_content)
                if title_match:
                    vuln_type = title_match.group(1).strip()
                else:
                    # Try to find a title in the format "**Title:** [Vuln Type]"
                    title_match = re.search(r'\*\*Title:\*\* (.*?)(?:\n|$)', template_content)
                    if title_match:
                        vuln_type = title_match.group(1).strip()
                    else:
                        # If no title found, use the first heading
                        heading_match = re.search(r'# (.*?)(?:\n|$)', template_content)
                        if heading_match:
                            vuln_type = heading_match.group(1).strip()
                        else:
                            # Default fallback
                            vuln_type = "Unknown Vulnerability Type"
                
                # Skip if this vulnerability type already exists
                if vuln_type in existing_vuln_types:
                    console.print(f"Skipping existing template: {vuln_type}")
                    continue
                
                # Create minimal details structure
                details = {
                    "vuln_type": vuln_type,
                    "questions": ["What are the security implications?", 
                                 "How can this vulnerability be exploited?", 
                                 "What are the best practices to prevent this issue?"],
                    "vulnerable_examples": [],
                    "fixed_examples": [],
                    "insights": [f"Imported from cached template: {os.path.basename(template_file)}"],
                    "severity_ratings": []
                }
                
                # Insert into database
                c.execute('''
                    INSERT OR REPLACE INTO detection_library (vuln_type, details, template)
                    VALUES (?, ?, ?)
                ''', (vuln_type, json.dumps(details), template_content))
                
                count += 1
                existing_vuln_types.add(vuln_type)
                console.print(f"Imported template: {vuln_type}")
                
            except Exception as e:
                console.print(f"[red]Error processing {template_file}: {str(e)}[/red]")
        
        conn.commit()
        conn.close()
        
        console.print(f"[green]Successfully imported {count} new templates to database.[/green]")
        
        # Show next steps
        if count > 0:
            console.print("\n[bold]Next steps:[/bold]")
            console.print("1. Run copy_templates.py to transfer templates to DeepCurrent")
            console.print("2. Or select option 5 to view the detection library")
        
    except Exception as e:
        console.print(f"[red]Error during template import: {str(e)}[/red]")

def update_api_keys():
    """Update API keys for the current session only - keys are not saved to disk"""
    global OPENROUTER_API_KEY, USE_API, DEFAULT_MODEL, DEFAULT_OLLAMA_MODEL
    
    console.print(Panel.fit(
        "[bold]API Key Management[/bold]\n\n"
        "Update your API keys for the current session.\n"
        "[bold cyan]For security, keys are only stored in memory and not saved to disk.[/bold cyan]",
        title="Session-Based API Key Management",
        border_style="blue"
    ))
    
    # Display current settings
    settings_table = Table(show_header=False, box=SIMPLE)
    settings_table.add_column("Setting", style="cyan")
    settings_table.add_column("Value", style="green")
    
    settings_table.add_row("API Provider", USE_API)
    if USE_API == "openrouter":
        # Show masked API key if available
        masked_key = "Not set"
        if OPENROUTER_API_KEY:
            # Mask the key, showing only first 4 and last 4 characters
            if len(OPENROUTER_API_KEY) > 8:
                masked_key = OPENROUTER_API_KEY[:4] + "*" * (len(OPENROUTER_API_KEY) - 8) + OPENROUTER_API_KEY[-4:]
            else:
                masked_key = "*" * len(OPENROUTER_API_KEY)
        settings_table.add_row("OpenRouter API Key", masked_key)
        settings_table.add_row("Default Model", DEFAULT_MODEL)
    else:
        settings_table.add_row("Ollama Model", DEFAULT_OLLAMA_MODEL)
    
    console.print(settings_table)
    console.print("")
    
    # Menu options
    options = [
        "Update OpenRouter API Key",
        "Switch to Ollama (local)",
        "Switch to OpenRouter (cloud)",
        "Update Default Model",
        "Back to Main Menu"
    ]
    
    for i, option in enumerate(options, 1):
        console.print(f"[bold blue]{i}.[/bold blue] {option}")
    
    choice = Prompt.ask("Select an option", choices=[str(i) for i in range(1, len(options) + 1)], default="5")
    
    if choice == "1":  # Update OpenRouter API Key
        new_key = Prompt.ask("Enter your OpenRouter API key", password=True)
        if new_key.strip():
            OPENROUTER_API_KEY = new_key
            USE_API = "openrouter"  # Switch to OpenRouter when key is provided
            console.print("[green]OpenRouter API key updated for this session.[/green]")
        else:
            console.print("[yellow]No API key provided. Key not updated.[/yellow]")
    
    elif choice == "2":  # Switch to Ollama
        USE_API = "ollama"
        console.print("[green]Switched to Ollama for local LLM processing.[/green]")
    
    elif choice == "3":  # Switch to OpenRouter
        if OPENROUTER_API_KEY:
            USE_API = "openrouter"
            console.print("[green]Switched to OpenRouter for cloud LLM processing.[/green]")
        else:
            console.print("[yellow]No OpenRouter API key available. Please set a key first.[/yellow]")
            new_key = Prompt.ask("Enter your OpenRouter API key", password=True)
            if new_key.strip():
                OPENROUTER_API_KEY = new_key
                USE_API = "openrouter"
                console.print("[green]OpenRouter API key set and provider selected.[/green]")
    
    elif choice == "4":  # Update Default Model
        if USE_API == "openrouter":
            models = [
                "deepseek/deepseek-r1-distill-llama-70b:free",
                "deepseek/deepseek-r1:32b",
                "anthropic/claude-3-sonnet",
                "anthropic/claude-3-opus",
                "meta-llama/llama-3-70b-instruct",
                "google/gemini-pro"
            ]
            console.print("[bold]Available OpenRouter Models:[/bold]")
            for i, model in enumerate(models, 1):
                console.print(f"[bold blue]{i}.[/bold blue] {model}")
            model_choice = Prompt.ask("Select a model or enter a custom model ID", default="1")
            
            try:
                model_index = int(model_choice) - 1
                if 0 <= model_index < len(models):
                    DEFAULT_MODEL = models[model_index]
                else:
                    DEFAULT_MODEL = model_choice  # Use input as custom model ID
            except ValueError:
                DEFAULT_MODEL = model_choice  # Use input as custom model ID
                
            console.print(f"[green]Default model updated to: {DEFAULT_MODEL}[/green]")
        else:
            models = ["deepseek-r1:32b", "gemma:2b", "llama3:8b", "phi3:mini"]
            console.print("[bold]Available Ollama Models:[/bold]")
            for i, model in enumerate(models, 1):
                console.print(f"[bold blue]{i}.[/bold blue] {model}")
            model_choice = Prompt.ask("Select a model or enter a custom model ID", default="1")
            
            try:
                model_index = int(model_choice) - 1
                if 0 <= model_index < len(models):
                    DEFAULT_OLLAMA_MODEL = models[model_index]
                else:
                    DEFAULT_OLLAMA_MODEL = model_choice  # Use input as custom model ID
            except ValueError:
                DEFAULT_OLLAMA_MODEL = model_choice  # Use input as custom model ID
                
            console.print(f"[green]Default Ollama model updated to: {DEFAULT_OLLAMA_MODEL}[/green]")
    
    # Always pause before returning to main menu
    console.input("\nPress Enter to return to the Main Menu...")

def main():
    init_db()
    init_detection_library_table()
    console.clear()
    
    # Initialize API keys if available
    global OPENROUTER_API_KEY, USE_API, DEFAULT_MODEL, DEFAULT_OLLAMA_MODEL
    # Prompt for OpenRouter API key if not in environment
    if not OPENROUTER_API_KEY:
        console.print(Panel.fit(
            "[bold]API Key Selection[/bold]\n\n"
            "You can use Ollama (local) or OpenRouter (cloud) for LLM services.\n"
            "OpenRouter provides access to more powerful models but requires an API key.\n"
            "[bold cyan]For security, your API key will only be stored in memory for this session.[/bold cyan]",
            title="Welcome to  VectorEyes",
            border_style="blue"
        ))
        
        use_openrouter = Prompt.ask(
            "Would you like to use OpenRouter?", 
            choices=["yes", "no"], 
            default="no"
        )
        
        if use_openrouter.lower() == "yes":
            OPENROUTER_API_KEY = Prompt.ask("Enter your OpenRouter API key", password=True)
            if OPENROUTER_API_KEY:
                USE_API = "openrouter"
                console.print("[green]OpenRouter API key set for this session (will not be saved).[/green]")
            else:
                USE_API = "ollama"
                console.print("[yellow]No API key provided, defaulting to Ollama.[/yellow]")
        else:
            USE_API = "ollama"
            console.print("[cyan]Using Ollama for local LLM processing.[/cyan]")
    else:
        USE_API = "openrouter"
        console.print("[green]Using OpenRouter API key from environment variable.[/green]")
    
    console.print("[green]Loading embedding model...[/green]")
    # Using our simplified embedding approach instead of SentenceTransformer
    console.print("[yellow]Using simplified embedding method (no external model required)[/yellow]")
    model_instance = None  # No model needed for our simplified embedding
    executor = ThreadPoolExecutor(max_workers=2)
    futures = []
    while True:
        console.clear()
        outer_layout = render_layout()
        console.print(outer_layout)
        choice = console.input("[bold yellow]Select an option (1-10):[/bold yellow] ").strip()
        if choice == "1":
            url = console.input("Enter URL to a Markdown report or GitHub repo: ").strip()
            report_key = hashlib.sha256(url.encode("utf-8")).hexdigest()
            with task_lock:
                task_status[report_key] = "Task submitted"
            if url.lower().endswith(".md") or "issues" in url:
                future = executor.submit(process_single_file, url, model_instance)
            else:
                future = executor.submit(process_repo, url, model_instance)
            futures.append(future)

        elif choice == "2":
            console.clear()
            view_reports()
            console.input("Press Enter to return...")

        elif choice == "3":
            delete_reports()
            console.input("Press Enter to return...")

        elif choice == "4":
            # Build and save detection library using LLM-based clustering
            library = build_detection_library()
            display_detection_library(library)
            save_detection_library_to_db(library)
            console.input("Press Enter to return...")

        elif choice == "5":
            console.clear()
            view_detection_library()
            console.input("Press Enter to return...")

        elif choice == "6":
            delete_detection_library_entries()
            console.input("Press Enter to return...")

        elif choice == "7":
            # Clean Unknown Reports
            clean_unknown_reports()
            console.input("Press Enter to return...")

        elif choice == "8":
            # Import Cached Templates
            import_cached_templates()
            console.input("Press Enter to return...")

        elif choice == "9":
            # API Key Management
            # Handle API key updates for the current session
            update_api_keys()
                
        elif choice == "10":
            stop_choice = console.input("Stop running tasks? (Y/N): ").strip().lower()
            if stop_choice == "y":
                for f in futures:
                    f.cancel()
                executor.shutdown(wait=False)
            else:
                for f in as_completed(futures):
                    try:
                        f.result()
                    except Exception as e:
                        console.print(f"Task error: {e}")
                executor.shutdown(wait=True)
            console.print("[green]Exiting...[/green]")
            break

        else:
            console.print("[red]Invalid option. Try again.[/red]")
        time.sleep(0.5)

if __name__ == "__main__":
    main()