#!/usr/bin/env python
# rebuild_vuln_library.py - A dedicated script to rebuild the vulnerability library
# This script bypasses the complex scoping issues in the main application

import os
import sys
import json
import sqlite3
import hashlib
from datetime import datetime
import requests
import time
from collections import defaultdict
from rich.console import Console
from rich.progress import Progress, TextColumn, BarColumn, SpinnerColumn

# Directory path
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
DB_PATH = os.path.join(SCRIPT_DIR, "vectorisation.db")

# Initialize console for rich output
console = Console()

# OpenRouter settings - will be updated by command line args
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
OPENROUTER_MODEL = os.getenv("DEFAULT_MODEL", "qwen/qwen3-0.6b-04-28:free")
OPENROUTER_API_URL = "https://openrouter.ai/api/v1/chat/completions"
USE_API = "openrouter"  # Default to OpenRouter

# Ollama settings
OLLAMA_API_URL = "http://localhost:11434/api/chat"
OLLAMA_MODEL = os.getenv("DEFAULT_OLLAMA_MODEL", "deepseek-r1:32b")

def call_openrouter_api(prompt, model=OPENROUTER_MODEL, max_attempts=3):
    """
    Call the OpenRouter API with proper retry logic
    """
    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json"
    }
    
    data = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a security expert analyzing smart contract vulnerabilities."},
            {"role": "user", "content": prompt}
        ]
    }
    
    for attempt in range(1, max_attempts + 1):
        try:
            console.print(f"Attempt {attempt}/{max_attempts} using OpenRouter...")
            response = requests.post(OPENROUTER_API_URL, headers=headers, json=data, timeout=60)
            
            if response.status_code == 200:
                response_data = response.json()
                console.print(f"OpenRouter response keys: {list(response_data.keys())}")
                
                if "choices" in response_data and response_data["choices"]:
                    return response_data["choices"][0]["message"]["content"]
                else:
                    console.print(f"OpenRouter error: {response_data.get('error', 'Unknown error')}")
            else:
                console.print(f"OpenRouter HTTP error: {response.status_code} - {response.text}")
            
            # Wait before retrying (exponential backoff)
            wait_time = 2 ** attempt
            console.print(f"OpenRouter processing error: OpenRouter API error: {response.text}. Retrying...")
            time.sleep(wait_time)
            
        except Exception as e:
            console.print(f"Request error: {e}")
            time.sleep(3)
    
    return "Error: Failed to get a valid response after multiple attempts."

def call_ollama_api(prompt, model=OLLAMA_MODEL, max_attempts=3):
    """
    Call the Ollama API with proper retry logic
    """
    data = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a security expert analyzing smart contract vulnerabilities."},
            {"role": "user", "content": prompt}
        ]
    }
    
    for attempt in range(1, max_attempts + 1):
        try:
            console.print(f"Attempt {attempt}/{max_attempts} using Ollama...")
            response = requests.post(OLLAMA_API_URL, json=data, timeout=60)
            
            if response.status_code == 200:
                response_data = response.json()
                return response_data["message"]["content"]
            else:
                console.print(f"Ollama HTTP error: {response.status_code} - {response.text}")
            
            # Wait before retrying
            time.sleep(2)
            
        except Exception as e:
            console.print(f"Ollama request error: {e}")
            time.sleep(3)
    
    return "Error: Failed to get a valid response from Ollama after multiple attempts."

def get_vulnerability_details_from_db():
    """
    Extract vulnerability details from the database
    """
    console.print("[cyan]Loading vulnerability reports from database...[/cyan]")
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Get total reports count
        cursor.execute("SELECT COUNT(*) FROM reports")
        total_reports = cursor.fetchone()[0]
        console.print(f"[green]Found {total_reports} reports in the database[/green]")
        
        # Extract analysis summaries
        cursor.execute("SELECT analysis_summary FROM reports")
        rows = cursor.fetchall()
        conn.close()
        
        vuln_details_list = []
        valid_count = 0
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        ) as progress:
            task = progress.add_task("[cyan]Processing reports...", total=len(rows))
            
            for idx, (analysis_summary,) in enumerate(rows):
                try:
                    if analysis_summary:
                        details = json.loads(analysis_summary)
                        vuln_details_list.append(details)
                        valid_count += 1
                except Exception as e:
                    if idx < 5:  # Show only the first few errors to avoid spam
                        console.print(f"[yellow]Error parsing report {idx}: {e}[/yellow]")
                
                progress.update(task, advance=1)
        
        console.print(f"[green]Successfully processed {valid_count} valid reports[/green]")
        return vuln_details_list
    
    except Exception as e:
        console.print(f"[red]Error accessing database: {e}[/red]")
        return []

def cluster_vulnerabilities(vuln_details_list, batch_size=40):
    """
    Cluster vulnerabilities into categories using LLM
    """
    console.print("🔍 Starting enhanced vulnerability clustering...")
    console.print(f"Found {len(vuln_details_list)} vulnerability reports to analyze")
    
    if len(vuln_details_list) == 0:
        console.print("[red]No vulnerability details found to cluster[/red]")
        return {}
    
    # If using OpenRouter and we have many reports, use batch processing
    if USE_API == "openrouter" and len(vuln_details_list) > batch_size:
        console.print(f"Large dataset detected with OpenRouter. Using batch processing.")
        return batch_process_vulnerabilities(vuln_details_list, batch_size)
    
    # Generate the prompt for the LLM
    prompt = generate_clustering_prompt(vuln_details_list)
    
    # Call the appropriate API
    if USE_API == "openrouter":
        response = call_openrouter_api(prompt, OPENROUTER_MODEL)
    else:
        response = call_ollama_api(prompt, OLLAMA_MODEL)
    
    # Parse the response
    try:
        # Try to find a JSON block in the response
        json_start = response.find('{')
        json_end = response.rfind('}') + 1
        
        if json_start >= 0 and json_end > json_start:
            json_str = response[json_start:json_end]
            library = json.loads(json_str)
            return library
        else:
            console.print("[red]No valid JSON found in LLM response[/red]")
            return {}
    
    except Exception as e:
        console.print(f"[red]Error parsing LLM response: {e}[/red]")
        console.print(f"Response snippet: {response[:200]}...")
        return {}

def batch_process_vulnerabilities(vuln_details_list, batch_size=40):
    """
    Process vulnerabilities in batches to avoid token limit issues
    """
    # Calculate number of batches
    num_batches = (len(vuln_details_list) + batch_size - 1) // batch_size
    console.print(f"Processing {num_batches} batches of ~{batch_size} reports each using LLM analysis")
    
    # Combined results
    combined_library = {}
    
    for batch_idx in range(num_batches):
        start_idx = batch_idx * batch_size
        end_idx = min(start_idx + batch_size, len(vuln_details_list))
        batch = vuln_details_list[start_idx:end_idx]
        
        console.print(f"\nProcessing batch {batch_idx+1}/{num_batches} with LLM...")
        start_time = time.time()
        
        # Generate the prompt for this batch
        prompt = generate_clustering_prompt(batch)
        
        # Call the appropriate API
        if USE_API == "openrouter":
            response = call_openrouter_api(prompt, OPENROUTER_MODEL, max_attempts=3)
        else:
            response = call_ollama_api(prompt, OLLAMA_MODEL, max_attempts=3)
        
        # Parse the response
        try:
            # Try to find a JSON block in the response
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            
            if json_start >= 0 and json_end > json_start:
                json_str = response[json_start:json_end]
                batch_library = json.loads(json_str)
                
                # Merge with combined results
                for vuln_type, details in batch_library.items():
                    if vuln_type in combined_library:
                        # Merge details (combine questions, examples, etc.)
                        for key in details:
                            if isinstance(details[key], list) and key in combined_library[vuln_type]:
                                # Combine lists (questions, attack vectors, etc.)
                                combined_library[vuln_type][key].extend(details[key])
                                # Remove duplicates
                                if isinstance(combined_library[vuln_type][key][0], str):
                                    combined_library[vuln_type][key] = list(set(combined_library[vuln_type][key]))
                            else:
                                # For non-list fields, prefer the batch with more detail
                                combined_library[vuln_type][key] = details[key]
                    else:
                        # New vulnerability type
                        combined_library[vuln_type] = details
                
                elapsed = time.time() - start_time
                console.print(f"✅ Batch {batch_idx+1}/{num_batches} categorized into {len(batch_library)} vulnerability types in {elapsed:.1f}s")
            else:
                console.print(f"[red]No valid JSON found in batch {batch_idx+1} LLM response[/red]")
        
        except Exception as e:
            console.print(f"[red]Error parsing batch {batch_idx+1} LLM response: {e}[/red]")
            console.print(f"Response snippet: {response[:200]}...")
    
    console.print(f"\n✅ Successfully processed {len(vuln_details_list)} reports into {len(combined_library)} vulnerability categories using LLM-powered batch processing")
    return combined_library

def generate_clustering_prompt(vuln_details_list):
    """
    Generate a prompt for the LLM to cluster vulnerabilities
    """
    # Extract key information from each vulnerability
    simplified_vulns = []
    for details in vuln_details_list:
        vuln_type = details.get("vuln_type", "Unknown")
        vuln_desc = details.get("vulnerability_description", "")
        if not vuln_desc and details.get("researcher_insights"):
            vuln_desc = details.get("researcher_insights")
        
        simplified_vulns.append({
            "vuln_type": vuln_type,
            "description": vuln_desc[:200] + "..." if len(vuln_desc) > 200 else vuln_desc,
            "has_code_examples": bool(details.get("vulnerable_code") or details.get("vulnerable_examples"))
        })
    
    # Create the prompt with properly escaped curly braces in JSON examples
    prompt = f"""As a smart contract security expert, I need you to analyze {len(vuln_details_list)} vulnerability reports and categorize them into distinct vulnerability types.

Step 1: Group similar vulnerabilities together based on their root causes and security implications.
Step 2: For each vulnerability category, compile:
- A clear name with CWE ID if applicable
- Key security questions that auditors should ask
- Common attack vectors
- Detection strategies
- Relevant code patterns

Here's my data (showing first 10 examples):
{json.dumps(simplified_vulns[:10], indent=2)}
{f"...and {len(simplified_vulns) - 10} more reports..." if len(simplified_vulns) > 10 else ""}

Provide your structured analysis as a JSON object where:
- Each key is a vulnerability category name
- Each value is an object with:
  - "questions": Array of 3-5 key security questions
  - "attack_vectors": Array of common attack vectors
  - "detection_signatures": Array of detection strategies
  - "vulnerable_examples": Array of vulnerable code patterns (if available)
  - "fixed_examples": Array of fixed code patterns (if available)

Example format:
```json
{{
  "Integer Overflow (CWE-190)": {{
    "questions": ["Does the contract check for integer overflow?", "..."],
    "attack_vectors": ["Manipulating input values to cause overflow", "..."],
    "detection_signatures": ["Check arithmetic operations on user inputs", "..."],
    "vulnerable_examples": ["function withdraw(uint amount) {{ balances[msg.sender] -= amount; }}", "..."],
    "fixed_examples": ["function withdraw(uint amount) {{ require(balances[msg.sender] >= amount); balances[msg.sender] -= amount; }}", "..."]
  }}
}}
```

Return ONLY the JSON object, no additional text."""
    
    return prompt

def save_detection_library_to_db(library, db_path=DB_PATH):
    """
    Save the clustered vulnerability library to the database
    """
    if not library:
        console.print("[red]No library data to save[/red]")
        return
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Ensure detection_library table exists
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS detection_library (
                vuln_type TEXT PRIMARY KEY,
                details TEXT,
                template TEXT,
                vector_embedding BLOB,
                llm_template TEXT,
                schema_version INTEGER DEFAULT 1,
                last_updated TEXT
            )
        """)
        
        # First, delete existing entries
        cursor.execute("DELETE FROM detection_library")
        
        # Insert new entries
        count = 0
        for vuln_type, details in library.items():
            # Generate a simple detection template
            template = f"# {vuln_type}\n\n"
            
            # Add questions as bullet points
            if "questions" in details and details["questions"]:
                template += "## Security Questions to Ask\n\n"
                for question in details["questions"]:
                    template += f"- {question}\n"
                template += "\n"
            
            # Add detection strategies
            if "detection_signatures" in details and details["detection_signatures"]:
                template += "## Detection Strategies\n\n"
                for strategy in details["detection_signatures"]:
                    template += f"- {strategy}\n"
            
            # Insert into the database
            cursor.execute(
                "INSERT OR REPLACE INTO detection_library (vuln_type, details, template, last_updated) VALUES (?, ?, ?, ?)",
                (vuln_type, json.dumps(details), template, datetime.now().isoformat())
            )
            count += 1
        
        conn.commit()
        conn.close()
        
        console.print(f"[green]✅ Successfully saved {count} vulnerability types to the database[/green]")
        return True
    
    except Exception as e:
        console.print(f"[red]Error saving detection library: {e}[/red]")
        return False

def rebuild_vulnerability_library():
    """
    Main function to rebuild the vulnerability library
    """
    console.print("[bold cyan]👷 Rebuilding Vulnerability Detection Library[/bold cyan]")
    
    # 1. Fetch vulnerability details from the database
    vuln_details_list = get_vulnerability_details_from_db()
    
    if not vuln_details_list:
        console.print("[red]Failed to retrieve vulnerability details from database[/red]")
        return False
    
    # 2. Cluster vulnerabilities using LLM
    library = cluster_vulnerabilities(vuln_details_list)
    
    if not library:
        console.print("[red]LLM clustering failed to generate a valid library[/red]")
        return False
    
    # 3. Save the library to the database
    success = save_detection_library_to_db(library)
    
    if not success:
        console.print("[red]Failed to save detection library to database[/red]")
        return False
    
    console.print("[bold green]🎉 Vulnerability detection library rebuilt successfully![/bold green]")
    return True

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Rebuild the vulnerability detection library")
    parser.add_argument("--api", choices=["openrouter", "ollama"], default="openrouter", help="API to use for LLM processing")
    parser.add_argument("--openrouter-key", help="OpenRouter API key")
    parser.add_argument("--openrouter-model", help="OpenRouter model to use")
    parser.add_argument("--ollama-model", help="Ollama model to use")
    parser.add_argument("--batch-size", type=int, default=40, help="Batch size for processing")
    
    args = parser.parse_args()
    
    # Update global variables based on args
    USE_API = args.api
    
    if args.openrouter_key:
        OPENROUTER_API_KEY = args.openrouter_key
    
    if args.openrouter_model:
        OPENROUTER_MODEL = args.openrouter_model
    
    if args.ollama_model:
        OLLAMA_MODEL = args.ollama_model
    
    rebuild_vulnerability_library()
