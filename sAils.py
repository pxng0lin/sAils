#!/usr/bin/env python
# /// script
# requires-python = ">=3.8"
# dependencies = [
#     "prefect",
#     "requests",
#     "rich",
#     "aiohttp",
#     "diskcache",
#     "dask[distributed]",
#     "pdfplumber",
#     "markdown",
#     "beautifulsoup4",
#     "PyMuPDF",
#     "ollama>=0.1.6",
#     "sentence-transformers",
#     "regex",
#     "numpy",
#     "watchdog"
# ]
# ///

import os
import argparse
import asyncio
import time
import hashlib
import sqlite3
import concurrent.futures
from datetime import datetime
from pathlib import Path
from typing import Optional, List



# Ensure DB paths are resolved relative to where the script file lives (not where it's run from)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
VECTOR_DB_PATH = os.path.join(SCRIPT_DIR, "vectorisation.db")
DEEP_DB_PATH = os.path.join(SCRIPT_DIR, "smart_contracts_analysis.db")

# Centralized sessions directory
SESSIONS_DIR = os.path.join(SCRIPT_DIR, "sessions")
# Ensure the sessions directory exists
os.makedirs(SESSIONS_DIR, exist_ok=True)


from rich.prompt import Prompt
from prefect import task, flow
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from VectorEyes import process_markdown_file, init_db as init_vector_db, build_detection_library
from DeepCurrent import (
    init_db as init_deep_db,
    process_contracts_parallel,
    process_document,
    scan_contracts_for_vulnerabilities,
    ask_questions_about_analysis,
    call_llm,
    gather_analysis_context
)

DEFAULT_LLM_PROVIDER = "ollama"
DEFAULT_OLLAMA_MODEL = "deepseek-r1:32b"
DEFAULT_OPENROUTER_MODEL = "google/gemini-2.5-pro-exp-03-25:free"

@task
def initialize_databases():
    init_vector_db()
    init_deep_db()
    return True

@task
def ingest_reports(report_urls: List[str]):
    if not report_urls:
        print("No reports provided, skipping ingestion.")
        return 0
    for url in report_urls:
        process_markdown_file(url, url)
    return len(report_urls)

@task
def build_vuln_library(report_count: int):
    try:
        conn = sqlite3.connect(VECTOR_DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM detection_library")
        detection_count = cur.fetchone()[0]
        conn.close()
        if detection_count > 0:
            print(f"[INFO] Detection library already populated with {detection_count} templates. Skipping rebuild.")
            return True
    except Exception as e:
        print(f"[ERROR] Could not check detection_library table: {e}")
        return False

    if report_count <= 0:
        print("[WARN] No new reports ingested this session and detection library is empty.")
        return False

    return build_detection_library()

def is_contract_already_analyzed(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        file_hash = hashlib.sha256(content.encode()).hexdigest()
        conn = sqlite3.connect(DEEP_DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT id FROM contracts WHERE id = ?", (file_hash,))
        exists = cur.fetchone() is not None
        conn.close()
        return exists
    except Exception as e:
        print(f"[WARN] Could not check for duplicate: {file_path} — {e}")
        return False

@task
def scan_contracts(contract_dir: str, session_folder: str):
    contract_files = []
    for root, _, files in os.walk(contract_dir):
        for f in files:
            if f.endswith(('.sol', '.vy', '.rs', '.ts', '.move')):
                full_path = os.path.join(root, f)
                if not is_contract_already_analyzed(full_path):
                    contract_files.append(full_path)
                else:
                    print(f"[SKIP] Already analyzed: {full_path}")

    if not contract_files:
        print(f"[SKIP] No new contract files found in '{contract_dir}'. Watching but skipping analysis.")
        return 0

    os.makedirs(session_folder, exist_ok=True)
    asyncio.run(process_contracts_parallel(contract_files, session_folder))
    return len(contract_files)

@task
def vuln_scan(session_folder: str):
    scan_contracts_for_vulnerabilities(session_folder)
    return True

@task
def analyze_docs(doc_paths: List[str], session_folder: str):
    if not doc_paths:
        print("No documents provided, skipping document analysis.")
        return 0
    os.makedirs(session_folder, exist_ok=True)
    count = 0
    for path in doc_paths:
        process_document(path, session_folder)
        count += 1
    return count

@task
def notify(summary: dict):
    now = datetime.now().isoformat()
    print(f"\nPipeline completed at {now}")
    for k, v in summary.items():
        print(f"- {k}: {v}")
    return True

@flow(name="Vuln Pipeline")
def vuln_pipeline(
    report_urls: List[str],
    contract_dir: str,
    doc_paths: List[str],
    session_folder: str,
    llm_provider: Optional[str] = None,
    openrouter_key: Optional[str] = None,
    openrouter_model: Optional[str] = None,
    ollama_model: Optional[str] = None,
    run_vuln_scan: bool = False
):
    provider = llm_provider or DEFAULT_LLM_PROVIDER
    print(f"Using LLM provider: {provider}")

    if provider == "openrouter":
        model = openrouter_model or DEFAULT_OPENROUTER_MODEL
    else:
        model = ollama_model or DEFAULT_OLLAMA_MODEL

    initialize_databases()
    ingested = ingest_reports(report_urls)
    built = build_vuln_library(ingested)
    analyzed = scan_contracts(contract_dir, session_folder)
    docs = analyze_docs(doc_paths, session_folder)
    vuln_results = vuln_scan(session_folder) if run_vuln_scan else False

    ask_questions_about_analysis(session_folder)

    context = gather_analysis_context(session_folder, [], [])
    auto_questions = [
        "What are the most questionable assumptions in this contract?",
        "How would this code behave if an attacker calls this function repeatedly?",
        "Does the design violate any known smart contract principles?",
        "What could break if the protocol scales rapidly?",
        "How resilient is this to changes in gas prices or chain conditions?",
        "What does this contract depend on that it doesn't control?",
        "Are there any implicit trust assumptions that could be dangerous?"
    ]

    qna_log = os.path.join(session_folder, "automated_insights.md")

    def generate_answer(q):
        prompt = f"""
# Invasive Smart Contract Analysis

## Context:
{context[:48000]}

## Question:
{q}

## Instructions:
- Use ONLY the context above to answer.
- Be critical, in-depth, and honest.
- Suggest deeper tests, adversarial situations, or design clarifications.
- Keep answers tightly focused, clear, and useful for auditors.
"""
        return q, call_llm(prompt)

    with open(qna_log, "w", encoding="utf-8") as f:
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = executor.map(generate_answer, auto_questions)
            for question, answer in futures:
                f.write(f"### Q: {question}\n\n{answer}\n\n---\n")

    notify({
        "reports_ingested": ingested,
        "library_built": built,
        "contracts_analyzed": analyzed,
        "docs_analyzed": docs,
        "vulnerabilities_scanned": vuln_results,
        "session_folder": session_folder
    })

WATCHED_DIR = None

class NewDirectoryHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            self._handle_event(event.src_path, "created")

    def on_moved(self, event):
        if event.is_directory:
            self._handle_event(event.dest_path, "moved")

    def _handle_event(self, path, trigger):
        if not os.path.isdir(path):
            return

        session_name = f"analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        print(f"\n📁 Directory {trigger}: {path}")
        print(f"🚀 Triggering analysis in session: {session_name}")

        vuln_pipeline(
            report_urls=[],
            contract_dir=path,
            doc_paths=[],
            session_folder=session_name,
            run_vuln_scan=True
        )

def watch_for_new_dirs():
    global WATCHED_DIR
    WATCHED_DIR = Prompt.ask("📂 Enter a glob pattern for folders to watch (e.g. '~/Documents/web3/*')", default=" ~/Documents/web3/*")
    WATCHED_DIR = os.path.expanduser(WATCHED_DIR)
    print(f"📡 Resolving glob: {WATCHED_DIR}")

    import glob
    matching_dirs = [d for d in glob.glob(WATCHED_DIR) if os.path.isdir(d)]

    if not matching_dirs:
        print(f"[WARN] No directories matched: {WATCHED_DIR}")
        return

    print(f"👀 Watching the following directories:")
    for d in matching_dirs:
        print(f"  - {d}")

    event_handler = NewDirectoryHandler()
    observer = Observer()
    for path in matching_dirs:
        observer.schedule(event_handler, path=path, recursive=True)

    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

def main():
    """Main function for sAils application."""
    from datetime import datetime  # Import datetime at the function level
    parser = argparse.ArgumentParser(description='Run the sAils AI agent for smart contract and documentation analysis.')
    parser.add_argument("--reports", nargs="+", default=[], help="List of report URLs or file paths.")
    parser.add_argument("--contracts", help="Directory or single file containing contract(s).")
    parser.add_argument("--docs", nargs="*", default=[], help="List of doc paths/URLs (pdf, md, url).")
    parser.add_argument("--session", help="Session name (will be stored in centralized sessions directory)")
    
    # LLM provider options
    parser.add_argument("--llm-provider", choices=["ollama", "openrouter"], help="Choose LLM backend: 'ollama' or 'openrouter'.")
    parser.add_argument("--openrouter-key", help="Your OpenRouter API key for cloud LLM usage.")
    parser.add_argument("--openrouter-model", help="OpenRouter model to use (default %s)." % DEFAULT_OPENROUTER_MODEL)
    parser.add_argument("--ollama-model", help="Local Ollama model name (default %s)." % DEFAULT_OLLAMA_MODEL)
    
    # Core sAils options
    parser.add_argument("--vuln-scan", action="store_true", help="Run vulnerability scanning on the analyzed contracts.")
    parser.add_argument("--watch", action="store_true", help="Watch a folder for new contract directories.")
    parser.add_argument("--vuln-scan-only", action="store_true", help="Only run vulnerability scan on given session or contracts.")
    
    # Additional options from DeepCurrent and VectorEyes
    parser.add_argument("--test-llm-connection", action="store_true", help="Test connection to the LLM provider and display available models.")
    parser.add_argument("--analysis-model", help="Specify the model to use for analysis tasks (overrides --ollama-model for analysis).")
    parser.add_argument("--query-model", help="Specify the model to use for query tasks (overrides --ollama-model for queries).")
    
    # Vulnerability library management
    vuln_lib_group = parser.add_argument_group('Vulnerability Library Management')
    vuln_lib_group.add_argument("--recategorize-other-vulns", action="store_true", help="Recategorize vulnerabilities categorized as 'Other' into specific types.")
    vuln_lib_group.add_argument("--fix-unknown-reports", action="store_true", help="Fix reports with unknown vulnerability types and recategorize them.")
    vuln_lib_group.add_argument("--view-vuln-library", action="store_true", help="View the vulnerability detection library.")
    vuln_lib_group.add_argument("--vuln-detail", help="Show detailed information for a specific vulnerability type.")
    vuln_lib_group.add_argument("--export-vuln-library", help="Export the vulnerability library to a markdown file.")
    vuln_lib_group.add_argument("--build-vuln-library", action="store_true", help="Rebuild the vulnerability detection library.")
    vuln_lib_group.add_argument("--build-direct-templates", action="store_true", help="Build templates directly from reports with less clustering.")
    vuln_lib_group.add_argument("--min-examples", type=int, default=2, help="Minimum code examples for direct template building (default: 2).")
    vuln_lib_group.add_argument("--clean-reports", action="store_true", help="Clean reports with unknown vulnerability types.")
    vuln_lib_group.add_argument("--diagnose-library", action="store_true", help="Run diagnostic tests on the vulnerability library and fix issues.")
    vuln_lib_group.add_argument("--rebuild-with-llm", action="store_true", help="Use dedicated LLM-powered process to rebuild the vulnerability library.")
    vuln_lib_group.add_argument("--api", choices=["openrouter", "ollama"], help="API to use for the rebuild process.")
    
    
    # LLM enhancement options
    llm_group = parser.add_argument_group('LLM Enhancement Options')
    llm_group.add_argument("--enhance-library", action="store_true", help="Enhance the vulnerability library with LLM-optimized features.")
    llm_group.add_argument("--semantic-search", help="Search vulnerabilities semantically using natural language.")
    llm_group.add_argument("--llm-prompt", help="Generate an LLM detection prompt for a specific vulnerability type.")
    llm_group.add_argument("--llm-model", help="Specify target LLM model for prompt generation (affects context size).")
    llm_group.add_argument("--openai-compatible", action="store_true", help="Make generated prompts compatible with OpenAI API format.")
    
    
    # Database management options
    db_group = parser.add_argument_group('Database Management')
    db_group.add_argument("--merge-databases", help="Merge databases from another sAils directory into the current databases.")
    db_group.add_argument("--no-llm-merge", action="store_true", help="Disable LLM for similarity detection during database merge.")
    
    # Other options
    parser.add_argument("--qa-mode", action="store_true", help="Run in Q&A mode for analyzed contracts.")
    
    args = parser.parse_args()

    # ✅ Ensure session name is always set
    session_name = args.session or f"analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    # Validate the session name
    session_path = Path(session_name)
    if session_path.is_absolute():
        # If an absolute path was provided, extract just the name
        session_name = session_path.name
        print(f"[INFO] Using session name '{session_name}' from the provided path")
    
    # Check if the session name is a file (invalid)
    if os.path.isfile(session_name):
        print(f"[WARN] Session name '{session_name}' matches a file. Using fallback name instead.")
        session_name = f"analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    # Create the full session path in the centralized sessions directory
    session = os.path.join(SESSIONS_DIR, session_name)
    
    # Special handling for QA mode - session must exist
    if args.qa_mode:
        if not os.path.exists(session):
            # Check if user is using a legacy local path
            local_session = args.session
            if local_session and os.path.exists(local_session) and os.path.isdir(local_session):
                print(f"[INFO] Found session at local path '{local_session}'")
                print(f"[INFO] Consider moving this session to the centralized directory: {SESSIONS_DIR}")
                session = local_session
            else:
                print(f"[ERROR] Session folder '{session}' does not exist. Please provide a valid session.")
                return
        
        print(f"[INFO] Using session directory: {session}")
        ask_questions_about_analysis(session)
        return
    
    # For all non-QA modes, ensure the directory exists
    print(f"[INFO] Using session directory: {session}")
    os.makedirs(session, exist_ok=True)
    
    # Initialize databases for any mode
    initialize_databases()
        
    # Configure LLM settings for both DeepCurrent and VectorEyes
    import DeepCurrent
    import VectorEyes
    
    # Set LLM provider if specified
    if args.llm_provider:
        DeepCurrent.LLM_PROVIDER = args.llm_provider
        
    # Configure OpenRouter
    if args.llm_provider == "openrouter":
        if args.openrouter_key:
            DeepCurrent.OPENROUTER_API_KEY = args.openrouter_key
            # Also set it for VectorEyes
            VectorEyes.OPENROUTER_API_KEY = args.openrouter_key
            VectorEyes.USE_API = "openrouter"
            
        model = args.openrouter_model or DEFAULT_OPENROUTER_MODEL
        DeepCurrent.ANALYSIS_MODEL = args.analysis_model or model
        DeepCurrent.QUERY_MODEL = args.query_model or model
        
        # Make sure VectorEyes uses the right OpenRouter model too
        VectorEyes.DEFAULT_MODEL = args.openrouter_model or DEFAULT_OPENROUTER_MODEL
            
    # Configure Ollama
    elif args.llm_provider == "ollama" or not args.llm_provider:
        model = args.ollama_model or DEFAULT_OLLAMA_MODEL
        DeepCurrent.ANALYSIS_MODEL = args.analysis_model or model
        DeepCurrent.QUERY_MODEL = args.query_model or model
        
        # Configure VectorEyes to use Ollama
        VectorEyes.USE_API = "ollama"
        VectorEyes.DEFAULT_OLLAMA_MODEL = args.ollama_model or DEFAULT_OLLAMA_MODEL
    
    # Handle LLM enhancement options
    if args.enhance_library or args.semantic_search or args.llm_prompt:
        try:
            from llm_enhancer import enhance_detection_library, search_vulnerabilities_semantic, display_semantic_search_results, generate_llm_detection_prompt, MODEL_CONTEXT_SIZES
            from rich.console import Console
            from rich.markdown import Markdown
            
            console = Console()
            
            if args.enhance_library:
                console.print("[bold cyan]Enhancing vulnerability library with LLM-optimized features...[/bold cyan]")
                enhance_detection_library()
                return
            
            elif args.semantic_search:
                query = args.semantic_search
                console.print(f"[bold cyan]Performing semantic search for: [/bold cyan][yellow]{query}[/yellow]")
                results = search_vulnerabilities_semantic(query, top_n=10)
                display_semantic_search_results(results)
                return
            
            elif args.llm_prompt:
                vuln_type = args.llm_prompt
                model = args.llm_model or "default"
                context_size = MODEL_CONTEXT_SIZES.get(model, MODEL_CONTEXT_SIZES["default"])
                
                console.print(f"[bold cyan]Generating LLM detection prompt for: [/bold cyan][yellow]{vuln_type}[/yellow]")
                prompt = generate_llm_detection_prompt(vuln_type, context_size)
                
                if args.openai_compatible:
                    # Format for use with OpenAI API
                    openai_prompt = {
                        "model": model if model != "default" else "gpt-4",
                        "messages": [
                            {"role": "system", "content": "You are a smart contract security auditor looking for vulnerabilities."}, 
                            {"role": "user", "content": prompt}
                        ]
                    }
                    import json
                    console.print(json.dumps(openai_prompt, indent=2))
                else:
                    # Display as markdown
                    console.print(Markdown(prompt))
                return
                
        except ImportError:
            console.print("[red]Error: LLM enhancer module not found. Make sure llm_enhancer.py is in the same directory.[/red]")
            return
        except Exception as e:
            console.print(f"[red]Error: {str(e)}[/red]")
            return
    
    # Handle vulnerability library commands
    if args.view_vuln_library or args.vuln_detail or args.export_vuln_library:
        # Import VectorEyes functions
        from VectorEyes import view_detection_library, DB_PATH as vector_db_path
        import sqlite3
        import json
        from rich.table import Table
        from rich.console import Console
        from rich.panel import Panel
        from rich.markdown import Markdown
        from rich.syntax import Syntax
        
        console = Console()
        
        if args.vuln_detail:
            # Show detailed information for a specific vulnerability type
            try:
                conn = sqlite3.connect(vector_db_path)
                cur = conn.cursor()
                
                # First check if the exact vulnerability type exists
                cur.execute("SELECT details, template FROM detection_library WHERE vuln_type = ?", (args.vuln_detail,))
                row = cur.fetchone()
                
                if not row:
                    # If not found, try a partial match (case insensitive)
                    cur.execute("SELECT vuln_type, details, template FROM detection_library WHERE LOWER(vuln_type) LIKE ?", (f"%{args.vuln_detail.lower()}%",))
                    matches = cur.fetchall()
                    
                    if not matches:
                        console.print(f"[red]No vulnerability found matching '{args.vuln_detail}'.[/red]")
                        conn.close()
                        return
                    elif len(matches) > 1:
                        # Show a list of matching vulnerabilities
                        console.print(f"[yellow]Multiple vulnerabilities found matching '{args.vuln_detail}':[/yellow]")
                        table = Table(title="Matching Vulnerabilities")
                        table.add_column("Vulnerability Type", style="cyan")
                        for match in matches:
                            table.add_row(match[0])
                        console.print(table)
                        console.print("[yellow]Please specify a more precise vulnerability type.[/yellow]")
                        conn.close()
                        return
                    else:
                        # Single match found, show details
                        vuln_type, details, template = matches[0]
                else:
                    vuln_type, details, template = args.vuln_detail, row[0], row[1]
                
                # Show detailed information
                console.print(f"\n[bold cyan]Vulnerability Type:[/bold cyan] {vuln_type}\n")
                
                # Parse the details JSON
                details_dict = json.loads(details)
                
                # Display vulnerability details in organized sections
                if "questions" in details_dict and details_dict["questions"]:
                    console.print(Panel("\n".join([f"• {q}" for q in details_dict["questions"]]), 
                                 title="[bold magenta]Security Questions[/bold magenta]", 
                                 expand=False))
                
                # Display attack vectors if available
                if "attack_vectors" in details_dict and details_dict["attack_vectors"]:
                    console.print(Panel("\n".join([f"• {v}" for v in details_dict["attack_vectors"]]), 
                                 title="[bold red]Attack Vectors[/bold red]", 
                                 expand=False))
                
                # Display severity ratings if available
                if "severity_ratings" in details_dict and details_dict["severity_ratings"]:
                    console.print(Panel("\n".join([f"• {r}" for r in details_dict["severity_ratings"]]), 
                                 title="[bold yellow]Severity Ratings[/bold yellow]", 
                                 expand=False))
                
                # Display examples if available
                if "vulnerable_examples" in details_dict and details_dict["vulnerable_examples"]:
                    for i, example in enumerate(details_dict["vulnerable_examples"][:2]):
                        # Create Syntax object without title, then wrap in Panel
                        syntax = Syntax(example, "solidity", theme="monokai")
                        console.print(Panel(syntax, title=f"[bold red]Vulnerable Example {i+1}[/bold red]"))
                
                if "fixed_examples" in details_dict and details_dict["fixed_examples"]:
                    for i, example in enumerate(details_dict["fixed_examples"][:2]):
                        # Create Syntax object without title, then wrap in Panel
                        syntax = Syntax(example, "solidity", theme="monokai")
                        console.print(Panel(syntax, title=f"[bold green]Fixed Example {i+1}[/bold green]"))
                
                # Display the detection template
                if template:
                    console.print(Panel(Markdown(template), 
                                 title="[bold blue]Detection Template[/bold blue]", 
                                 expand=True))
                
                conn.close()
            except Exception as e:
                console.print(f"[red]Error viewing vulnerability details: {e}[/red]")
            return
            
        elif args.export_vuln_library:
            # Export the vulnerability library to a markdown file
            try:
                export_path = args.export_vuln_library
                if not export_path.endswith(".md"):
                    export_path += ".md"
                
                conn = sqlite3.connect(vector_db_path)
                cur = conn.cursor()
                cur.execute("SELECT vuln_type, details, template FROM detection_library ORDER BY vuln_type")
                rows = cur.fetchall()
                conn.close()
                
                if not rows:
                    console.print("[yellow]No vulnerabilities found in the detection library.[/yellow]")
                    return
                
                # Generate markdown content
                md_content = f"# Vulnerability Detection Library\n\nGenerated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
                md_content += f"Total Vulnerabilities: {len(rows)}\n\n"
                
                # Table of contents
                md_content += "## Table of Contents\n\n"
                for i, (vuln_type, _, _) in enumerate(rows):
                    md_content += f"{i+1}. [{vuln_type}](#{vuln_type.lower().replace(' ', '-').replace('(', '').replace(')', '')})\n"
                
                # Vulnerability details
                for vuln_type, details, template in rows:
                    md_content += f"\n## {vuln_type}\n\n"
                    
                    # Parse the details JSON
                    details_dict = json.loads(details)
                    
                    # Questions section
                    md_content += "### Security Questions\n\n"
                    if "questions" in details_dict and details_dict["questions"]:
                        for q in details_dict["questions"]:
                            md_content += f"- {q}\n"
                    else:
                        md_content += "*No specific questions available*\n"
                    
                    # Attack vectors section
                    md_content += "\n### Attack Vectors\n\n"
                    if "attack_vectors" in details_dict and details_dict["attack_vectors"]:
                        for v in details_dict["attack_vectors"]:
                            md_content += f"- {v}\n"
                    else:
                        md_content += "*No attack vectors specified*\n"
                    
                    # Code examples
                    if "vulnerable_examples" in details_dict and details_dict["vulnerable_examples"]:
                        md_content += "\n### Vulnerable Code Example\n\n```solidity\n"
                        md_content += details_dict["vulnerable_examples"][0]
                        md_content += "\n```\n"
                    
                    if "fixed_examples" in details_dict and details_dict["fixed_examples"]:
                        md_content += "\n### Fixed Code Example\n\n```solidity\n"
                        md_content += details_dict["fixed_examples"][0]
                        md_content += "\n```\n"
                    
                    # Detection template
                    md_content += "\n### Detection Template\n\n"
                    if template:
                        md_content += template
                    else:
                        md_content += "*No template available*\n"
                    
                    md_content += "\n---\n"
                
                # Write to file
                with open(export_path, "w") as f:
                    f.write(md_content)
                
                console.print(f"[green]Vulnerability library exported to: {export_path}[/green]")
            except Exception as e:
                console.print(f"[red]Error exporting vulnerability library: {e}[/red]")
            return
        else:
            # Default view of the detection library
            view_detection_library()
            return
    
    if args.build_direct_templates:
        # Import required modules at the handler level
        import sqlite3
        import json
        from datetime import datetime
        from rich.progress import Progress
        from rich.panel import Panel
        from rich.table import Table
        import sys
        
        # First check the number of reports in the database
        try:
            conn = sqlite3.connect(VECTOR_DB_PATH)
            cur = conn.cursor()
            
            # Count reports
            cur.execute("SELECT COUNT(*) FROM reports")
            report_count = cur.fetchone()[0]
            
            # Get current template count
            cur.execute("SELECT COUNT(*) FROM detection_library")
            current_template_count = cur.fetchone()[0]
            
            if report_count == 0:
                console.print("[red]No reports found in the database. Please add reports first using --reports.[/red]")
                return
            
            console.print(f"[cyan]Building direct templates from {report_count} reports...[/cyan]")
            min_examples = args.min_examples or 2
            console.print(f"[cyan]Using minimum of {min_examples} code examples per template[/cyan]")
            
            if current_template_count > 0:
                confirmation = Prompt.ask(
                    f"Detection library already has {current_template_count} templates. Add to existing library? (Y/N)", 
                    default="Y"
                )
                if confirmation.lower() != "y":
                    console.print("[yellow]Template building cancelled.[/yellow]")
                    return
            
            # Get all reports
            cur.execute("SELECT analysis_summary FROM reports")
            rows = cur.fetchall()
            
            # Create a dictionary to hold vulnerability details by type
            vuln_types = {}
            
            # Process all reports
            with Progress() as progress:
                task = progress.add_task("[cyan]Processing reports...", total=len(rows))
                
                for (analysis_summary,) in rows:
                    try:
                        if not analysis_summary:
                            progress.update(task, advance=1)
                            continue
                            
                        details = json.loads(analysis_summary)
                        vuln_type = details.get("vuln_type")
                        
                        if not vuln_type:
                            progress.update(task, advance=1)
                            continue
                        
                        # Initialize the vulnerability type entry if it doesn't exist
                        if vuln_type not in vuln_types:
                            vuln_types[vuln_type] = {
                                "questions": [],
                                "attack_vectors": [],
                                "detection_signatures": [],
                                "vulnerable_examples": [],
                                "fixed_examples": [],
                                "severity_ratings": [],
                                "researcher_insights": []
                            }
                        
                        # Collect questions
                        if "questions" in details and details["questions"]:
                            for q in details["questions"]:
                                if q not in vuln_types[vuln_type]["questions"]:
                                    vuln_types[vuln_type]["questions"].append(q)
                        
                        # Collect attack vectors
                        if "attack_vectors" in details and details["attack_vectors"]:
                            for v in details["attack_vectors"]:
                                if v not in vuln_types[vuln_type]["attack_vectors"]:
                                    vuln_types[vuln_type]["attack_vectors"].append(v)
                        
                        # Collect detection signatures
                        if "detection_signatures" in details and details["detection_signatures"]:
                            for s in details["detection_signatures"]:
                                if s not in vuln_types[vuln_type]["detection_signatures"]:
                                    vuln_types[vuln_type]["detection_signatures"].append(s)
                        
                        # Collect code examples
                        if "vulnerable_code" in details and details["vulnerable_code"]:
                            if details["vulnerable_code"] not in vuln_types[vuln_type]["vulnerable_examples"]:
                                vuln_types[vuln_type]["vulnerable_examples"].append(details["vulnerable_code"])
                        
                        if "fixed_code" in details and details["fixed_code"]:
                            if details["fixed_code"] not in vuln_types[vuln_type]["fixed_examples"]:
                                vuln_types[vuln_type]["fixed_examples"].append(details["fixed_code"])
                        
                        # Collect severity rating
                        if "severity_rating" in details and details["severity_rating"]:
                            if details["severity_rating"] not in vuln_types[vuln_type]["severity_ratings"]:
                                vuln_types[vuln_type]["severity_ratings"].append(details["severity_rating"])
                            
                    except Exception as e:
                        console.print(f"[yellow]Error processing report: {e}[/yellow]")
                    
                    progress.update(task, advance=1)
            
            # Filter vulnerability types based on minimum examples
            filtered_vuln_types = {}
            for vuln_type, details in vuln_types.items():
                if len(details["vulnerable_examples"]) >= min_examples or len(details["fixed_examples"]) >= min_examples:
                    filtered_vuln_types[vuln_type] = details
            
            console.print(f"[green]Found {len(vuln_types)} vulnerability types across all reports[/green]")
            console.print(f"[green]After filtering for at least {min_examples} examples: {len(filtered_vuln_types)} vulnerability types[/green]")
            
            # Save templates to the database
            # Import required VectorEyes functions
            from VectorEyes import compute_embedding, generate_robust_detection_template, save_detection_library_to_db
            
            # Get existing vulnerability types
            cur.execute("SELECT vuln_type FROM detection_library")
            existing_types = [row[0] for row in cur.fetchall()]
            
            # Save templates
            new_count = 0
            updated_count = 0
            
            with Progress() as progress:
                task = progress.add_task("[cyan]Saving templates...", total=len(filtered_vuln_types))
                
                for vuln_type, details in filtered_vuln_types.items():
                    # Generate a vector embedding for this vulnerability type
                    embedding = compute_embedding(vuln_type)
                    
                    # Create a template if one doesn't exist yet
                    template = None
                    try:
                        # Use the vulnerability details to generate a robust detection template
                        template = generate_robust_detection_template(vuln_type, details)
                    except Exception as e:
                        console.print(f"[yellow]Warning: Could not generate template for {vuln_type}: {e}[/yellow]")
                    
                    # Save to the database
                    if vuln_type in existing_types:
                        cur.execute(
                            "UPDATE detection_library SET details = ?, vector_embedding = ?, template = ?, last_updated = ? WHERE vuln_type = ?",
                            (json.dumps(details), json.dumps(embedding), template, datetime.now().isoformat(), vuln_type)
                        )
                        updated_count += 1
                    else:
                        cur.execute(
                            "INSERT INTO detection_library (vuln_type, details, vector_embedding, template, schema_version, last_updated) VALUES (?, ?, ?, ?, ?, ?)",
                            (vuln_type, json.dumps(details), json.dumps(embedding), template, 1, datetime.now().isoformat())
                        )
                        new_count += 1
                    
                    conn.commit()
                    progress.update(task, advance=1)
            
            console.print(f"[green]Successfully added {new_count} new templates and updated {updated_count} existing templates![/green]")
            console.print("[green]Template building complete![/green]")
            
            conn.close()
        except Exception as e:
            console.print(f"[red]Error building direct templates: {e}[/red]")
        return
    
    if args.build_vuln_library:
        # Import required modules at the handler level
        import sqlite3
        import json
        
        # First check the number of reports in the database
        try:
            conn = sqlite3.connect(VECTOR_DB_PATH)
            cur = conn.cursor()
            
            # Check if we already have a populated detection library
            cur.execute("SELECT COUNT(*) FROM detection_library")
            detection_count = cur.fetchone()[0]
            if detection_count > 0:
                print(f"[INFO] Detection library already populated with {detection_count} templates.")
                confirmation = Prompt.ask("Do you want to rebuild the library? This may take a long time (Y/N)", default="N")
                if confirmation.lower() != "y":
                    print("[INFO] Skipping library rebuild.")
                    return
            
            # Count reports
            cur.execute("SELECT COUNT(*) FROM reports")
            report_count = cur.fetchone()[0]
            conn.close()
            
            if report_count == 0:
                print("[ERROR] No reports found in the database. Please add reports first using --reports.")
                return
                
            # Use functions from both modules to handle the library building
            from VectorEyes import build_detection_library
            from DeepCurrent import direct_copy_vulnerability_templates as direct_copy_templates
            
            # With LLM provider configured above, directly proceed to building the library
            choice = Prompt.ask(
                "Choose library building method:\n1. Full library rebuild (LLM-based, slow but comprehensive)\n2. Quick copy of existing templates (fast)", 
                choices=["1", "2"], 
                default="2"
            )
            
            if choice == "1":
                print(f"[INFO] Building vulnerability library from {report_count} reports using {args.llm_provider} LLM...")
                print("[WARN] This may take several minutes. Press Ctrl+C to cancel.")
                
                # Define a simple wrapper to handle potential errors
                def build_library_with_provider():
                    # Ensure all necessary modules are imported within this function's scope
                    import sqlite3
                    import json
                    from VectorEyes import build_detection_library, cluster_vulnerabilities, save_detection_library_to_db
                    
                    if args.llm_provider == "openrouter":
                        print(f"[INFO] Using OpenRouter with model: {VectorEyes.DEFAULT_MODEL}")
                    else:
                        print(f"[INFO] Using Ollama with model: {VectorEyes.DEFAULT_OLLAMA_MODEL}")
                        
                    # Build the library with a direct approach to avoid scope issues
                    try:
                        # Get vulnerability details from the database
                        conn = sqlite3.connect(VECTOR_DB_PATH)
                        c = conn.cursor()
                        c.execute("SELECT analysis_summary FROM reports")
                        rows = c.fetchall()
                        conn.close()
                        
                        # Parse the vulnerability details
                        vuln_details_list = []
                        for (analysis_summary,) in rows:
                            try:
                                if analysis_summary:
                                    details = json.loads(analysis_summary)
                                    vuln_details_list.append(details)
                            except Exception:
                                continue
                        
                        # Use LLM to cluster the vulnerabilities
                        library = cluster_vulnerabilities(vuln_details_list)
                        
                        # Save the library to the database
                        if library:
                            save_detection_library_to_db(library, VECTOR_DB_PATH)
                            return True
                        return False
                    except Exception as e:
                        print(f"[ERROR] Failed to build library: {e}")
                        return False
                
                try:
                    result = build_library_with_provider()
                    return result
                except Exception as e:
                    print(f"[ERROR] Failed to build vulnerability library: {e}")
                    return False
        except Exception as e:
            print(f"[ERROR] Failed to build vulnerability library: {e}")
        return
        
    if args.recategorize_other_vulns:
        try:
            from recategorize_vulns import VulnerabilityRecategorizer
            recategorizer = VulnerabilityRecategorizer()
            recategorizer.recategorize_vulnerabilities()
            print("[INFO] Vulnerability recategorization completed!")
        except Exception as e:
            print(f"[ERROR] Failed to recategorize vulnerabilities: {e}")
        return
        
    if args.fix_unknown_reports:
        try:
            # Import from the specialized script
            from fix_unknown_reports import UnknownReportFixer
            fixer = UnknownReportFixer()
            fixer.fix_unknown_reports()
            print("[INFO] Unknown report fixing completed!")
        except Exception as e:
            print(f"[ERROR] Failed to fix unknown reports: {e}")
        return
        
    if args.merge_databases:
        # Import Rich console for pretty printing
        from rich.console import Console
        console = Console()
        
        source_dir = args.merge_databases
        use_llm = not args.no_llm_merge
        
        # First validate that the source directory exists
        if not os.path.isdir(source_dir):
            console.print(f"[red]Error: Source directory '{source_dir}' does not exist or is not a directory.[/red]")
            return
        
        # Display confirmation
        confirmation = Prompt.ask(
            f"Merge databases from '{source_dir}' into the current databases? This operation will make backups but cannot be undone (Y/N)", 
            default="N"
        )
        if confirmation.lower() != "y":
            console.print("[yellow]Database merge cancelled.[/yellow]")
            return
        
        try:
            # Import the database_merger module
            from database_merger import merge_databases
            
            # Perform the merge operation
            console.print(f"[cyan]Merging databases from '{source_dir}'...[/cyan]")
            stats = merge_databases(source_dir, use_llm=use_llm)
            
            if stats:
                console.print("[green]Database merge completed successfully![/green]")
            else:
                console.print("[red]Database merge failed. See error messages above.[/red]")
        except ImportError:
            console.print("[red]Error: database_merger.py module not found. Please ensure it's in the same directory.[/red]")
        except Exception as e:
            console.print(f"[red]Error during database merge: {e}[/red]")
        
        return
    
    if args.clean_reports:
        from VectorEyes import clean_unknown_reports
        clean_unknown_reports()
        return
        
    # Handle vulnerability library diagnostic tool
    if args.diagnose_library:
        try:
            # Use subprocess to call the standalone script
            import subprocess
            import sys
            from rich.console import Console
            console = Console()
            
            console.print("[bold cyan]Running vulnerability library diagnostic tool...[/bold cyan]")
            
            # Call the vuln_library_doctor.py script
            script_path = os.path.join(SCRIPT_DIR, "vuln_library_doctor.py")
            
            if os.path.exists(script_path):
                # Execute the script directly, allowing output to flow to console
                console.print("[cyan]Running script directly for better visibility...[/cyan]")
                
                # Run the script directly without capturing output
                result = subprocess.call([sys.executable, script_path])
                
                if result == 0:
                    # Success
                    console.print("[bold green]Vulnerability library diagnostic completed successfully![/bold green]")
                else:
                    # Error
                    console.print(f"[bold red]Error running diagnostic tool. Exit code: {result}[/bold red]")
            else:
                # Script doesn't exist
                console.print(f"[bold red]Error: vuln_library_doctor.py not found at {script_path}[/bold red]")
                console.print("[yellow]Please make sure the script is in the same directory as sAils.py[/yellow]")
        
        except Exception as e:
            from rich.console import Console
            console = Console()
            console.print(f"[bold red]Error running diagnostic tool: {str(e)}[/bold red]")
        
        return
        
    # Handle dedicated LLM rebuild tool
    if args.rebuild_with_llm:
        try:
            # Use subprocess to call the standalone script
            import subprocess
            import sys
            from rich.console import Console
            console = Console()
            
            console.print("[bold cyan]Rebuilding vulnerability library using dedicated LLM process...[/bold cyan]")
            
            # Call the rebuild_vuln_library.py script
            script_path = os.path.join(SCRIPT_DIR, "rebuild_vuln_library.py")
            
            if os.path.exists(script_path):
                # Prepare command parameters
                cmd = [sys.executable, script_path]
                
                # Handle API selection
                api = args.api or "openrouter"  # Default to openrouter
                cmd.extend(["--api", api])
                
                # Add API keys and models
                if api == "openrouter":
                    openrouter_key = args.openrouter_key or os.environ.get("OPENROUTER_API_KEY", None)
                    if not openrouter_key:
                        console.print("[bold red]Error: OpenRouter API key is required for OpenRouter API.[/bold red]")
                        console.print("[yellow]Use --openrouter-key to provide your API key or set the OPENROUTER_API_KEY environment variable.[/yellow]")
                        return
                    cmd.extend(["--openrouter-key", openrouter_key])
                    
                    # Add model if specified
                    if args.openrouter_model:
                        cmd.extend(["--openrouter-model", args.openrouter_model])
                elif api == "ollama":
                    # Add ollama model if specified
                    if args.ollama_model:
                        cmd.extend(["--ollama-model", args.ollama_model])
                
                # Execute the script directly, allowing output to flow to console
                console.print(f"[cyan]Executing: {' '.join(cmd)}[/cyan]")
                console.print("[cyan]Running script directly for better visibility...[/cyan]")
                
                # Run the script directly without capturing output
                result = subprocess.call(cmd)
                
                if result == 0:
                    # Success
                    console.print("[bold green]Vulnerability library rebuilt successfully![/bold green]")
                else:
                    # Error
                    console.print(f"[bold red]Error rebuilding vulnerability library. Exit code: {result}[/bold red]")
            else:
                # Script doesn't exist
                console.print(f"[bold red]Error: rebuild_vuln_library.py not found at {script_path}[/bold red]")
                console.print("[yellow]Please make sure the script is in the same directory as sAils.py[/yellow]")
                
        except Exception as e:
            from rich.console import Console
            console = Console()
            console.print(f"[bold red]Error rebuilding library: {str(e)}[/bold red]")
        
        return
    
    # Handle DeepCurrent special commands
    if args.test_llm_connection:
        if args.llm_provider == "openrouter":
            from DeepCurrent import test_openrouter_connection
            test_openrouter_connection(args.openrouter_key)
        else: # default to ollama
            from DeepCurrent import test_ollama_connection
            test_ollama_connection()
        return
            
    # Check if vuln-scan-only is specified
    if args.vuln_scan_only:
        # Session directory is already created above
        print(f"[INFO] Running vulnerability scan in session: {session}")
        
        if not args.contracts:
            print("[ERROR] For --vuln-scan-only without an existing session, you must specify --contracts.")
            return
            
        # Let's process the contracts first
        analyzed = scan_contracts(args.contracts, session)
        if analyzed <= 0:
            print("[ERROR] No contracts were analyzed. Vulnerability scan cannot proceed.")
            return
            
        # Check if detection_library already exists and is populated
        try:
            conn = sqlite3.connect(VECTOR_DB_PATH)
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM detection_library")
            count = cur.fetchone()[0]
            conn.close()
            if count == 0:
                print("[ERROR] Detection library is empty. Please run with --build-vuln-library first.")
                return
            else:
                print(f"[INFO] Detection library ready with {count} templates.")
        except Exception as e:
            print(f"[ERROR] Failed to access detection library: {e}")
            return
            
        print(f"[INFO] Running vulnerability scan on session: {session}")
        vuln_scan(session)
        return
    
    # Main application flows
    if args.watch:
        # Set global WATCHED_DIR to help with the watch flow
        global WATCHED_DIR
        WATCHED_DIR = Prompt.ask("Enter the directory path to watch for new folders (e.g., ~/Documents/web3/*)")
        watch_for_new_dirs()
    else:
        if not args.contracts and not (args.reports or args.docs):
            parser.error("--contracts, --reports, or --docs is required unless --watch is used.")

        # Ensure contract_dir is a string even when None
        contract_dir = args.contracts if args.contracts is not None else ""
        
        vuln_pipeline(
            report_urls=args.reports,
            contract_dir=contract_dir,
            doc_paths=args.docs,
            session_folder=session,
            llm_provider=args.llm_provider,
            openrouter_key=args.openrouter_key,
            openrouter_model=args.openrouter_model,
            ollama_model=args.ollama_model,
            run_vuln_scan=args.vuln_scan
        )

if __name__ == "__main__":
    main()