# sAils.py - enhanced to auto-trigger on new directory creation and recursively find contracts

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
from datetime import datetime
from typing import Optional, List

from prefect import task, flow
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from VectorEyes import process_markdown_file, init_db as init_vector_db, build_detection_library
import DeepCurrent
from DeepCurrent import (
    init_db as init_deep_db,
    process_contracts_parallel,
    process_document,
    scan_contracts_for_vulnerabilities
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
    if report_count <= 0:
        print("No reports ingested, skipping library build.")
        return False
    return build_detection_library()

def is_contract_already_analyzed(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        file_hash = hashlib.sha256(content.encode()).hexdigest()
        conn = sqlite3.connect("smart_contracts_analysis.db")
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
    DeepCurrent.LLM_PROVIDER = provider
    print(f"Using LLM provider: {provider}")

    if provider == "openrouter":
        model = openrouter_model or DEFAULT_OPENROUTER_MODEL
        DeepCurrent.OPENROUTER_API_KEY = openrouter_key or DeepCurrent.OPENROUTER_API_KEY
        DeepCurrent.ANALYSIS_MODEL = model
        DeepCurrent.QUERY_MODEL = model
        print(f"Using OpenRouter model: {model}")
    else:
        model = ollama_model or DEFAULT_OLLAMA_MODEL
        DeepCurrent.MODEL_NAME = model
        DeepCurrent.ANALYSIS_MODEL = model
        DeepCurrent.QUERY_MODEL = model
        print(f"Using Ollama model: {model}")

    initialize_databases()
    ingested = ingest_reports(report_urls)
    built = build_vuln_library(ingested)
    analyzed = scan_contracts(contract_dir, session_folder)
    docs = analyze_docs(doc_paths, session_folder)
    vuln_results = False
    if run_vuln_scan:
        vuln_results = vuln_scan(session_folder)
    notify({
        "reports_ingested": ingested,
        "library_built": built,
        "contracts_analyzed": analyzed,
        "docs_analyzed": docs,
        "vulnerabilities_scanned": vuln_results,
        "session_folder": session_folder
    })

from rich.prompt import Prompt

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
        print(f"📁 Directory {trigger}: {path}")
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
    WATCHED_DIR = Prompt.ask("📂 Enter a glob pattern for folders to watch (e.g. '~/dev/*/web3')", default="~/Documents/web3/*")
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
    parser = argparse.ArgumentParser(description="Run end-to-end vulnerability analysis pipeline.")
    parser.add_argument("--reports", nargs="+", default=[], help="List of report URLs or file paths.")
    parser.add_argument("--contracts", help="Directory or single file containing contract(s).")
    parser.add_argument("--docs", nargs="*", default=[], help="List of doc paths/URLs (pdf, md, url).")
    parser.add_argument("--session", default=f"analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}", help="Output session folder.")
    parser.add_argument("--llm-provider", choices=["ollama", "openrouter"], help="Choose LLM backend: 'ollama' or 'openrouter'.")
    parser.add_argument("--openrouter-key", help="Your OpenRouter API key for cloud LLM usage.")
    parser.add_argument("--openrouter-model", help="OpenRouter model to use (default %s)." % DEFAULT_OPENROUTER_MODEL)
    parser.add_argument("--ollama-model", help="Local Ollama model name (default %s)." % DEFAULT_OLLAMA_MODEL)
    parser.add_argument("--vuln-scan", action="store_true", help="Run vulnerability scanning on the analyzed contracts.")
    parser.add_argument("--watch", action="store_true", help="Watch a folder for new contract directories.")
    args = parser.parse_args()

    if args.watch:
        watch_for_new_dirs()
    else:
        if not args.contracts:
            parser.error("--contracts is required unless --watch is used.")

        vuln_pipeline(
            report_urls=args.reports,
            contract_dir=args.contracts,
            doc_paths=args.docs,
            session_folder=args.session,
            llm_provider=args.llm_provider,
            openrouter_key=args.openrouter_key,
            openrouter_model=args.openrouter_model,
            ollama_model=args.ollama_model,
            run_vuln_scan=args.vuln_scan
        )

if __name__ == "__main__":
    main()



# ~/Documents/web3/*
