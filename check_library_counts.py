#!/usr/bin/env python

import os
import sqlite3
import json

print("Checking vulnerability library counts...")

# Get the database path (same as in the main scripts)
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
VECTOR_DB_PATH = os.path.join(SCRIPT_DIR, "vectorisation.db")

if not os.path.exists(VECTOR_DB_PATH):
    print(f"ERROR: Database file not found at {VECTOR_DB_PATH}")
    exit(1)

conn = sqlite3.connect(VECTOR_DB_PATH)
c = conn.cursor()

# Check tables
print("Checking tables in the database...")
c.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = [table[0] for table in c.fetchall()]
print(f"Tables found: {', '.join(tables)}")

# Check vulnerability_reports if it exists
if "vulnerability_reports" in tables:
    c.execute("SELECT COUNT(*) FROM vulnerability_reports")
    reports_count = c.fetchone()[0]
    print(f"Vulnerability reports count: {reports_count}")
    
    # Get a sample of report types
    c.execute("SELECT vulnerability_type FROM vulnerability_reports LIMIT 5")
    sample_reports = [report[0] for report in c.fetchall()]
    print(f"Sample report types: {', '.join(sample_reports)}")
else:
    print("No vulnerability_reports table found.")

# Check detection_library if it exists
if "detection_library" in tables:
    c.execute("SELECT COUNT(*) FROM detection_library")
    library_count = c.fetchone()[0]
    print(f"Detection library entries: {library_count}")
    
    # Get a sample of vulnerability types
    c.execute("SELECT vuln_type FROM detection_library LIMIT 5")
    sample_types = [vuln[0] for vuln in c.fetchall()]
    print(f"Sample vulnerability types: {', '.join(sample_types)}")
    
    # Check how many have vector embeddings
    c.execute("SELECT COUNT(*) FROM detection_library WHERE vector_embedding IS NOT NULL AND vector_embedding != ''")
    vector_count = c.fetchone()[0]
    print(f"Entries with vector embeddings: {vector_count}")
    
    # Check how many have LLM templates
    c.execute("SELECT COUNT(*) FROM detection_library WHERE llm_template IS NOT NULL AND llm_template != ''")
    template_count = c.fetchone()[0]
    print(f"Entries with LLM templates: {template_count}")
else:
    print("No detection_library table found.")

conn.close()
print("Check completed.")
