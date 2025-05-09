#!/usr/bin/env python
"""
Direct Template Builder

This script builds detection templates directly from vulnerability reports
without aggressive LLM clustering, preserving more granularity in the
vulnerability types. It provides a more comprehensive detection library
with closer to a 1:1 mapping of reports to templates.

Usage:
    python3 direct_build_templates.py [--limit N] [--min-examples 2]
"""

import os
import sys
import json
import sqlite3
import argparse
from pathlib import Path
from datetime import datetime

# Import core functions for consistency
from VectorEyes import DB_PATH, compute_embedding
from VectorEyes import generate_robust_detection_template

# Try to import from rich for nice output
try:
    from rich.console import Console
    from rich.progress import Progress
    from rich.panel import Panel
    from rich.table import Table
    console = Console()
    has_rich = True
except ImportError:
    has_rich = False
    print("Note: Install 'rich' for prettier output")
    class FakeConsole:
        def print(self, *args, **kwargs):
            print(*args)
    console = FakeConsole()

def print_progress(current, total, message="Processing"):
    """Print progress in a simple way or using rich if available."""
    if has_rich:
        # Rich progress is handled externally
        pass
    else:
        percent = int(current / total * 100)
        print(f"\r{message}: {current}/{total} ({percent}%)", end="")

def get_direct_templates(limit=None, min_examples=2):
    """
    Extract templates directly from reports without aggressive clustering.
    
    This creates more granular vulnerability templates by using the original 
    vulnerability types from reports rather than consolidating them.
    
    Args:
        limit: Maximum number of templates to create (None for all)
        min_examples: Minimum number of code examples required for a valid template
        
    Returns:
        Dictionary of vulnerability templates
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Get the report count
    cursor.execute("SELECT COUNT(*) FROM reports")
    total_reports = cursor.fetchone()[0]
    
    # Fetch all reports
    cursor.execute("SELECT analysis_summary FROM reports")
    rows = cursor.fetchall()
    
    # Create a dictionary to hold vulnerability details by type
    vuln_types = {}
    processed = 0
    
    # Use rich progress if available
    if has_rich:
        with Progress() as progress:
            task = progress.add_task("[cyan]Processing reports...", total=len(rows))
            
            for (analysis_summary,) in rows:
                if limit and processed >= limit:
                    break
                    
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
                    
                    # Add questions
                    if "questions" in details and details["questions"]:
                        for q in details["questions"]:
                            if q not in vuln_types[vuln_type]["questions"]:
                                vuln_types[vuln_type]["questions"].append(q)
                    
                    # Add attack vectors
                    if "attack_vectors" in details and details["attack_vectors"]:
                        for v in details["attack_vectors"]:
                            if v not in vuln_types[vuln_type]["attack_vectors"]:
                                vuln_types[vuln_type]["attack_vectors"].append(v)
                    
                    # Add detection signatures
                    if "detection_signatures" in details and details["detection_signatures"]:
                        for s in details["detection_signatures"]:
                            if s not in vuln_types[vuln_type]["detection_signatures"]:
                                vuln_types[vuln_type]["detection_signatures"].append(s)
                    
                    # Add code examples
                    if "vulnerable_code" in details and details["vulnerable_code"]:
                        if details["vulnerable_code"] not in vuln_types[vuln_type]["vulnerable_examples"]:
                            vuln_types[vuln_type]["vulnerable_examples"].append(details["vulnerable_code"])
                    
                    if "fixed_code" in details and details["fixed_code"]:
                        if details["fixed_code"] not in vuln_types[vuln_type]["fixed_examples"]:
                            vuln_types[vuln_type]["fixed_examples"].append(details["fixed_code"])
                    
                    # Add severity rating
                    if "severity_rating" in details and details["severity_rating"]:
                        if details["severity_rating"] not in vuln_types[vuln_type]["severity_ratings"]:
                            vuln_types[vuln_type]["severity_ratings"].append(details["severity_rating"])
                    
                    # Add researcher insights
                    if "researcher_insights" in details and details["researcher_insights"]:
                        insights = details["researcher_insights"]
                        if isinstance(insights, dict):
                            insight_str = json.dumps(insights)
                            if insight_str not in [json.dumps(i) for i in vuln_types[vuln_type]["researcher_insights"]]:
                                vuln_types[vuln_type]["researcher_insights"].append(insights)
                        elif isinstance(insights, str):
                            if insights not in vuln_types[vuln_type]["researcher_insights"]:
                                vuln_types[vuln_type]["researcher_insights"].append(insights)
                    
                    processed += 1
                except Exception as e:
                    console.print(f"[red]Error processing report: {e}[/red]")
                
                progress.update(task, advance=1)
    else:
        # No rich progress bar, use simple progress
        for i, (analysis_summary,) in enumerate(rows):
            if limit and processed >= limit:
                break
                
            try:
                if not analysis_summary:
                    print_progress(i + 1, len(rows))
                    continue
                    
                details = json.loads(analysis_summary)
                vuln_type = details.get("vuln_type")
                
                if not vuln_type:
                    print_progress(i + 1, len(rows))
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
                
                # Add questions
                if "questions" in details and details["questions"]:
                    for q in details["questions"]:
                        if q not in vuln_types[vuln_type]["questions"]:
                            vuln_types[vuln_type]["questions"].append(q)
                
                # Add attack vectors
                if "attack_vectors" in details and details["attack_vectors"]:
                    for v in details["attack_vectors"]:
                        if v not in vuln_types[vuln_type]["attack_vectors"]:
                            vuln_types[vuln_type]["attack_vectors"].append(v)
                
                # Add detection signatures
                if "detection_signatures" in details and details["detection_signatures"]:
                    for s in details["detection_signatures"]:
                        if s not in vuln_types[vuln_type]["detection_signatures"]:
                            vuln_types[vuln_type]["detection_signatures"].append(s)
                
                # Add code examples
                if "vulnerable_code" in details and details["vulnerable_code"]:
                    if details["vulnerable_code"] not in vuln_types[vuln_type]["vulnerable_examples"]:
                        vuln_types[vuln_type]["vulnerable_examples"].append(details["vulnerable_code"])
                
                if "fixed_code" in details and details["fixed_code"]:
                    if details["fixed_code"] not in vuln_types[vuln_type]["fixed_examples"]:
                        vuln_types[vuln_type]["fixed_examples"].append(details["fixed_code"])
                
                # Add severity rating
                if "severity_rating" in details and details["severity_rating"]:
                    if details["severity_rating"] not in vuln_types[vuln_type]["severity_ratings"]:
                        vuln_types[vuln_type]["severity_ratings"].append(details["severity_rating"])
                
                # Add researcher insights
                if "researcher_insights" in details and details["researcher_insights"]:
                    insights = details["researcher_insights"]
                    if isinstance(insights, dict):
                        insight_str = json.dumps(insights)
                        if insight_str not in [json.dumps(i) for i in vuln_types[vuln_type]["researcher_insights"]]:
                            vuln_types[vuln_type]["researcher_insights"].append(insights)
                    elif isinstance(insights, str):
                        if insights not in vuln_types[vuln_type]["researcher_insights"]:
                            vuln_types[vuln_type]["researcher_insights"].append(insights)
                
                processed += 1
            except Exception as e:
                print(f"Error processing report: {e}")
            
            print_progress(i + 1, len(rows))
        
        print()  # End the progress line
    
    # Filter vulnerability types based on minimum examples
    filtered_vuln_types = {}
    for vuln_type, details in vuln_types.items():
        if len(details["vulnerable_examples"]) >= min_examples or len(details["fixed_examples"]) >= min_examples:
            filtered_vuln_types[vuln_type] = details
    
    console.print(f"Processed {processed} reports and found {len(vuln_types)} vulnerability types")
    console.print(f"After filtering for at least {min_examples} examples: {len(filtered_vuln_types)} vulnerability types")
    
    conn.close()
    return filtered_vuln_types

def save_templates_to_db(templates):
    """Save the templates to the detection_library table."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # If saving to an existing database, get the current entries
    cursor.execute("SELECT vuln_type FROM detection_library")
    existing_types = [row[0] for row in cursor.fetchall()]
    
    new_count = 0
    updated_count = 0
    
    if has_rich:
        with Progress() as progress:
            task = progress.add_task("[cyan]Saving templates...", total=len(templates))
            
            for vuln_type, details in templates.items():
                progress.update(task, description=f"[cyan]Processing: {vuln_type[:30]}..." if len(vuln_type) > 30 else f"[cyan]Processing: {vuln_type}")
                
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
                    cursor.execute(
                        "UPDATE detection_library SET details = ?, vector_embedding = ?, template = ?, last_updated = ? WHERE vuln_type = ?",
                        (json.dumps(details), json.dumps(embedding), template, datetime.now().isoformat(), vuln_type)
                    )
                    updated_count += 1
                else:
                    cursor.execute(
                        "INSERT INTO detection_library (vuln_type, details, vector_embedding, template, schema_version, last_updated) VALUES (?, ?, ?, ?, ?, ?)",
                        (vuln_type, json.dumps(details), json.dumps(embedding), template, 1, datetime.now().isoformat())
                    )
                    new_count += 1
                
                conn.commit()
                progress.update(task, advance=1)
    else:
        # No rich progress bar
        count = 0
        for vuln_type, details in templates.items():
            print_progress(count, len(templates), "Saving templates")
            
            # Generate a vector embedding for this vulnerability type
            embedding = compute_embedding(vuln_type)
            
            # Create a template if one doesn't exist yet
            template = None
            try:
                # Use the vulnerability details to generate a robust detection template
                template = generate_robust_detection_template(vuln_type, details)
            except Exception as e:
                print(f"Warning: Could not generate template for {vuln_type}: {e}")
            
            # Save to the database
            if vuln_type in existing_types:
                cursor.execute(
                    "UPDATE detection_library SET details = ?, vector_embedding = ?, template = ?, last_updated = ? WHERE vuln_type = ?",
                    (json.dumps(details), json.dumps(embedding), template, datetime.now().isoformat(), vuln_type)
                )
                updated_count += 1
            else:
                cursor.execute(
                    "INSERT INTO detection_library (vuln_type, details, vector_embedding, template, schema_version, last_updated) VALUES (?, ?, ?, ?, ?, ?)",
                    (vuln_type, json.dumps(details), json.dumps(embedding), template, 1, datetime.now().isoformat())
                )
                new_count += 1
            
            conn.commit()
            count += 1
            
        print()  # End the progress line
    
    conn.close()
    
    result = {
        "new_templates": new_count,
        "updated_templates": updated_count,
        "total_templates": new_count + updated_count
    }
    
    return result

def main():
    parser = argparse.ArgumentParser(description="Build detection templates directly from reports")
    parser.add_argument("--limit", type=int, help="Limit the number of templates to create")
    parser.add_argument("--min-examples", type=int, default=2, help="Minimum number of code examples required for a template")
    args = parser.parse_args()
    
    # Get direct templates from reports
    templates = get_direct_templates(limit=args.limit, min_examples=args.min_examples)
    
    if not templates:
        console.print("[red]No valid templates generated. Check your reports or lower the min-examples threshold.[/red]")
        return
    
    # Save templates to the database
    console.print("[cyan]Saving templates to database...[/cyan]")
    result = save_templates_to_db(templates)
    
    console.print(f"[green]Success! Added {result['new_templates']} new templates and updated {result['updated_templates']} existing templates.[/green]")
    
    # Print a helpful command to view the results
    console.print("[cyan]To view your new templates, run:[/cyan]")
    console.print("uv run sAils.py --view-vuln-library")

if __name__ == "__main__":
    main()
