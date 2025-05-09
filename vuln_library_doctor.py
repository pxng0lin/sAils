#!/usr/bin/env python
# vuln_library_doctor.py - A diagnostic and repair tool for the vulnerability detection library

import os
import sys
import json
import sqlite3
import hashlib
from datetime import datetime
from collections import defaultdict
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskID

# Define script directory 
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))

# Get DB path from VectorEyes if possible, otherwise use default location
try:
    from VectorEyes import DB_PATH
except ImportError:
    DB_PATH = os.path.join(SCRIPT_DIR, "vectorisation.db")

console = Console()

def diagnose_and_fix():
    """
    Diagnose and fix issues with the vulnerability detection library
    """
    console.print("[bold cyan]Vulnerability Library Doctor[/bold cyan]")
    console.print("This tool will diagnose and fix issues with your vulnerability detection library.")
    
    # Check if the database exists
    if not os.path.exists(DB_PATH):
        console.print(f"[bold red]Error: Database file not found at {DB_PATH}[/bold red]")
        return
    
    console.print(f"[green]Found database at {DB_PATH}[/green]")
    
    try:
        # Connect to the database
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Check if detection_library table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='detection_library'")
        if not cursor.fetchone():
            console.print("[bold red]Error: detection_library table does not exist![/bold red]")
            return
            
        # Get the total number of vulnerabilities
        cursor.execute("SELECT COUNT(*) FROM detection_library")
        total_vulns = cursor.fetchone()[0]
        console.print(f"[green]Found {total_vulns} vulnerability entries in the library.[/green]")
        
        # Check for empty or NULL values
        cursor.execute("SELECT COUNT(*) FROM detection_library WHERE details IS NULL OR details = '' OR details = '{}' OR details = 'null'")
        empty_details = cursor.fetchone()[0]
        if empty_details > 0:
            console.print(f"[yellow]Warning: {empty_details} vulnerabilities have empty or NULL details.[/yellow]")
        
        # Get schema info
        cursor.execute("PRAGMA table_info(detection_library)")
        columns = cursor.fetchall()
        column_names = [col[1] for col in columns]
        console.print(f"[cyan]Current table schema: {', '.join(column_names)}[/cyan]")
        
        # Check if we need to add the enhanced columns
        schema_needs_update = False
        missing_columns = []
        
        for col in ["vector_embedding", "llm_template", "schema_version", "last_updated"]:
            if col not in column_names:
                missing_columns.append(col)
                schema_needs_update = True
        
        if schema_needs_update:
            console.print(f"[yellow]Schema needs update. Missing columns: {', '.join(missing_columns)}[/yellow]")
            
            # Add missing columns
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                console=console
            ) as progress:
                update_task = progress.add_task("[cyan]Updating schema...", total=len(missing_columns))
                
                for col in missing_columns:
                    if col == "vector_embedding":
                        cursor.execute("ALTER TABLE detection_library ADD COLUMN vector_embedding BLOB")
                    elif col == "llm_template":
                        cursor.execute("ALTER TABLE detection_library ADD COLUMN llm_template TEXT")
                    elif col == "schema_version":
                        cursor.execute("ALTER TABLE detection_library ADD COLUMN schema_version INTEGER DEFAULT 1")
                    elif col == "last_updated":
                        cursor.execute("ALTER TABLE detection_library ADD COLUMN last_updated TEXT")
                    
                    progress.update(update_task, advance=1)
                
                conn.commit()
            
            console.print("[green]Schema updated successfully![/green]")
        
        # Verify all vulnerability entries have valid details JSON
        cursor.execute("SELECT vuln_type, details FROM detection_library")
        vulns = cursor.fetchall()
        
        valid_count = 0
        invalid_count = 0
        fixed_count = 0
        fixed_vulns = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console
        ) as progress:
            verify_task = progress.add_task("[cyan]Verifying vulnerability details...", total=len(vulns))
            
            for vuln_type, details in vulns:
                progress.update(verify_task, advance=1)
                
                # Check if details is valid JSON
                try:
                    if details:
                        details_obj = json.loads(details)
                        valid_count += 1
                    else:
                        # Empty details, create a placeholder
                        details_obj = {
                            "vulnerability_description": f"A vulnerability of type {vuln_type}",
                            "questions": [f"What security issues are associated with {vuln_type}?"],
                            "attack_vectors": [],
                            "detection_signatures": []
                        }
                        fixed_vulns.append((vuln_type, json.dumps(details_obj)))
                        fixed_count += 1
                except Exception:
                    # Invalid JSON, create a placeholder
                    details_obj = {
                        "vulnerability_description": f"A vulnerability of type {vuln_type}",
                        "questions": [f"What security issues are associated with {vuln_type}?"],
                        "attack_vectors": [],
                        "detection_signatures": []
                    }
                    fixed_vulns.append((vuln_type, json.dumps(details_obj)))
                    invalid_count += 1
        
        console.print(f"[green]Verification complete: {valid_count} valid, {invalid_count} invalid, {fixed_count} empty[/green]")
        
        # Fix invalid entries
        if fixed_vulns:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                console=console
            ) as progress:
                fix_task = progress.add_task("[cyan]Fixing invalid entries...", total=len(fixed_vulns))
                
                for vuln_type, fixed_details in fixed_vulns:
                    cursor.execute(
                        "UPDATE detection_library SET details = ? WHERE vuln_type = ?",
                        (fixed_details, vuln_type)
                    )
                    progress.update(fix_task, advance=1)
                
                conn.commit()
            
            console.print(f"[green]Fixed {len(fixed_vulns)} invalid entries![/green]")
        
        # Check for vector embeddings and LLM templates
        cursor.execute("SELECT COUNT(*) FROM detection_library WHERE vector_embedding IS NULL OR vector_embedding = ''")
        missing_embeddings = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM detection_library WHERE llm_template IS NULL OR llm_template = ''")
        missing_templates = cursor.fetchone()[0]
        
        # Fix missing embeddings and templates
        if missing_embeddings > 0 or missing_templates > 0:
            console.print(f"[yellow]Found {missing_embeddings} entries without embeddings and {missing_templates} without LLM templates[/yellow]")
            
            # Generate prompt for continuation
            should_fix = console.input("[cyan]Would you like to create these now? (y/n): [/cyan]").lower() == 'y'
            
            if should_fix:
                # Import enhancer functions
                try:
                    from llm_enhancer import create_vector_embedding, generate_llm_prompt_template
                except ImportError:
                    console.print("[red]Error: llm_enhancer.py not found. Please run this after creating that file.[/red]")
                    return
                
                cursor.execute("SELECT vuln_type, details FROM detection_library WHERE vector_embedding IS NULL OR vector_embedding = '' OR llm_template IS NULL OR llm_template = ''")
                vulns_to_fix = cursor.fetchall()
                
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                    console=console
                ) as progress:
                    enhance_task = progress.add_task("[cyan]Enhancing vulnerabilities...", total=len(vulns_to_fix))
                    
                    for vuln_type, details in vulns_to_fix:
                        try:
                            # Create embedding and template
                            vector_embedding = create_vector_embedding(vuln_type, details)
                            llm_template = generate_llm_prompt_template(vuln_type, details)
                            
                            # Update the database
                            cursor.execute(
                                """
                                UPDATE detection_library
                                SET vector_embedding = ?,
                                    llm_template = ?,
                                    schema_version = 2,
                                    last_updated = ?
                                WHERE vuln_type = ?
                                """,
                                (
                                    json.dumps(vector_embedding),
                                    llm_template,
                                    datetime.now().isoformat(),
                                    vuln_type
                                )
                            )
                        except Exception as e:
                            console.print(f"[red]Error enhancing '{vuln_type}': {e}[/red]")
                        
                        progress.update(enhance_task, advance=1)
                    
                    conn.commit()
                
                console.print("[green]Enhancement complete![/green]")
        
        # Final verification
        cursor.execute("SELECT COUNT(*) FROM detection_library")
        final_total = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM detection_library WHERE vector_embedding IS NOT NULL AND vector_embedding != ''")
        with_embeddings = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM detection_library WHERE llm_template IS NOT NULL AND llm_template != ''")
        with_templates = cursor.fetchone()[0]
        
        console.print("\n[bold cyan]Final Library Status:[/bold cyan]")
        table = Table()
        table.add_column("Metric", style="cyan")
        table.add_column("Count", style="green")
        table.add_column("Percentage", style="yellow")
        
        table.add_row("Total Vulnerabilities", str(final_total), "100%")
        table.add_row(
            "With Vector Embeddings", 
            str(with_embeddings), 
            f"{with_embeddings/final_total*100:.1f}%" if final_total > 0 else "0%"
        )
        table.add_row(
            "With LLM Templates", 
            str(with_templates), 
            f"{with_templates/final_total*100:.1f}%" if final_total > 0 else "0%"
        )
        
        console.print(table)
        
        # Export library report
        should_export = console.input("[cyan]Would you like to export a library report? (y/n): [/cyan]").lower() == 'y'
        if should_export:
            export_path = os.path.join(SCRIPT_DIR, "vulnerability_library_report.md")
            
            cursor.execute("SELECT vuln_type, details FROM detection_library ORDER BY vuln_type")
            all_vulns = cursor.fetchall()
            
            md_content = f"# Vulnerability Detection Library Report\n\n"
            md_content += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            md_content += f"Total Vulnerabilities: {final_total}\n\n"
            
            md_content += "## Table of Contents\n\n"
            for i, (vuln_type, _) in enumerate(all_vulns):
                md_content += f"{i+1}. [{vuln_type}](#{vuln_type.lower().replace(' ', '-').replace('(', '').replace(')', '')})\n"
            
            for vuln_type, details in all_vulns:
                md_content += f"\n## {vuln_type}\n\n"
                
                try:
                    details_dict = json.loads(details) if details else {}
                    
                    # Description
                    description = details_dict.get('vulnerability_description', '')
                    if description:
                        md_content += f"{description}\n\n"
                    
                    # Questions
                    if details_dict.get('questions'):
                        md_content += "### Security Questions\n\n"
                        for q in details_dict.get('questions', []):
                            md_content += f"- {q}\n"
                        md_content += "\n"
                    
                    # Attack vectors
                    if details_dict.get('attack_vectors'):
                        md_content += "### Attack Vectors\n\n"
                        for v in details_dict.get('attack_vectors', []):
                            md_content += f"- {v}\n"
                        md_content += "\n"
                    
                    # Code examples (simple version to avoid complexity)
                    if details_dict.get('vulnerable_examples') or details_dict.get('vulnerable_code'):
                        md_content += "### Has Code Examples: Yes\n\n"
                    
                except Exception:
                    md_content += "*Details parsing error*\n\n"
                
                md_content += "---\n"
            
            with open(export_path, "w") as f:
                f.write(md_content)
            
            console.print(f"[green]Report exported to: {export_path}[/green]")
        
        conn.close()
        console.print("[bold green]Vulnerability library diagnostic and repair complete![/bold green]")
        
    except Exception as e:
        console.print(f"[bold red]Error: {e}[/bold red]")
        import traceback
        console.print(traceback.format_exc())


if __name__ == "__main__":
    diagnose_and_fix()
