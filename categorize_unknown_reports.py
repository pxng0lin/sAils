#!/usr/bin/env python
"""
Categorize Unknown Reports

This script identifies reports with unknown vulnerability types and uses LLM
to categorize them into proper, specific vulnerability types.
"""

import os
import json
import sqlite3
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.progress import Progress
from rich.table import Table
from rich.prompt import Confirm

# Try to import from the project
try:
    from DeepCurrent import call_llm, DB_PATH
    from recategorize_vulns import get_standard_vuln_types
except ImportError:
    # Fallback to local definitions
    DB_PATH = "vectorisation.db"
    
    def call_llm(prompt, max_tokens=1024):
        """Placeholder for LLM call if DeepCurrent module is not available."""
        print(f"Would call LLM with prompt: {prompt[:100]}...")
        return "Response would go here"
    
    def get_standard_vuln_types():
        """Return a list of standard vulnerability types."""
        return [
            "Reentrancy",
            "Access Control",
            "Integer Overflow/Underflow",
            "Front-running",
            "Unchecked Return Values",
            "Timestamp Dependence",
            "Race Conditions",
            "Denial of Service",
            "Block Gas Limit",
            "Logic Errors",
            "Oracle Manipulation",
            "Flash Loan Attacks",
            "Price Manipulation",
            "Governance Manipulation",
        ]

# Initialize console
console = Console()

class ReportCategorizer:
    """Categorize reports with unknown vulnerability types."""
    
    def __init__(self, db_path=DB_PATH):
        """Initialize with database path."""
        self.db_path = db_path
        self.standard_vuln_types = get_standard_vuln_types()
        self.categorized_count = 0
        self.failed_count = 0
        
    def get_unknown_reports(self):
        """Get all reports with unknown vulnerability types."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT id, content FROM reports WHERE analysis_summary IS NULL OR analysis_summary = 'Unknown'")
        reports = cursor.fetchall()
        conn.close()
        return reports
    
    def determine_vulnerability_category(self, report_content):
        """Use LLM to determine the vulnerability category for a report."""
        try:
            if not report_content:
                return None
                
            # Limit report size for LLM prompt
            shortened_content = report_content[:10000]
                
            # Prepare the prompt for LLM
            prompt = f"""Analyze this smart contract audit report and determine the most specific vulnerability type.
            
Report: {shortened_content}

Here are common vulnerability types for reference (but you are not limited to these):
{', '.join(self.standard_vuln_types)}

Respond with ONLY the vulnerability type name, be specific and precise. Include relevant CWE numbers if applicable. 
DO NOT respond with "Unknown" or generic categories. DO NOT include explanations or additional text."""
            
            # Call LLM for categorization
            response = call_llm(prompt)
            
            # Clean up response (remove quotes, extra whitespace, etc.)
            category = response.strip().strip('"\'').split('\n')[0]
            
            # Validate the result is not "Unknown" again
            if category.lower() == "unknown" or "cannot determine" in category.lower():
                return None
                
            return category
            
        except Exception as e:
            console.print(f"[red]Error determining category: {e}[/red]")
            return None
    
    def update_report_category(self, report_id, category):
        """Update a report with the determined vulnerability category."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Create a simple JSON object with the category
            analysis_summary = json.dumps({"vulnerability_type": category})
            
            # Update the report
            cursor.execute(
                "UPDATE reports SET analysis_summary = ? WHERE id = ?",
                (analysis_summary, report_id)
            )
            conn.commit()
            return cursor.rowcount > 0
        except Exception as e:
            console.print(f"[red]Error updating report: {e}[/red]")
            conn.rollback()
            return False
        finally:
            conn.close()
    
    def categorize_reports(self):
        """Main method to categorize unknown reports."""
        # Get all unknown reports
        reports = self.get_unknown_reports()
        console.print(f"[cyan]Found {len(reports)} reports with unknown vulnerability types[/cyan]")
        
        if not reports:
            console.print("[green]No unknown reports found. All reports are properly categorized![/green]")
            return
            
        # Confirm before proceeding
        if not Confirm.ask(f"Proceed with categorizing {len(reports)} reports?", default=True):
            console.print("[yellow]Operation cancelled.[/yellow]")
            return
            
        # Create a backup of the database
        backup_path = f"{self.db_path}_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        try:
            import shutil
            shutil.copy2(self.db_path, backup_path)
            console.print(f"[green]Created database backup at {backup_path}[/green]")
        except Exception as e:
            console.print(f"[yellow]Warning: Could not create database backup: {e}[/yellow]")
            if not Confirm.ask("Continue without backup?", default=False):
                console.print("[yellow]Operation cancelled.[/yellow]")
                return
        
        # Process each report
        with Progress() as progress:
            task = progress.add_task("[cyan]Categorizing reports...", total=len(reports))
            
            for report_id, report_content in reports:
                # Determine vulnerability category
                category = self.determine_vulnerability_category(report_content)
                
                if not category:
                    console.print(f"[yellow]Could not determine category for report ID {report_id}[/yellow]")
                    self.failed_count += 1
                    progress.update(task, advance=1)
                    continue
                
                # Update the report
                success = self.update_report_category(report_id, category)
                
                if success:
                    console.print(f"[green]Categorized report ID {report_id} as '{category}'[/green]")
                    self.categorized_count += 1
                else:
                    console.print(f"[red]Failed to update report ID {report_id}[/red]")
                    self.failed_count += 1
                
                progress.update(task, advance=1)
        
        # Summary
        console.print("\n[bold green]Categorization Complete![/bold green]")
        console.print(f"[green]Successfully categorized: {self.categorized_count}[/green]")
        console.print(f"[yellow]Failed to categorize: {self.failed_count}[/yellow]")
        
        # Next steps
        console.print("\n[cyan]Next steps:[/cyan]")
        console.print("1. Run [bold]uv run sAils.py --build-vuln-library[/bold] to rebuild the detection library")
        console.print("2. Use [bold]uv run sAils.py --recategorize-other-vulns[/bold] if needed to improve categorization")

def main():
    """Main entry point."""
    console.print("[bold cyan]Starting Unknown Report Categorization[/bold cyan]")
    
    categorizer = ReportCategorizer()
    categorizer.categorize_reports()

if __name__ == "__main__":
    main()
