#!/usr/bin/env python
"""
Fix Unknown Reports

This script identifies reports marked as 'Unknown' vulnerability types in the reports table
and recategorizes them using LLM analysis to make them valid for the detection library.
"""

import os
import json
import sqlite3
from datetime import datetime
from rich.console import Console
from rich.progress import Progress
from rich.panel import Panel
from rich.prompt import Confirm

# Try to import from the project
try:
    from DeepCurrent import call_llm
    from recategorize_vulns import get_standard_vuln_types
    DB_PATH = "vectorisation.db"
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
            "Reentrancy (CWE-841)",
            "Access Control (CWE-284)",
            "Integer Overflow/Underflow (CWE-190/191)",
            "Front-running (CWE-362)",
            "Unchecked Return Values (CWE-252)",
            "Timestamp Dependence (CWE-829)",
            "Race Conditions",
            "Denial of Service (CWE-400)",
            "Block Gas Limit (CWE-770)",
            "Logic Errors (CWE-670)",
            "Oracle Manipulation",
            "Flash Loan Attacks",
            "Precision Loss (CWE-1339)",
            "MEV Issues",
            "Governance Manipulation"
        ]

# Initialize console
console = Console()

class UnknownReportFixer:
    """Fix reports with unknown vulnerability types in the database."""
    
    def __init__(self, db_path=DB_PATH):
        """Initialize with database path."""
        self.db_path = db_path
        self.standard_vuln_types = get_standard_vuln_types()
        self.fixed_count = 0
        self.failed_count = 0
        
    def get_unknown_reports(self):
        """Get all reports with unknown vulnerability types using the same criteria as clean_unknown_reports."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT id, content, analysis_summary FROM reports WHERE analysis_summary IS NOT NULL")
        
        unknown_reports = []
        
        for report_id, content, analysis_summary in cursor.fetchall():
            try:
                analysis = json.loads(analysis_summary)
                vuln_type = analysis.get('vuln_type', 'Unknown')
                
                if vuln_type == 'Unknown' or 'unknown' in vuln_type.lower():
                    unknown_reports.append((report_id, content, analysis_summary))
            except (json.JSONDecodeError, KeyError, TypeError):
                # Also include reports with parsing errors
                unknown_reports.append((report_id, content, analysis_summary))
        
        conn.close()
        return unknown_reports
    
    def determine_vulnerability_type(self, report_content):
        """Use LLM to determine the vulnerability category for a report."""
        try:
            if not report_content:
                return None
                
            # Extract code examples if present (often most indicative of vulnerability type)
            code_pattern = r'```[^\n]*\n(.*?)```'
            code_blocks = re.findall(code_pattern, report_content, re.DOTALL)
            code_context = "\n".join(code_blocks[:2]) if code_blocks else ""
            
            # Limit report size for LLM prompt but prioritize code examples
            max_context = 5000
            if len(code_context) > 0:
                remaining_context = max(max_context - len(code_context) - 500, 1000)
                shortened_content = report_content[:remaining_context]
                combined_content = f"{shortened_content}\n\nRelevant code examples:\n{code_context}"
            else:
                shortened_content = report_content[:max_context]
                combined_content = shortened_content
                
            # Prepare the prompt for LLM
            prompt = f"""Analyze this smart contract audit report and determine the most specific vulnerability type.
            
Report: {combined_content}

Here are common vulnerability types for reference (but you are not limited to these):
{', '.join(self.standard_vuln_types)}

Your task is to identify the SPECIFIC vulnerability type mentioned in this report.
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
    
    def update_report_analysis(self, report_id, vuln_type, old_analysis_json):
        """Update a report with the determined vulnerability category."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Parse existing analysis if possible, or create new structure
            try:
                analysis = json.loads(old_analysis_json) if old_analysis_json else {}
            except (json.JSONDecodeError, TypeError):
                analysis = {}
            
            # Update the vuln_type field
            analysis['vuln_type'] = vuln_type
            
            # Update the report
            new_analysis_json = json.dumps(analysis)
            cursor.execute(
                "UPDATE reports SET analysis_summary = ? WHERE id = ?",
                (new_analysis_json, report_id)
            )
            conn.commit()
            return cursor.rowcount > 0
        except Exception as e:
            console.print(f"[red]Error updating report: {e}[/red]")
            conn.rollback()
            return False
        finally:
            conn.close()
    
    def fix_unknown_reports(self):
        """Main method to fix reports with unknown vulnerability types."""
        # Get all unknown reports
        reports = self.get_unknown_reports()
        console.print(f"[cyan]Found {len(reports)} reports with unknown vulnerability types[/cyan]")
        
        if not reports:
            console.print("[green]No unknown reports found. All reports are properly categorized![/green]")
            return
            
        # Confirm before proceeding
        if not Confirm.ask(f"Proceed with fixing {len(reports)} unknown reports?", default=True):
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
            task = progress.add_task("[cyan]Fixing unknown reports...", total=len(reports))
            
            for report_id, content, analysis_summary in reports:
                # Determine vulnerability category
                vuln_type = self.determine_vulnerability_type(content)
                
                if not vuln_type:
                    console.print(f"[yellow]Could not determine category for report ID {report_id}[/yellow]")
                    self.failed_count += 1
                    progress.update(task, advance=1)
                    continue
                
                # Update the report
                success = self.update_report_analysis(report_id, vuln_type, analysis_summary)
                
                if success:
                    console.print(f"[green]Fixed report ID {report_id} with type '{vuln_type}'[/green]")
                    self.fixed_count += 1
                else:
                    console.print(f"[red]Failed to update report ID {report_id}[/red]")
                    self.failed_count += 1
                
                progress.update(task, advance=1)
        
        # Summary
        console.print("\n[bold green]Report Fixing Complete![/bold green]")
        console.print(f"[green]Successfully fixed: {self.fixed_count}[/green]")
        console.print(f"[yellow]Failed to fix: {self.failed_count}[/yellow]")
        
        # Next steps
        console.print("\n[cyan]Next steps:[/cyan]")
        console.print("1. Run [bold]uv run sAils.py --build-vuln-library[/bold] to rebuild the detection library")
        console.print("2. Use [bold]uv run sAils.py --recategorize-other-vulns[/bold] if needed to improve categorization")

def main():
    """Main entry point."""
    console.print(Panel.fit(
        "[bold]Fix Unknown Reports[/bold]\n\n"
        "This utility will identify reports with 'Unknown' vulnerability types\n"
        "and recategorize them to make them valid for the detection library.",
        title="Report Fix Utility",
        border_style="cyan"
    ))
    
    fixer = UnknownReportFixer()
    fixer.fix_unknown_reports()

if __name__ == "__main__":
    import re  # Import needed for regex pattern matching
    main()
