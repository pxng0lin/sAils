#!/usr/bin/env python
"""
Recategorize Vulnerability Types

This script identifies vulnerabilities categorized as "Other" and uses LLM
to recategorize them into proper, specific vulnerability types.
"""

import os
import json
import sqlite3
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.progress import Progress
from rich.table import Table

# Try to import from the project
try:
    from DeepCurrent import call_llm, DB_PATH
    from utils import get_standard_vuln_types
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

class VulnerabilityRecategorizer:
    """Recategorize vulnerabilities from 'Other' to more specific types."""
    
    def __init__(self, db_path=DB_PATH):
        """Initialize with database path."""
        self.db_path = db_path
        self.standard_vuln_types = get_standard_vuln_types()
        self.recategorized_count = 0
        self.failed_count = 0
        
    def get_other_vulnerabilities(self):
        """Get all vulnerabilities categorized as 'Other'."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT vuln_type, details, template FROM detection_library WHERE vuln_type = ? OR vuln_type LIKE ?", 
                      ("Other", "%Other%"))
        vulns = cursor.fetchall()
        conn.close()
        return vulns
    
    def determine_proper_category(self, details_json, template):
        """Use LLM to determine the proper category for a vulnerability."""
        try:
            # Parse details
            details = json.loads(details_json) if details_json else {}
            
            # Extract information from details
            description = details.get("vulnerability_description", "")
            questions = details.get("questions", [])
            if questions:
                description += "\n" + "\n".join(questions)
                
            # If description is still empty, use template text
            if not description and template:
                description = template[:1000]  # Limit template size
                
            if not description:
                return None
                
            # Prepare the prompt for LLM
            prompt = f"""Analyze this smart contract vulnerability description and determine the most specific vulnerability type.
            
Description: {description[:1500]}

Here are common vulnerability types for reference (but you are not limited to these):
{', '.join(self.standard_vuln_types)}

Respond with ONLY the vulnerability type name, be specific and precise. Include relevant CWE numbers if applicable. 
DO NOT respond with "Other" or generic categories. DO NOT include explanations or additional text."""
            
            # Call LLM for categorization
            response = call_llm(prompt)
            
            # Clean up response (remove quotes, extra whitespace, etc.)
            category = response.strip().strip('"\'').split('\n')[0]
            
            # Validate the result is not "Other" again
            if category.lower() == "other" or "cannot determine" in category.lower():
                return None
                
            return category
            
        except Exception as e:
            console.print(f"[red]Error determining category: {e}[/red]")
            return None
    
    def update_vulnerability_category(self, old_vuln_type, new_vuln_type, details_json):
        """Update a vulnerability with a new category."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # First check if the new category already exists to avoid UNIQUE constraint error
            cursor.execute("SELECT vuln_type, details FROM detection_library WHERE vuln_type = ?", (new_vuln_type,))
            existing = cursor.fetchone()
            
            if existing:
                # Category already exists, need to merge
                console.print(f"[yellow]New category '{new_vuln_type}' already exists. Merging content...[/yellow]")
                
                # Get details of both vulnerabilities
                old_details = json.loads(details_json) if details_json else {}
                existing_details_json = existing[1] if len(existing) > 1 else "{}"
                existing_details = json.loads(existing_details_json) if existing_details_json else {}
                
                # Merge details
                merged_details = existing_details.copy()
                
                # Merge examples and other list fields
                for field in ["vulnerable_examples", "fixed_examples", "questions", "detection_signatures"]:
                    if field in old_details and old_details[field]:
                        if field not in merged_details:
                            merged_details[field] = []
                        if isinstance(old_details[field], list):
                            # Add only unique items
                            for item in old_details[field]:
                                if item not in merged_details[field]:
                                    merged_details[field].append(item)
                
                # Update description if needed
                if "vulnerability_description" in old_details and len(old_details.get("vulnerability_description", "")) > len(merged_details.get("vulnerability_description", "")):
                    merged_details["vulnerability_description"] = old_details["vulnerability_description"]
                
                # Update the existing vulnerability with merged details
                cursor.execute(
                    "UPDATE detection_library SET details = ?, last_updated = ? WHERE vuln_type = ?",
                    (json.dumps(merged_details), datetime.now().isoformat(), new_vuln_type)
                )
                
                # Delete the old 'Other' entry
                cursor.execute("DELETE FROM detection_library WHERE vuln_type = ? AND details = ?", 
                              (old_vuln_type, details_json))
                conn.commit()
                return True
            else:
                # New category doesn't exist, perform standard update
                cursor.execute(
                    "UPDATE detection_library SET vuln_type = ?, last_updated = ? WHERE vuln_type = ? AND details = ?",
                    (new_vuln_type, datetime.now().isoformat(), old_vuln_type, details_json)
                )
                conn.commit()
                return cursor.rowcount > 0
        except Exception as e:
            console.print(f"[red]Error updating vulnerability: {e}[/red]")
            conn.rollback()
            return False
        finally:
            conn.close()
    
    def recategorize_vulnerabilities(self):
        """Main method to recategorize 'Other' vulnerabilities."""
        # Get all "Other" vulnerabilities
        vulns = self.get_other_vulnerabilities()
        console.print(f"[cyan]Found {len(vulns)} vulnerabilities categorized as 'Other'[/cyan]")
        
        if not vulns:
            console.print("[green]No 'Other' vulnerabilities found. Library is well-categorized![/green]")
            return
            
        # Process each vulnerability
        with Progress() as progress:
            task = progress.add_task("[cyan]Recategorizing vulnerabilities...", total=len(vulns))
            
            for vuln_type, details_json, template in vulns:
                # Determine proper category
                new_category = self.determine_proper_category(details_json, template)
                
                if not new_category:
                    console.print(f"[yellow]Could not determine category for vulnerability[/yellow]")
                    self.failed_count += 1
                    progress.update(task, advance=1)
                    continue
                
                # Update the vulnerability
                success = self.update_vulnerability_category(vuln_type, new_category, details_json)
                
                if success:
                    console.print(f"[green]Recategorized: '{vuln_type}' → '{new_category}'[/green]")
                    self.recategorized_count += 1
                else:
                    console.print(f"[red]Failed to update vulnerability[/red]")
                    self.failed_count += 1
                
                progress.update(task, advance=1)
        
        # Summary
        console.print("\n[bold green]Recategorization Complete![/bold green]")
        console.print(f"[green]Successfully recategorized: {self.recategorized_count}[/green]")
        console.print(f"[yellow]Failed to recategorize: {self.failed_count}[/yellow]")

def main():
    """Main entry point."""
    console.print("[bold cyan]Starting Vulnerability Recategorization[/bold cyan]")
    
    recategorizer = VulnerabilityRecategorizer()
    recategorizer.recategorize_vulnerabilities()

if __name__ == "__main__":
    main()
