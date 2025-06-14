#!/usr/bin/env python
"""
Fix Unknown Reports

This script identifies reports marked as 'Unknown' vulnerability types in the reports table
and recategorizes them using LLM analysis to make them valid for the detection library.
"""

import os
import json
import sqlite3
import re  # Added missing import for regular expressions
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
    
    def rule_based_classification(self, report_content):
        """Use rule-based pattern matching to identify vulnerability types."""
        try:
            # Common patterns that strongly indicate specific vulnerability types
            patterns = [
                # Reentrancy patterns
                (r'(?:re-?entr\w+|recursive\s+call)', 'Reentrancy'),
                
                # Integer overflow/underflow
                (r'(?:integer|arithmetic)\s*(?:overflow|underflow)', 'Integer Overflow/Underflow'),
                (r'(?:uint|int)\d+\s*(?:overflow|underflow)', 'Integer Overflow/Underflow'),
                
                # Access control
                (r'(?:access\s*control|permission|authorization)\s*(?:issue|bug|vulnerability|missing)', 'Access Control'),
                (r'(?:missing|improper)\s*(?:access\s*control|permission\s*check)', 'Access Control'),
                
                # Front-running
                (r'(?:front.?run\w+|transaction\s*ordering)', 'Front-Running'),
                
                # Oracle manipulation
                (r'(?:oracle\s*manipulation|price\s*manipulation)', 'Oracle Manipulation'),
                
                # Signature verification
                (r'(?:signature\s*(?:verification|validation)|ecrecover)', 'Signature Verification'),
                
                # Flash loan attacks
                (r'(?:flash\s*loan|flash\s*attack)', 'Flash Loan Attack'),
                
                # Denial of Service
                (r'(?:denial.?of.?service|dos\b)', 'Denial of Service'),
                
                # Race conditions
                (r'race\s*condition', 'Race Condition'),
                
                # Timestamp dependence
                (r'(?:timestamp|block\.timestamp|now)\s*(?:dependence|manipulation)', 'Timestamp Dependence'),
                
                # Weak randomness
                (r'(?:weak|insufficient|predictable)\s*(?:randomness|entropy)', 'Weak Randomness'),
                
                # Unchecked return values
                (r'(?:unchecked|ignored)\s*(?:return|value)', 'Unchecked Return Value'),
                
                # Delegatecall issues
                (r'(?:delegatecall|callcode)\s*(?:issue|vulnerability)', 'Delegatecall Misuse'),
                
                # Function visibility
                (r'(?:function|method)\s*(?:visibility|access)', 'Function Visibility'),
                
                # Uninitialized variables
                (r'(?:uninitialized|unassigned)\s*(?:variable|storage)', 'Uninitialized Variable'),
                
                # Zero address checks
                (r'(?:zero|null)\s*address\s*(?:check|validation)', 'Zero Address Check'),
                
                # Logic errors
                (r'(?:logic|business)\s*(?:error|flaw|bug)', 'Logic Error'),
                
                # Gas optimization
                (r'gas\s*(?:optimization|efficiency)', 'Gas Optimization'),
                
                # Precision loss
                (r'(?:precision|rounding)\s*(?:loss|error)', 'Precision Loss'),
                
                # Token approvals
                (r'(?:token\s*approval|allowance)\s*(?:issue|vulnerability)', 'Token Approval'),
                
                # ERC compliance
                (r'erc\d+\s*(?:compliance|standard)', 'ERC Compliance'),
                
                # Unsafe casting
                (r'(?:unsafe|improper)\s*(?:cast|type\s*conversion)', 'Unsafe Type Casting'),
                
                # Variable shadowing
                (r'(?:variable|parameter)\s*shadowing', 'Variable Shadowing')
            ]
            
            # Convert to lowercase for case-insensitive matching
            content_lower = report_content.lower()
            
            # Check each pattern
            for pattern, vuln_type in patterns:
                if re.search(pattern, content_lower, re.IGNORECASE):
                    return vuln_type
                    
            return None
        except Exception as e:
            console.print(f"[yellow]Error in rule-based classification: {e}[/yellow]")
            return None
    
    def determine_vulnerability_type(self, report_content):
        """Determine the vulnerability category for a report using multiple methods."""
        try:
            if not report_content:
                return "Logic Error"
            
            # STEP 1: Try rule-based pattern matching first (fastest and most reliable)
            rule_based_type = self.rule_based_classification(report_content)
            if rule_based_type:
                console.print(f"[green]Found vulnerability type using rule-based classification: {rule_based_type}[/green]")
                return rule_based_type
                
            # STEP 2: Try to extract from headers and title
            extracted_type = self.extract_vulnerability_type_from_headers(report_content)
            if extracted_type:
                console.print(f"[green]Found vulnerability type in headers/title: {extracted_type}[/green]")
                return extracted_type
            
            # STEP 3: Try keyword-based classification
            keyword_type = self.determine_fallback_category(report_content)
            if keyword_type and keyword_type != "Smart Contract Security Issue" and keyword_type != "Security Vulnerability":
                console.print(f"[green]Found vulnerability type using keyword analysis: {keyword_type}[/green]")
                return keyword_type
            
            # STEP 4: Only if all else fails, try LLM-based classification
            # Extract code examples if present (often most indicative of vulnerability type)
            code_pattern = r'```[^\n]*\n(.*?)```'
            code_blocks = re.findall(code_pattern, report_content, re.DOTALL)
            code_context = "\n".join(code_blocks[:2]) if code_blocks else ""
            
            # Prepare content for LLM analysis
            # Extract title and first paragraph for focused analysis
            title_match = re.search(r'(?:^|\n)\s*#+\s*(.+?)\s*(?:\n|$)', report_content)
            title = title_match.group(1) if title_match else ""
            
            # Extract first paragraph (often contains vulnerability description)
            first_para_match = re.search(r'(?:^|\n)\s*([^#\n][^\n]{10,})\s*(?:\n|$)', report_content)
            first_para = first_para_match.group(1) if first_para_match else ""
            
            # Look for specific sections that might contain vulnerability info
            vuln_sections = []
            section_patterns = [
                r'(?:^|\n)\s*#+\s*(?:Vulnerability|Issue|Bug|Finding|Problem|Weakness)\s*[:\n]\s*([^#\n][^\n]{10,})',
                r'(?:^|\n)\s*(?:Vulnerability|Issue)\s*(?:Type|Category|Classification)\s*[:\n]\s*([^#\n][^\n]{10,})',
                r'(?:^|\n)\s*(?:Impact|Severity|Risk)\s*[:\n]\s*([^#\n][^\n]{10,})',
                r'(?:^|\n)\s*(?:Description|Summary|Overview)\s*[:\n]\s*([^#\n][^\n]{10,})'
            ]
            
            for pattern in section_patterns:
                matches = re.findall(pattern, report_content, re.IGNORECASE)
                vuln_sections.extend(matches)
            
            # Prepare focused content for the LLM
            focused_content = f"TITLE: {title}\n\n"
            if first_para:
                focused_content += f"DESCRIPTION: {first_para}\n\n"
            if vuln_sections:
                focused_content += f"VULNERABILITY DETAILS:\n" + "\n".join(vuln_sections[:3]) + "\n\n"
            if code_context:
                focused_content += f"CODE CONTEXT:\n{code_context}\n\n"
            
            # Add a short excerpt from the full content as backup
            focused_content += f"FULL REPORT EXCERPT:\n{report_content[:1000]}"
            
            # Prepare the prompt for LLM with the enhanced focused content
            prompt = f"""You are a smart contract security expert analyzing audit reports. Your task is to determine the SPECIFIC vulnerability type described in this report.

I've extracted key sections from the report to help you identify the vulnerability type:

{focused_content}

Common vulnerability types for reference (you are not limited to these):
{', '.join(self.standard_vuln_types)}

IMPORTANT INSTRUCTIONS:
1. Respond with ONLY the vulnerability type name - be specific and technical (e.g. 'Reentrancy', 'Integer Overflow', 'Access Control').
2. Include CWE numbers if applicable (e.g. 'Reentrancy (CWE-841)').
3. If multiple vulnerabilities are present, identify the MAIN vulnerability type.
4. DO NOT use phrases like 'The vulnerability type is' - just provide the type directly.
5. DO NOT respond with 'Unknown' or generic categories like 'Smart Contract Vulnerability'.
6. DO NOT include explanations, reasoning, or any additional text.
7. DO NOT use XML-like tags such as <think> or <analysis>.
8. Pay special attention to the TITLE and VULNERABILITY DETAILS sections.
9. If you see code patterns like reentrancy, integer overflow, etc., prioritize those technical classifications.
10. If you absolutely cannot determine a specific type, respond with 'Logic Error'.

Vulnerability type:"""
            
            try:
                # Call LLM for categorization with timeout handling
                response = call_llm(prompt)
                
                # Clean up response (remove quotes, extra whitespace, etc.)
                category = response.strip().strip('"\'\'').split('\n')[0]
                
                # If we got a valid category from LLM, return it
                if category and len(category) > 3 and not any(marker in category.lower() for marker in ['<', '>', 'think', 'analysis', 'reasoning']):
                    console.print(f"[green]Found vulnerability type using LLM: {category}[/green]")
                    return category
            except Exception as e:
                console.print(f"[yellow]LLM analysis failed: {e}[/yellow]")
            
            # STEP 5: If all methods fail, use a specific default category
            return "Logic Error"
            if category and category.lower() != "unclassified security issue":
                return category
            
            # If LLM failed but we extracted a type from headers, use that as fallback
            if extracted_type:
                console.print(f"[yellow]Using extracted type from report headers: {extracted_type}[/yellow]")
                return extracted_type
            
            # If all else fails, use a generic but useful category based on keywords in the report
            fallback_type = self.determine_fallback_category(report_content)
            if fallback_type:
                console.print(f"[yellow]Using fallback category based on keywords: {fallback_type}[/yellow]")
                return fallback_type
            
            # If absolutely nothing worked, use a specific category that won't be treated as unknown
            console.print(f"[yellow]All detection methods failed, using default category 'Logic Error'[/yellow]")
            return "Logic Error"
            
        except Exception as e:
            console.print(f"[red]Error determining category: {e}, using default category[/red]")
            return "Logic Error"
    
    def extract_vulnerability_type_from_headers(self, report_content):
        """Extract vulnerability type from report headers or title."""
        try:
            # Look for common patterns in report titles and headers
            title_patterns = [
                r'#\s*(.+?)\s*Vulnerability',  # Matches: # Access Control Vulnerability
                r'#+\s*(.+?)\s*\((?:High|Medium|Critical|Low)\)',  # Matches: # Reentrancy (High)
                r'\*\*Vulnerability\s*Type\*\*\s*:?\s*(.+?)(?:\n|$)',  # Matches: **Vulnerability Type**: Reentrancy
                r'\*\*Type\*\*\s*:?\s*(.+?)(?:\n|$)',  # Matches: **Type**: Reentrancy
                r'Vulnerability\s*Name\s*:?\s*(.+?)(?:\n|$)',  # Matches: Vulnerability Name: Reentrancy
                r'Issue\s*Type\s*:?\s*(.+?)(?:\n|$)'  # Matches: Issue Type: Reentrancy
            ]
            
            # Try each pattern
            for pattern in title_patterns:
                match = re.search(pattern, report_content, re.IGNORECASE)
                if match:
                    extracted_type = match.group(1).strip()
                    # Clean up the extracted type
                    extracted_type = re.sub(r'\s*vulnerability\s*$', '', extracted_type, flags=re.IGNORECASE)
                    if len(extracted_type) > 3 and not extracted_type.lower() == "unknown":
                        return extracted_type
            
            return None
        except Exception as e:
            console.print(f"[red]Error extracting type from headers: {e}[/red]")
            return None
    
    def determine_fallback_category(self, report_content):
        """Determine a fallback category based on keywords in the report."""
        try:
            # Define keyword mappings to vulnerability types
            keyword_mappings = {
                'reentrancy': 'Reentrancy',
                'front run': 'Front-Running',
                'frontrun': 'Front-Running',
                'overflow': 'Integer Overflow',
                'underflow': 'Integer Underflow',
                'access control': 'Access Control',
                'authorization': 'Authorization',
                'authentication': 'Authentication',
                'privilege': 'Privilege Escalation',
                'dos': 'Denial of Service',
                'denial of service': 'Denial of Service',
                'race condition': 'Race Condition',
                'flash loan': 'Flash Loan Attack',
                'oracle': 'Oracle Manipulation',
                'price manipul': 'Price Manipulation',
                'signature': 'Signature Verification',
                'replay': 'Replay Attack',
                'timestamp': 'Timestamp Dependence',
                'randomness': 'Weak Randomness',
                'centralization': 'Centralization Risk',
                'governance': 'Governance Issue',
                'proxy': 'Proxy Implementation',
                'storage': 'Storage Collision',
                'delegate': 'Delegatecall Misuse',
                'selfdestruct': 'Selfdestruct Misuse',
                'suicide': 'Selfdestruct Misuse',
                'gas': 'Gas Optimization',
                'precision': 'Precision Loss',
                'rounding': 'Rounding Error',
                'token approval': 'Token Approval',
                'allowance': 'Allowance Issue',
                'erc20': 'ERC20 Compliance',
                'erc721': 'ERC721 Compliance',
                'erc1155': 'ERC1155 Compliance',
                'unchecked': 'Unchecked Return Value',
                'revert': 'Improper Error Handling',
                'require': 'Improper Validation',
                'assert': 'Assertion Failure',
                'exception': 'Exception Handling',
                'visibility': 'Function Visibility',
                'initialization': 'Uninitialized Variable',
                'zero address': 'Zero Address Check',
                'unsafe cast': 'Unsafe Type Casting',
                'shadowing': 'Variable Shadowing',
                'naming': 'Naming Convention',
                'documentation': 'Documentation Issue',
                'upgradeable': 'Upgrade Mechanism',
                'liquidity': 'Liquidity Issue',
                'collateral': 'Collateral Management',
                'voting': 'Voting Mechanism',
                'multisig': 'Multisig Security',
                'escrow': 'Escrow Implementation',
                'vesting': 'Vesting Implementation',
                'staking': 'Staking Mechanism',
                'reward': 'Reward Distribution',
                'nft': 'NFT Implementation',
                'auction': 'Auction Mechanism',
                'royalty': 'Royalty Implementation',
                'metadata': 'Metadata Management',
                'uri': 'URI Management',
                'blacklist': 'Access Control',
                'whitelist': 'Access Control',
                'pausable': 'Emergency Mechanism',
                'emergency': 'Emergency Mechanism',
                'circuit breaker': 'Emergency Mechanism',
                'upgrade': 'Upgrade Mechanism',
                'migration': 'Migration Issue'
            }
            
            # Convert report content to lowercase for case-insensitive matching
            content_lower = report_content.lower()
            
            # Find all matching keywords
            matches = []
            for keyword, vuln_type in keyword_mappings.items():
                if keyword.lower() in content_lower:
                    matches.append((keyword, vuln_type))
            
            # If we have matches, return the most specific one (usually the longest keyword)
            if matches:
                # Sort by keyword length (descending) to prioritize more specific matches
                matches.sort(key=lambda x: len(x[0]), reverse=True)
                return matches[0][1]
            
            # If no specific matches, return a generic but useful category
            return "Smart Contract Security Issue"
            
        except Exception as e:
            console.print(f"[red]Error determining fallback category: {e}[/red]")
            return "Security Vulnerability"
    
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
                
                # If we still couldn't determine a category, use a more specific default category
                if not vuln_type:
                    console.print(f"[yellow]Could not determine category for report ID {report_id}, using default category[/yellow]")
                    # Use a specific category that won't be treated as unknown
                    vuln_type = "Logic Error"
                
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
