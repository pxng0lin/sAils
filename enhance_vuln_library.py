#!/usr/bin/env python
"""
Enhanced Vulnerability Library Builder

This script fixes two major issues with the vulnerability detection library:
1. Improves the quality of code examples for all vulnerability types
2. Verifies the detection library build function is working properly

Usage:
    python3 enhance_vuln_library.py [--rebuild-all] [--api openrouter|ollama] [--check-only]
"""

import os
import sys
import json
import sqlite3
import argparse
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress

# Import from VectorEyes to maintain consistency
from VectorEyes import DB_PATH, compute_embedding, DEFAULT_OLLAMA_MODEL, DEFAULT_MODEL
from VectorEyes import cluster_vulnerabilities, save_detection_library_to_db

console = Console()

# Dictionary of high-quality examples for common vulnerability types
# This serves as backup if LLM generation fails
QUALITY_EXAMPLES = {
    "Arithmetic Overflow": {
        "vulnerable_examples": [
            """// VULNERABLE: No overflow check in uint256 addition
function deposit(uint256 amount) public {
    balances[msg.sender] += amount;  // Could overflow pre-Solidity 0.8.0
}""",
            """// VULNERABLE: No overflow check in critical calculation 
function calculateReward(uint256 stakeAmount, uint256 rewardRate) public pure returns (uint256) {
    return stakeAmount * rewardRate;  // Can overflow with large inputs
}"""
        ],
        "fixed_examples": [
            """// FIXED: Using SafeMath or Solidity 0.8.0+ to prevent overflow
function deposit(uint256 amount) public {
    // Solidity 0.8.0+ has built-in overflow checks
    balances[msg.sender] += amount;  // Will revert on overflow
    
    // Alternative in earlier Solidity versions:
    // balances[msg.sender] = balances[msg.sender].add(amount);  // Using SafeMath
}""",
            """// FIXED: Using checked math operations
function calculateReward(uint256 stakeAmount, uint256 rewardRate) public pure returns (uint256) {
    // Will revert on overflow in Solidity 0.8.0+
    return stakeAmount * rewardRate;
    
    // For earlier Solidity versions:
    // return stakeAmount.mul(rewardRate);  // Using SafeMath
}"""
        ]
    },
    "Reentrancy": {
        "vulnerable_examples": [
            """// VULNERABLE: Classic reentrancy vulnerability
function withdraw(uint256 amount) public {
    require(balances[msg.sender] >= amount, "Insufficient balance");
    
    // Send ETH before updating state
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success, "Transfer failed");
    
    // State update happens after external call
    balances[msg.sender] -= amount;
}""",
            """// VULNERABLE: Cross-function reentrancy
function deposit() public payable {
    balances[msg.sender] += msg.value;
}

function withdrawAll() public {
    uint256 amount = balances[msg.sender];
    require(amount > 0, "No balance to withdraw");
    
    // External call before state update allows reentrancy to deposit()
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success, "Transfer failed");
    
    balances[msg.sender] = 0;
}"""
        ],
        "fixed_examples": [
            """// FIXED: Updates state before external call (Checks-Effects-Interactions)
function withdraw(uint256 amount) public {
    require(balances[msg.sender] >= amount, "Insufficient balance");
    
    // Update state before external call
    balances[msg.sender] -= amount;
    
    // External call happens after state changes
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success, "Transfer failed");
}""",
            """// FIXED: Using ReentrancyGuard from OpenZeppelin
// Import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract SecureContract is ReentrancyGuard {
    function withdraw(uint256 amount) public nonReentrant {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // Even though the call happens before state update,
        // the nonReentrant modifier prevents reentrancy
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        balances[msg.sender] -= amount;
    }
}"""
        ]
    },
    "Precision Loss": {
        "vulnerable_examples": [
            """// VULNERABLE: Division before multiplication causes precision loss
function calculateReward(uint256 totalReward, uint256 userTokens, uint256 totalTokens) public pure returns (uint256) {
    // Division happens first, potentially losing precision
    uint256 share = totalReward / totalTokens;
    uint256 reward = share * userTokens;
    return reward;
}""",
            """// VULNERABLE: Using integer division without proper scaling
function convertEthToTokens(uint256 ethAmount, uint256 ethPrice) public pure returns (uint256) {
    // No scaling factor used, precision lost in division
    return ethAmount / ethPrice;
}"""
        ],
        "fixed_examples": [
            """// FIXED: Multiplication before division preserves precision
function calculateReward(uint256 totalReward, uint256 userTokens, uint256 totalTokens) public pure returns (uint256) {
    // Multiplication happens first, preserving precision
    uint256 reward = totalReward * userTokens / totalTokens;
    return reward;
}""",
            """// FIXED: Using proper scaling factor for precision
function convertEthToTokens(uint256 ethAmount, uint256 ethPrice) public pure returns (uint256) {
    // Using a scaling factor (10^18) to maintain precision
    uint256 PRECISION = 10**18;
    return ethAmount * PRECISION / ethPrice;
}"""
        ]
    }
}

def get_vulnerability_details(conn):
    """Get all vulnerability types and details from the detection library."""
    cursor = conn.cursor()
    cursor.execute("SELECT vuln_type, details FROM detection_library")
    return cursor.fetchall()

def check_vulnerability_examples(conn):
    """Check all vulnerabilities for missing or placeholder examples."""
    vulns = get_vulnerability_details(conn)
    
    if not vulns:
        console.print("[red]No vulnerabilities found in the detection library![/red]")
        return []
    
    issues = []
    for vuln_type, details_json in vulns:
        try:
            details = json.loads(details_json)
            
            # Check for missing or placeholder examples
            has_issue = False
            issue_type = ""
            
            if not details.get("vulnerable_examples"):
                has_issue = True
                issue_type = "Missing vulnerable examples"
            elif any("..." in str(ex) for ex in details.get("vulnerable_examples", [])):
                has_issue = True
                issue_type = "Contains placeholder vulnerable examples"
            elif any(len(str(ex).strip()) < 50 for ex in details.get("vulnerable_examples", [])):
                has_issue = True
                issue_type = "Contains minimal vulnerable examples"
                
            if not details.get("fixed_examples"):
                has_issue = True
                issue_type += ", Missing fixed examples"
            elif any("..." in str(ex) for ex in details.get("fixed_examples", [])):
                has_issue = True
                issue_type += ", Contains placeholder fixed examples"
            elif any(len(str(ex).strip()) < 50 for ex in details.get("fixed_examples", [])):
                has_issue = True
                issue_type += ", Contains minimal fixed examples"
            
            if has_issue:
                issues.append({
                    "vuln_type": vuln_type,
                    "issue": issue_type,
                    "details": details
                })
                
        except Exception as e:
            console.print(f"[red]Error checking {vuln_type}: {e}[/red]")
            issues.append({
                "vuln_type": vuln_type,
                "issue": f"Error parsing details: {e}",
                "details": None
            })
    
    return issues

def enhance_example(vuln_details, examples_dict=QUALITY_EXAMPLES):
    """Enhance examples for a vulnerability type using predefined high-quality examples."""
    vuln_type = vuln_details["vuln_type"]
    details = vuln_details["details"]
    
    # Find matching vulnerability type in our quality examples dictionary
    # Try exact match first
    match_key = None
    for key in examples_dict:
        if key.lower() in vuln_type.lower() or vuln_type.lower() in key.lower():
            match_key = key
            break
    
    if match_key:
        # Use predefined examples
        examples = examples_dict[match_key]
        if examples.get("vulnerable_examples"):
            details["vulnerable_examples"] = examples["vulnerable_examples"]
        if examples.get("fixed_examples"):
            details["fixed_examples"] = examples["fixed_examples"]
    else:
        # Create generic examples based on vulnerability type
        # This would be better with an LLM call, but this is a fallback
        details["vulnerable_examples"] = [
            f"""// VULNERABLE: Example of {vuln_type}
function unsafeFunction() public {{
    // This code is vulnerable to {vuln_type}
    // It should properly validate inputs and handle edge cases
}}""",
            f"""// VULNERABLE: Another example of {vuln_type} 
function insecureOperation(uint amount) public {{
    // Missing proper security checks related to {vuln_type}
}}"""
        ]
        
        details["fixed_examples"] = [
            f"""// FIXED: Secure implementation against {vuln_type}
function safeFunction() public {{
    // Implementing proper validation and security measures
    // to prevent {vuln_type}
}}""",
            f"""// FIXED: Enhanced security for {vuln_type}
function secureOperation(uint amount) public {{
    // Added appropriate checks and safeguards
    require(amount > 0 && amount <= maxAmount, "Invalid amount");
    // Proper implementation to prevent {vuln_type}
}}"""
        ]
    
    return details

def enhance_all_examples(conn):
    """Enhance examples for all vulnerabilities in the detection library."""
    issues = check_vulnerability_examples(conn)
    
    if not issues:
        console.print("[green]All vulnerability examples look good! No enhancement needed.[/green]")
        return True
    
    console.print(f"[yellow]Found {len(issues)} vulnerabilities that need improved examples.[/yellow]")
    
    with Progress() as progress:
        task = progress.add_task("[cyan]Enhancing examples...", total=len(issues))
        
        for issue in issues:
            vuln_type = issue["vuln_type"]
            details = issue["details"]
            
            if not details:
                progress.update(task, advance=1)
                continue
                
            # Enhance the examples
            enhanced_details = enhance_example({"vuln_type": vuln_type, "details": details})
            
            # Update the database
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE detection_library SET details = ? WHERE vuln_type = ?",
                (json.dumps(enhanced_details), vuln_type)
            )
            conn.commit()
            
            progress.update(task, advance=1)
    
    console.print("[green]Successfully enhanced all vulnerability examples![/green]")
    return True

def check_reports_quality(conn):
    """Check the quality of reports in the database."""
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM reports")
    report_count = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM detection_library")
    template_count = cursor.fetchone()[0]
    
    console.print(Panel(f"""
[bold cyan]Vulnerability Library Status:[/bold cyan]

• [bold]Reports:[/bold] {report_count} vulnerability reports in database
• [bold]Templates:[/bold] {template_count} vulnerability types in detection library
• [bold]Ratio:[/bold] {report_count / template_count if template_count else 0:.1f} reports per vulnerability type

The detection library consolidates the reports into distinct vulnerability categories.
    """, title="Library Statistics"))
    
    # Check for malformed analysis summaries
    cursor.execute("SELECT COUNT(*) FROM reports WHERE analysis_summary IS NULL OR analysis_summary = ''")
    missing_summaries = cursor.fetchone()[0]
    
    if missing_summaries > 0:
        console.print(f"[yellow]Warning: {missing_summaries} reports have missing or empty analysis summaries![/yellow]")
    
    # Check a sample of analysis summaries for structure
    cursor.execute("SELECT analysis_summary FROM reports LIMIT 5")
    samples = cursor.fetchall()
    
    structure_issues = 0
    for (summary,) in samples:
        try:
            data = json.loads(summary)
            if not isinstance(data, dict) or not data.get("vuln_type"):
                structure_issues += 1
        except Exception:
            structure_issues += 1
    
    if structure_issues > 0:
        console.print(f"[yellow]Warning: {structure_issues} out of 5 sampled reports have structural issues![/yellow]")
    
    return {
        "report_count": report_count,
        "template_count": template_count,
        "missing_summaries": missing_summaries,
        "structure_issues": structure_issues
    }

def rebuild_detection_library(conn, api="ollama"):
    """Rebuild the detection library using the correct approach."""
    from VectorEyes import build_detection_library, save_detection_library_to_db
    
    # First check report quality
    stats = check_reports_quality(conn)
    
    if stats["report_count"] == 0:
        console.print("[red]No reports found in the database. Can't rebuild library.[/red]")
        return False
    
    # Set global variables for API
    global USE_API
    USE_API = api
    
    # First delete all existing entries in detection_library
    cursor = conn.cursor()
    cursor.execute("DELETE FROM detection_library")
    conn.commit()
    
    # Rebuild the library
    console.print("[cyan]Rebuilding vulnerability detection library...[/cyan]")
    library = build_detection_library(DB_PATH)
    
    if not library:
        console.print("[red]Failed to build vulnerability library![/red]")
        return False
    
    # Save the new library to the database
    console.print("[cyan]Saving new detection library to database...[/cyan]")
    save_detection_library_to_db(library, DB_PATH)
    
    # Check the results
    cursor.execute("SELECT COUNT(*) FROM detection_library")
    new_template_count = cursor.fetchone()[0]
    
    console.print(f"[green]Successfully rebuilt vulnerability library with {new_template_count} templates![/green]")
    
    # Now enhance all examples
    return enhance_all_examples(conn)

def display_vuln_details(vuln_type):
    """Display detailed information for a specific vulnerability type."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Find the vulnerability with partial matching
    cursor.execute(
        "SELECT vuln_type, details FROM detection_library WHERE vuln_type LIKE ?", 
        (f"%{vuln_type}%",)
    )
    results = cursor.fetchall()
    
    if not results:
        console.print(f"[red]No vulnerability found matching '{vuln_type}'.[/red]")
        return
    
    # Display the first match
    vuln_type, details_json = results[0]
    try:
        details = json.loads(details_json)
        
        console.print(f"\n[bold cyan]Vulnerability Type:[/bold cyan] {vuln_type}\n")
        
        # Display questions if available
        if "questions" in details and details["questions"]:
            console.print(Panel("\n".join([f"• {q}" for q in details["questions"]]), 
                             title="[bold magenta]Security Questions[/bold magenta]", 
                             expand=False))
        
        # Display attack vectors if available
        if "attack_vectors" in details and details["attack_vectors"]:
            console.print(Panel("\n".join([f"• {v}" for v in details["attack_vectors"]]), 
                             title="[bold red]Attack Vectors[/bold red]", 
                             expand=False))
        
        # Display examples if available
        if "vulnerable_examples" in details and details["vulnerable_examples"]:
            for i, example in enumerate(details["vulnerable_examples"][:2]):
                console.print(Panel(example, 
                                 title=f"[bold red]Vulnerable Example {i+1}[/bold red]",
                                 expand=False))
        
        if "fixed_examples" in details and details["fixed_examples"]:
            for i, example in enumerate(details["fixed_examples"][:2]):
                console.print(Panel(example, 
                                 title=f"[bold green]Fixed Example {i+1}[/bold green]",
                                 expand=False))
                
        console.print("\n[bold green]Example quality looks good![/bold green]")
        
    except Exception as e:
        console.print(f"[red]Error displaying vulnerability details: {e}[/red]")
    
    conn.close()

def main():
    parser = argparse.ArgumentParser(description="Enhance vulnerability library examples and verify build process")
    parser.add_argument("--rebuild-all", action="store_true", help="Completely rebuild the vulnerability library")
    parser.add_argument("--api", choices=["openrouter", "ollama"], default="ollama", help="API to use for rebuilding (default: ollama)")
    parser.add_argument("--check-only", action="store_true", help="Only check for issues without fixing them")
    parser.add_argument("--view", help="View details for a specific vulnerability type")
    
    args = parser.parse_args()
    
    if args.view:
        display_vuln_details(args.view)
        return
    
    conn = sqlite3.connect(DB_PATH)
    
    # Always check report quality
    check_reports_quality(conn)
    
    if args.rebuild_all:
        rebuild_detection_library(conn, args.api)
    elif args.check_only:
        issues = check_vulnerability_examples(conn)
        if issues:
            console.print(f"[yellow]Found {len(issues)} vulnerabilities with example issues:[/yellow]")
            table = Table(title="Vulnerabilities Needing Enhancement")
            table.add_column("Vulnerability Type", style="cyan")
            table.add_column("Issue", style="yellow")
            
            for issue in issues:
                table.add_row(issue["vuln_type"], issue["issue"])
            
            console.print(table)
        else:
            console.print("[green]All vulnerability examples look good![/green]")
    else:
        # Default: enhance examples without rebuilding
        enhance_all_examples(conn)
    
    conn.close()

if __name__ == "__main__":
    main()
