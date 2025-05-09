#!/usr/bin/env python
# llm_enhancer.py - Adds LLM-specific enhancements to the vulnerability detection library

import os
import sys
import json
import sqlite3
import hashlib
import numpy as np
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown

# Import paths from VectorEyes to ensure consistency
from VectorEyes import DB_PATH, compute_embedding

console = Console()

# Default LLM context sizes for different models
MODEL_CONTEXT_SIZES = {
    "gpt-3.5-turbo": 16000,
    "gpt-4": 8000,
    "gpt-4-turbo": 128000, 
    "claude-3-opus": 200000,
    "claude-3-sonnet": 180000,
    "claude-3-haiku": 150000,
    "mistral-small": 32000,
    "mistral-medium": 32000,
    "mistral-large": 32000,
    "qwen": 32000,
    "llama-3": 16000,
    "default": 8000  # Conservative default
}

def generate_llm_prompt_template(vuln_type, details_json):
    """
    Generate an LLM-friendly prompt template for a specific vulnerability type.
    This template can be used to guide LLMs in detecting this vulnerability.
    
    Args:
        vuln_type (str): The vulnerability type name
        details_json (str or dict): The vulnerability details
        
    Returns:
        str: A formatted prompt template for LLM detection
    """
    # Parse details if it's a string
    details = {}
    if isinstance(details_json, str):
        try:
            details = json.loads(details_json)
        except Exception:
            # If we can't parse the JSON, create a minimal set of details
            details = {"vulnerability_description": f"A vulnerability of type {vuln_type}"}
    else:
        details = details_json if details_json else {}
    
    # Safety check - treat None or empty as empty dict
    if not details:
        details = {}
    
    # Construct a comprehensive prompt template
    prompt = f"""# Smart Contract Vulnerability Detection: {vuln_type}

## Vulnerability Description
"""
    
    # Add description with fallbacks
    description = details.get('vulnerability_description', '')
    if not description and details.get('researcher_insights'):
        description = details.get('researcher_insights', '')
    if not description and details.get('questions') and len(details.get('questions', [])) > 0:
        description = f"This vulnerability involves issues related to {details.get('questions', ['security issues'])[0]}"
    if not description:
        description = f"A vulnerability of type {vuln_type} that affects smart contract security."
    
    prompt += f"{description}\n\n## Key Indicators\nLook for these patterns and indicators in the code:\n"
    
    # Add attack vectors with safety checks
    attack_vectors = details.get('attack_vectors', [])
    if attack_vectors and isinstance(attack_vectors, list) and len(attack_vectors) > 0:
        prompt += "\n### Attack Vectors\n"
        for vector in attack_vectors:
            if vector and isinstance(vector, str):
                prompt += f"- {vector}\n"
    
    # Add security questions with safety checks
    questions = details.get('questions', [])
    if questions and isinstance(questions, list) and len(questions) > 0:
        prompt += "\n### Critical Questions to Answer\n"
        for question in questions:
            if question and isinstance(question, str):
                prompt += f"- {question}\n"
    
    # Add code patterns section header
    prompt += "\n## Code Patterns\n"
    
    # Add vulnerable patterns with backup options and safety checks
    vulnerable_examples = []
    if details.get('vulnerable_examples') and isinstance(details.get('vulnerable_examples'), list):
        vulnerable_examples = details.get('vulnerable_examples')
    elif details.get('vulnerable_code') and isinstance(details.get('vulnerable_code'), str):
        vulnerable_examples = [details.get('vulnerable_code')]
    
    if vulnerable_examples and len(vulnerable_examples) > 0:
        prompt += "\n### Vulnerable Pattern Examples\n"
        for example in vulnerable_examples[:2]:  # Limit to 2 examples max
            if example and isinstance(example, str):
                prompt += f"```solidity\n{example.strip()}\n```\n"
    
    # Add fixed patterns with backup options and safety checks
    fixed_examples = []
    if details.get('fixed_examples') and isinstance(details.get('fixed_examples'), list):
        fixed_examples = details.get('fixed_examples')
    elif details.get('fixed_code') and isinstance(details.get('fixed_code'), str):
        fixed_examples = [details.get('fixed_code')]
    
    if fixed_examples and len(fixed_examples) > 0:
        prompt += "\n### Fixed Pattern Examples\n"
        for example in fixed_examples[:2]:  # Limit to 2 examples max
            if example and isinstance(example, str):
                prompt += f"```solidity\n{example.strip()}\n```\n"
    
    # Add detection strategy with safety checks
    prompt += "\n## Detection Strategy\n"
    detection_signatures = details.get('detection_signatures', [])
    if detection_signatures and isinstance(detection_signatures, list) and len(detection_signatures) > 0:
        for signature in detection_signatures:
            if signature and isinstance(signature, str):
                prompt += f"- {signature}\n"
    else:
        # Generic detection strategies if none are provided
        prompt += "- Examine function calls and state changes\n"
        prompt += "- Check for proper validation of inputs\n"
        prompt += "- Verify proper access controls\n"
    
    # Add JSON schema for structured output
    prompt += """
## JSON Output Schema
```json
{
  "vulnerability_detected": true|false,
  "confidence": 0.0-1.0,
  "locations": [
    {
      "file": "filename.sol",
      "line_number": 123,
      "code_snippet": "vulnerable code here",
      "explanation": "Why this is vulnerable"
    }
  ],
  "severity": "Critical|High|Medium|Low|Informational",
  "recommendation": "How to fix this vulnerability"
}
```
"""
    return prompt


def create_vector_embedding(vuln_type, details_json):
    """
    Create a vector embedding for a vulnerability type using its details.
    This embedding can be used for semantic search of vulnerabilities.
    
    Args:
        vuln_type (str): The vulnerability type name
        details_json (str or dict): The vulnerability details
        
    Returns:
        list: Vector embedding of the vulnerability
    """
    try:
        # Parse details if it's a string
        details = {}
        if isinstance(details_json, str):
            try:
                details = json.loads(details_json)
            except Exception:
                # If JSON parsing fails, use just the vuln_type
                return compute_embedding(vuln_type)
        else:
            # Handle None or non-dict types
            if not details_json or not isinstance(details_json, dict):
                return compute_embedding(vuln_type)
            details = details_json
        
        # Combine all relevant information for embedding with safety checks
        embedding_parts = [vuln_type]
        
        # Add vulnerability description with fallbacks
        description = details.get('vulnerability_description', '')
        if description:
            embedding_parts.append(description)
        elif details.get('researcher_insights'):
            embedding_parts.append(details.get('researcher_insights', ''))
        
        # Add attack vectors with safety checks
        attack_vectors = details.get('attack_vectors', [])
        if attack_vectors and isinstance(attack_vectors, list):
            for vector in attack_vectors:
                if vector and isinstance(vector, str):
                    embedding_parts.append(vector)
        
        # Add questions with safety checks
        questions = details.get('questions', [])
        if questions and isinstance(questions, list):
            for question in questions:
                if question and isinstance(question, str):
                    embedding_parts.append(question)
        
        # Add detection signatures with safety checks
        signatures = details.get('detection_signatures', [])
        if signatures and isinstance(signatures, list):
            for signature in signatures:
                if signature and isinstance(signature, str):
                    embedding_parts.append(signature)
                    
        # If we're left with just the vuln_type, consider adding any string values
        if len(embedding_parts) <= 1:
            for key, value in details.items():
                if isinstance(value, str) and value and key != 'vuln_type':
                    embedding_parts.append(value)
        
        # Join all parts with newlines
        embedding_text = "\n".join(embedding_parts)
        
        # Create the embedding
        return compute_embedding(embedding_text)
    except Exception as e:
        # Final fallback - just use the vulnerability type name
        return compute_embedding(vuln_type)


def enhance_detection_library(verbose=True):
    """
    Enhance the existing detection library with LLM-friendly features:
    1. Add vector embeddings for semantic search
    2. Create prompt templates optimized for LLMs
    3. Update the schema version
    
    This preserves all existing data while adding new capabilities.
    
    Args:
        verbose (bool): Whether to print detailed diagnostic information for each vulnerability
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # First check if the columns exist, if not add them
        cursor.execute("PRAGMA table_info(detection_library)")
        columns = cursor.fetchall()
        column_names = [col[1] for col in columns]
        
        # Add new columns if they don't exist
        if "vector_embedding" not in column_names:
            cursor.execute("ALTER TABLE detection_library ADD COLUMN vector_embedding BLOB")
            console.print("[yellow]Added vector_embedding column[/yellow]")
            
        if "llm_template" not in column_names:
            cursor.execute("ALTER TABLE detection_library ADD COLUMN llm_template TEXT")
            console.print("[yellow]Added llm_template column[/yellow]")
            
        if "schema_version" not in column_names:
            cursor.execute("ALTER TABLE detection_library ADD COLUMN schema_version INTEGER DEFAULT 1")
            console.print("[yellow]Added schema_version column[/yellow]")
            
        if "last_updated" not in column_names:
            cursor.execute("ALTER TABLE detection_library ADD COLUMN last_updated TEXT")
            console.print("[yellow]Added last_updated column[/yellow]")
        
        # Fetch all vulnerabilities
        cursor.execute("SELECT vuln_type, details FROM detection_library")
        vulnerabilities = cursor.fetchall()
        
        console.print(f"[cyan]Found {len(vulnerabilities)} vulnerabilities in the detection library[/cyan]")
        enhanced_count = 0
        skipped_count = 0
        error_count = 0
        
        # Process each vulnerability
        for vuln_type, details in vulnerabilities:
            try:
                if not details or details == "{}" or details == "null":
                    if verbose:
                        console.print(f"[yellow]Skipping '{vuln_type}' - No details available[/yellow]")
                    skipped_count += 1
                    continue
                
                # Create vector embedding with error handling
                try:
                    vector_embedding = create_vector_embedding(vuln_type, details)
                except Exception as embed_err:
                    if verbose:
                        console.print(f"[yellow]Warning: Could not create embedding for '{vuln_type}': {embed_err}[/yellow]")
                    vector_embedding = compute_embedding(vuln_type)  # Fallback to simple embedding
                
                # Generate LLM prompt template with error handling
                try:
                    llm_template = generate_llm_prompt_template(vuln_type, details)
                except Exception as prompt_err:
                    if verbose:
                        console.print(f"[yellow]Warning: Could not create prompt template for '{vuln_type}': {prompt_err}[/yellow]")
                    # Create a minimal but valid template as fallback
                    llm_template = f"# Smart Contract Vulnerability: {vuln_type}\n\nPlease analyze the code for this vulnerability type.\n"
                
                # Update the detection library
                cursor.execute("""
                    UPDATE detection_library
                    SET vector_embedding = ?,
                        llm_template = ?,
                        schema_version = 2,
                        last_updated = ?
                    WHERE vuln_type = ?
                """, (
                    json.dumps(vector_embedding),
                    llm_template,
                    datetime.now().isoformat(),
                    vuln_type
                ))
                enhanced_count += 1
                if verbose and enhanced_count % 20 == 0:
                    console.print(f"[green]Processed {enhanced_count} vulnerabilities so far...[/green]")
                    
            except Exception as vuln_err:
                error_count += 1
                if verbose:
                    console.print(f"[red]Error processing '{vuln_type}': {vuln_err}[/red]")
        
        conn.commit()
        conn.close()
        
        # Final summary
        console.print(f"[bold green]✅ Successfully enhanced {enhanced_count} vulnerabilities with LLM-friendly features![/bold green]")
        if skipped_count > 0:
            console.print(f"[yellow]Skipped {skipped_count} vulnerabilities due to missing or invalid details[/yellow]")
        if error_count > 0:
            console.print(f"[red]Encountered errors with {error_count} vulnerabilities[/red]")
            
        return True
    except Exception as e:
        console.print(f"[red]Error enhancing detection library: {e}[/red]")
        import traceback
        console.print(f"[red]{traceback.format_exc()}[/red]")
        return False


def search_vulnerabilities_semantic(query, top_n=5):
    """
    Search for vulnerabilities semantically using vector embeddings.
    Returns the top N matches based on cosine similarity.
    """
    try:
        # Create query embedding
        query_embedding = compute_embedding(query)
        
        # Get all vulnerabilities with embeddings
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT vuln_type, details, vector_embedding FROM detection_library")
        vulnerabilities = cursor.fetchall()
        conn.close()
        
        results = []
        
        for vuln_type, details, vector_embedding in vulnerabilities:
            if not vector_embedding:
                continue
            
            # Parse the embedding
            try:
                embedding = json.loads(vector_embedding)
            except Exception:
                continue
            
            # Calculate cosine similarity
            similarity = cosine_similarity(query_embedding, embedding)
            results.append((vuln_type, details, similarity))
        
        # Sort by similarity (highest first)
        results.sort(key=lambda x: x[2], reverse=True)
        
        # Return top N results
        return results[:top_n]
    except Exception as e:
        console.print(f"[red]Error searching vulnerabilities: {e}[/red]")
        return []


def cosine_similarity(vec1, vec2):
    """Calculate cosine similarity between two vectors."""
    try:
        # Convert to numpy arrays if they aren't already
        a = np.array(vec1)
        b = np.array(vec2)
        
        # Calculate cosine similarity
        dot_product = np.dot(a, b)
        norm_a = np.linalg.norm(a)
        norm_b = np.linalg.norm(b)
        
        # Avoid division by zero
        if norm_a == 0 or norm_b == 0:
            return 0
        
        return dot_product / (norm_a * norm_b)
    except Exception:
        return 0


def display_semantic_search_results(results):
    """Display semantic search results in a nicely formatted table."""
    if not results:
        console.print("[yellow]No matching vulnerabilities found.[/yellow]")
        return
    
    table = Table(title="Semantic Vulnerability Search Results")
    table.add_column("Vulnerability Type", style="cyan")
    table.add_column("Similarity", style="green")
    table.add_column("Description", style="magenta")
    
    for vuln_type, details, similarity in results:
        # Parse details
        try:
            details_dict = json.loads(details)
            description = details_dict.get('vulnerability_description', '')
            if not description and details_dict.get('questions'):
                description = details_dict['questions'][0]  # Use first question if no description
            if len(description) > 100:
                description = description[:97] + "..."
        except Exception:
            description = "No description available"
        
        # Format similarity as percentage
        similarity_str = f"{similarity * 100:.1f}%"
        
        table.add_row(vuln_type, similarity_str, description)
    
    console.print(table)


def generate_llm_detection_prompt(vuln_type, context_size=None):
    """
    Generate a comprehensive, context-size-aware detection prompt for a specific vulnerability.
    This is optimized for LLM use in vulnerability detection tasks.
    Supports fuzzy matching for vulnerability type names.
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # First try exact match
        cursor.execute("SELECT details, llm_template, vuln_type FROM detection_library WHERE vuln_type = ?", (vuln_type,))
        row = cursor.fetchone()
        
        # If exact match fails, try fuzzy matching
        if not row:
            # Get all vulnerability types for fuzzy matching
            cursor.execute("SELECT vuln_type FROM detection_library")
            all_vuln_types = [v[0] for v in cursor.fetchall()]
            
            # Fuzzy match options:
            # 1. Case-insensitive match
            case_insensitive_matches = [vt for vt in all_vuln_types 
                                      if vuln_type.lower() in vt.lower() or vt.lower() in vuln_type.lower()]
            
            # 2. Word similarity (any word matches)
            query_words = set(vuln_type.lower().split())
            word_matches = []
            for vt in all_vuln_types:
                vt_words = set(vt.lower().split())
                # If any words match, consider it a potential match
                if query_words.intersection(vt_words):
                    word_matches.append((vt, len(query_words.intersection(vt_words)) / max(len(query_words), len(vt_words))))
            
            # Sort word matches by similarity score (descending)
            word_matches.sort(key=lambda x: x[1], reverse=True)
            word_match_types = [match[0] for match in word_matches[:3]]  # Top 3 matches
            
            # Combine different fuzzy match strategies
            fuzzy_matches = set(case_insensitive_matches + word_match_types)
            
            if fuzzy_matches:
                # If we have fuzzy matches, get the first match's details
                best_match = list(fuzzy_matches)[0]  # Choose the first match
                cursor.execute("SELECT details, llm_template, vuln_type FROM detection_library WHERE vuln_type = ?", (best_match,))
                row = cursor.fetchone()
                
                # If more than one fuzzy match, display suggestions
                if len(fuzzy_matches) > 1:
                    console.print(f"[yellow]'{vuln_type}' not found. Using closest match: '{best_match}'[/yellow]")
                    console.print(f"[yellow]Other potential matches: {', '.join([m for m in list(fuzzy_matches)[1:]])}[/yellow]")
                else:
                    console.print(f"[yellow]'{vuln_type}' not found. Using closest match: '{best_match}'[/yellow]")
        
        conn.close()
        
        if not row:
            return f"No vulnerability found with type: {vuln_type}"
        
        details, llm_template, matched_vuln_type = row
        
        # If we already have an LLM template, use it
        if llm_template:
            # Truncate if needed for context size
            if context_size and len(llm_template) > context_size * 0.7:  # Use 70% of context for template
                # Simple truncation - in a real system you'd be smarter about what to keep
                return llm_template[:int(context_size * 0.7)] + "\n...(truncated for context size)..."
            return llm_template
        
        # Otherwise, generate one now
        return generate_llm_prompt_template(matched_vuln_type, details)
    except Exception as e:
        return f"Error generating detection prompt: {e}"


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        console.print("[bold cyan]LLM Enhancer for Vulnerability Detection Library[/bold cyan]")
        console.print("Commands:")
        console.print("  enhance - Enhance the entire detection library with LLM features")
        console.print("  search <query> - Search vulnerabilities semantically")
        console.print("  prompt <vuln_type> [model] - Generate a detection prompt for a vulnerability type")
        sys.exit(0)
    
    command = sys.argv[1]
    
    if command == "enhance":
        enhance_detection_library()
    elif command == "search" and len(sys.argv) > 2:
        query = sys.argv[2]
        results = search_vulnerabilities_semantic(query)
        display_semantic_search_results(results)
    elif command == "prompt" and len(sys.argv) > 2:
        vuln_type = sys.argv[2]
        model = sys.argv[3] if len(sys.argv) > 3 else "default"
        context_size = MODEL_CONTEXT_SIZES.get(model, MODEL_CONTEXT_SIZES["default"])
        prompt = generate_llm_detection_prompt(vuln_type, context_size)
        console.print(Markdown(prompt))
    else:
        console.print("[red]Invalid command or missing arguments[/red]")
