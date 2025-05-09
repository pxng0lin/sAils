#!/usr/bin/env python
"""
Database Merger for sAils

This module provides functionality to merge sAils databases from another directory
into the current database, handling deduplication and conflict resolution.

It supports merging both vectorisation.db (reports and vulnerability library)
and smart_contracts_analysis.db (contract analysis data).
"""

import os
import sys
import json
import sqlite3
import hashlib
import shutil
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Any, Optional

try:
    from rich.console import Console
    from rich.progress import Progress, TaskID
    from rich.panel import Panel
    from rich.table import Table
    has_rich = True
    console = Console()
except ImportError:
    has_rich = False
    print("Install 'rich' for prettier output")
    
    class FakeConsole:
        def print(self, text, **kwargs):
            print(text)
    console = FakeConsole()

# Import from VectorEyes to maintain access to constants and key functions
try:
    from VectorEyes import compute_embedding, DB_PATH as VECTOR_DB_PATH
    from DeepCurrent import DB_PATH as DEEP_DB_PATH
except ImportError:
    # Fallbacks if importing fails
    SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
    VECTOR_DB_PATH = os.path.join(SCRIPT_DIR, "vectorisation.db")
    DEEP_DB_PATH = os.path.join(SCRIPT_DIR, "smart_contracts_analysis.db")

# LLM imports for similarity detection
DEFAULT_LLM_PROVIDER = "ollama"
DEFAULT_OLLAMA_MODEL = "deepseek-r1:32b"

def calculate_similarity(text1, text2):
    """
    Calculate simple text similarity between two strings.
    This is a basic fallback when LLM is not available.
    """
    if not text1 or not text2:
        return 0.0
        
    # Create sets of words
    words1 = set(text1.lower().split())
    words2 = set(text2.lower().split())
    
    # Calculate Jaccard similarity
    intersection = len(words1.intersection(words2))
    union = len(words1.union(words2))
    
    return intersection / union if union > 0 else 0.0

def get_text_hash(text):
    """Generate a hash for text content to help with deduplication."""
    if not text:
        return None
    return hashlib.md5(text.encode('utf-8')).hexdigest()

def compute_text_similarity_with_llm(text1, text2, threshold=0.8):
    """
    Use LLM to determine if two texts are similar enough to be considered duplicates.
    Returns a similarity score between 0 and 1.
    
    Falls back to simpler methods if LLM is not available or if it fails.
    """
    # First, try the simple similarity as a quick check
    simple_score = calculate_similarity(text1, text2)
    
    # If simple score is very high or very low, no need to use LLM
    if simple_score > 0.8 or simple_score < 0.2:
        return simple_score
    
    # For borderline cases, try to use LLM if available and enabled
    if global_use_llm:
        try:
            from DeepCurrent import call_llm
            import time
            
            # Prepare a shorter prompt to avoid token limits
            text1_short = text1[:300] if text1 else ""
            text2_short = text2[:300] if text2 else ""
            
            prompt = f"""Rate similarity: 0.0 (different) to 1.0 (identical).
Text1: {text1_short}
Text2: {text2_short}
Just give a number:"""
            
            try:
                # Add timeout for LLM call
                response = call_llm(prompt)
                
                # Extract the similarity score
                import re
                match = re.search(r'(\d+\.\d+)', response)
                if match:
                    return float(match.group(1))
                
                # If no decimal found, look for an integer
                match = re.search(r'(\d+)', response)
                if match:
                    return float(match.group(1))
            except Exception as e:
                console.print(f"[yellow]LLM similarity check failed, using fallback: {str(e)[:100]}...[/yellow]")
        except (ImportError, Exception) as e:
            console.print(f"[yellow]Using fallback similarity method: {str(e)[:100]}...[/yellow]")
    
    # Fall back to more advanced text similarity without LLM
    return advanced_similarity(text1, text2)

def advanced_similarity(text1, text2):
    """More advanced text similarity calculation without using LLM"""
    if not text1 or not text2:
        return 0.0
    
    # Remove common punctuation and convert to lowercase
    import re
    text1 = re.sub(r'[^\w\s]', ' ', text1.lower())
    text2 = re.sub(r'[^\w\s]', ' ', text2.lower())
    
    # Split into words and remove common stop words
    stopwords = {'a', 'an', 'the', 'and', 'or', 'but', 'is', 'are', 'in', 'on', 'at', 'to', 'for', 'with'}
    words1 = [w for w in text1.split() if w not in stopwords]
    words2 = [w for w in text2.split() if w not in stopwords]
    
    # Create sets for Jaccard similarity
    set1 = set(words1)
    set2 = set(words2)
    
    # Calculate Jaccard similarity
    intersection = len(set1.intersection(set2))
    union = len(set1.union(set2))
    jaccard = intersection / union if union > 0 else 0.0
    
    # Check for common consecutive words (phrases)
    phrase_similarity = 0.0
    if len(words1) > 1 and len(words2) > 1:
        phrases1 = [' '.join(words1[i:i+2]) for i in range(len(words1)-1)]
        phrases2 = [' '.join(words2[i:i+2]) for i in range(len(words2)-1)]
        common_phrases = set(phrases1).intersection(set(phrases2))
        phrase_similarity = len(common_phrases) / max(len(phrases1), len(phrases2)) if max(len(phrases1), len(phrases2)) > 0 else 0.0
    
    # Combine the scores, giving more weight to phrases
    return 0.7 * jaccard + 0.3 * phrase_similarity

# Global flag for LLM usage
global_use_llm = True

class DatabaseMerger:
    """Handles merging of sAils databases with deduplication."""
    
    def __init__(self, source_dir, target_vector_db="vectorisation.db", target_deep_db="smart_contracts_analysis.db", use_llm=True):
        """
        Initialize the merger with source and target database paths.
        
        Args:
            source_dir: Directory containing the source databases
            target_vector_db: Path to target vectorisation.db
            target_deep_db: Path to target smart_contracts_analysis.db
            use_llm: Whether to use LLM for similarity detection
        """
        self.source_dir = Path(source_dir)
        self.target_vector_db = Path(target_vector_db)
        self.target_deep_db = Path(target_deep_db)
        self.use_llm = use_llm
        
        # Source database paths
        self.source_vector_db = self.source_dir / "vectorisation.db"
        self.source_deep_db = self.source_dir / "smart_contracts_analysis.db"
        
        self.stats = {
            "reports": {"found": 0, "added": 0, "duplicates": 0, "errors": 0},
            "detection_library": {"found": 0, "added": 0, "duplicates": 0, "updated": 0, "errors": 0},
            "patterns": {"found": 0, "added": 0, "duplicates": 0, "errors": 0},
            "contracts": {"found": 0, "added": 0, "duplicates": 0, "errors": 0},
            "documents": {"found": 0, "added": 0, "duplicates": 0, "errors": 0},
            "analyses": {"found": 0, "added": 0, "duplicates": 0, "errors": 0},
        }
        
        # Validation
        self._validate_source_databases()
    
    def _validate_source_databases(self):
        """Validate that source databases exist and are readable."""
        errors = []
        
        if not self.source_dir.exists():
            errors.append(f"Source directory {self.source_dir} does not exist")
        
        if not self.source_vector_db.exists():
            errors.append(f"Source vectorisation.db not found at {self.source_vector_db}")
        
        if not self.source_deep_db.exists():
            errors.append(f"Source smart_contracts_analysis.db not found at {self.source_deep_db}")
        
        if errors:
            raise ValueError("Database validation errors:\n" + "\n".join(errors))
    
    def merge_databases(self):
        """
        Merge both databases, handling all tables appropriately.
        Returns summary statistics of the merge operation.
        """
        console.print("[bold cyan]Starting database merge operation...[/bold cyan]")
        
        # Create backups first
        self._create_backups()
        
        # Merge vector database (reports and vulnerability library)
        self._merge_vector_database()
        
        # Merge deep database (contract analyses)
        self._merge_deep_database()
        
        # Display summary
        self._display_merge_summary()
        
        return self.stats
    
    def _create_backups(self):
        """Create backups of the target databases before merging."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        console.print("[yellow]Creating database backups before merge...[/yellow]")
        
        # Backup vector database
        if self.target_vector_db.exists():
            backup_path = self.target_vector_db.with_name(f"vectorisation_backup_{timestamp}.db")
            shutil.copy2(self.target_vector_db, backup_path)
            console.print(f"[green]Created backup: {backup_path}[/green]")
        
        # Backup deep database
        if self.target_deep_db.exists():
            backup_path = self.target_deep_db.with_name(f"smart_contracts_analysis_backup_{timestamp}.db")
            shutil.copy2(self.target_deep_db, backup_path)
            console.print(f"[green]Created backup: {backup_path}[/green]")
    
    def _merge_vector_database(self):
        """Merge the vectorisation.db database."""
        console.print("[bold cyan]Merging vulnerability reports and detection library...[/bold cyan]")
        
        # Open database connections
        source_conn = sqlite3.connect(self.source_vector_db)
        target_conn = sqlite3.connect(self.target_vector_db)
        
        try:
            # 1. Merge reports table
            self._merge_reports_table(source_conn, target_conn)
            
            # 2. Merge detection_library table
            self._merge_detection_library_table(source_conn, target_conn)
            
            # 3. Merge patterns table
            self._merge_patterns_table(source_conn, target_conn)
        finally:
            source_conn.close()
            target_conn.close()
    
    def _merge_deep_database(self):
        """Merge the smart_contracts_analysis.db database."""
        console.print("[bold cyan]Merging contract and document analyses...[/bold cyan]")
        
        # Open database connections
        source_conn = sqlite3.connect(self.source_deep_db)
        target_conn = sqlite3.connect(self.target_deep_db)
        
        try:
            # 1. Merge contracts table
            self._merge_contracts_table(source_conn, target_conn)
            
            # 2. Merge documents table
            self._merge_documents_table(source_conn, target_conn)
            
            # 3. Merge analyses table
            self._merge_analyses_table(source_conn, target_conn)
        finally:
            source_conn.close()
            target_conn.close()
    
    def _merge_reports_table(self, source_conn, target_conn):
        """Merge reports from source to target, handling duplicates."""
        console.print("[cyan]Merging vulnerability reports...[/cyan]")
        
        source_cursor = source_conn.cursor()
        target_cursor = target_conn.cursor()
        
        # Get existing report IDs in target
        target_cursor.execute("SELECT id FROM reports")
        existing_ids = {row[0] for row in target_cursor.fetchall()}
        
        # Get all reports from source with schema checking
        required_columns = ["id", "source"]
        optional_columns = ["content", "overall_embedding", "section_embeddings", "analysis_summary", "metadata"]
        source_reports, _ = self._get_table_data_with_schema_check(source_conn, "reports", required_columns, optional_columns)
        self.stats["reports"]["found"] = len(source_reports)
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Processing reports...", total=len(source_reports))
            
            for report in source_reports:
                report_id = report[0]
                
                try:
                    # Check if report ID already exists
                    if report_id in existing_ids:
                        self.stats["reports"]["duplicates"] += 1
                        progress.update(task, advance=1)
                        continue
                    
                    # Insert the report into target
                    target_cursor.execute(
                        "INSERT INTO reports (id, source, content, overall_embedding, section_embeddings, analysis_summary, metadata) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        report
                    )
                    target_conn.commit()
                    self.stats["reports"]["added"] += 1
                except Exception as e:
                    console.print(f"[red]Error merging report {report_id}: {e}[/red]")
                    self.stats["reports"]["errors"] += 1
                
                progress.update(task, advance=1)
    
    def _merge_detection_library_table(self, source_conn, target_conn):
        """Merge vulnerability detection library, using LLM to help with deduplication."""
        console.print("[cyan]Merging vulnerability detection library...[/cyan]")
        
        source_cursor = source_conn.cursor()
        target_cursor = target_conn.cursor()
        
        # Get existing vulnerability types in target
        target_cursor.execute("SELECT vuln_type, details FROM detection_library")
        existing_types = {row[0]: row[1] for row in target_cursor.fetchall()}
        
        # Get vulnerability data with schema checking
        required_columns = ["vuln_type", "details"]
        optional_columns = ["template", "vector_embedding", "llm_template", "schema_version", "last_updated"]
        source_vulns, _ = self._get_table_data_with_schema_check(source_conn, "detection_library", required_columns, optional_columns)
        self.stats["detection_library"]["found"] = len(source_vulns)
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Processing vulnerability types...", total=len(source_vulns))
            
            for vuln in source_vulns:
                vuln_type = vuln[0]
                details = vuln[1]
                
                try:
                    # Case 1: Exact vulnerability type match
                    if vuln_type in existing_types:
                        # Check if the source has more comprehensive details
                        source_details = json.loads(details) if details else {}
                        target_details = json.loads(existing_types[vuln_type]) if existing_types[vuln_type] else {}
                        
                        # Merge details if source has more information
                        merged_details = self._merge_vulnerability_details(target_details, source_details)
                        if merged_details != target_details:
                            # Update with merged details
                            target_cursor.execute(
                                "UPDATE detection_library SET details = ?, template = ?, last_updated = ? WHERE vuln_type = ?",
                                (json.dumps(merged_details), vuln[2], datetime.now().isoformat(), vuln_type)
                            )
                            target_conn.commit()
                            self.stats["detection_library"]["updated"] += 1
                        else:
                            self.stats["detection_library"]["duplicates"] += 1
                    else:
                        # Case 2: Check for similar vulnerability types using LLM
                        similar_type = self._find_similar_vulnerability_type(vuln_type, details, existing_types)
                        
                        if similar_type:
                            # Merge with similar vulnerability
                            source_details = json.loads(details) if details else {}
                            target_details = json.loads(existing_types[similar_type]) if existing_types[similar_type] else {}
                            
                            merged_details = self._merge_vulnerability_details(target_details, source_details)
                            target_cursor.execute(
                                "UPDATE detection_library SET details = ?, last_updated = ? WHERE vuln_type = ?",
                                (json.dumps(merged_details), datetime.now().isoformat(), similar_type)
                            )
                            target_conn.commit()
                            self.stats["detection_library"]["updated"] += 1
                        else:
                            # Case 3: New vulnerability type
                            target_cursor.execute(
                                "INSERT INTO detection_library (vuln_type, details, template, vector_embedding, llm_template, schema_version, last_updated) VALUES (?, ?, ?, ?, ?, ?, ?)",
                                vuln
                            )
                            target_conn.commit()
                            self.stats["detection_library"]["added"] += 1
                except Exception as e:
                    console.print(f"[red]Error merging vulnerability type {vuln_type}: {e}[/red]")
                    self.stats["detection_library"]["errors"] += 1
                
                progress.update(task, advance=1)
    
    def _find_similar_vulnerability_type(self, vuln_type, details_json, existing_types):
        """
        Use LLM to find similar vulnerability types to avoid duplication.
        Returns the similar type if found, None otherwise.
        """
        if not self.use_llm or not vuln_type or not details_json:
            return None
            
        try:
            details = json.loads(details_json)
            
            # Get a description or question to use for comparison
            vuln_desc = ""
            if "vulnerability_description" in details:
                vuln_desc = details["vulnerability_description"]
            elif "questions" in details and details["questions"]:
                vuln_desc = details["questions"][0]
            elif "attack_vectors" in details and details["attack_vectors"]:
                vuln_desc = details["attack_vectors"][0]
            else:
                vuln_desc = vuln_type
                
            # Check similarity with each existing type
            best_match = None
            best_score = 0.0
            
            for existing_type, existing_details_json in existing_types.items():
                # Skip if types are very different
                if len(set(vuln_type.lower().split()) & set(existing_type.lower().split())) == 0:
                    continue
                    
                try:
                    existing_details = json.loads(existing_details_json)
                    
                    # Get description for comparison
                    existing_desc = ""
                    if "vulnerability_description" in existing_details:
                        existing_desc = existing_details["vulnerability_description"]
                    elif "questions" in existing_details and existing_details["questions"]:
                        existing_desc = existing_details["questions"][0]
                    elif "attack_vectors" in existing_details and existing_details["attack_vectors"]:
                        existing_desc = existing_details["attack_vectors"][0]
                    else:
                        existing_desc = existing_type
                    
                    # Compare using LLM or fallback
                    similarity = compute_text_similarity_with_llm(vuln_desc, existing_desc)
                    
                    if similarity > best_score and similarity >= 0.7:  # Threshold for similarity
                        best_score = similarity
                        best_match = existing_type
                except Exception:
                    continue
            
            return best_match
        except Exception:
            return None
    
    def _merge_vulnerability_details(self, target_details, source_details):
        """
        Merge vulnerability details from source into target, keeping unique items.
        Returns the merged details dictionary.
        """
        # Start with a copy of the target
        merged = target_details.copy()
        
        # Merge various list fields
        for field in ["questions", "attack_vectors", "detection_signatures", "severity_ratings", "researcher_insights"]:
            if field in source_details and source_details[field]:
                if field not in merged:
                    merged[field] = []
                
                # Add unique items from source
                if isinstance(source_details[field], list):
                    for item in source_details[field]:
                        item_str = json.dumps(item) if not isinstance(item, str) else item
                        # Check if this item already exists in the merged list
                        exists = False
                        for existing_item in merged[field]:
                            existing_str = json.dumps(existing_item) if not isinstance(existing_item, str) else existing_item
                            if item_str == existing_str:
                                exists = True
                                break
                        
                        if not exists:
                            merged[field].append(item)
        
        # Merge code examples
        for field in ["vulnerable_examples", "fixed_examples", "vulnerable_code", "fixed_code"]:
            if field in source_details and source_details[field]:
                # Convert to the standard field names for examples
                target_field = field
                if field == "vulnerable_code":
                    target_field = "vulnerable_examples"
                elif field == "fixed_code":
                    target_field = "fixed_examples"
                
                if target_field not in merged:
                    merged[target_field] = []
                
                # Add unique code examples
                if isinstance(source_details[field], list):
                    for code in source_details[field]:
                        code_hash = get_text_hash(code)
                        # Check if this code already exists in the merged list
                        exists = False
                        for existing_code in merged[target_field]:
                            if get_text_hash(existing_code) == code_hash:
                                exists = True
                                break
                        
                        if not exists:
                            merged[target_field].append(code)
                elif isinstance(source_details[field], str) and source_details[field].strip():
                    code_hash = get_text_hash(source_details[field])
                    # Check if this code already exists
                    exists = False
                    for existing_code in merged[target_field]:
                        if get_text_hash(existing_code) == code_hash:
                            exists = True
                            break
                    
                    if not exists:
                        merged[target_field].append(source_details[field])
        
        return merged
    
    def _get_table_data_with_schema_check(self, conn, table_name, required_columns, optional_columns=None):
        """Helper method to get data from a table with schema checking.
        
        Args:
            conn: Database connection
            table_name: Name of the table to query
            required_columns: List of columns that must exist
            optional_columns: List of optional columns to include if they exist
            
        Returns:
            Tuple of (rows, columns) where rows is the data and columns is the list of column names
        """
        cursor = conn.cursor()
        optional_columns = optional_columns or []
        all_expected_columns = required_columns + optional_columns
        
        try:
            # Get the column names from the table
            cursor.execute(f"PRAGMA table_info({table_name})")
            existing_columns = [column[1] for column in cursor.fetchall()]
            
            if not existing_columns:
                console.print(f"[yellow]Warning: {table_name} table not found in database[/yellow]")
                return [], all_expected_columns
            
            # Check for required columns
            missing_required = [col for col in required_columns if col not in existing_columns]
            if missing_required:
                console.print(f"[yellow]Warning: Required columns {missing_required} missing from {table_name}[/yellow]")
                return [], all_expected_columns
            
            # Build query with available columns
            query_columns = required_columns.copy()
            
            # Add optional columns if they exist
            for col in optional_columns:
                if col in existing_columns:
                    query_columns.append(col)
                else:
                    console.print(f"[yellow]Note: Optional column '{col}' not found in {table_name}. Will use defaults.[/yellow]")
            
            # Execute the query
            query = f"SELECT {', '.join(query_columns)} FROM {table_name}"
            cursor.execute(query)
            rows_raw = cursor.fetchall()
            
            # Pad rows with None for missing columns
            padded_rows = []
            for row in rows_raw:
                padded_row = list(row)
                while len(padded_row) < len(all_expected_columns):
                    padded_row.append(None)
                padded_rows.append(padded_row)
            
            return padded_rows, all_expected_columns
            
        except Exception as e:
            console.print(f"[red]Error checking {table_name} schema: {e}[/red]")
            return [], all_expected_columns

    def _merge_patterns_table(self, source_conn, target_conn):
        """Merge detection patterns."""
        console.print("[cyan]Merging detection patterns...[/cyan]")
        
        source_cursor = source_conn.cursor()
        target_cursor = target_conn.cursor()
        
        # Get existing patterns in target
        target_cursor.execute("SELECT report_id, pattern FROM patterns")
        existing_patterns = {(row[0], row[1]) for row in target_cursor.fetchall()}
        
        # Get all patterns from source with schema checking
        required_columns = ["report_id", "pattern"]
        source_patterns, _ = self._get_table_data_with_schema_check(source_conn, "patterns", required_columns)
        self.stats["patterns"]["found"] = len(source_patterns)
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Processing patterns...", total=len(source_patterns))
            
            for pattern in source_patterns:
                report_id, pattern_text = pattern
                
                try:
                    # Check if pattern already exists
                    if (report_id, pattern_text) in existing_patterns:
                        self.stats["patterns"]["duplicates"] += 1
                        progress.update(task, advance=1)
                        continue
                    
                    # Insert the pattern into target
                    target_cursor.execute(
                        "INSERT INTO patterns (report_id, pattern) VALUES (?, ?)",
                        pattern
                    )
                    target_conn.commit()
                    self.stats["patterns"]["added"] += 1
                except Exception as e:
                    console.print(f"[red]Error merging pattern for report {report_id}: {e}[/red]")
                    self.stats["patterns"]["errors"] += 1
                
                progress.update(task, advance=1)
    
    def _check_table_schema(self, conn, table_name):
        """Check if a table exists and return its column names."""
        cursor = conn.cursor()
        cursor.execute(f"PRAGMA table_info({table_name})")
        columns = [col[1] for col in cursor.fetchall()]
        return columns

    def _merge_contracts_table(self, source_conn, target_conn):
        """Merge contracts table with support for different schema versions."""
        console.print("[cyan]Merging contracts...[/cyan]")
        
        # First, check if the contracts table exists in both databases
        source_columns = self._check_table_schema(source_conn, "contracts")
        target_columns = self._check_table_schema(target_conn, "contracts")
        
        if not source_columns:
            console.print("[yellow]No contracts table found in source database. Skipping.[/yellow]")
            self.stats["contracts"]["found"] = 0
            return
            
        if not target_columns:
            console.print("[yellow]No contracts table found in target database. Creating table.[/yellow]")
            # Create contracts table in target if it doesn't exist
            target_conn.execute("""
                CREATE TABLE IF NOT EXISTS contracts (
                    file_path TEXT PRIMARY KEY,
                    content TEXT,
                    name TEXT,
                    analysis_time TEXT,
                    session_id TEXT
                )
            """)
            target_columns = ["file_path", "content", "name", "analysis_time", "session_id"]
        
        source_cursor = source_conn.cursor()
        target_cursor = target_conn.cursor()
        
        # Determine the key column for contracts
        # In V1 it might be 'path' while in V3.1 it's 'file_path'
        key_column_source = "file_path" if "file_path" in source_columns else "path"
        key_column_target = "file_path" if "file_path" in target_columns else "path"
        
        if key_column_source not in source_columns or key_column_target not in target_columns:
            console.print(f"[yellow]Cannot find key column in contracts table. Source has: {source_columns}, Target has: {target_columns}. Skipping.[/yellow]")
            self.stats["contracts"]["found"] = 0
            return
        
        # Get existing contracts in target
        target_cursor.execute(f"SELECT {key_column_target} FROM contracts")
        existing_contracts = {row[0] for row in target_cursor.fetchall()}
        
        # Map columns between different versions
        column_mapping = {
            "path": "file_path",
            "file_path": "file_path",
            "code": "content",
            "content": "content"
        }
        
        # Get available columns for query
        query_columns = []
        for col in source_columns:
            if col in column_mapping:
                query_columns.append(col)
        
        if not query_columns:
            console.print("[yellow]No usable columns found in source contracts table. Skipping.[/yellow]")
            self.stats["contracts"]["found"] = 0
            return
            
        # Build the query
        query = f"SELECT {', '.join(query_columns)} FROM contracts"
        source_cursor.execute(query)
        source_contracts_raw = source_cursor.fetchall()
        
        self.stats["contracts"]["found"] = len(source_contracts_raw)
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Processing contracts...", total=len(source_contracts_raw))
            
            for source_contract in source_contracts_raw:
                # Map the source columns to target columns
                mapped_values = {}
                for i, col in enumerate(query_columns):
                    if col in column_mapping and i < len(source_contract):
                        mapped_values[column_mapping[col]] = source_contract[i]
                
                # Get the contract path (key column)
                contract_path = source_contract[query_columns.index(key_column_source)] if key_column_source in query_columns else None
                
                if not contract_path:
                    self.stats["contracts"]["errors"] += 1
                    progress.update(task, advance=1)
                    continue
                
                try:
                    # Check if contract already exists
                    if contract_path in existing_contracts:
                        self.stats["contracts"]["duplicates"] += 1
                        progress.update(task, advance=1)
                        continue
                    
                    # Prepare insert query with available columns
                    target_cols = [col for col in target_columns if col in mapped_values]
                    if not target_cols:
                        self.stats["contracts"]["errors"] += 1
                        progress.update(task, advance=1)
                        continue
                        
                    placeholders = ', '.join(['?'] * len(target_cols))
                    values = [mapped_values[col] for col in target_cols]
                    
                    # Insert the contract into target
                    insert_query = f"INSERT INTO contracts ({', '.join(target_cols)}) VALUES ({placeholders})"
                    target_cursor.execute(insert_query, values)
                    target_conn.commit()
                    self.stats["contracts"]["added"] += 1
                except Exception as e:
                    console.print(f"[red]Error merging contract {contract_path}: {e}[/red]")
                    self.stats["contracts"]["errors"] += 1
                
                progress.update(task, advance=1)
    
    def _merge_documents_table(self, source_conn, target_conn):
        """Merge documents table with support for different schema versions."""
        console.print("[cyan]Merging documents...[/cyan]")
        
        # First, check if the documents table exists in both databases
        source_columns = self._check_table_schema(source_conn, "documents")
        target_columns = self._check_table_schema(target_conn, "documents")
        
        if not source_columns:
            console.print("[yellow]No documents table found in source database. Skipping.[/yellow]")
            self.stats["documents"]["found"] = 0
            return
            
        if not target_columns:
            console.print("[yellow]No documents table found in target database. Creating table.[/yellow]")
            # Create documents table in target if it doesn't exist
            target_conn.execute("""
                CREATE TABLE IF NOT EXISTS documents (
                    file_path TEXT PRIMARY KEY,
                    content TEXT,
                    title TEXT,
                    analysis_time TEXT,
                    session_id TEXT
                )
            """)
            target_columns = ["file_path", "content", "title", "analysis_time", "session_id"]
        
        source_cursor = source_conn.cursor()
        target_cursor = target_conn.cursor()
        
        # Determine the key column for documents
        # In V1 it might be 'path' while in V3.1 it's 'file_path'
        key_column_source = "file_path" if "file_path" in source_columns else "path"
        key_column_target = "file_path" if "file_path" in target_columns else "path"
        
        if key_column_source not in source_columns or key_column_target not in target_columns:
            console.print(f"[yellow]Cannot find key column in documents table. Source has: {source_columns}, Target has: {target_columns}. Skipping.[/yellow]")
            self.stats["documents"]["found"] = 0
            return
        
        # Get existing documents in target
        target_cursor.execute(f"SELECT {key_column_target} FROM documents")
        existing_documents = {row[0] for row in target_cursor.fetchall()}
        
        # Map columns between different versions
        column_mapping = {
            "path": "file_path",
            "file_path": "file_path",
            "content": "content",
            "title": "title"
        }
        
        # Get available columns for query
        query_columns = []
        for col in source_columns:
            if col in column_mapping:
                query_columns.append(col)
        
        if not query_columns:
            console.print("[yellow]No usable columns found in source documents table. Skipping.[/yellow]")
            self.stats["documents"]["found"] = 0
            return
            
        # Build the query
        query = f"SELECT {', '.join(query_columns)} FROM documents"
        source_cursor.execute(query)
        source_documents_raw = source_cursor.fetchall()
        
        self.stats["documents"]["found"] = len(source_documents_raw)
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Processing documents...", total=len(source_documents_raw))
            
            for source_document in source_documents_raw:
                # Map the source columns to target columns
                mapped_values = {}
                for i, col in enumerate(query_columns):
                    if col in column_mapping and i < len(source_document):
                        mapped_values[column_mapping[col]] = source_document[i]
                
                # Get the document path (key column)
                document_path = source_document[query_columns.index(key_column_source)] if key_column_source in query_columns else None
                
                if not document_path:
                    self.stats["documents"]["errors"] += 1
                    progress.update(task, advance=1)
                    continue
                
                try:
                    # Check if document already exists
                    if document_path in existing_documents:
                        self.stats["documents"]["duplicates"] += 1
                        progress.update(task, advance=1)
                        continue
                    
                    # Prepare insert query with available columns
                    target_cols = [col for col in target_columns if col in mapped_values]
                    if not target_cols:
                        self.stats["documents"]["errors"] += 1
                        progress.update(task, advance=1)
                        continue
                        
                    placeholders = ', '.join(['?'] * len(target_cols))
                    values = [mapped_values[col] for col in target_cols]
                    
                    # Insert the document into target
                    insert_query = f"INSERT INTO documents ({', '.join(target_cols)}) VALUES ({placeholders})"
                    target_cursor.execute(insert_query, values)
                    target_conn.commit()
                    self.stats["documents"]["added"] += 1
                except Exception as e:
                    console.print(f"[red]Error merging document {document_path}: {e}[/red]")
                    self.stats["documents"]["errors"] += 1
                
                progress.update(task, advance=1)
    
    def _merge_analyses_table(self, source_conn, target_conn):
        """Merge analyses table, which may contain contract or document analyses."""
        console.print("[cyan]Merging analyses...[/cyan]")
        
        # First, check if the analyses table exists in both databases
        source_columns = self._check_table_schema(source_conn, "analyses")
        target_columns = self._check_table_schema(target_conn, "analyses")
        
        if not source_columns:
            console.print("[yellow]No analyses table found in source database. Skipping.[/yellow]")
            self.stats["analyses"]["found"] = 0
            return
            
        if not target_columns:
            console.print("[yellow]No analyses table found in target database. Creating table.[/yellow]")
            # Create analyses table in target if it doesn't exist
            target_conn.execute("""
                CREATE TABLE IF NOT EXISTS analyses (
                    file_path TEXT PRIMARY KEY,
                    analysis_data TEXT,
                    analysis_type TEXT,
                    analysis_time TEXT,
                    session_id TEXT
                )
            """)
            target_columns = ["file_path", "analysis_data", "analysis_type", "analysis_time", "session_id"]
        
        source_cursor = source_conn.cursor()
        target_cursor = target_conn.cursor()
        
        # Determine the key column for analyses
        # In V1 it might be 'path' while in V3.1 it's 'file_path'
        key_column_source = "file_path" if "file_path" in source_columns else "path"
        key_column_target = "file_path" if "file_path" in target_columns else "path"
        
        if key_column_source not in source_columns or key_column_target not in target_columns:
            console.print(f"[yellow]Cannot find key column in analyses table. Source has: {source_columns}, Target has: {target_columns}. Skipping.[/yellow]")
            self.stats["analyses"]["found"] = 0
            return
        
        # Get existing analyses in target
        target_cursor.execute(f"SELECT {key_column_target} FROM analyses")
        existing_analyses = {row[0] for row in target_cursor.fetchall()}
        
        # Map columns between different versions
        column_mapping = {
            "path": "file_path",
            "file_path": "file_path",
            "analysis": "analysis_data",
            "analysis_data": "analysis_data",
            "type": "analysis_type",
            "analysis_type": "analysis_type"
        }
        
        # Get available columns for query
        query_columns = []
        for col in source_columns:
            if col in column_mapping:
                query_columns.append(col)
        
        if not query_columns:
            console.print("[yellow]No usable columns found in source analyses table. Skipping.[/yellow]")
            self.stats["analyses"]["found"] = 0
            return
            
        # Build the query
        query = f"SELECT {', '.join(query_columns)} FROM analyses"
        source_cursor.execute(query)
        source_analyses_raw = source_cursor.fetchall()
        
        self.stats["analyses"]["found"] = len(source_analyses_raw)
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Processing analyses...", total=len(source_analyses_raw))
            
            for source_analysis in source_analyses_raw:
                # Map the source columns to target columns
                mapped_values = {}
                for i, col in enumerate(query_columns):
                    if col in column_mapping and i < len(source_analysis):
                        mapped_values[column_mapping[col]] = source_analysis[i]
                
                # Get the analysis path (key column)
                analysis_path = source_analysis[query_columns.index(key_column_source)] if key_column_source in query_columns else None
                
                if not analysis_path:
                    self.stats["analyses"]["errors"] += 1
                    progress.update(task, advance=1)
                    continue
                
                try:
                    # Check if analysis already exists
                    if analysis_path in existing_analyses:
                        self.stats["analyses"]["duplicates"] += 1
                        progress.update(task, advance=1)
                        continue
                    
                    # Prepare insert query with available columns
                    target_cols = [col for col in target_columns if col in mapped_values]
                    if not target_cols:
                        self.stats["analyses"]["errors"] += 1
                        progress.update(task, advance=1)
                        continue
                        
                    placeholders = ', '.join(['?'] * len(target_cols))
                    values = [mapped_values[col] for col in target_cols]
                    
                    # Insert the analysis into target
                    insert_query = f"INSERT INTO analyses ({', '.join(target_cols)}) VALUES ({placeholders})"
                    target_cursor.execute(insert_query, values)
                    target_conn.commit()
                    self.stats["analyses"]["added"] += 1
                except Exception as e:
                    console.print(f"[red]Error merging analysis for {analysis_path}: {e}[/red]")
                    self.stats["analyses"]["errors"] += 1
                
                progress.update(task, advance=1)
    
    def _display_merge_summary(self):
        """Display a summary of the merge operation."""
        if has_rich:
            table = Table(title="Database Merge Summary")
            table.add_column("Category", style="cyan")
            table.add_column("Found", style="blue")
            table.add_column("Added", style="green")
            table.add_column("Updated", style="yellow")
            table.add_column("Duplicates", style="magenta")
            table.add_column("Errors", style="red")
            
            for category, stats in self.stats.items():
                updated = stats.get("updated", 0)
                table.add_row(
                    category.replace("_", " ").title(),
                    str(stats["found"]),
                    str(stats["added"]),
                    str(updated),
                    str(stats["duplicates"]),
                    str(stats["errors"])
                )
            
            console.print("\n")
            console.print(table)
        else:
            print("\nDatabase Merge Summary:")
            for category, stats in self.stats.items():
                updated = stats.get("updated", 0)
                print(f"{category.replace('_', ' ').title()}:")
                print(f"  Found: {stats['found']}")
                print(f"  Added: {stats['added']}")
                print(f"  Updated: {updated}")
                print(f"  Duplicates: {stats['duplicates']}")
                print(f"  Errors: {stats['errors']}")
                print("")

def merge_databases(source_dir, use_llm=True):
    """
    Main entry point for database merging.
    Merges databases from another directory into the current databases.
    
    Args:
        source_dir: Path to the source directory containing the databases
        use_llm: Whether to use LLM for similarity detection during merging
        
    Returns:
        Dictionary of statistics about the merge operation
    """
    # Set the global flag for LLM usage
    global global_use_llm
    global_use_llm = use_llm
    
    # Check if source directory exists
    if not os.path.exists(source_dir):
        console.print(f"[red]Error: Source directory '{source_dir}' does not exist.[/red]")
        return None
    
    # Ask for confirmation
    confirm = input(f"Merge databases from '{source_dir}' into the current databases? "
                   f"This operation will make backups but cannot be undone (Y/N) (N): ")
    
    if confirm.lower() != 'y':
        console.print("[yellow]Database merge operation cancelled.[/yellow]")
        return None
        
    # Perform the merge operation
    console.print(f"[cyan]Merging databases from '{source_dir}'...[/cyan]")
    if not use_llm:
        console.print("[yellow]LLM similarity detection is disabled. Using fallback methods.[/yellow]")
    
    try:
        merger = DatabaseMerger(source_dir)
        stats = merger.merge_databases()
        
        # Display a summary of what happened
        console.print("\n[bold green]Database Merge Complete![/bold green]")
        console.print("[bold cyan]Summary:[/bold cyan]")
        
        for table, count in stats.items():
            console.print(f"[yellow]{table}:[/yellow] Found: {count['found']}, Added: {count['added']}, Duplicates: {count['duplicates']}, Errors: {count['errors']}")
            
            # Special case for detection library
            if table == "detection_library" and "updated" in count and count["updated"] > 0:
                console.print(f"  [green]Updated existing entries: {count['updated']}[/green]")
                
        # Provide helpful tips
        if any(count["errors"] > 0 for count in stats.values()):
            console.print("\n[yellow]Note: Some errors occurred during the merge. This is normal when merging databases with different schemas.[/yellow]")
            console.print("[yellow]Check your data to ensure everything important was successfully merged.[/yellow]")
            
        console.print("\n[green]You can now continue using your sAils installation with the merged data.[/green]")
        console.print("[green]Database backups were created before the merge in case you need to restore.[/green]")
                
        return stats
    except Exception as e:
        console.print(f"[red]Error during database merge: {e}[/red]")
        return None

if __name__ == "__main__":
    import argparse
    import os
    
    parser = argparse.ArgumentParser(description="Merge sAils databases from another directory")
    parser.add_argument("source_dir", help="Directory containing the source databases to merge")
    parser.add_argument("--no-llm", action="store_true", help="Disable LLM for similarity detection")
    
    args = parser.parse_args()
    
    merge_databases(args.source_dir, use_llm=not args.no_llm)
