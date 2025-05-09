#!/usr/bin/env python
"""
This script updates the Precision Loss (CWE-681) vulnerability examples in the detection library
to provide more useful and educational code examples.
"""

import sqlite3
import json
from pathlib import Path

# Path to the vector database
DB_PATH = Path(__file__).parent / "vectorisation.db"

# Better code examples for Precision Loss vulnerability
VULNERABLE_EXAMPLES = [
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
]

FIXED_EXAMPLES = [
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

def update_precision_loss_examples():
    """Update the Precision Loss vulnerability examples in the database."""
    try:
        # Connect to the database
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Get the current details for Precision Loss
        cursor.execute("SELECT details FROM detection_library WHERE vuln_type LIKE '%Precision Loss%'")
        result = cursor.fetchone()
        
        if not result:
            print("Precision Loss vulnerability not found in the database")
            return False
        
        # Parse the details
        details = json.loads(result[0])
        
        # Update the examples
        details["vulnerable_examples"] = VULNERABLE_EXAMPLES
        details["fixed_examples"] = FIXED_EXAMPLES
        
        # Save the updated details back to the database
        cursor.execute(
            "UPDATE detection_library SET details = ? WHERE vuln_type LIKE '%Precision Loss%'",
            (json.dumps(details),)
        )
        
        # Commit the changes
        conn.commit()
        conn.close()
        
        print("Successfully updated Precision Loss examples!")
        return True
    
    except Exception as e:
        print(f"Error updating Precision Loss examples: {e}")
        return False


if __name__ == "__main__":
    update_precision_loss_examples()
