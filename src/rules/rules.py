"""
Rule-Based Prompt Injection Detection Engine
=============================================

Layer 1 of the Hybrid LLM Prompt Injection Detection System.

Input:
    Dynamic user prompt

Output:
    - is_injection
    - risk_score (0-100)
    - risk_level
    - decision
    - attack_types
    - matched_rules
    - rule_details

Decision:
    LOW / MEDIUM  -> ALLOW
    HIGH          -> REVIEW
    CRITICAL      -> BLOCK
"""

import re
from typing import Dict, List


# ============================================================
# RISK THRESHOLDS
# ============================================================

RISK_THRESHOLDS = {
    "LOW": (0, 19),
    "MEDIUM": (20, 49),
    "HIGH": (50, 74),
    "CRITICAL": (75, 100),
}


# ============================================================
# DECISION THRESHOLDS
# ============================================================

DECISION_THRESHOLDS = {
    "REVIEW": 50,
    "BLOCK": 75,
}


# ============================================================
# RULE DEFINITIONS
# ============================================================

RULES = [

    # ========================================================
    # 1. INSTRUCTION OVERRIDE
    # ========================================================

    {
        "name": "instruction_override",
        "category": "INSTRUCTION_OVERRIDE",
        "description": (
            "Attempts to ignore, discard, replace, or override "
            "previous instructions or rules."
        ),
        "weight": 30,
        "patterns": [

            # Ignore previous instructions
            r"\bignore\s+(all\s+|any\s+|the\s+)?"
            r"(previous|prior|above|earlier)\s+"
            r"(instructions?|rules?|prompts?)\b",

            # Disregard previous instructions
            r"\bdisregard\s+(all\s+|any\s+|the\s+)?"
            r"(previous|prior|above|earlier)\s+"
            r"(instructions?|rules?|prompts?)\b",

            # Forget previous instructions
            r"\bforget\s+(all\s+|any\s+|the\s+)?"
            r"(previous|prior|above|earlier)\s+"
            r"(instructions?|rules?|prompts?)\b",

            # Discard previous instructions/rules
            r"\bdiscard\s+(all\s+|any\s+|the\s+)?"
            r"(previous|prior|above|earlier)\s+"
            r"(instructions?|rules?|prompts?)\b",

            # Throw away previous instructions
            r"\bthrow\s+away\s+(all\s+|any\s+|the\s+)?"
            r"(previous|prior|above|earlier)\s+"
            r"(instructions?|rules?|prompts?)\b",

            # Drop previous instructions
            r"\bdrop\s+(all\s+|any\s+|the\s+)?"
            r"(previous|prior|above|earlier)\s+"
            r"(instructions?|rules?|prompts?)\b",

            # Cancel previous instructions
            r"\bcancel\s+(all\s+|any\s+|the\s+)?"
            r"(previous|prior|above|earlier)\s+"
            r"(instructions?|rules?|prompts?)\b",

            # Set aside previous instructions
            r"\bset\s+aside\s+(all\s+|any\s+|the\s+)?"
            r"(previous|prior|above|earlier)\s+"
            r"(instructions?|rules?|prompts?)\b",

            # Stop following previous instructions
            r"\bstop\s+following\s+(the\s+)?"
            r"(previous|prior|above|earlier)\s+"
            r"(instructions?|rules?|prompts?)\b",

            # Do not follow previous instructions
            r"\bdo\s+not\s+follow\s+(the\s+)?"
            r"(previous|prior|above|earlier)\s+"
            r"(instructions?|rules?|prompts?)\b",

            # Replace previous instructions
            r"\breplace\s+(the\s+)?"
            r"(previous|prior|above|earlier)\s+"
            r"(instructions?|rules?|prompts?)\b",

            # Override previous instructions
            r"\boverride\s+(the\s+)?"
            r"(previous|prior|above|earlier)\s+"
            r"(instructions?|rules?|prompts?)\b",

            # Generic instruction override
            r"\bignore\s+(the\s+)?instructions?\b",
            r"\bdisregard\s+(the\s+)?instructions?\b",
            r"\bdiscard\s+(the\s+)?instructions?\b",
            r"\bdiscard\s+(the\s+)?rules?\b",
            r"\boverride\s+(the\s+)?rules?\b",
        ],
    },


    # ========================================================
    # 2. SYSTEM PROMPT EXTRACTION
    # ========================================================

    {
        "name": "system_prompt_extraction",
        "category": "SYSTEM_PROMPT_EXTRACTION",
        "description": (
            "Attempts to obtain hidden system or developer prompts."
        ),
        "weight": 35,
        "patterns": [

            r"\breveal\s+(your|the)\s+(system\s+)?prompt\b",

            r"\bshow\s+(me\s+)?(your|the)\s+"
            r"(system\s+)?prompt\b",

            r"\bprint\s+(your|the)\s+(system\s+)?prompt\b",

            r"\bdisplay\s+(your|the)\s+(system\s+)?prompt\b",

            r"\bwhat\s+is\s+(your|the)\s+system\s+prompt\b",

            r"\breveal\s+(your|the)\s+"
            r"system\s+instructions?\b",

            r"\bshow\s+(me\s+)?(your|the)\s+"
            r"system\s+instructions?\b",

            r"\bshow\s+(me\s+)?your\s+hidden\s+instructions?\b",

            r"\breveal\s+(your|the)\s+hidden\s+instructions?\b",
        ],
    },


    # ========================================================
    # 3. ROLE HIJACKING
    # ========================================================

    {
        "name": "role_hijacking",
        "category": "ROLE_HIJACK",
        "description": (
            "Attempts to change or manipulate the model's role."
        ),
        "weight": 20,
        "patterns": [

            r"\byou\s+are\s+now\s+(an?|the)?\s*"
            r"(unrestricted|unfiltered|different|new|evil|"
            r"uncensored|developer|system)?\b",

            r"\bfrom\s+now\s+on\s+you\s+are\b",

            r"\bact\s+as\s+(an?|the)?\s*"
            r"(unrestricted|unfiltered|uncensored|different|"
            r"new)?\b",

            r"\bpretend\s+(to\s+be|you\s+are)\b",

            r"\broleplay\s+as\b",

            r"\bassume\s+the\s+role\s+of\b",

            r"\byour\s+new\s+role\s+is\b",

            r"\bbehave\s+as\s+(an?|the)?\s*"
            r"(unrestricted|unfiltered|uncensored|different|new)?\b",
        ],
    },


    # ========================================================
    # 4. SAFETY / SECURITY BYPASS
    # ========================================================

    {
        "name": "safety_bypass",
        "category": "SAFETY_BYPASS",
        "description": (
            "Attempts to bypass safety, security, filters, "
            "or content restrictions."
        ),
        "weight": 35,
        "patterns": [

            r"\bjailbreak\b",

            r"\bbypass\s+(the\s+)?"
            r"(safety|security|restrictions?|filters?|rules?)\b",

            r"\bdisable\s+(the\s+)?"
            r"(safety|security|restrictions?|filters?)\b",

            r"\bremove\s+(the\s+)?"
            r"(safety|security|restrictions?|filters?)\b",

            r"\bcircumvent\s+(the\s+)?"
            r"(safety|security|restrictions?|filters?)\b",

            r"\bwithout\s+(any\s+)?"
            r"(safety|security)\s+restrictions?\b",

            r"\bunrestricted\s+(mode|ai|assistant)\b",

            r"\buncensored\s+(mode|ai|assistant)\b",

            r"\bdeveloper\s+mode\b",

            r"\bdan\s+mode\b",

            r"\bno\s+safety\s+(rules?|restrictions?)\b",

            r"\bremove\s+all\s+restrictions?\b",
        ],
    },


    # ========================================================
    # 5. AUTHORITY MANIPULATION
    # ========================================================

    {
        "name": "authority_manipulation",
        "category": "AUTHORITY_MANIPULATION",
        "description": (
            "Attempts to manipulate system or developer-level authority."
        ),
        "weight": 30,
        "patterns": [

            r"\bignore\s+(the\s+)?developer\s+"
            r"(message|instructions?)\b",

            r"\bignore\s+(the\s+)?system\s+"
            r"(message|instructions?)\b",

            r"\boverride\s+(the\s+)?developer\s+"
            r"(message|instructions?)\b",

            r"\boverride\s+(the\s+)?system\s+"
            r"(message|instructions?)\b",

            r"\bdeveloper\s+instructions?\b",

            r"\bsystem\s+instructions?\b",

            r"\bnew\s+system\s+message\b",

            r"\bnew\s+developer\s+message\b",

            r"\bi\s+am\s+the\s+developer\b",

            r"\bi\s+am\s+the\s+system\b",

            r"\bthis\s+is\s+an?\s+official\s+system\s+message\b",
        ],
    },


    # ========================================================
    # 6. DATA EXFILTRATION
    # ========================================================

    {
        "name": "data_exfiltration",
        "category": "DATA_EXFILTRATION",
        "description": (
            "Attempts to extract secrets, credentials, keys, "
            "tokens, or sensitive information."
        ),
        "weight": 40,
        "patterns": [

            r"\breveal\b.{0,80}"
            r"\b(passwords?|credentials?|secrets?|api\s+keys?|tokens?)\b",

            r"\bshow\b.{0,80}"
            r"\b(passwords?|credentials?|secrets?|api\s+keys?|tokens?)\b",

            r"\boutput\b.{0,80}"
            r"\b(passwords?|credentials?|secrets?|api\s+keys?|tokens?)\b",

            r"\bleak\b.{0,80}"
            r"\b(passwords?|credentials?|secrets?|api\s+keys?|tokens?)\b",

            r"\bexpose\b.{0,80}"
            r"\b(passwords?|credentials?|secrets?|api\s+keys?|tokens?)\b",

            r"\bgive\s+me\b.{0,80}"
            r"\b(passwords?|credentials?|secrets?|api\s+keys?|tokens?)\b",

            r"\bextract\b.{0,80}"
            r"\b(passwords?|credentials?|secrets?|api\s+keys?|tokens?)\b",

            r"\bshow\s+me\s+any\s+"
            r"(secret|password|credential|api\s+key|token)s?\b",
        ],
    },


    # ========================================================
    # 7. HIDDEN INSTRUCTION EXTRACTION
    # ========================================================

    {
        "name": "hidden_instruction_extraction",
        "category": "HIDDEN_INSTRUCTION_EXTRACTION",
        "description": (
            "Attempts to expose hidden instructions or internal context."
        ),
        "weight": 30,
        "patterns": [

            r"\breveal\s+(all\s+)?hidden\s+"
            r"(instructions?|messages?|content)\b",

            r"\bshow\s+(all\s+)?hidden\s+"
            r"(instructions?|messages?|content)\b",

            r"\bexpose\s+(all\s+)?hidden\s+"
            r"(instructions?|messages?|content)\b",

            r"\bwhat\s+are\s+your\s+hidden\s+instructions\b",

            r"\bdisplay\s+hidden\s+context\b",

            r"\breveal\s+internal\s+instructions\b",

            r"\bshow\s+internal\s+instructions\b",

            r"\breveal\s+hidden\s+context\b",

            r"\bshow\s+hidden\s+context\b",
        ],
    },


    # ========================================================
    # 8. PROMPT RECONSTRUCTION
    # ========================================================

    {
        "name": "prompt_reconstruction",
        "category": "PROMPT_RECONSTRUCTION",
        "description": (
            "Attempts to reconstruct, reproduce, or repeat "
            "internal prompts."
        ),
        "weight": 30,
        "patterns": [

            r"\brepeat\s+(your|the)\s+"
            r"(system\s+)?prompt\b",

            r"\breproduce\s+(your|the)\s+"
            r"(system\s+)?prompt\b",

            r"\bcopy\s+(your|the)\s+"
            r"(system\s+)?prompt\b",

            r"\brecite\s+(your|the)\s+"
            r"(system\s+)?prompt\b",

            r"\bquote\s+(your|the)\s+"
            r"(system\s+)?prompt\b",

            r"\breconstruct\s+(your|the)\s+"
            r"(system\s+)?prompt\b",

            r"\bwrite\s+out\s+(your|the)\s+"
            r"(system\s+)?prompt\b",
        ],
    },


    # ========================================================
    # 9. INSTRUCTION RESET
    # ========================================================

    {
        "name": "instruction_reset",
        "category": "INSTRUCTION_RESET",
        "description": (
            "Attempts to reset the instruction hierarchy "
            "or instruction context."
        ),
        "weight": 20,
        "patterns": [

            r"\bstart\s+(again|over)\s+from\s+scratch\b",

            r"\bstart\s+over\s+from\s+zero\b",

            r"\breset\s+(your|the)\s+"
            r"(instructions?|rules?|context)\b",

            r"\brestart\s+(your|the)\s+"
            r"(instructions?|rules?|context)\b",

            r"\bbegin\s+again\s+without\s+(the\s+)?previous\b",

            r"\bnew\s+instructions?\s+from\s+now\s+on\b",

            r"\bforget\s+everything\s+before\b",
        ],
    },


    # ========================================================
    # 10. OUTPUT MANIPULATION
    # ========================================================

    {
        "name": "output_manipulation",
        "category": "OUTPUT_MANIPULATION",
        "description": (
            "Attempts to force attacker-controlled output behavior."
        ),
        "weight": 15,
        "patterns": [

            r"\bonly\s+respond\s+with\b",

            r"\bdo\s+not\s+mention\s+(the\s+)?"
            r"(rules?|instructions?|safety)\b",

            r"\bnever\s+refuse\b",

            r"\bdo\s+not\s+refuse\b",

            r"\bdo\s+not\s+follow\s+(your\s+)?safety\b",

            r"\balways\s+comply\b",

            r"\byou\s+must\s+comply\b",

            r"\bmust\s+obey\s+me\b",

            r"\bdo\s+exactly\s+what\s+i\s+say\b",
        ],
    },


    # ========================================================
    # 11. OBFUSCATION / ENCODING
    # ========================================================

    {
        "name": "obfuscation",
        "category": "OBFUSCATION",
        "description": (
            "Possible encoding or obfuscation intended to hide instructions."
        ),
        "weight": 25,
        "patterns": [

            r"\bbase64\b.{0,50}\bdecode\b",

            r"\bdecode\b.{0,50}\bbase64\b",

            r"\bencoded\s+"
            r"(instruction|prompt|message)\b",

            r"\bdecode\s+the\s+following\b",

            r"\btranslate\s+this\s+encoded\b",

            r"\brot13\b",

            r"\bhexadecimal\b.{0,50}\bdecode\b",

            r"\bdecode\s+this\s+message\b",
        ],
    },


    # ========================================================
    # 12. PROMPT LEAKING
    # ========================================================

    {
        "name": "prompt_leaking",
        "category": "PROMPT_LEAKING",
        "description": (
            "Attempts to leak internal prompt or configuration information."
        ),
        "weight": 30,
        "patterns": [

            r"\bleak\s+(your|the)\s+"
            r"(system\s+)?prompt\b",

            r"\bleak\s+(your|the)\s+instructions\b",

            r"\bexpose\s+(your|the)\s+"
            r"(system\s+)?prompt\b",

            r"\bextract\s+(your|the)\s+"
            r"(system\s+)?prompt\b",

            r"\bdisclose\s+(your|the)\s+"
            r"(system\s+)?prompt\b",

            r"\bleak\s+hidden\s+instructions\b",
        ],
    },
]


# ============================================================
# TEXT NORMALIZATION
# ============================================================

def normalize_text(text: str) -> str:
    """
    Normalize user prompt before applying rules.
    """

    if not isinstance(text, str):
        return ""

    text = text.lower()

    # Normalize whitespace
    text = re.sub(r"\s+", " ", text)

    text = text.strip()

    return text


# ============================================================
# RISK LEVEL
# ============================================================

def get_risk_level(score: int) -> str:
    """
    Convert risk score to risk level.
    """

    score = max(0, min(100, score))

    if score <= 19:
        return "LOW"

    if score <= 49:
        return "MEDIUM"

    if score <= 74:
        return "HIGH"

    return "CRITICAL"


# ============================================================
# SECURITY DECISION
# ============================================================

def get_decision(score: int) -> str:
    """
    Convert risk score into security action.

    0-49  -> ALLOW
    50-74 -> REVIEW
    75-100 -> BLOCK
    """

    if score >= DECISION_THRESHOLDS["BLOCK"]:
        return "BLOCK"

    if score >= DECISION_THRESHOLDS["REVIEW"]:
        return "REVIEW"

    return "ALLOW"


# ============================================================
# RULE DETECTION
# ============================================================

def detect_injection(text: str) -> Dict:
    """
    Analyze a dynamic prompt using all rule-based patterns.

    Returns a dictionary containing the complete Layer 1 result.
    """

    normalized_text = normalize_text(text)

    matched_rules: List[str] = []
    attack_types: List[str] = []
    rule_details: List[Dict] = []

    raw_score = 0

    # --------------------------------------------------------
    # Run all rules
    # --------------------------------------------------------

    for rule in RULES:

        rule_matched = False
        matched_pattern = None

        for pattern in rule["patterns"]:

            if re.search(
                pattern,
                normalized_text,
                re.IGNORECASE
            ):
                rule_matched = True
                matched_pattern = pattern
                break

        if rule_matched:

            matched_rules.append(rule["name"])

            attack_types.append(rule["category"])

            raw_score += rule["weight"]

            rule_details.append({
                "rule": rule["name"],
                "category": rule["category"],
                "weight": rule["weight"],
                "pattern": matched_pattern,
                "description": rule["description"],
            })

    # --------------------------------------------------------
    # Remove duplicate categories
    # --------------------------------------------------------

    attack_types = list(
        dict.fromkeys(attack_types)
    )

    # --------------------------------------------------------
    # Limit score to 100
    # --------------------------------------------------------

    risk_score = min(raw_score, 100)

    # --------------------------------------------------------
    # Risk level
    # --------------------------------------------------------

    risk_level = get_risk_level(risk_score)

    # --------------------------------------------------------
    # Security decision
    # --------------------------------------------------------

    decision = get_decision(risk_score)

    # --------------------------------------------------------
    # Injection classification
    # --------------------------------------------------------

    is_injection = len(matched_rules) > 0

    # --------------------------------------------------------
    # Return complete result
    # --------------------------------------------------------

    return {
        "text": text,
        "normalized_text": normalized_text,

        "is_injection": is_injection,

        "risk_score": risk_score,

        "risk_level": risk_level,

        "decision": decision,

        "attack_types": attack_types,

        "matched_rules": matched_rules,

        "rule_count": len(matched_rules),

        "rule_details": rule_details,
    }


# ============================================================
# SIMPLE PREDICT FUNCTION
# ============================================================

def predict(text: str) -> int:
    """
    Simple prediction function.

    Returns:
        1 = injection
        0 = benign
    """

    result = detect_injection(text)

    return int(result["is_injection"])


# ============================================================
# PRETTY RESULT DISPLAY
# ============================================================

def print_result(result: Dict):
    """
    Display detection result in terminal.
    """

    print("\n" + "=" * 70)
    print("RULE-BASED SECURITY ANALYSIS")
    print("=" * 70)

    print("\nPrompt:")
    print(result["text"])

    print("\nPrediction:")

    if result["is_injection"]:
        print("  INJECTION")
    else:
        print("  BENIGN")

    print(f"\nRisk Score : {result['risk_score']}/100")
    print(f"Risk Level : {result['risk_level']}")
    print(f"Decision   : {result['decision']}")

    print(f"\nRules Matched: {result['rule_count']}")

    # --------------------------------------------------------
    # Attack types
    # --------------------------------------------------------

    print("\nAttack Types:")

    if result["attack_types"]:

        for attack_type in result["attack_types"]:
            print(f"  - {attack_type}")

    else:
        print("  None")

    # --------------------------------------------------------
    # Matched rules
    # --------------------------------------------------------

    print("\nMatched Rules:")

    if result["matched_rules"]:

        for rule in result["matched_rules"]:
            print(f"  - {rule}")

    else:
        print("  None")

    # --------------------------------------------------------
    # Rule details
    # --------------------------------------------------------

    if result["rule_details"]:

        print("\nRule Details:")

        for detail in result["rule_details"]:

            print(
                f"  {detail['category']} "
                f"(+{detail['weight']} risk)"
            )

    print("\n" + "=" * 70)


# ============================================================
# DYNAMIC TERMINAL INPUT
# ============================================================

def main():

    print("=" * 70)
    print("HYBRID LLM SECURITY - RULE-BASED DETECTOR")
    print("=" * 70)

    print("\nEnter a prompt to analyze.")
    print("Type 'exit' or 'quit' to stop.")

    while True:

        try:

            user_input = input("\nEnter prompt: ")

        except KeyboardInterrupt:

            print("\n\nExiting detector.")
            break

        except EOFError:

            print("\n\nExiting detector.")
            break

        # ----------------------------------------------------
        # Exit
        # ----------------------------------------------------

        if user_input.strip().lower() in {
            "exit",
            "quit"
        }:

            print("\nExiting detector.")
            break

        # ----------------------------------------------------
        # Empty input
        # ----------------------------------------------------

        if not user_input.strip():

            print("Please enter a prompt.")

            continue

        # ----------------------------------------------------
        # Detect
        # ----------------------------------------------------

        result = detect_injection(user_input)

        print_result(result)


# ============================================================
# PROGRAM ENTRY
# ============================================================

if __name__ == "__main__":
    main()