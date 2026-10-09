import json
from pathlib import Path


KNOWLEDGE_BASE_PATH = (
    Path(__file__).resolve().parent.parent
    / "knowledge_base"
    / "cwe_patterns.json"
)


def match_cwe(threat):
    """Return the first local CWE pattern matching both category and protocol."""
    with open(KNOWLEDGE_BASE_PATH, "r", encoding="utf-8-sig") as file:
        patterns = json.load(file)

    category = threat.get("stride_category")
    protocol = threat.get("protocol")

    for pattern in patterns:
        if category in pattern["stride"] and protocol in pattern["protocols"]:
            return {
                "cwe": pattern["cwe"],
                "cwe_name": pattern["name"],
                "cwe_severity": pattern["severity"],
                "cwe_recommendation": pattern["recommendation"],
            }

    return {
        "cwe": "N/A",
        "cwe_name": "No matching CWE pattern",
        "cwe_severity": "N/A",
        "cwe_recommendation": "Perform manual security review.",
    }