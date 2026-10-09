import json
import sys
from pathlib import Path

# Ensure backend and project root are in sys.path
backend_dir = Path(__file__).resolve().parent
project_root = backend_dir.parent
for path in (str(backend_dir), str(project_root)):
    if path not in sys.path:
        sys.path.insert(0, path)

if __package__:
    from .security_engine import identify_attack_surfaces
    from .threat_engine import generate_threats
    from .risk_engine import calculate_risk
    from .cwe_engine import match_cwe
else:
    from security_engine import identify_attack_surfaces
    from threat_engine import generate_threats
    from risk_engine import calculate_risk
    from cwe_engine import match_cwe


def analyze_architecture(architecture: dict = None):
    if architecture is None:
        data_path = Path(__file__).resolve().parent.parent / "test_data" / "vehicle_v1.json"
        with open(data_path, "r", encoding="utf-8") as file:
            architecture = json.load(file)

    print("System:", architecture["system"])

    print("\nComponents:")
    for component in architecture["components"]:
        print("-", component["name"])

    print("\nInterfaces:")
    for interface in architecture["interfaces"]:
        print(
            "-",
            interface["protocol"],
            ":",
            interface["source"],
            "->",
            interface["target"],
        )

    attack_surfaces = identify_attack_surfaces(architecture["interfaces"])

    print("\nAttack Surfaces:")
    for surface in attack_surfaces:
        print(
            "-",
            surface["protocol"],
            ":",
            surface["source"],
            "->",
            surface["target"],
            "| Type:",
            surface["type"],
        )

    threats = generate_threats(attack_surfaces)

    print("\nThreat Model:")
    for threat in threats:
        print(f"- [{threat['threat_id']}] {threat['stride_category']}")
        print("  Protocol:", threat["protocol"])
        print("  Source:", threat["source"])
        print("  Target:", threat["target"])
        print("  Severity:", threat["severity"])
        print("  Description:", threat["description"])
        print("  Mitigation:", threat["mitigation"])

    findings = []
    for threat in threats:
        finding = calculate_risk(threat)
        finding.update(match_cwe(finding))
        findings.append(finding)

    print("\nFinal Security Findings:")
    for finding in findings:
        print(f"[{finding['threat_id']}]")
        print("Threat:", finding["stride_category"])
        print("Protocol:", finding["protocol"])
        print("Severity:", finding["severity"])
        print("Risk Score:", finding["risk_score"])
        print("Risk Level:", finding["risk_level"])
        print("Impact:", finding["impact"])
        print("Exploitability:", finding["exploitability"])
        print("Exposure:", finding["exposure"])
        print("CWE:", finding["cwe"])
        print("CWE Name:", finding["cwe_name"])
        print("Mitigation:", finding["mitigation"])
        print("CWE Recommendation:", finding["cwe_recommendation"])

    return {
        "system": architecture.get("system"),
        "components": architecture.get("components", []),
        "interfaces": architecture.get("interfaces", []),
        "attack_surfaces": attack_surfaces,
        "threats": threats,
        "security_findings": findings,
    }


if __name__ == "__main__":
    analyze_architecture()