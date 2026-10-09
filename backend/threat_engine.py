STRIDE_RULES = {
    ("Bluetooth", "External"): [
        (
            "Spoofing",
            "High",
            "An attacker may impersonate a paired device to access vehicle services.",
            "Require secure pairing, mutual authentication, and authenticated reconnection.",
        ),
        (
            "Information Disclosure",
            "High",
            "Sensitive vehicle or user data may be exposed over a Bluetooth connection.",
            "Encrypt Bluetooth traffic and limit accessible data and services.",
        ),
        (
            "Denial of Service",
            "Medium",
            "Repeated connection attempts or malformed traffic may disrupt Bluetooth services.",
            "Rate-limit connection attempts and safely handle malformed requests.",
        ),
    ],
    ("CAN", "Internal Communication"): [
        (
            "Tampering",
            "High",
            "An attacker with access to the bus may alter messages such as engine or brake commands.",
            "Validate message values and add message authentication where supported.",
        ),
        (
            "Denial of Service",
            "High",
            "High-priority or excessive CAN traffic may prevent legitimate messages from being delivered.",
            "Monitor bus load and use gateway filtering and rate limits.",
        ),
        (
            "Spoofing",
            "High",
            "An attacker may send CAN frames that impersonate a trusted ECU.",
            "Authenticate critical messages and monitor for unexpected message patterns.",
        ),
    ],
    ("Ethernet", "Network"): [
        (
            "Spoofing",
            "High",
            "An attacker may impersonate a vehicle network host or service.",
            "Use mutual authentication and restrict network access to trusted devices.",
        ),
        (
            "Tampering",
            "High",
            "An attacker may modify network traffic carrying vehicle data or commands.",
            "Protect communications with integrity checks and secure transport.",
        ),
        (
            "Information Disclosure",
            "High",
            "Unprotected network traffic may expose vehicle data or diagnostic information.",
            "Encrypt sensitive traffic and restrict access to network services.",
        ),
        (
            "Denial of Service",
            "High",
            "Flooding or malformed packets may disrupt vehicle network communications.",
            "Filter traffic at gateways and apply rate limits and monitoring.",
        ),
    ],
    ("Wi-Fi", "External"): [
        (
            "Spoofing",
            "High",
            "A rogue access point or client may impersonate a trusted network participant.",
            "Use strong authentication and validate network identities.",
        ),
        (
            "Tampering",
            "High",
            "An attacker may alter data sent over an inadequately protected wireless connection.",
            "Use authenticated encryption and reject unauthenticated traffic.",
        ),
        (
            "Information Disclosure",
            "High",
            "Weak wireless security may expose vehicle or user data.",
            "Use modern Wi-Fi security and encrypt sensitive application traffic.",
        ),
        (
            "Denial of Service",
            "Medium",
            "Wireless interference or connection flooding may make services unavailable.",
            "Monitor wireless availability and limit connection attempts.",
        ),
    ],
    ("USB", "Physical"): [
        (
            "Tampering",
            "High",
            "A physically connected device may provide modified files or data to vehicle systems.",
            "Validate imported data and allow only approved USB functions.",
        ),
        (
            "Information Disclosure",
            "Medium",
            "Data stored on or accessible through a USB connection may be copied.",
            "Restrict data access and encrypt sensitive stored information.",
        ),
        (
            "Elevation of Privilege",
            "High",
            "Malicious USB content may exploit software parsing the connected device.",
            "Keep parsers updated, validate inputs, and isolate USB-handling processes.",
        ),
    ],
    ("Diagnostic", "Service/Diagnostic"): [
        (
            "Spoofing",
            "High",
            "An unauthorized tester may impersonate a trusted diagnostic tool.",
            "Require diagnostic authentication and authorize tester identities.",
        ),
        (
            "Tampering",
            "High",
            "Unauthorized diagnostic commands may modify ECU settings or firmware.",
            "Restrict write operations and verify firmware updates cryptographically.",
        ),
        (
            "Repudiation",
            "Medium",
            "Diagnostic actions may be difficult to trace if service commands are not logged.",
            "Keep tamper-resistant logs of diagnostic access and commands.",
        ),
        (
            "Elevation of Privilege",
            "High",
            "Abuse of diagnostic services may grant access to privileged ECU functions.",
            "Enforce role-based authorization and lock sensitive services when not required.",
        ),
    ],
}


def generate_threats(attack_surfaces):
    """Return STRIDE threats applicable to the supplied attack surfaces."""
    threats = []

    for surface in attack_surfaces:
        rules = STRIDE_RULES.get((surface["protocol"], surface["type"]), [])

        for category, severity, description, mitigation in rules:
            threat_id = f"THREAT-{len(threats) + 1:03d}"
            threats.append(
                {
                    "threat_id": threat_id,
                    "stride_category": category,
                    "protocol": surface["protocol"],
                    "source": surface["source"],
                    "target": surface["target"],
                    "description": description,
                    "severity": severity,
                    "mitigation": mitigation,
                }
            )

    return threats