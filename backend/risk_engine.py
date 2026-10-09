IMPACT_VALUES = {
    "Critical": 100,
    "High": 80,
    "Medium": 50,
    "Low": 25,
}

EXPLOITABILITY_VALUES = {
    "Bluetooth": 90,
    "Wi-Fi": 90,
    "Ethernet": 80,
    "CAN": 80,
    "Diagnostic": 70,
    "USB": 60,
}

EXPOSURE_VALUES = {
    "External": 100,
    "Network": 90,
    "Service/Diagnostic": 80,
    "Internal Communication": 70,
    "Physical": 50,
}

PROTOCOL_EXPOSURE = {
    "Bluetooth": "External",
    "Wi-Fi": "External",
    "Ethernet": "Network",
    "CAN": "Internal Communication",
    "Diagnostic": "Service/Diagnostic",
    "USB": "Physical",
}


def _risk_level(score):
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def calculate_risk(threat):
    """Return the threat with transparent impact, exploitability, and exposure scores."""
    impact = IMPACT_VALUES.get(threat.get("severity"), IMPACT_VALUES["Medium"])

    protocol = threat.get("protocol")
    exploitability = EXPLOITABILITY_VALUES.get(protocol, 50)

    surface_type = threat.get("type") or PROTOCOL_EXPOSURE.get(protocol, "Physical")
    exposure = EXPOSURE_VALUES.get(surface_type, 50)

    raw_score = (impact * 0.5) + (exploitability * 0.3) + (exposure * 0.2)
    score = max(0, min(100, int(raw_score + 0.5)))

    return {
        **threat,
        "impact": impact,
        "exploitability": exploitability,
        "exposure": exposure,
        "risk_score": score,
        "risk_level": _risk_level(score),
    }