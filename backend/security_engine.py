ATTACK_SURFACE_RULES = {
    "Bluetooth": "External",
    "Wi-Fi": "External",
    "Ethernet": "Network",
    "CAN": "Internal Communication",
    "USB": "Physical",
    "Diagnostic": "Service/Diagnostic"
}


def identify_attack_surfaces(interfaces):
    attack_surfaces = []

    for interface in interfaces:
        protocol = interface["protocol"]

        if protocol in ATTACK_SURFACE_RULES:
            attack_surfaces.append({
                "protocol": protocol,
                "source": interface["source"],
                "target": interface["target"],
                "type": ATTACK_SURFACE_RULES[protocol]
            })

    return attack_surfaces