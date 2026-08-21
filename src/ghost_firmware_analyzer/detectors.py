from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from .models import Finding


STRING_RULES = (
    ("FW-SVC-TELNET", "Telnet service indicator", "high", "medium", re.compile(r"\btelnetd\b", re.I), "An embedded telnet daemon indicator was found.", "Disable Telnet and require an authenticated encrypted management channel."),
    ("FW-SVC-DROPBEAR", "Dropbear SSH service indicator", "medium", "low", re.compile(r"\bdropbear\b", re.I), "A Dropbear SSH indicator was found; the presence alone does not establish a vulnerability.", "Verify version, host-key handling, authentication policy, and exposure."),
    ("FW-CRED-DEFAULT", "Default credential indicator", "high", "medium", re.compile(r"(?:admin:admin|root:root|default[_ -]?password|password=admin)", re.I), "A string associated with a default credential was found.", "Verify the credential source and remove default credentials before deployment."),
    ("FW-CRED-AUTHKEY", "Embedded SSH authorization material", "critical", "high", re.compile(r"(?:authorized_keys|BEGIN (?:RSA|OPENSSH|EC|DSA) PRIVATE KEY)", re.I), "SSH authorization or private-key material appears to be embedded.", "Rotate the exposed key, remove it from the image, and review build provenance."),
    ("FW-SHELL-EXEC", "Shell execution interface", "medium", "low", re.compile(r"(?:/bin/(?:ba)?sh|system\s*\(|popen\s*\(|busybox\s+sh)", re.I), "A shell or shell-execution indicator was found. This is contextual evidence, not proof of a backdoor.", "Review the owning component, exposed interfaces, and command authorization boundaries."),
)

PROTOCOL_RULES = (
    ("FW-PROTO-HTTP", "HTTP endpoint indicator", "low", "low", re.compile(r"(?:https?://|HTTP/1\\.[01]|HTTP/2)", re.I), "An HTTP endpoint or protocol marker was found in the analyzed content.", "Inventory the endpoint, enforce TLS where applicable, and review certificate validation."),
    ("FW-PROTO-MQTT", "MQTT protocol indicator", "low", "low", re.compile(r"(?:mqtt|1883|8883)", re.I), "An MQTT marker or common port reference was found.", "Review broker authentication, topic authorization, and TLS settings."),
    ("FW-PROTO-TFTP", "TFTP protocol indicator", "medium", "low", re.compile(r"(?:tftp|\\b69/udp\\b)", re.I), "A TFTP marker was found; TFTP does not provide transport authentication.", "Disable it unless required and isolate any required recovery service."),
    ("FW-PROTO-UBUS", "Embedded management bus indicator", "medium", "low", re.compile(r"(?:ubus|uci\\s+get|rpcd)", re.I), "An embedded management bus indicator was found.", "Review local and network-facing access controls for management APIs."),
    ("FW-PROTO-RAW-SOCKET", "Raw socket or packet interface indicator", "medium", "low", re.compile(r"(?:AF_PACKET|SOCK_RAW|raw[_ -]?socket|pcap_open_live)", re.I), "A raw packet interface indicator was found.", "Confirm the component's need for packet access and apply least privilege."),
)

HARDWARE_INDICATOR_RULES = (
    ("FW-HW-JTAG", "Hardware debug interface indicator", "high", "low", re.compile(r"(?:\\bjtag\\b|\\bswd\\b|debug[_ -]?enable|test[_ -]?point)", re.I), "A hardware debug or test interface marker was found in the image.", "Verify production fuses, debug lock state, board straps, and manufacturing configuration."),
    ("FW-HW-UNSIGNED", "Signature verification path indicator", "high", "low", re.compile(r"(?:verify[_ -]?signature|secure[_ -]?boot|sigcheck|firmware[_ -]?signature)", re.I), "A secure-boot or signature-verification path marker was found; this scan does not validate the chain of trust.", "Validate the boot ROM, key hierarchy, signature policy, rollback protection, and update path on hardware."),
    ("FW-HW-DEBUG-ENV", "Debug environment indicator", "medium", "low", re.compile(r"(?:gdbserver|strace|ltrace|debugfs|/sys/kernel/debug)", re.I), "A debugging environment indicator was found.", "Remove development diagnostics from production images or protect them with authorization."),
    ("FW-HW-BACKDOOR-TERM", "Backdoor-related indicator", "high", "low", re.compile(r"(?:backdoor|covert[_ -]?channel|hidden[_ -]?command|magic[_ -]?packet)", re.I), "A backdoor-related term was found in static content. This is an indicator only and is not proof of a hardware backdoor.", "Escalate to controlled hardware validation, reproducible builds, binary diffing, and vendor provenance review."),
)


def _finding(rule_id: str, title: str, severity: str, confidence: str, description: str, evidence: str, source: str, remediation: str, tags: tuple[str, ...], location: str | None = None) -> Finding:
    return Finding(rule_id=rule_id, title=title, severity=severity, confidence=confidence, description=description, evidence=evidence[:500], source=source, location=location, remediation=remediation, tags=tags)


def scan_strings(strings: Iterable[str], source: str, location: str | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for value in strings:
        for rule_id, title, severity, confidence, pattern, description, remediation in STRING_RULES:
            if pattern.search(value):
                findings.append(_finding(rule_id, title, severity, confidence, description, value, source, remediation, ("firmware", "static-content"), location))
        for rule_id, title, severity, confidence, pattern, description, remediation in PROTOCOL_RULES:
            if pattern.search(value):
                findings.append(_finding(rule_id, title, severity, confidence, description, value, source, remediation, ("firmware", "protocol"), location))
        for rule_id, title, severity, confidence, pattern, description, remediation in HARDWARE_INDICATOR_RULES:
            if pattern.search(value):
                findings.append(_finding(rule_id, title, severity, confidence, description, value, source, remediation, ("firmware", "hardware-indicator"), location))
    return deduplicate(findings)


def deduplicate(findings: Iterable[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, str | None]] = set()
    result: list[Finding] = []
    for finding in findings:
        key = (finding.rule_id, finding.evidence, finding.location)
        if key not in seen:
            seen.add(key)
            result.append(finding)
    return result


def scan_file_text(path: Path, root: Path) -> list[Finding]:
    from .artifacts import printable_strings, safe_relative

    data = path.read_bytes()
    strings = printable_strings(data)
    return scan_strings(strings, source="rootfs-file", location=safe_relative(path, root))
