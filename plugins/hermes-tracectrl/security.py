"""Security detection helpers — direct port of openclaw-tracectrl security.ts.

Detects dangerous tools, dangerous commands, sensitive file access, and prompt
injection patterns. Findings are stamped on spans as tracectrl.security.* attributes
and counted via the tracectrl.security.events metric.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any


# ---------------------------------------------------------------------------
# Dangerous tool names (Hermes equivalents included)
# ---------------------------------------------------------------------------
DANGEROUS_TOOLS = frozenset({
    "bash", "shell", "exec", "execute", "run_command",
    "terminal", "subprocess", "execute_code",
})

# ---------------------------------------------------------------------------
# Sensitive file patterns
# ---------------------------------------------------------------------------
SENSITIVE_FILE_PATTERNS = [
    re.compile(r"/etc/passwd"),
    re.compile(r"/etc/shadow"),
    re.compile(r"\.env($|\.)"),
    re.compile(r"private[_\-]?key", re.IGNORECASE),
    re.compile(r"id_rsa"),
    re.compile(r"id_ed25519"),
    re.compile(r"credentials\.json", re.IGNORECASE),
    re.compile(r"\.pem$"),
    re.compile(r"\.key$"),
    re.compile(r"aws_credentials", re.IGNORECASE),
    re.compile(r"\.kube/config"),
    re.compile(r"token\.json", re.IGNORECASE),
    re.compile(r"secrets?\.(ya?ml|json|toml)", re.IGNORECASE),
]

# ---------------------------------------------------------------------------
# Prompt injection patterns
# ---------------------------------------------------------------------------
INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
    re.compile(r"ignore\s+(all\s+)?prior\s+instructions", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?previous", re.IGNORECASE),
    re.compile(r"system\s+prompt\s+override", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(a|an)\s+", re.IGNORECASE),
    re.compile(r"new\s+instructions?\s*:", re.IGNORECASE),
    re.compile(r"forget\s+(all\s+)?your\s+(rules|instructions)", re.IGNORECASE),
    re.compile(r"pretend\s+you\s+are", re.IGNORECASE),
    re.compile(r"act\s+as\s+if\s+you\s+have\s+no\s+restrictions", re.IGNORECASE),
    re.compile(r"bypass\s+(your\s+)?(safety|content)\s+(filter|policy)", re.IGNORECASE),
    re.compile(r"do\s+not\s+follow\s+your\s+(rules|guidelines)", re.IGNORECASE),
    re.compile(r"jailbreak", re.IGNORECASE),
    re.compile(r"DAN\s+mode", re.IGNORECASE),
]

# ---------------------------------------------------------------------------
# Dangerous command patterns within tool inputs
# ---------------------------------------------------------------------------
DANGEROUS_COMMAND_PATTERNS = [
    re.compile(r"\brm\s+-rf?\s"),
    re.compile(r"\bsudo\s"),
    re.compile(r"\bchmod\s+777\b"),
    re.compile(r"\bcurl\s+.*\|\s*(bash|sh)\b"),
    re.compile(r"\bwget\s+.*\|\s*(bash|sh)\b"),
    re.compile(r"\beval\s*\("),
    re.compile(r"\b(nc|netcat|ncat)\s+-l"),
    re.compile(r"\breverse\s*shell", re.IGNORECASE),
    re.compile(r"\bbase64\s+-d\b.*\|\s*(bash|sh)"),
]

# ---------------------------------------------------------------------------
# Severity ordering
# ---------------------------------------------------------------------------
_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@dataclass
class SecurityFinding:
    severity: str  # "low" | "medium" | "high" | "critical"
    category: str
    description: str
    detail: str = ""


def analyse_tool_call(
    tool_name: str,
    tool_input: str | None,
    span: Any,
    telemetry: Any,
) -> list[SecurityFinding]:
    """Analyse a tool call for security-relevant signals.

    Port of analyseToolCall() from security.ts. Every finding is stamped on
    the span and the security events counter is incremented.
    """
    findings: list[SecurityFinding] = []

    if tool_name.lower() in DANGEROUS_TOOLS:
        findings.append(SecurityFinding(
            severity="high",
            category="dangerous_tool",
            description=f"Invocation of dangerous tool: {tool_name}",
        ))

    if tool_input:
        for pattern in DANGEROUS_COMMAND_PATTERNS:
            match = pattern.search(tool_input)
            if match:
                findings.append(SecurityFinding(
                    severity="high",
                    category="dangerous_command",
                    description=f"Dangerous command pattern detected: {match.group(0)}",
                    detail=tool_input[:500],
                ))
                break

    if tool_input:
        for pattern in SENSITIVE_FILE_PATTERNS:
            if pattern.search(tool_input):
                findings.append(SecurityFinding(
                    severity="medium",
                    category="sensitive_file_access",
                    description=f"Sensitive file access detected: {pattern.pattern}",
                    detail=tool_input[:500],
                ))
                break

    _stamp_findings(findings, span, telemetry)
    return findings


def analyse_message_content(
    text: str,
    span: Any,
    telemetry: Any,
) -> list[SecurityFinding]:
    """Scan message text for prompt-injection patterns.

    Port of analyseMessageContent() from security.ts.
    """
    findings: list[SecurityFinding] = []

    for pattern in INJECTION_PATTERNS:
        match = pattern.search(text)
        if match:
            findings.append(SecurityFinding(
                severity="critical",
                category="prompt_injection",
                description=f'Possible prompt injection detected: "{match.group(0)}"',
                detail=text[:500],
            ))
            break

    _stamp_findings(findings, span, telemetry)
    return findings


def _stamp_findings(
    findings: list[SecurityFinding],
    span: Any,
    telemetry: Any,
) -> None:
    """Write findings onto the span as attributes and increment the counter."""
    if not findings:
        return

    span.set_attribute("tracectrl.security.flagged", True)
    span.set_attribute("tracectrl.security.finding_count", len(findings))

    max_severity = max(
        findings,
        key=lambda f: _SEVERITY_ORDER.get(f.severity, 0),
    ).severity
    span.set_attribute("tracectrl.security.max_severity", max_severity)

    span.set_attribute(
        "tracectrl.security.findings",
        json.dumps([{"severity": f.severity, "category": f.category, "description": f.description} for f in findings]),
    )

    if telemetry and hasattr(telemetry, "counters") and telemetry.counters.security_events:
        telemetry.counters.security_events.add(len(findings), {
            "tracectrl.security.max_severity": max_severity,
        })
