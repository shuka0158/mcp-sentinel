"""Core data models for scan findings."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0

    def __str__(self) -> str:
        return self.name

    @property
    def color(self) -> str:
        return {
            Severity.CRITICAL: "bold red",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "cyan",
            Severity.INFO: "dim",
        }[self]


class Category(Enum):
    COMMAND_EXECUTION = "command-execution"
    ARBITRARY_FILE_ACCESS = "arbitrary-file-access"
    NETWORK_EXFILTRATION = "network-exfiltration"
    SECRETS_EXPOSURE = "secrets-exposure"
    UNSAFE_DESERIALIZATION = "unsafe-deserialization"
    PROMPT_INJECTION_SURFACE = "prompt-injection-surface"
    OVERBROAD_PERMISSIONS = "overbroad-permissions"
    SUPPLY_CHAIN = "supply-chain"
    MISSING_INPUT_VALIDATION = "missing-input-validation"
    INSECURE_TRANSPORT = "insecure-transport"


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: Severity
    category: Category
    description: str
    remediation: str
    file: str | None = None
    line: int | None = None
    snippet: str | None = None
    tool_name: str | None = None
    confidence: str = "high"  # high | medium | low

    def location(self) -> str:
        if self.file and self.line:
            return f"{self.file}:{self.line}"
        if self.file:
            return self.file
        if self.tool_name:
            return f"tool:{self.tool_name}"
        return "-"


@dataclass
class ScanResult:
    target: str
    scanner: str  # "static" | "dynamic"
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    tools_inspected: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def risk_score(self) -> int:
        """0-100, weighted by severity, saturating so a handful of
        criticals doesn't already max out and mask everything after."""
        weights = {
            Severity.CRITICAL: 30,
            Severity.HIGH: 15,
            Severity.MEDIUM: 6,
            Severity.LOW: 2,
            Severity.INFO: 0,
        }
        raw = sum(weights[f.severity] for f in self.findings)
        return min(100, raw)

    @property
    def grade(self) -> str:
        score = self.risk_score
        if score == 0:
            return "A"
        if score < 15:
            return "B"
        if score < 40:
            return "C"
        if score < 70:
            return "D"
        return "F"

    def by_severity(self) -> dict[Severity, list[Finding]]:
        out: dict[Severity, list[Finding]] = {s: [] for s in Severity}
        for f in self.findings:
            out[f.severity].append(f)
        return out

    def counts(self) -> dict[str, int]:
        c = {s.name: 0 for s in Severity}
        for f in self.findings:
            c[f.severity.name] += 1
        return c
