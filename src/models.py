from pydantic import BaseModel, Field
from typing import Literal
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Finding(BaseModel):
    severity: Severity
    category: str = Field(description="e.g. 'Hardcoded Secret', 'SQL Injection', 'Missing Test'")
    file_path: str
    line_number: int = Field(default=0, description="0 if not applicable to a specific line")
    title: str
    description: str
    recommendation: str


class TriageDecision(BaseModel):
    should_run_vuln_scan: bool
    should_run_drift_check: bool
    should_run_standards_check: bool
    reason: str
    risk_level: Literal["LOW", "MEDIUM", "HIGH"]


class VulnReport(BaseModel):
    findings: list[Finding]
    summary: str
    has_critical: bool


class QualityReport(BaseModel):
    score: int = Field(ge=0, le=100)
    findings: list[Finding]
    test_coverage_note: str
    summary: str


class DriftReport(BaseModel):
    violations: list[Finding]
    summary: str
    adr_references: list[str]


class FinalReview(BaseModel):
    overall_severity: Severity
    recommendation: Literal["APPROVE", "REQUEST_CHANGES", "COMMENT"]
    summary: str
    vuln_findings: list[Finding]
    drift_findings: list[Finding]
    quality_findings: list[Finding]
    quality_score: int
    action_items: list[str]
