"""Pydantic v2 models for GuardBench test cases and results."""

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field

CoSAICategory = Literal[
    "T1", "T2", "T3", "T4", "T5", "T6", "T7", "T8", "T9", "T10", "T11", "T12"
]


class TestCase(BaseModel):
    id: str
    cosai_category: CoSAICategory
    mitre_technique_id: str
    attack_vector: str
    attack_type: str
    expected_verdict: Literal["block", "allow"]
    source: Literal["cve-derived", "taxonomy-derived", "synthetic"]
    obfuscation_level: Literal["none", "light", "heavy"]
    cve_reference: Optional[str] = None


class Result(BaseModel):
    test_case_id: str
    tool_name: str
    blocked: bool
    confidence: float = Field(ge=0.0, le=1.0)
    explanation: str
    latency_ms: int
    raw_output: dict
    timestamp: datetime
