"""
Pydantic models for request/response validation
Python 3.9 Compatible Version
"""
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum

class ScanType(str, Enum):
    PHISHING = "phishing"
    OWASP = "owasp"
    COMPREHENSIVE = "comprehensive"

class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

# Request Models
class PhishingAnalysisRequest(BaseModel):
    email_content: Optional[str] = Field(None, min_length=1, max_length=100000)
    url: Optional[str] = None
    headers: Optional[Dict[str, str]] = None

class OWAPScanRequest(BaseModel):
    target_url: str
    scan_depth: str = Field(default="basic", pattern="^(basic|standard|deep)$")
    include_remediation: bool = True

class ComprehensiveScanRequest(BaseModel):
    url: str
    email_sample: Optional[str] = None
    scan_options: Dict[str, Any] = Field(default_factory=dict)

# Response Models
class Indicator(BaseModel):
    name: str
    description: str
    severity: RiskLevel
    evidence: Optional[str] = None
    owasp_category: Optional[str] = None

class PhishingAnalysisResponse(BaseModel):
    risk_score: float = Field(..., ge=0.0, le=1.0)
    risk_level: RiskLevel
    is_phishing: bool
    indicators: List[Indicator]
    analysis_timestamp: datetime = Field(default_factory=datetime.utcnow)
    recommendations: List[str]
    confidence: float = Field(..., ge=0.0, le=1.0)
    llm_reasoning: Optional[str] = None  # Added for LLM output

class OWASPScanResult(BaseModel):
    vulnerability_id: str
    title: str
    category: str
    severity: RiskLevel
    description: str
    affected_endpoint: Optional[str] = None
    proof_of_concept: Optional[str] = None
    remediation: Optional[str] = None
    cvss_score: Optional[float] = None

class OWASPScanResponse(BaseModel):
    target_url: str
    scan_timestamp: datetime = Field(default_factory=datetime.utcnow)
    scan_duration_seconds: float
    vulnerabilities_found: int
    results: List[OWASPScanResult]
    summary: Dict[str, int]
    remediation_summary: List[str]

class ComprehensiveScanResponse(BaseModel):
    phishing_analysis: Optional[PhishingAnalysisResponse]
    owasp_scan: Optional[OWASPScanResponse]
    overall_risk_score: float
    overall_risk_level: RiskLevel
    executive_summary: str
    next_steps: List[str]

# Utility Models
class ScanStatus(BaseModel):
    scan_id: str
    status: str
    progress: float = Field(..., ge=0.0, le=1.0)
    message: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    result: Optional[Any] = None