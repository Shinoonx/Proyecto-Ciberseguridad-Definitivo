from pydantic import BaseModel, Field
from typing import List, Optional

class Finding(BaseModel):
    rule_id: str
    severity: Optional[str] = None
    message: str
    file: str
    start_line: int

class Repository(BaseModel):
    name: str
    url: str
    status: str  # ej: "analyzed", "failed", "unsupported", "clone_error"
    languages: List[str] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)

class Summary(BaseModel):
    repositories: int = 0
    analyzed: int = 0
    failed: int = 0
    unsupported: int = 0
    findings: int = 0

class OrganizationReport(BaseModel):
    organization: str
    summary: Summary
    repositories: List[Repository] = Field(default_factory=list)