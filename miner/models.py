from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

class Finding(BaseModel):
    rule_id: str
    severity: Optional[str] = None
    message: str
    file: str
    start_line: int

# NUEVA ESTRUCTURA PARA EL SBOM (Tarea 4)
class SbomInfo(BaseModel):
    commit: str
    generation_date: str
    syft_version: str
    status: str  # Puede ser: "success", "failed", "no_components"
    components_count: int
    sbom_path: Optional[str] = None

# ACTUALIZADO: Agregamos full_name y sbom
class Repository(BaseModel):
    name: str
    full_name: Optional[str] = None
    url: str
    status: str
    languages: List[str]
    findings: Optional[List[Finding]] = []
    sbom: Optional[SbomInfo] = None

class Summary(BaseModel):
    repositories: int = 0
    analyzed: int = 0
    failed: int = 0
    unsupported: int = 0
    findings: int = 0

class OrganizationReport(BaseModel):
    organization: str
    summary: Summary
    repositories: List[Repository]