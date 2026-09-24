import json
from pathlib import Path
from typing import List
from .models import Finding

def parse_sarif(sarif_path: Path) -> List[Finding]:
    """
    Lee un archivo SARIF generado por CodeQL y extrae los hallazgos
    adaptándolos a nuestro modelo Pydantic 'Finding'.
    """
    if not sarif_path.exists():
        return []
        
    try:
        with open(sarif_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError:
        return []
        
    findings = []
    runs = data.get("runs", [])
    if not runs:
        return findings
        
    # CodeQL almacena los resultados en el primer "run"
    results = runs[0].get("results", [])
    
    for result in results:
        rule_id = result.get("ruleId", "unknown")
        message = result.get("message", {}).get("text", "Sin descripción")
        
        # Extraer archivo y línea navegando por la estructura SARIF
        locations = result.get("locations", [])
        file_path = "unknown"
        start_line = 0
        
        if locations:
            physical_loc = locations[0].get("physicalLocation", {})
            file_path = physical_loc.get("artifactLocation", {}).get("uri", "unknown")
            start_line = physical_loc.get("region", {}).get("startLine", 0)
            
        # Extraer severidad (CodeQL a veces la deja en 'level' o dentro de 'properties')
        severity = result.get("level")
        if not severity:
            severity = result.get("properties", {}).get("security-severity", None)
            
        # Instanciar nuestro modelo Pydantic exacto
        finding = Finding(
            rule_id=rule_id,
            severity=str(severity) if severity else None,
            message=message,
            file=file_path,
            start_line=start_line
        )
        findings.append(finding)
        
    return findings