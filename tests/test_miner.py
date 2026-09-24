import json
from miner.models import Finding, Repository, Summary, OrganizationReport
from miner.parser import parse_sarif

def test_pydantic_models():
    """Prueba que los modelos Pydantic se instancien y estructuren correctamente."""
    finding = Finding(
        rule_id="py/test-rule",
        severity="warning",
        message="Test de vulnerabilidad",
        file="src/main.py",
        start_line=10
    )
    
    repo = Repository(
        name="test-repo",
        url="https://github.com/org/test-repo",
        status="analyzed",
        languages=["python"],
        findings=[finding]
    )
    
    assert repo.name == "test-repo"
    assert len(repo.findings) == 1
    assert repo.findings[0].severity == "warning"

def test_parse_sarif(tmp_path):
    """Prueba que el parser extraiga correctamente los datos de un archivo SARIF simulado."""
    # 1. Crear un JSON simulado con la estructura de SARIF
    mock_sarif = {
        "runs": [
            {
                "results": [
                    {
                        "ruleId": "py/sql-injection",
                        "level": "error",
                        "message": {"text": "Posible inyección SQL"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "app/db.py"},
                                    "region": {"startLine": 42}
                                }
                            }
                        ]
                    }
                ]
            }
        ]
    }
    
    # 2. Guardarlo en un archivo temporal usando el fixture tmp_path de pytest
    fake_sarif_file = tmp_path / "fake_results.sarif"
    with open(fake_sarif_file, "w") as f:
        json.dump(mock_sarif, f)
        
    # 3. Ejecutar nuestra función parse_sarif
    findings = parse_sarif(fake_sarif_file)
    
    # 4. Validar que la información se extrajo bien
    assert len(findings) == 1
    assert findings[0].rule_id == "py/sql-injection"
    assert findings[0].severity == "error"
    assert findings[0].message == "Posible inyección SQL"
    assert findings[0].file == "app/db.py"
    assert findings[0].start_line == 42