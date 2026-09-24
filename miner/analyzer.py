import subprocess
import shutil
import json
from pathlib import Path
from typing import Optional, List

# Mapeo de lenguajes de GitHub a los identificadores que soporta CodeQL
SUPPORTED_LANGUAGES = {
    "python": "python",
    "javascript": "javascript",
    "typescript": "javascript",
    "java": "java",
    "c": "cpp",
    "c++": "cpp",
    "c#": "csharp",
    "go": "go",
    "ruby": "ruby",
    "swift": "swift"
}

class CodeQLAnalyzer:
    def __init__(self, workspace_dir: str = "workspace"):
        # Carpeta temporal donde descargaremos los repos y crearemos las bases de datos
        self.workspace = Path(workspace_dir)
        self.workspace.mkdir(exist_ok=True)

    def is_supported(self, github_language: str) -> Optional[str]:
        if not github_language:
            return None
        return SUPPORTED_LANGUAGES.get(github_language.lower())

    def clone_repository(self, clone_url: str, repo_name: str) -> Optional[Path]:
        repo_path = self.workspace / repo_name
        
        # Si la carpeta ya existe de una ejecución anterior, la limpiamos
        if repo_path.exists():
            shutil.rmtree(repo_path)
            
        try:
            # Usamos --depth 1 para descargar solo el último commit y hacerlo mucho más rápido
            subprocess.run(
                ["git", "clone", "--depth", "1", clone_url, str(repo_path)],
                check=True,
                capture_output=True,
                text=True
            )
            return repo_path
        except subprocess.CalledProcessError:
            return None

    def create_database(self, repo_path: Path, language: str, db_path: Path) -> bool:
        try:
            subprocess.run(
                ["codeql", "database", "create", str(db_path), "--language", language, "--source-root", str(repo_path)],
                check=True,
                capture_output=True,
                text=True
            )
            return True
        except subprocess.CalledProcessError:
            return False

    def analyze_database(self, db_path: Path, sarif_output: Path) -> bool:
        try:
            # Ejecuta el análisis y exporta a SARIF
            subprocess.run(
                ["codeql", "database", "analyze", str(db_path), "--format=sarif-latest", "--output", str(sarif_output)],
                check=True,
                capture_output=True,
                text=True
            )
            return True
        except subprocess.CalledProcessError:
            return False

    def cleanup(self, path: Path):
        """Elimina archivos residuales para no llenar el disco"""
        if path.exists():
            shutil.rmtree(path, ignore_errors=True)

    def get_commit_hash(self, repo_path: Path) -> str:
        """Obtiene el hash del commit actual del repositorio clonado usando Git."""
        try:
            res = subprocess.run(
                ["git", "-C", str(repo_path), "rev-parse", "HEAD"], 
                capture_output=True, text=True, check=True
            )
            return res.stdout.strip()
        except subprocess.CalledProcessError:
            return "unknown"

    def get_syft_version(self) -> str:
        """Obtiene la versión instalada de Syft."""
        try:
            res = subprocess.run(
                ["syft", "version", "-o", "json"], 
                capture_output=True, text=True, check=True
            )
            data = json.loads(res.stdout)
            return data.get("version", "unknown")
        except (subprocess.CalledProcessError, json.JSONDecodeError):
            return "unknown"

    def generate_sbom(self, repo_path: Path, output_file: Path) -> dict:
        """
        Ejecuta Syft sobre el directorio y guarda el JSON CycloneDX.
        Retorna un diccionario con el estado y la cantidad de componentes.
        """
        try:
            # syft scan dir:<ruta> -o cyclonedx-json=<salida>
            subprocess.run(
                ["syft", "scan", f"dir:{repo_path}", "-o", f"cyclonedx-json={output_file}"],
                capture_output=True, text=True, check=True
            )
            
            # Leer el JSON generado para contar los componentes
            if output_file.exists():
                with open(output_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                # CycloneDX guarda los componentes en la clave "components"
                components = data.get("components", [])
                count = len(components)
                
                # Distinguir entre éxito con componentes y éxito sin componentes (exigencia de la rúbrica)
                status = "success" if count > 0 else "no_components"
                return {"status": status, "count": count}
            else:
                return {"status": "failed", "count": 0}
                
        except (subprocess.CalledProcessError, json.JSONDecodeError):
            return {"status": "failed", "count": 0}