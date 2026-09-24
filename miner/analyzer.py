import subprocess
import shutil
from pathlib import Path
from typing import Optional, Tuple

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