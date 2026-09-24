import json
import typer
from pathlib import Path
from datetime import datetime

from .github import get_repositories
from .analyzer import CodeQLAnalyzer
from .parser import parse_sarif
from .models import OrganizationReport, Summary, Repository, SbomInfo

app = typer.Typer(help="Miner de vulnerabilidades para organizaciones de GitHub")

@app.callback()
def callback():
    pass

@app.command()
def scan(
    organization: str = typer.Option(..., "--organization", help="Nombre de la organización de GitHub"),
    output: Path = typer.Option(..., "--output", help="Archivo JSON de salida")
):
    typer.secho(f"Iniciando análisis para la organización: {organization}", fg=typer.colors.BLUE)
    
    try:
        repos_data = get_repositories(organization)
        typer.secho(f"Se encontraron {len(repos_data)} repositorios.", fg=typer.colors.CYAN)
    except Exception as e:
        typer.secho(f"Error al conectar con GitHub API: {e}", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    analyzer = CodeQLAnalyzer()
    summary = Summary(repositories=len(repos_data))
    repositories_list = []

    # Procesamos repositorio por repositorio
    for repo_info in repos_data:
        repo_name = repo_info["name"]
        github_lang = repo_info["language"]
        clone_url = repo_info["clone_url"]
        
        typer.echo(f"Procesando: {repo_name}...", nl=False)
        
        repo_model = Repository(
            name=repo_name,
            url=repo_info["url"],
            status="pending",
            languages=[github_lang] if github_lang else []
        )
        
        # 1. Validar lenguaje
        codeql_lang = analyzer.is_supported(github_lang)
        if not codeql_lang:
            repo_model.status = "unsupported"
            summary.unsupported += 1
            typer.secho(" Saltado (Lenguaje no soportado)", fg=typer.colors.YELLOW)
            repositories_list.append(repo_model)
            continue
            
        # 2. Clonar repositorio
        repo_path = analyzer.clone_repository(clone_url, repo_name)
        if not repo_path:
            repo_model.status = "failed"
            summary.failed += 1
            typer.secho(" Error al clonar", fg=typer.colors.RED)
            repositories_list.append(repo_model)
            continue
            
        # 3. Crear base de datos CodeQL
        db_path = analyzer.workspace / f"{repo_name}_db"
        sarif_path = analyzer.workspace / f"{repo_name}.sarif"
        
        if not analyzer.create_database(repo_path, codeql_lang, db_path):
            repo_model.status = "failed"
            summary.failed += 1
            typer.secho(" Error al crear DB de CodeQL", fg=typer.colors.RED)
            analyzer.cleanup(repo_path)
            analyzer.cleanup(db_path)
            repositories_list.append(repo_model)
            continue
            
        # 4. Analizar con CodeQL
        if not analyzer.analyze_database(db_path, sarif_path):
            repo_model.status = "failed"
            summary.failed += 1
            typer.secho(" Error en análisis CodeQL", fg=typer.colors.RED)
            analyzer.cleanup(repo_path)
            analyzer.cleanup(db_path)
            repositories_list.append(repo_model)
            continue
            
        # 5. Parsear resultados SARIF
        findings = parse_sarif(sarif_path)
        
        # Orden reproducible: por archivo, luego línea, luego regla
        findings.sort(key=lambda x: (x.file, x.start_line, x.rule_id))
        
        repo_model.findings = findings
        repo_model.status = "analyzed"
        summary.analyzed += 1
        summary.findings += len(findings)
        
        typer.secho(f" ¡Listo! ({len(findings)} hallazgos)", fg=typer.colors.GREEN)
        
        # Limpieza de temporales (repo_path está comentado para retener el código fuente para Syft)
        # analyzer.cleanup(repo_path)
        analyzer.cleanup(db_path)
        analyzer.cleanup(sarif_path)
        
        repositories_list.append(repo_model)

    # Orden reproducible: repositorios ordenados alfabéticamente
    repositories_list.sort(key=lambda r: r.name.lower())

    # Generar el modelo final
    report = OrganizationReport(
        organization=organization,
        summary=summary,
        repositories=repositories_list
    )

    # Escribir el JSON de salida usando Pydantic
    try:
        with open(output, "w", encoding="utf-8") as f:
            # model_dump_json serializa correctamente nuestras clases de Pydantic
            f.write(report.model_dump_json(indent=2))
        typer.secho(f"\nProceso finalizado. Resultados guardados en {output}", fg=typer.colors.BLUE, bold=True)
    except Exception as e:
        typer.secho(f"\nError al guardar el archivo JSON: {e}", fg=typer.colors.RED)


@app.command()
def sbom(
    organization: str = typer.Option(..., "--organization", help="Nombre de la organización de GitHub"),
    sbom_dir: Path = typer.Option(..., "--sbom-dir", help="Directorio donde se guardarán los archivos SBOM"),
    output: Path = typer.Option(..., "--output", help="Archivo JSON general de resultados")
):
    """
    Genera un SBOM (Software Bill of Materials) usando Syft para cada repositorio.
    """
    typer.secho(f"Iniciando generación de SBOMs para: {organization}", fg=typer.colors.BLUE)
    
    # Crear directorio para los SBOMs si no existe
    sbom_dir.mkdir(parents=True, exist_ok=True)
    
    try:
        repos_data = get_repositories(organization)
        typer.secho(f"Se encontraron {len(repos_data)} repositorios.", fg=typer.colors.CYAN)
    except Exception as e:
        typer.secho(f"Error al conectar con GitHub API: {e}", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    analyzer = CodeQLAnalyzer()
    syft_version = analyzer.get_syft_version()
    summary = Summary(repositories=len(repos_data))
    repositories_list = []

    for repo_info in repos_data:
        repo_name = repo_info["name"]
        # Armamos el full_name si la API no lo trajo directamente
        full_name = repo_info.get("full_name", f"{organization}/{repo_name}")
        clone_url = repo_info["clone_url"]
        github_lang = repo_info["language"]
        
        repo_path = analyzer.workspace / repo_name
        
        typer.echo(f"Procesando SBOM para: {repo_name}...", nl=False)
        
        repo_model = Repository(
            name=repo_name,
            full_name=full_name,
            url=repo_info.get("url", clone_url),
            status="pending",
            languages=[github_lang] if github_lang else []
        )
        
        # Reutilizar repositorio clonado, si no existe, lo clonamos rápidamente
        if not repo_path.exists():
            repo_path = analyzer.clone_repository(clone_url, repo_name)
            
        if not repo_path or not repo_path.exists():
            repo_model.status = "failed"
            summary.failed += 1
            typer.secho(" Error: Repositorio no encontrado o no se pudo clonar", fg=typer.colors.RED)
            repositories_list.append(repo_model)
            continue
            
        # Generar SBOM
        sbom_file_path = sbom_dir / f"{repo_name}_sbom.json"
        sbom_result = analyzer.generate_sbom(repo_path, sbom_file_path)
        
        # Guardar metadatos en el modelo Pydantic
        repo_model.sbom = SbomInfo(
            commit=analyzer.get_commit_hash(repo_path),
            generation_date=datetime.now().isoformat(),
            syft_version=syft_version,
            status=sbom_result["status"],
            components_count=sbom_result["count"],
            sbom_path=str(sbom_file_path) if sbom_result["status"] != "failed" else None
        )
        
        repo_model.status = "analyzed"
        summary.analyzed += 1
        
        # Mostrar el resultado por consola
        if sbom_result["status"] == "success":
            typer.secho(f" ¡Listo! ({sbom_result['count']} componentes)", fg=typer.colors.GREEN)
        elif sbom_result["status"] == "no_components":
            typer.secho(" ¡Listo! (0 componentes detectados)", fg=typer.colors.YELLOW)
        else:
            typer.secho(" Error al generar SBOM", fg=typer.colors.RED)
            
        repositories_list.append(repo_model)

    # Ordenar alfabéticamente para mantener la reproducibilidad
    repositories_list.sort(key=lambda r: r.name.lower())

    report = OrganizationReport(
        organization=organization,
        summary=summary,
        repositories=repositories_list
    )

    try:
        # exclude_none=True evita que se impriman valores nulos (como findings en el reporte de SBOM)
        with open(output, "w", encoding="utf-8") as f:
            f.write(report.model_dump_json(indent=2, exclude_none=True))
        typer.secho(f"\nProceso finalizado. SBOMs generados en '{sbom_dir}/' y JSON consolidado en '{output}'", fg=typer.colors.BLUE, bold=True)
    except Exception as e:
        typer.secho(f"\nError al guardar: {e}", fg=typer.colors.RED)