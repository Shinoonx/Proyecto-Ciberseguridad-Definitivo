import json
import typer
from pathlib import Path

from .github import get_repositories
from .analyzer import CodeQLAnalyzer
from .parser import parse_sarif
from .models import OrganizationReport, Summary, Repository

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
        
        # Limpieza de temporales
        analyzer.cleanup(repo_path)
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