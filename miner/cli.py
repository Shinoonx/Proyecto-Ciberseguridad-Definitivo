import typer
from pathlib import Path
from .github import get_repositories

app = typer.Typer(help="Miner de vulnerabilidades para organizaciones de GitHub")

@app.callback()
def callback():
    pass

@app.command()
def scan(
    organization: str = typer.Option(..., "--organization", help="Nombre de la organización de GitHub"),
    output: Path = typer.Option(..., "--output", help="Archivo JSON de salida")
):
    typer.echo(f"Iniciando análisis para la organización: {organization}")
    
    try:
        repos = get_repositories(organization)
        typer.echo(f"Se encontraron {len(repos)} repositorios.")
        
        # Mostramos los primeros 5 para no saturar la terminal
        for repo in repos[:5]:
            typer.echo(f" - {repo['name']} (Lenguaje principal: {repo['language']})")
            
        if len(repos) > 5:
            typer.echo(f"   ... y {len(repos) - 5} más.")
            
    except Exception as e:
        typer.secho(f"Error crítico: {e}", fg=typer.colors.RED)
        raise typer.Exit(code=1)