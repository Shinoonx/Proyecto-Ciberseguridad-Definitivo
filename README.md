# Vulnerability Miner

Miner automatizado en Python que consulta repositorios de una organización en GitHub, los clona y ejecuta análisis estático de vulnerabilidades utilizando CodeQL, consolidando los hallazgos en un reporte JSON.

## Requisitos Previos

- Python 3.10 o superior.
- Git instalado.
- [CodeQL CLI](https://codeql.github.com/docs/codeql-cli/getting-started-with-the-codeql-cli/) instalado y disponible en el `PATH`.
- Un Token de Acceso Personal (Classic) de GitHub con el alcance `repo`.

## Instalación

1. Clona este repositorio.
2. Crea y activa un entorno virtual:
   ```bash
   python -m venv env
   source env/bin/activate