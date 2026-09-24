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



   ## Generación de SBOMs (Software Bill of Materials)

El miner ahora incluye la capacidad de generar inventarios de software utilizando [Syft](https://github.com/anchore/syft). Los resultados se exportan en formato CycloneDX JSON.

bash
sudo pacman -S syft
### Instalación de Syft (Arch Linux / General)
Puedes instalar Syft utilizando el gestor de paquetes de Arch Linux:


### Ejecución
Una vez clonados los repositorios, puedes generar los SBOMs reutilizando el espacio de trabajo local:

bash
miner sbom --organization we45 --sbom-dir sboms_we45 --output reporte_sbom_we45.json

### Análisis de Componentes Identificados
**Nota sobre discrepancias en dependencias:** 
Al contrastar los componentes reportados por Syft en el archivo CycloneDX con los archivos de declaración originales (como `requirements.txt` o `package.json`), se observa que Syft reporta una cantidad mayor de componentes. Esto ocurre porque Syft no solo lee las dependencias directas declaradas, sino que también resuelve y lista las **dependencias transitivas** (las librerías que tus librerías necesitan para funcionar), ofreciendo un inventario real y profundo del software.

git add .gitignore README.md
git commit -m "docs: actualizar README y gitignore para entrega de la Tarea 4"