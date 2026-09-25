# GitHub CodeQL & SBOM Miner

Herramienta automatizada en Python para realizar análisis de vulnerabilidades con **CodeQL** sobre los repositorios de una organización de GitHub y generar un **SBOM** (Software Bill of Materials) en formato **CycloneDX JSON** por repositorio usando **Syft**. 

Este proyecto fue desarrollado como parte de los requerimientos de evaluación en ingeniería civil informática (UFRO, Temuco).

Para cada repositorio la herramienta:
1. Clona el código fuente desde GitHub.
2. Ejecuta un escaneo estático de seguridad (SAST) detectando el lenguaje y creando una base de datos CodeQL.
3. Genera su SBOM con Syft.
4. Registra los hallazgos y el resultado del SBOM en un informe JSON.

La CLI está construida con **Typer** y los datos de salida son modelados y validados estrictamente mediante **Pydantic**.

## Requisitos Previos

- Python 3.10 o superior.
- **git** disponible en el `PATH` para el clonado de los repositorios.
- **CodeQL CLI** disponible en el `PATH` para la creación y análisis de bases de datos.
- **Syft** disponible en el `PATH` para la generación del SBOM.

### Instalación de Syft

Para entornos Arch Linux, puedes instalar la herramienta directamente desde los repositorios oficiales usando pacman:

```bash
sudo pacman -S syft
```

Alternativamente, puedes usar el script oficial para cualquier distribución de Linux/macOS:

```bash
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b ~/.local/bin
```

Confirma que quedó disponible en el `PATH` ejecutando `syft version`.

## Instalación y Configuración

1. Clona este repositorio y accede a la carpeta del proyecto.
2. Activa tu entorno virtual de Python:
   ```bash
   source env/bin/activate
   ```
3. Exporta tu token de acceso personal de GitHub en tu terminal para evitar los límites de tasa de la API.

## Uso de la CLI

La CLI dispone de dos comandos principales para separar la carga de trabajo: `miner scan` y `miner sbom`.

### Análisis de Vulnerabilidades (`miner scan`)
Analiza los repositorios de una organización, filtra los lenguajes soportados y extrae los hallazgos críticos de seguridad detectados por CodeQL.

```bash
miner scan --organization we45 --output reporte_codeql.json
```

### Generación de SBOMs (`miner sbom`)
Genera un SBOM por repositorio reutilizando los repositorios ya clonados, sin volver a ejecutar CodeQL. 

```bash
miner sbom --organization we45 --sbom-dir sboms_we45 --output reporte_sboms.json
```

## Archivos de Salida

### Informe JSON Consolidado
El reporte principal agrupa los resultados en bloques lógicos, incluyendo un resumen (`summary`) con métricas globales, y el detalle de los repositorios (`repositories`).

Dentro de cada repositorio procesado, el objeto `sbom` documenta datos clave:
- Hash del commit analizado (HEAD del clon).
- Fecha y hora exacta de la generación.
- Versión de Syft usada.
- Estado de la ejecución.
- Cantidad de componentes detectados.

### SBOM individuales
Por cada repositorio se escribe un archivo CycloneDX JSON independiente dentro del directorio especificado en los comandos.

### Análisis de Componentes y Dependencias Transitivas
Al contrastar los componentes reportados por Syft en el archivo CycloneDX con los archivos de declaración originales (como `requirements.txt` o `package.json`), es normal observar una cantidad significativamente mayor de componentes. Esto ocurre porque Syft resuelve y lista las **dependencias transitivas** (librerías secundarias requeridas por las librerías principales), ofreciendo un inventario realista y profundo de la superficie de ataque del software.

## Solución de Problemas

- **Token ausente o sin permisos:** La API de GitHub rechazará la conexión impidiendo obtener la lista de repositorios a procesar.
- **`codeql` o `syft` no encontrados:** Si los binarios no están en el `PATH`, la ejecución de los subprocesos fallará, marcando los repositorios con estado de error.
- **SBOM sin componentes (`no_components`):** No es un error; significa que Syft no identificó dependencias. Esto sucede habitualmente si el repositorio no contiene archivos de manifiesto o bloqueo que Syft pueda interpretar.