# Vandal - Escáner de Vulnerabilidades Web

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://www.python.org/)
[![Licencia](https://img.shields.io/badge/Licencia-MIT-green.svg)](LICENSE)

## Descripción

**Vandal** es un escáner de vulnerabilidades web que desarrollé para automatizar las tareas de reconocimiento y detección de fallos de seguridad más comunes en aplicaciones web. Lo diseñé pensando en que sea rápido, modular y fácil de usar desde la terminal.

Con un solo comando podés analizar uno o varios objetivos buscando XSS reflejado, inyecciones SQL, headers de seguridad faltantes, subdominios expuestos, URLs históricas y parámetros ocultos. Todo desde la línea de comandos y con salida en JSON si lo necesitás integrar en tu pipeline.

---

## Características

- **Detección de XSS reflejado** con múltiples variantes de payloads
- **Testing de inyección SQL** (basado en errores + basado en tiempo, con payloads seguros)
- **Auditoría de headers de seguridad** (7 headers clave)
- **Enumeración de subdominios** vía logs de Certificate Transparency (crt.sh)
- **Recolección de URLs históricas** desde Wayback Machine
- **Fuzzing de parámetros** con profundidad configurable
- **Detección de WAF** con backoff ante respuestas 403/429
- **Niveles de severidad**: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`
- **Salida en JSON** para integración con otras herramientas
- **Dos modos de escaneo**: rápido (por defecto) y completo
- **Soporte multi-objetivo**: escaneá varias URLs en una sola ejecución

---

## Requisitos

- Python 3.9 o superior
- pip (gestor de paquetes de Python)
- Conexión a internet

---

## Instalación

```bash
git clone https://github.com/44ghost44/Vandal.git
cd Vandal
pip install -r requirements.txt
```

---

## Uso

### Escaneo básico (modo rápido)

```bash
python3 vandal.py https://ejemplo.com
```

### Escaneo completo

```bash
python3 vandal.py https://ejemplo.com --full
```

### Escanear múltiples objetivos

```bash
python3 vandal.py https://ejemplo.com https://otro-sitio.com https://tercer-objetivo.org
```

### Escaneo completo con User-Agent personalizado

```bash
python3 vandal.py https://ejemplo.com --full --user-agent "Mozilla/5.0 (X11; Linux x86_64)"
```

### Escaneo con delay entre requests

```bash
python3 vandal.py https://ejemplo.com --delay 2
```

### Guardar resultados en archivo JSON

```bash
python3 vandal.py https://ejemplo.com --full -o resultados.json
```

### Modo silencioso (solo resultados críticos)

```bash
python3 vandal.py https://ejemplo.com -q
```

### Combinar todo

```bash
python3 vandal.py https://ejemplo.com https://otro-sitio.com --full --delay 1 --user-agent "CustomBot/1.0" -o reporte.json
```

### Ver la versión

```bash
python3 vandal.py -V
```

---

## Flags CLI

| Flag | Descripción |
|------|-------------|
| `URL [URL...]` | Uno o más objetivos a escanear (obligatorio) |
| `--full` | Ejecuta todos los módulos de escaneo (modo completo) |
| `--user-agent UA` | Define un User-Agent personalizado para las peticiones |
| `--delay SECS` | Segundos de espera entre cada petición |
| `-o FILE` | Guarda los resultados en un archivo JSON |
| `-q` | Modo silencioso: suprime la salida detallada |
| `-V` | Muestra la versión de Vandal |

---

## Módulos de escaneo

### XSS Reflejado

Inyecta múltiples variantes de payloads XSS en los parámetros de la URL y analiza si alguno se refleja sin sanitizar en la respuesta. Detecta tanto reflexiones directas como parciales. Severidad: **HIGH** a **CRITICAL**.

### Inyección SQL

Realiza dos tipos de pruebas:

- **Basada en errores**: envía payloads que provocan mensajes de error de bases de datos conocidas (MySQL, PostgreSQL, MSSQL, Oracle, SQLite) y verifica si aparecen en la respuesta.
- **Basada en tiempo**: mide diferencias en el tiempo de respuesta para detectar inyecciones ciegas.

Todos los payloads son seguros y no modifican datos. Severidad: **HIGH** a **CRITICAL**.

### Auditoría de Headers de Seguridad

Verifica la presencia y configuración de 7 headers de seguridad HTTP:

| Header | Propósito |
|--------|-----------|
| `X-Frame-Options` | Prevención de clickjacking |
| `Content-Security-Policy` | Control de recursos cargados |
| `X-XSS-Protection` | Filtro XSS del navegador (legacy) |
| `Strict-Transport-Security` | Forzar HTTPS (HSTS) |
| `X-Content-Type-Options` | Prevención de MIME sniffing |
| `Referrer-Policy` | Control de información del referer |
| `Permissions-Policy` | Restricción de APIs del navegador |

Severidad: **LOW** a **MEDIUM**.

### Enumeración de Subdominios

Consulta los logs de Certificate Transparency a través de **crt.sh** para descubrir subdominios asociados al dominio objetivo. Útil para ampliar la superficie de ataque durante un reconocimiento. Severidad: informativo.

### Recolección de URLs (Wayback Machine)

Obtiene URLs históricas del objetivo desde la **Wayback Machine** de Internet Archive. Permite descubrir endpoints, archivos y rutas que pueden seguir activos o exponer información sensible. Severidad: informativo.

### Fuzzing de Parámetros

Prueba parámetros comunes y personalizados contra el objetivo con profundidad configurable. Busca parámetros ocultos que no están expuestos en la interfaz pero que el servidor acepta y procesa. Severidad: **MEDIUM**.

### Detección de WAF

Identifica la presencia de Web Application Firewalls analizando respuestas con códigos 403 y 429. Implementa backoff automático para evitar bloqueos durante el escaneo.

---

## Tests

El proyecto incluye tests para validar el funcionamiento de los módulos:

```bash
pip install pytest
python3 -m pytest test_vandal.py -v
```

---

## Limitaciones

- La detección es por firmas y heurísticas; pueden ocurrir falsos positivos y falsos negativos.
- No reemplaza un pentest manual ni herramientas como Burp Suite.
- Single-threaded: listas grandes de objetivos van a tardar.
- La enumeración de subdominios depende de la disponibilidad de crt.sh.
- La recolección de URLs históricas está sujeta a la cobertura de Wayback Machine.

---

## Aviso Legal

Esta herramienta fue creada con fines **educativos y de investigación en seguridad**. Usala únicamente en sistemas para los cuales tenés autorización explícita por escrito. El uso no autorizado contra sistemas de terceros es ilegal y puede tener consecuencias legales graves. No me hago responsable del mal uso que se le pueda dar a esta herramienta.

**Usá Vandal de forma ética y responsable.**

---

## Autor

**Alan Newberry** (alias `44ghost44`)

---

## Licencia

Este proyecto está bajo la licencia [MIT](LICENSE).
