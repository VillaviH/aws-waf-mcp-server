#!/usr/bin/env python3
"""
AWS WAF Logs MCP Server
Analiza logs de AWS WAF y genera reportes utiles
"""

import json
import gzip
import os
from datetime import datetime
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any
import boto3
from fastmcp import FastMCP

mcp = FastMCP("AWS WAF Logs Analyzer")

# Mapeo de codigos ISO de pais a nombre y bandera emoji
COUNTRY_MAP = {
    'US': ('Estados Unidos', '🇺🇸'), 'GB': ('Reino Unido', '🇬🇧'),
    'CA': ('Canada', '🇨🇦'), 'AU': ('Australia', '🇦🇺'),
    'DE': ('Alemania', '🇩🇪'), 'FR': ('Francia', '🇫🇷'),
    'ES': ('Espana', '🇪🇸'), 'IT': ('Italia', '🇮🇹'),
    'BR': ('Brasil', '🇧🇷'), 'MX': ('Mexico', '🇲🇽'),
    'AR': ('Argentina', '🇦🇷'), 'CO': ('Colombia', '🇨🇴'),
    'CL': ('Chile', '🇨🇱'), 'PE': ('Peru', '🇵🇪'),
    'EC': ('Ecuador', '🇪🇨'), 'VE': ('Venezuela', '🇻🇪'),
    'CN': ('China', '🇨🇳'), 'JP': ('Japon', '🇯🇵'),
    'KR': ('Corea del Sur', '🇰🇷'), 'IN': ('India', '🇮🇳'),
    'RU': ('Rusia', '🇷🇺'), 'UA': ('Ucrania', '🇺🇦'),
    'PL': ('Polonia', '🇵🇱'), 'NL': ('Paises Bajos', '🇳🇱'),
    'SE': ('Suecia', '🇸🇪'), 'NO': ('Noruega', '🇳🇴'),
    'FI': ('Finlandia', '🇫🇮'), 'DK': ('Dinamarca', '🇩🇰'),
    'CH': ('Suiza', '🇨🇭'), 'AT': ('Austria', '🇦🇹'),
    'BE': ('Belgica', '🇧🇪'), 'PT': ('Portugal', '🇵🇹'),
    'IE': ('Irlanda', '🇮🇪'), 'GR': ('Grecia', '🇬🇷'),
    'TR': ('Turquia', '🇹🇷'), 'ZA': ('Sudafrica', '🇿🇦'),
    'EG': ('Egipto', '🇪🇬'), 'NG': ('Nigeria', '🇳🇬'),
    'KE': ('Kenia', '🇰🇪'), 'MA': ('Marruecos', '🇲🇦'),
    'TH': ('Tailandia', '🇹🇭'), 'VN': ('Vietnam', '🇻🇳'),
    'PH': ('Filipinas', '🇵🇭'), 'ID': ('Indonesia', '🇮🇩'),
    'MY': ('Malasia', '🇲🇾'), 'SG': ('Singapur', '🇸🇬'),
    'TW': ('Taiwan', '🇹🇼'), 'HK': ('Hong Kong', '🇭🇰'),
    'IL': ('Israel', '🇮🇱'), 'SA': ('Arabia Saudita', '🇸🇦'),
    'AE': ('Emiratos Arabes', '🇦🇪'), 'IR': ('Iran', '🇮🇷'),
    'IQ': ('Irak', '🇮🇶'), 'PK': ('Pakistan', '🇵🇰'),
    'BD': ('Bangladesh', '🇧🇩'), 'NZ': ('Nueva Zelanda', '🇳🇿'),
    'MU': ('Mauricio', '🇲🇺'), 'KH': ('Camboya', '🇰🇭'),
    'SY': ('Siria', '🇸🇾'), 'AL': ('Albania', '🇦🇱'),
    'BY': ('Bielorrusia', '🇧🇾'), 'MN': ('Mongolia', '🇲🇳'),
    'MC': ('Monaco', '🇲🇨'), 'CZ': ('Republica Checa', '🇨🇿'),
    'RO': ('Rumania', '🇷🇴'), 'HU': ('Hungria', '🇭🇺'),
    'BG': ('Bulgaria', '🇧🇬'), 'HR': ('Croacia', '🇭🇷'),
    'RS': ('Serbia', '🇷🇸'), 'SK': ('Eslovaquia', '🇸🇰'),
    'LT': ('Lituania', '🇱🇹'), 'LV': ('Letonia', '🇱🇻'),
    'EE': ('Estonia', '🇪🇪'), 'AZ': ('Azerbaiyan', '🇦🇿'),
    'GE': ('Georgia', '🇬🇪'), 'AM': ('Armenia', '🇦🇲'),
    'UY': ('Uruguay', '🇺🇾'), 'PY': ('Paraguay', '🇵🇾'),
    'BO': ('Bolivia', '🇧🇴'), 'CR': ('Costa Rica', '🇨🇷'),
    'PA': ('Panama', '🇵🇦'), 'DO': ('Rep. Dominicana', '🇩🇴'),
    'GT': ('Guatemala', '🇬🇹'), 'HN': ('Honduras', '🇭🇳'),
    'SV': ('El Salvador', '🇸🇻'), 'NI': ('Nicaragua', '🇳🇮'),
    'CU': ('Cuba', '🇨🇺'), 'JM': ('Jamaica', '🇯🇲'),
    'Unknown': ('Desconocido', '🏳️'),
}


def get_country_display(code: str) -> str:
    """Retorna bandera + nombre del pais dado su codigo ISO"""
    if code in COUNTRY_MAP:
        name, flag = COUNTRY_MAP[code]
        return f"{flag} {name} ({code})"
    return f"🏳️ {code}"


def get_country_html(code: str) -> str:
    """Retorna HTML con bandera + nombre del pais"""
    if code in COUNTRY_MAP:
        name, flag = COUNTRY_MAP[code]
        return f"{flag} {name} <small style='color:#888'>({code})</small>"
    return f"🏳️ {code}"


def parse_timestamp(ts: int) -> str:
    """Convierte timestamp de milisegundos a formato legible"""
    return datetime.fromtimestamp(ts / 1000).strftime('%Y-%m-%d %H:%M:%S')


def load_waf_logs(file_path: str) -> list[dict]:
    """Carga logs de WAF desde archivo (gz o json)"""
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Archivo no encontrado: {file_path}")

    try:
        if path.suffix == '.gz':
            try:
                with gzip.open(path, 'rt') as f:
                    return [json.loads(line) for line in f if line.strip()]
            except gzip.BadGzipFile:
                with open(path, 'r') as f:
                    return [json.loads(line) for line in f if line.strip()]
        else:
            with open(path, 'r') as f:
                return [json.loads(line) for line in f if line.strip()]
    except Exception as e:
        raise ValueError(f"Error al leer archivo: {str(e)}")


def load_all_logs_from_directory(directory: str) -> list[dict]:
    """Carga todos los logs .gz de un directorio recursivamente"""
    all_logs = []
    base = Path(directory)
    if not base.exists():
        raise FileNotFoundError(f"Directorio no encontrado: {directory}")

    for root, dirs, files in os.walk(directory):
        for f in sorted(files):
            if f.endswith('.gz'):
                filepath = os.path.join(root, f)
                try:
                    with gzip.open(filepath, 'rt') as gf:
                        for line in gf:
                            if line.strip():
                                all_logs.append(json.loads(line))
                except Exception:
                    pass
    return all_logs


@mcp.tool()
def analyze_waf_logs(file_path: str) -> str:
    """
    Analiza un archivo de logs de WAF y genera un reporte completo

    Args:
        file_path: Ruta al archivo de logs (.gz o .json)
    """
    logs = load_waf_logs(file_path)

    if not logs:
        return "No se encontraron logs en el archivo"

    actions = Counter(log.get('action') for log in logs)
    blocked_rules = Counter()
    blocked_uris = Counter()
    blocked_ips = Counter()
    blocked_countries = Counter()
    methods = Counter()

    for log in logs:
        if log.get('action') == 'BLOCK':
            rule = log.get('terminatingRuleId', 'Unknown')
            blocked_rules[rule] += 1
            uri = log.get('httpRequest', {}).get('uri', 'Unknown')
            blocked_uris[uri] += 1
            ip = log.get('httpRequest', {}).get('clientIP', 'Unknown')
            blocked_ips[ip] += 1
            country = log.get('httpRequest', {}).get('country', 'Unknown')
            blocked_countries[country] += 1

        method = log.get('httpRequest', {}).get('httpMethod', 'Unknown')
        methods[method] += 1

    report = []
    report.append("=" * 60)
    report.append("REPORTE DE LOGS AWS WAF")
    report.append("=" * 60)
    report.append(f"\nArchivo: {Path(file_path).name}")
    report.append(f"Total de requests: {len(logs)}")
    report.append(f"Permitidos (ALLOW): {actions.get('ALLOW', 0)}")
    report.append(f"Bloqueados (BLOCK): {actions.get('BLOCK', 0)}")

    if actions.get('BLOCK', 0) > 0:
        block_rate = (actions['BLOCK'] / len(logs)) * 100
        report.append(f"Tasa de bloqueo: {block_rate:.2f}%")

    if blocked_rules:
        report.append(f"\nTOP REGLAS QUE BLOQUEARON:")
        for rule, count in blocked_rules.most_common(5):
            report.append(f"   {rule}: {count} bloqueos")

    if blocked_uris:
        report.append(f"\nTOP URIs BLOQUEADAS:")
        for uri, count in blocked_uris.most_common(5):
            report.append(f"   {uri}: {count} veces")

    if blocked_ips:
        report.append(f"\nTOP IPs BLOQUEADAS:")
        for ip, count in blocked_ips.most_common(5):
            report.append(f"   {ip}: {count} intentos")

    if blocked_countries:
        report.append(f"\nPAISES BLOQUEADOS:")
        for country, count in blocked_countries.most_common():
            report.append(f"   {country}: {count} requests")

    report.append(f"\nMETODOS HTTP:")
    for method, count in methods.most_common():
        report.append(f"   {method}: {count} requests")

    report.append("\n" + "=" * 60)
    return "\n".join(report)


@mcp.tool()
def get_blocked_requests(file_path: str, limit: int = 10) -> str:
    """
    Lista los requests bloqueados con detalles

    Args:
        file_path: Ruta al archivo de logs
        limit: Numero maximo de requests a mostrar (default: 10)
    """
    logs = load_waf_logs(file_path)
    blocked = [log for log in logs if log.get('action') == 'BLOCK']

    if not blocked:
        return "No hay requests bloqueados en este archivo"

    report = []
    report.append("REQUESTS BLOQUEADOS\n")

    for i, log in enumerate(blocked[:limit], 1):
        ts = parse_timestamp(log.get('timestamp', 0))
        req = log.get('httpRequest', {})
        report.append(f"#{i} - {ts}")
        report.append(f"   IP: {req.get('clientIP', 'Unknown')}")
        report.append(f"   Pais: {req.get('country', 'Unknown')}")
        report.append(f"   Metodo: {req.get('httpMethod', 'Unknown')}")
        report.append(f"   URI: {req.get('uri', 'Unknown')}")
        report.append(f"   Regla: {log.get('terminatingRuleId', 'Unknown')}")
        report.append("")

    if len(blocked) > limit:
        report.append(f"... y {len(blocked) - limit} requests bloqueados mas")

    return "\n".join(report)


@mcp.tool()
def search_by_ip(file_path: str, ip_address: str) -> str:
    """
    Busca todos los requests de una IP especifica

    Args:
        file_path: Ruta al archivo de logs
        ip_address: Direccion IP a buscar
    """
    logs = load_waf_logs(file_path)
    ip_logs = [log for log in logs if log.get('httpRequest', {}).get('clientIP') == ip_address]

    if not ip_logs:
        return f"No se encontraron requests de la IP {ip_address}"

    report = []
    report.append(f"REQUESTS DE IP: {ip_address}")
    report.append(f"Total: {len(ip_logs)} requests\n")

    actions = Counter(log.get('action') for log in ip_logs)
    report.append(f"Permitidos: {actions.get('ALLOW', 0)}")
    report.append(f"Bloqueados: {actions.get('BLOCK', 0)}\n")

    for i, log in enumerate(ip_logs[:20], 1):
        ts = parse_timestamp(log.get('timestamp', 0))
        req = log.get('httpRequest', {})
        action = log.get('action')
        emoji = "[ALLOW]" if action == "ALLOW" else "[BLOCK]"
        report.append(f"{emoji} {ts} - {req.get('httpMethod')} {req.get('uri')}")
        if action == "BLOCK":
            report.append(f"   Regla: {log.get('terminatingRuleId')}")

    return "\n".join(report)


@mcp.tool()
def search_by_uri(file_path: str, uri_pattern: str) -> str:
    """
    Busca requests que contengan un patron en la URI

    Args:
        file_path: Ruta al archivo de logs
        uri_pattern: Patron a buscar en la URI (ej: /livewire, .env)
    """
    logs = load_waf_logs(file_path)
    matching = [log for log in logs if uri_pattern in log.get('httpRequest', {}).get('uri', '')]

    if not matching:
        return f"No se encontraron requests con URI que contenga '{uri_pattern}'"

    report = []
    report.append(f"REQUESTS CON URI: *{uri_pattern}*")
    report.append(f"Total: {len(matching)} requests\n")

    actions = Counter(log.get('action') for log in matching)
    report.append(f"Permitidos: {actions.get('ALLOW', 0)}")
    report.append(f"Bloqueados: {actions.get('BLOCK', 0)}\n")

    for i, log in enumerate(matching[:20], 1):
        ts = parse_timestamp(log.get('timestamp', 0))
        req = log.get('httpRequest', {})
        action = log.get('action')
        emoji = "[ALLOW]" if action == "ALLOW" else "[BLOCK]"
        report.append(f"{emoji} {ts}")
        report.append(f"   IP: {req.get('clientIP')}")
        report.append(f"   {req.get('httpMethod')} {req.get('uri')}")
        if action == "BLOCK":
            report.append(f"   Regla: {log.get('terminatingRuleId')}")
        report.append("")

    return "\n".join(report)


@mcp.tool()
def get_rule_details(file_path: str, rule_name: str) -> str:
    """
    Muestra detalles de una regla especifica

    Args:
        file_path: Ruta al archivo de logs
        rule_name: Nombre de la regla (ej: BlockSuspiciousCountries)
    """
    logs = load_waf_logs(file_path)
    rule_logs = [log for log in logs if log.get('terminatingRuleId') == rule_name]

    if not rule_logs:
        return f"No se encontraron requests bloqueados por la regla '{rule_name}'"

    report = []
    report.append(f"REGLA: {rule_name}")
    report.append(f"Total bloqueados: {len(rule_logs)}\n")

    ips = Counter(log.get('httpRequest', {}).get('clientIP') for log in rule_logs)
    report.append("Top IPs bloqueadas:")
    for ip, count in ips.most_common(5):
        report.append(f"   {ip}: {count} veces")

    uris = Counter(log.get('httpRequest', {}).get('uri') for log in rule_logs)
    report.append("\nTop URIs bloqueadas:")
    for uri, count in uris.most_common(5):
        report.append(f"   {uri}: {count} veces")

    countries = Counter(log.get('httpRequest', {}).get('country') for log in rule_logs)
    if countries:
        report.append("\nPaises:")
        for country, count in countries.most_common():
            report.append(f"   {country}: {count} requests")

    return "\n".join(report)


@mcp.tool()
def download_waf_logs_from_s3(bucket_name: str, prefix: str, output_dir: str = "./waf-logs") -> str:
    """
    Descarga logs de WAF desde S3

    Args:
        bucket_name: Nombre del bucket S3
        prefix: Prefijo de los logs (ej: AWSLogs/123456789/WAFLogs/)
        output_dir: Directorio donde guardar los logs (default: ./waf-logs)
    """
    try:
        s3 = boto3.client('s3')
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        response = s3.list_objects_v2(Bucket=bucket_name, Prefix=prefix)

        if 'Contents' not in response:
            return f"No se encontraron logs en s3://{bucket_name}/{prefix}"

        files = response['Contents']
        downloaded = []

        for obj in files[:10]:
            key = obj['Key']
            filename = Path(key).name
            local_path = output_path / filename
            s3.download_file(bucket_name, key, str(local_path))
            downloaded.append(str(local_path))

        report = []
        report.append(f"Descargados {len(downloaded)} archivos de logs")
        report.append(f"Ubicacion: {output_dir}\n")
        report.append("Archivos:")
        for f in downloaded:
            report.append(f"   {Path(f).name}")

        return "\n".join(report)

    except Exception as e:
        return f"Error al descargar logs: {str(e)}"


@mcp.tool()
def download_day_logs(date: str, output_dir: str = "./waf-logs") -> str:
    """
    Descarga TODOS los logs de WAF de un dia completo desde S3.
    Usa el bucket waf2privateupgrades-waflogbucket-18xw0mubgwqg5 con la estructura
    AWSLogs/year=YYYY/month=MM/day=DD/hour=HH/

    Args:
        date: Fecha en formato YYYY-MM-DD (ej: 2026-05-07)
        output_dir: Directorio base donde guardar los logs (default: ./waf-logs)
    """
    try:
        bucket_name = "waf2privateupgrades-waflogbucket-18xw0mubgwqg5"
        s3 = boto3.client('s3')

        # Parsear fecha
        dt = datetime.strptime(date, '%Y-%m-%d')
        year = dt.strftime('%Y')
        month = dt.strftime('%m')
        day = dt.strftime('%d')

        prefix = f"AWSLogs/year={year}/month={month}/day={day}/"
        day_label = dt.strftime('%b%d').lower()
        final_output = f"{output_dir}/{day_label}"

        output_path = Path(final_output)
        output_path.mkdir(parents=True, exist_ok=True)

        # Paginar resultados para obtener TODOS los archivos
        paginator = s3.get_paginator('list_objects_v2')
        all_objects = []

        for page in paginator.paginate(Bucket=bucket_name, Prefix=prefix):
            if 'Contents' in page:
                all_objects.extend(page['Contents'])

        if not all_objects:
            return f"No se encontraron logs para la fecha {date} en s3://{bucket_name}/{prefix}"

        downloaded = 0
        errors = 0

        for obj in all_objects:
            key = obj['Key']
            filename = Path(key).name
            if not filename.endswith('.gz'):
                continue

            # Extraer hora del path para organizar
            parts = key.split('/')
            hour_part = next((p for p in parts if p.startswith('hour=')), 'hour=00')

            hour_dir = output_path / hour_part
            hour_dir.mkdir(parents=True, exist_ok=True)

            local_path = hour_dir / filename
            try:
                s3.download_file(bucket_name, key, str(local_path))
                downloaded += 1
            except Exception:
                errors += 1

        report = []
        report.append(f"DESCARGA COMPLETADA - {date}")
        report.append(f"{'=' * 50}")
        report.append(f"Archivos descargados: {downloaded}")
        if errors > 0:
            report.append(f"Errores: {errors}")
        report.append(f"Ubicacion: {final_output}")
        report.append(f"Estructura: {final_output}/hour=HH/*.gz")

        # Contar por hora
        report.append(f"\nArchivos por hora:")
        for hour_dir in sorted(output_path.iterdir()):
            if hour_dir.is_dir():
                count = len(list(hour_dir.glob('*.gz')))
                report.append(f"   {hour_dir.name}: {count} archivos")

        return "\n".join(report)

    except ValueError:
        return f"Error: Formato de fecha invalido. Use YYYY-MM-DD (ej: 2026-05-07)"
    except Exception as e:
        return f"Error al descargar logs: {str(e)}"


@mcp.tool()
def analyze_full_day(directory: str) -> str:
    """
    Analiza TODOS los archivos de logs en un directorio (dia completo).
    Genera un reporte consolidado con totales, reglas, IPs, paises, dominios y trafico por hora.

    Args:
        directory: Ruta al directorio con los logs (ej: ./waf-logs/may7)
    """
    logs = load_all_logs_from_directory(directory)

    if not logs:
        return f"No se encontraron logs en {directory}"

    total = len(logs)
    actions = Counter()
    blocked_rules = Counter()
    blocked_uris = Counter()
    blocked_ips = Counter()
    blocked_countries = Counter()
    all_countries = Counter()
    methods = Counter()
    hourly_traffic = defaultdict(lambda: {"allow": 0, "block": 0})
    hosts = Counter()

    for log in logs:
        action = log.get('action', 'UNKNOWN')
        actions[action] += 1

        req = log.get('httpRequest', {})
        method = req.get('httpMethod', 'Unknown')
        methods[method] += 1

        country = req.get('country', 'Unknown')
        all_countries[country] += 1

        # Host header
        headers = req.get('headers', [])
        for h in headers:
            if h.get('name', '').lower() == 'host':
                hosts[h.get('value', 'Unknown')] += 1
                break

        # Hourly
        ts = log.get('timestamp', 0)
        if ts:
            dt = datetime.fromtimestamp(ts / 1000)
            hour = dt.strftime('%H:00')
            if action == 'ALLOW':
                hourly_traffic[hour]['allow'] += 1
            elif action == 'BLOCK':
                hourly_traffic[hour]['block'] += 1

        if action == 'BLOCK':
            rule = log.get('terminatingRuleId', 'Unknown')
            blocked_rules[rule] += 1
            uri = req.get('uri', 'Unknown')
            blocked_uris[uri] += 1
            ip = req.get('clientIP', 'Unknown')
            blocked_ips[ip] += 1
            blocked_countries[country] += 1

    blocked = actions.get('BLOCK', 0)
    allowed = actions.get('ALLOW', 0)
    num_hours = len(hourly_traffic) if hourly_traffic else 1

    report = []
    report.append("=" * 70)
    report.append("REPORTE CONSOLIDADO WAF - DIA COMPLETO")
    report.append("=" * 70)
    report.append(f"\nDirectorio: {directory}")
    report.append(f"Total de requests: {total:,}")
    report.append(f"Permitidos (ALLOW): {allowed:,} ({allowed/total*100:.1f}%)")
    report.append(f"Bloqueados (BLOCK): {blocked:,} ({blocked/total*100:.1f}%)")
    report.append(f"Requests/hora promedio: {total//num_hours:,}")
    report.append(f"Bloqueos/hora promedio: {blocked//num_hours}")

    # Dominios
    report.append(f"\n{'─' * 70}")
    report.append("DOMINIOS (por trafico):")
    for host, count in hosts.most_common(10):
        pct = count / total * 100
        report.append(f"   {host}: {count:,} ({pct:.1f}%)")

    # Trafico por hora
    report.append(f"\n{'─' * 70}")
    report.append("TRAFICO POR HORA (UTC):")
    for hour in sorted(hourly_traffic.keys()):
        data = hourly_traffic[hour]
        report.append(f"   {hour} | Allow: {data['allow']:>5} | Block: {data['block']:>4}")

    # Reglas
    report.append(f"\n{'─' * 70}")
    report.append("REGLAS QUE BLOQUEARON:")
    for rule, count in blocked_rules.most_common(10):
        pct = count / blocked * 100 if blocked > 0 else 0
        report.append(f"   {rule}: {count} ({pct:.1f}%)")

    # Top IPs bloqueadas
    report.append(f"\n{'─' * 70}")
    report.append("TOP 10 IPs BLOQUEADAS:")
    for ip, count in blocked_ips.most_common(10):
        report.append(f"   {ip}: {count} bloqueos")

    # Paises bloqueados
    report.append(f"\n{'─' * 70}")
    report.append("PAISES CON REQUESTS BLOQUEADOS:")
    for country, count in blocked_countries.most_common(15):
        report.append(f"   {country}: {count}")

    # Top URIs bloqueadas
    report.append(f"\n{'─' * 70}")
    report.append("TOP 15 URIs BLOQUEADAS:")
    for uri, count in blocked_uris.most_common(15):
        report.append(f"   {uri}: {count}")

    # Metodos
    report.append(f"\n{'─' * 70}")
    report.append("METODOS HTTP:")
    for method, count in methods.most_common():
        report.append(f"   {method}: {count:,}")

    # Paises top trafico
    report.append(f"\n{'─' * 70}")
    report.append("TOP 10 PAISES POR TRAFICO TOTAL:")
    for country, count in all_countries.most_common(10):
        blocked_c = blocked_countries.get(country, 0)
        report.append(f"   {country}: {count:,} total ({blocked_c} bloqueados)")

    # Estado
    report.append(f"\n{'═' * 70}")
    block_rate = blocked / total * 100 if total > 0 else 0
    if block_rate < 5:
        estado = "NORMAL"
    elif block_rate < 15:
        estado = "ELEVADO"
    else:
        estado = "ALTO - Posible ataque en curso"
    report.append(f"ESTADO: {estado} | Tasa de bloqueo: {block_rate:.2f}%")
    report.append("=" * 70)

    return "\n".join(report)


@mcp.tool()
def detect_attacks(directory: str) -> str:
    """
    Detecta patrones de ataque en los logs de un directorio.
    Busca: .env, .git, path traversal, shells PHP, passwd, wp-login,
    xmlrpc, phpmyadmin, SQL injection, y otros patrones sospechosos.

    Args:
        directory: Ruta al directorio con los logs (ej: ./waf-logs/may7)
    """
    logs = load_all_logs_from_directory(directory)

    if not logs:
        return f"No se encontraron logs en {directory}"

    # Patrones de ataque a buscar
    attack_patterns = {
        '.env': 'Acceso a variables de entorno (credenciales)',
        '.git/': 'Acceso a repositorio Git (codigo fuente)',
        '../': 'Path traversal (acceso a archivos del sistema)',
        'wp-login': 'Fuerza bruta WordPress login',
        'xmlrpc.php': 'Abuso de XML-RPC WordPress',
        'phpmyadmin': 'Acceso a phpMyAdmin',
        'shell': 'Intento de webshell',
        'passwd': 'Acceso a archivos de passwords',
        'eval(': 'Inyeccion de codigo PHP eval',
        'exec(': 'Inyeccion de codigo PHP exec',
        'SELECT ': 'SQL Injection (SELECT)',
        'UNION ': 'SQL Injection (UNION)',
        '/admin': 'Acceso a paneles administrativos',
        'wp-config': 'Acceso a configuracion WordPress',
        '/actuator': 'Spring Boot Actuator (info leak)',
        'sitecore': 'Sitecore CMS scan',
        '.asp': 'Escaneo de archivos ASP',
        'cmd=': 'Command injection',
        '/cgi-bin': 'Escaneo CGI',
        'wlwmanifest': 'WordPress discovery scan',
    }

    results = {}
    for pattern, description in attack_patterns.items():
        matches = []
        for log in logs:
            uri = log.get('httpRequest', {}).get('uri', '')
            if pattern.lower() in uri.lower():
                matches.append({
                    'uri': uri,
                    'action': log.get('action', 'UNKNOWN'),
                    'ip': log.get('httpRequest', {}).get('clientIP', 'Unknown'),
                    'country': log.get('httpRequest', {}).get('country', 'Unknown'),
                    'method': log.get('httpRequest', {}).get('httpMethod', 'Unknown'),
                    'rule': log.get('terminatingRuleId', '-'),
                })
        if matches:
            results[pattern] = {
                'description': description,
                'matches': matches,
                'total': len(matches),
                'blocked': sum(1 for m in matches if m['action'] == 'BLOCK'),
                'allowed': sum(1 for m in matches if m['action'] == 'ALLOW'),
            }

    report = []
    report.append("=" * 70)
    report.append("DETECCION DE ATAQUES Y PATRONES SOSPECHOSOS")
    report.append("=" * 70)
    report.append(f"Directorio: {directory}")
    report.append(f"Total logs analizados: {len(logs):,}\n")

    if not results:
        report.append("No se detectaron patrones de ataque conocidos.")
        return "\n".join(report)

    # Ordenar por riesgo (mas permitidos = mas riesgo)
    sorted_results = sorted(results.items(), key=lambda x: x[1]['allowed'], reverse=True)

    critical = []
    warning = []
    info = []

    for pattern, data in sorted_results:
        if data['allowed'] > 0 and pattern in ['.env', '.git/', '../', 'shell', 'passwd', 'cmd=', 'wp-config']:
            critical.append((pattern, data))
        elif data['allowed'] > 0:
            warning.append((pattern, data))
        else:
            info.append((pattern, data))

    if critical:
        report.append("!!! CRITICO - Ataques que PASARON el WAF:")
        report.append("-" * 70)
        for pattern, data in critical:
            report.append(f"\n  [{pattern}] {data['description']}")
            report.append(f"  Total: {data['total']} | Permitidos: {data['allowed']} | Bloqueados: {data['blocked']}")
            # Mostrar ejemplos permitidos
            allowed_examples = [m for m in data['matches'] if m['action'] == 'ALLOW'][:5]
            for ex in allowed_examples:
                report.append(f"    -> {ex['method']} {ex['uri']}")
                report.append(f"       IP: {ex['ip']} | Pais: {ex['country']}")

    if warning:
        report.append(f"\n\n{'─' * 70}")
        report.append("ADVERTENCIA - Escaneos permitidos (riesgo medio):")
        report.append("-" * 70)
        for pattern, data in warning:
            report.append(f"\n  [{pattern}] {data['description']}")
            report.append(f"  Total: {data['total']} | Permitidos: {data['allowed']} | Bloqueados: {data['blocked']}")

    if info:
        report.append(f"\n\n{'─' * 70}")
        report.append("INFO - Ataques correctamente bloqueados:")
        report.append("-" * 70)
        for pattern, data in info:
            report.append(f"  [{pattern}] {data['description']}: {data['blocked']} bloqueados")

    # Resumen de IPs atacantes
    report.append(f"\n\n{'═' * 70}")
    report.append("TOP IPs ATACANTES (con requests sospechosos permitidos):")
    attacker_ips = Counter()
    for pattern, data in sorted_results:
        for m in data['matches']:
            if m['action'] == 'ALLOW':
                attacker_ips[f"{m['ip']} ({m['country']})"] += 1

    for ip_info, count in attacker_ips.most_common(10):
        report.append(f"   {ip_info}: {count} requests sospechosos permitidos")

    report.append("\n" + "=" * 70)
    return "\n".join(report)


@mcp.tool()
def get_hourly_breakdown(directory: str) -> str:
    """
    Muestra el desglose de trafico y bloqueos por hora de un directorio de logs.
    Util para identificar picos de trafico y horas con mas ataques.

    Args:
        directory: Ruta al directorio con los logs (ej: ./waf-logs/may7)
    """
    logs = load_all_logs_from_directory(directory)

    if not logs:
        return f"No se encontraron logs en {directory}"

    hourly = defaultdict(lambda: {
        "allow": 0, "block": 0, "total": 0,
        "rules": Counter(), "countries": Counter(), "ips": Counter()
    })

    for log in logs:
        ts = log.get('timestamp', 0)
        if not ts:
            continue

        dt = datetime.fromtimestamp(ts / 1000)
        hour = dt.strftime('%H:00')
        action = log.get('action', 'UNKNOWN')
        req = log.get('httpRequest', {})

        hourly[hour]['total'] += 1
        if action == 'ALLOW':
            hourly[hour]['allow'] += 1
        elif action == 'BLOCK':
            hourly[hour]['block'] += 1
            rule = log.get('terminatingRuleId', 'Unknown')
            hourly[hour]['rules'][rule] += 1
            country = req.get('country', 'Unknown')
            hourly[hour]['countries'][country] += 1
            ip = req.get('clientIP', 'Unknown')
            hourly[hour]['ips'][ip] += 1

    report = []
    report.append("=" * 70)
    report.append("DESGLOSE POR HORA")
    report.append("=" * 70)
    report.append(f"Directorio: {directory}\n")

    report.append(f"{'Hora':<8}{'Total':>8}{'Allow':>8}{'Block':>8}{'%Block':>8}  {'Top Regla'}")
    report.append("-" * 70)

    for hour in sorted(hourly.keys()):
        data = hourly[hour]
        block_pct = (data['block'] / data['total'] * 100) if data['total'] > 0 else 0
        top_rule = data['rules'].most_common(1)[0][0] if data['rules'] else '-'
        # Truncar nombre de regla
        if len(top_rule) > 30:
            top_rule = top_rule[:27] + '...'
        report.append(f"{hour:<8}{data['total']:>8,}{data['allow']:>8,}{data['block']:>8}{block_pct:>7.1f}%  {top_rule}")

    # Hora pico
    report.append(f"\n{'─' * 70}")
    max_traffic = max(hourly.items(), key=lambda x: x[1]['total'])
    max_blocks = max(hourly.items(), key=lambda x: x[1]['block'])
    report.append(f"Hora pico trafico: {max_traffic[0]} ({max_traffic[1]['total']:,} requests)")
    report.append(f"Hora pico bloqueos: {max_blocks[0]} ({max_blocks[1]['block']} bloqueos)")

    # Detalle de la hora con mas bloqueos
    report.append(f"\nDetalle hora {max_blocks[0]}:")
    report.append(f"  Reglas activas:")
    for rule, count in max_blocks[1]['rules'].most_common(5):
        report.append(f"    {rule}: {count}")
    report.append(f"  Paises bloqueados:")
    for country, count in max_blocks[1]['countries'].most_common(5):
        report.append(f"    {country}: {count}")

    report.append("\n" + "=" * 70)
    return "\n".join(report)


@mcp.tool()
def generate_html_report(directory: str, output_file: str = "./waf-report.html") -> str:
    """
    Genera un reporte HTML interactivo con graficos y tablas del analisis WAF.
    Incluye graficos de trafico por hora, reglas, paises, y deteccion de ataques.

    Args:
        directory: Ruta al directorio con los logs (ej: ./waf-logs/may7)
        output_file: Ruta del archivo HTML de salida (default: ./waf-report.html)
    """
    logs = load_all_logs_from_directory(directory)

    if not logs:
        return f"No se encontraron logs en {directory}"

    # Recopilar datos
    total = len(logs)
    actions = Counter()
    blocked_rules = Counter()
    blocked_uris = Counter()
    blocked_ips = Counter()
    blocked_countries = Counter()
    all_countries = Counter()
    methods = Counter()
    hourly_traffic = defaultdict(lambda: {"allow": 0, "block": 0})
    hosts = Counter()
    blocked_details = []

    for log in logs:
        action = log.get('action', 'UNKNOWN')
        actions[action] += 1
        req = log.get('httpRequest', {})
        method = req.get('httpMethod', 'Unknown')
        methods[method] += 1
        country = req.get('country', 'Unknown')
        all_countries[country] += 1

        headers = req.get('headers', [])
        for h in headers:
            if h.get('name', '').lower() == 'host':
                hosts[h.get('value', 'Unknown')] += 1
                break

        ts = log.get('timestamp', 0)
        if ts:
            dt = datetime.fromtimestamp(ts / 1000)
            hour = dt.strftime('%H:00')
            if action == 'ALLOW':
                hourly_traffic[hour]['allow'] += 1
            elif action == 'BLOCK':
                hourly_traffic[hour]['block'] += 1

        if action == 'BLOCK':
            rule = log.get('terminatingRuleId', 'Unknown')
            blocked_rules[rule] += 1
            uri = req.get('uri', 'Unknown')
            blocked_uris[uri] += 1
            ip = req.get('clientIP', 'Unknown')
            blocked_ips[ip] += 1
            blocked_countries[country] += 1
            blocked_details.append({
                'ip': ip, 'country': country,
                'method': method, 'uri': uri, 'rule': rule
            })

    blocked = actions.get('BLOCK', 0)
    allowed = actions.get('ALLOW', 0)
    block_rate = blocked / total * 100 if total > 0 else 0

    # Detectar ataques
    attack_patterns = {
        '.env': 'Variables de entorno',
        '.git/': 'Repositorio Git',
        '../': 'Path traversal',
        'shell': 'Webshell',
        'passwd': 'Archivos password',
        'wp-login': 'WP Login brute force',
        'xmlrpc': 'XML-RPC abuse',
        'phpmyadmin': 'phpMyAdmin',
    }
    attacks_found = {}
    for pattern, desc in attack_patterns.items():
        matches = [l for l in logs if pattern.lower() in l.get('httpRequest', {}).get('uri', '').lower()]
        if matches:
            allowed_m = sum(1 for m in matches if m.get('action') == 'ALLOW')
            blocked_m = sum(1 for m in matches if m.get('action') == 'BLOCK')
            attacks_found[pattern] = {'desc': desc, 'total': len(matches), 'allowed': allowed_m, 'blocked': blocked_m}

    # Generar datos para graficos
    hours_sorted = sorted(hourly_traffic.keys())
    hours_labels = json.dumps(hours_sorted)
    hours_allow = json.dumps([hourly_traffic[h]['allow'] for h in hours_sorted])
    hours_block = json.dumps([hourly_traffic[h]['block'] for h in hours_sorted])

    rules_labels = json.dumps([r for r, _ in blocked_rules.most_common(8)])
    rules_data = json.dumps([c for _, c in blocked_rules.most_common(8)])

    countries_labels = json.dumps([get_country_display(c) for c, _ in blocked_countries.most_common(10)])
    countries_data = json.dumps([v for _, v in blocked_countries.most_common(10)])

    # Estado
    if block_rate < 5:
        estado = "NORMAL"
        estado_color = "#27ae60"
        estado_icon = "&#10004;"
    elif block_rate < 15:
        estado = "ELEVADO"
        estado_color = "#f39c12"
        estado_icon = "&#9888;"
    else:
        estado = "CRITICO"
        estado_color = "#e74c3c"
        estado_icon = "&#9888;"

    # Tabla de dominios
    domains_rows = ""
    for host, count in hosts.most_common(10):
        pct = count / total * 100
        domains_rows += f"<tr><td>{host}</td><td>{count:,}</td><td>{pct:.1f}%</td></tr>\n"

    # Tabla de paises trafico total
    traffic_countries_rows = ""
    for country, count in all_countries.most_common(15):
        blocked_c = blocked_countries.get(country, 0)
        pct = count / total * 100
        traffic_countries_rows += f"<tr><td>{get_country_html(country)}</td><td>{count:,}</td><td>{pct:.1f}%</td><td>{blocked_c}</td></tr>\n"

    # Tabla de ataques
    attacks_rows = ""
    for pattern, data in sorted(attacks_found.items(), key=lambda x: x[1]['allowed'], reverse=True):
        risk = "alto" if data['allowed'] > 0 and pattern in ['.env', '.git/', '../', 'shell', 'passwd'] else "medio" if data['allowed'] > 0 else "bajo"
        risk_badge = f'<span class="badge badge-{risk}">{risk.upper()}</span>'
        attacks_rows += f"<tr><td><code>{pattern}</code></td><td>{data['desc']}</td><td>{data['total']}</td><td>{data['allowed']}</td><td>{data['blocked']}</td><td>{risk_badge}</td></tr>\n"

    # Tabla de URIs bloqueadas
    uris_rows = ""
    for uri, count in blocked_uris.most_common(15):
        uris_rows += f"<tr><td><code>{uri}</code></td><td>{count}</td></tr>\n"

    # Tabla de paises bloqueados
    countries_rows = ""
    for country, count in blocked_countries.most_common(15):
        countries_rows += f"<tr><td>{get_country_html(country)}</td><td>{count}</td></tr>\n"

    # Generar HTML
    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reporte WAF - {directory}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #1a1a2e; color: #eee; padding: 20px; }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        h1 {{ text-align: center; margin-bottom: 10px; font-size: 2em; color: #fff; }}
        .subtitle {{ text-align: center; color: #888; margin-bottom: 30px; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .card {{ background: #16213e; border-radius: 12px; padding: 24px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }}
        .card h3 {{ color: #888; font-size: 0.85em; text-transform: uppercase; margin-bottom: 8px; }}
        .card .value {{ font-size: 2.2em; font-weight: bold; }}
        .card .value.green {{ color: #27ae60; }}
        .card .value.red {{ color: #e74c3c; }}
        .card .value.blue {{ color: #3498db; }}
        .card .value.orange {{ color: #f39c12; }}
        .chart-container {{ background: #16213e; border-radius: 12px; padding: 24px; margin-bottom: 30px; }}
        .chart-container h2 {{ margin-bottom: 20px; font-size: 1.3em; }}
        .two-charts {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 30px; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 10px 14px; text-align: left; border-bottom: 1px solid #2a2a4a; }}
        th {{ background: #0f3460; color: #aaa; font-size: 0.85em; text-transform: uppercase; }}
        tr:hover {{ background: #1a1a3e; }}
        code {{ background: #0f3460; padding: 2px 6px; border-radius: 4px; font-size: 0.9em; }}
        .badge {{ padding: 3px 10px; border-radius: 12px; font-size: 0.75em; font-weight: bold; }}
        .badge-alto {{ background: #e74c3c; color: #fff; }}
        .badge-medio {{ background: #f39c12; color: #fff; }}
        .badge-bajo {{ background: #27ae60; color: #fff; }}
        .status-banner {{ text-align: center; padding: 20px; border-radius: 12px; margin-bottom: 30px; background: {estado_color}22; border: 2px solid {estado_color}; }}
        .status-banner .icon {{ font-size: 2em; }}
        .status-banner .label {{ font-size: 1.5em; font-weight: bold; color: {estado_color}; }}
        @media (max-width: 768px) {{ .two-charts {{ grid-template-columns: 1fr; }} }}
    </style>
</head>
<body>
<div class="container">
    <h1>Reporte de Seguridad WAF</h1>
    <p class="subtitle">{directory} | Generado: {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>

    <div class="status-banner">
        <div class="icon">{estado_icon}</div>
        <div class="label">Estado: {estado}</div>
        <div>Tasa de bloqueo: {block_rate:.2f}%</div>
    </div>

    <div class="grid">
        <div class="card"><h3>Total Requests</h3><div class="value blue">{total:,}</div></div>
        <div class="card"><h3>Permitidos</h3><div class="value green">{allowed:,}</div></div>
        <div class="card"><h3>Bloqueados</h3><div class="value red">{blocked:,}</div></div>
        <div class="card"><h3>Tasa de Bloqueo</h3><div class="value orange">{block_rate:.2f}%</div></div>
    </div>

    <div class="chart-container">
        <h2>Trafico por Hora (UTC)</h2>
        <canvas id="hourlyChart" height="80"></canvas>
    </div>

    <div class="two-charts">
        <div class="chart-container">
            <h2>Reglas que Bloquearon</h2>
            <canvas id="rulesChart"></canvas>
        </div>
        <div class="chart-container">
            <h2>Paises Bloqueados</h2>
            <canvas id="countriesChart"></canvas>
        </div>
    </div>

    <div class="chart-container">
        <h2>Deteccion de Ataques</h2>
        <table>
            <thead><tr><th>Patron</th><th>Descripcion</th><th>Total</th><th>Permitidos</th><th>Bloqueados</th><th>Riesgo</th></tr></thead>
            <tbody>{attacks_rows}</tbody>
        </table>
    </div>

    <div class="two-charts">
        <div class="chart-container">
            <h2>Dominios</h2>
            <table>
                <thead><tr><th>Dominio</th><th>Requests</th><th>%</th></tr></thead>
                <tbody>{domains_rows}</tbody>
            </table>
        </div>
        <div class="chart-container">
            <h2>Paises Bloqueados</h2>
            <table>
                <thead><tr><th>Pais</th><th>Bloqueos</th></tr></thead>
                <tbody>{countries_rows}</tbody>
            </table>
        </div>
    </div>

    <div class="chart-container">
        <h2>Trafico por Pais (Top 15)</h2>
        <table>
            <thead><tr><th>Pais</th><th>Total Requests</th><th>%</th><th>Bloqueados</th></tr></thead>
            <tbody>{traffic_countries_rows}</tbody>
        </table>
    </div>

    <div class="chart-container">
        <h2>Top URIs Bloqueadas</h2>
        <table>
            <thead><tr><th>URI</th><th>Bloqueos</th></tr></thead>
            <tbody>{uris_rows}</tbody>
        </table>
    </div>
</div>

<script>
new Chart(document.getElementById('hourlyChart'), {{
    type: 'bar',
    data: {{
        labels: {hours_labels},
        datasets: [
            {{ label: 'Permitidos', data: {hours_allow}, backgroundColor: '#27ae6088', borderColor: '#27ae60', borderWidth: 1 }},
            {{ label: 'Bloqueados', data: {hours_block}, backgroundColor: '#e74c3c88', borderColor: '#e74c3c', borderWidth: 1 }}
        ]
    }},
    options: {{ responsive: true, scales: {{ x: {{ stacked: true }}, y: {{ stacked: true }} }} }}
}});

new Chart(document.getElementById('rulesChart'), {{
    type: 'doughnut',
    data: {{
        labels: {rules_labels},
        datasets: [{{ data: {rules_data}, backgroundColor: ['#e74c3c','#3498db','#f39c12','#9b59b6','#1abc9c','#e67e22','#2ecc71','#34495e'] }}]
    }},
    options: {{ responsive: true, plugins: {{ legend: {{ position: 'bottom', labels: {{ color: '#ccc', font: {{ size: 10 }} }} }} }} }}
}});

new Chart(document.getElementById('countriesChart'), {{
    type: 'bar',
    data: {{
        labels: {countries_labels},
        datasets: [{{ label: 'Bloqueos', data: {countries_data}, backgroundColor: '#e74c3c88', borderColor: '#e74c3c', borderWidth: 1 }}]
    }},
    options: {{ responsive: true, indexAxis: 'y' }}
}});
</script>
</body>
</html>"""

    # Escribir archivo
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding='utf-8')

    return f"Reporte HTML generado exitosamente: {output_file}\nTotal requests analizados: {total:,}\nAbrir en navegador para ver graficos interactivos."


if __name__ == "__main__":
    mcp.run()
