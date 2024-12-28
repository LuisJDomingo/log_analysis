import re
from collections import defaultdict
from datetime import datetime, timedelta

# Configuración principal del análisis de logs
LOG_FILE = "server.log"  # Archivo de logs a analizar
THRESHOLD_REQUESTS = 100  # Número de solicitudes en un periodo corto consideradas sospechosas
THRESHOLD_LOGIN_ATTEMPTS = 5  # Número de intentos fallidos de login antes de marcar como sospechoso
TIME_WINDOW = timedelta(minutes=5)  # Ventana de tiempo para detectar actividad sospechosa

# Expresiones regulares para extraer información relevante de los logs
IP_REGEX = re.compile(r'(\d{1,3}\.){3}\d{1,3}')  # Para identificar direcciones IP
LOGIN_FAILED_REGEX = re.compile(r'failed login', re.IGNORECASE)  # Para identificar intentos fallidos de login
CRITICAL_ACCESS_REGEX = re.compile(r'(/admin|/config|/etc/passwd)', re.IGNORECASE)  # Para detectar accesos a rutas críticas

def parse_logs(file_path):
    """
    Lee el archivo de logs y retorna las líneas del archivo.
    
    :param file_path: Ruta del archivo de logs
    :return: Lista de líneas del archivo
    """
    with open(file_path, 'r') as file:
        logs = file.readlines()
    return logs

def analyze_logs(logs):
    """
    Analiza las líneas de log para extraer actividad por IP, intentos fallidos y accesos críticos.
    
    :param logs: Lista de líneas del archivo de logs
    :return: Tupla con actividad por IP, intentos fallidos, y accesos a rutas críticas
    """
    ip_activity = defaultdict(list)  # Diccionario para almacenar actividad por IP
    failed_logins = defaultdict(int)  # Diccionario para contar intentos fallidos por IP
    critical_access = []  # Lista para guardar accesos a rutas críticas

    for log in logs:
        # Buscar direcciones IP en cada línea de log
        ip_match = IP_REGEX.search(log)
        if ip_match:
            ip = ip_match.group()
            # Extraer la marca de tiempo de la línea
            timestamp_match = re.search(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}', log)
            if timestamp_match:
                timestamp = datetime.strptime(timestamp_match.group(), '%Y-%m-%d %H:%M:%S')
                ip_activity[ip].append(timestamp)  # Registrar actividad por IP
        
        # Detectar intentos fallidos de login
        if LOGIN_FAILED_REGEX.search(log):
            if ip_match:
                ip = ip_match.group()
                failed_logins[ip] += 1  # Incrementar el contador de fallos para esta IP
        
        # Detectar accesos a rutas críticas
        if CRITICAL_ACCESS_REGEX.search(log):
            critical_access.append(log)  # Añadir línea sospechosa a la lista

    return ip_activity, failed_logins, critical_access

def detect_suspicious_activity(ip_activity, failed_logins):
    """
    Identifica actividad sospechosa en base a actividad por IP y fallos de login.
    
    :param ip_activity: Diccionario con actividad por IP
    :param failed_logins: Diccionario con intentos fallidos por IP
    :return: Conjuntos de IPs sospechosas y fallos de login reiterados
    """
    suspicious_ips = set()  # Conjunto para almacenar IPs sospechosas
    for ip, timestamps in ip_activity.items():
        timestamps.sort()  # Ordenar las marcas de tiempo
        for i in range(len(timestamps)):
            # Verificar si se excede el umbral en la ventana de tiempo
            if i + THRESHOLD_REQUESTS <= len(timestamps):
                if timestamps[i + THRESHOLD_REQUESTS - 1] - timestamps[i] <= TIME_WINDOW:
                    suspicious_ips.add(ip)
                    break
    
    # Filtrar IPs con intentos fallidos reiterados
    repeated_failed_logins = {ip: count for ip, count in failed_logins.items() if count > THRESHOLD_LOGIN_ATTEMPTS}

    return suspicious_ips, repeated_failed_logins

def main():
    """
    Función principal para ejecutar el análisis de seguridad sobre los logs.
    """
    logs = parse_logs(LOG_FILE)  # Leer los logs desde el archivo configurado
    ip_activity, failed_logins, critical_access = analyze_logs(logs)  # Analizar los logs
    suspicious_ips, repeated_failed_logins = detect_suspicious_activity(ip_activity, failed_logins)  # Detectar actividad sospechosa

    # Imprimir los resultados del análisis
    print("\n=== Análisis de Seguridad ===")
    print(f"Sospechosas IPs con alta actividad: {suspicious_ips}")
    print(f"Sospechosas IPs con múltiples fallos de login: {repeated_failed_logins}")
    print(f"Accesos a rutas críticas:\n" + "\n".join(critical_access))

if __name__ == "__main__":
    main()
