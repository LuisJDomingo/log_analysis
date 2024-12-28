import re
from collections import defaultdict
from datetime import datetime, timedelta

# Configuración
LOG_FILE = "server.log"
THRESHOLD_REQUESTS = 100  # Número de solicitudes por IP en un periodo corto que se consideran sospechosas
THRESHOLD_LOGIN_ATTEMPTS = 5  # Intentos de login fallidos antes de marcar como sospechoso
TIME_WINDOW = timedelta(minutes=5)  # Ventana de tiempo para análisis de actividad sospechosa

# Expresiones regulares para analizar logs
IP_REGEX = re.compile(r'(\d{1,3}\.){3}\d{1,3}')
LOGIN_FAILED_REGEX = re.compile(r'failed login', re.IGNORECASE)
CRITICAL_ACCESS_REGEX = re.compile(r'(/admin|/config|/etc/passwd)', re.IGNORECASE)

def parse_logs(file_path):
    with open(file_path, 'r') as file:
        logs = file.readlines()
    return logs

def analyze_logs(logs):
    ip_activity = defaultdict(list)
    failed_logins = defaultdict(int)
    critical_access = []

    for log in logs:
        # Buscar IPs
        ip_match = IP_REGEX.search(log)
        if ip_match:
            ip = ip_match.group()
            timestamp_match = re.search(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}', log)
            if timestamp_match:
                timestamp = datetime.strptime(timestamp_match.group(), '%Y-%m-%d %H:%M:%S')
                ip_activity[ip].append(timestamp)
        
        # Detectar intentos fallidos de login
        if LOGIN_FAILED_REGEX.search(log):
            if ip_match:
                ip = ip_match.group()
                failed_logins[ip] += 1
        
        # Detectar accesos a rutas críticas
        if CRITICAL_ACCESS_REGEX.search(log):
            critical_access.append(log)

    return ip_activity, failed_logins, critical_access

def detect_suspicious_activity(ip_activity, failed_logins):
    suspicious_ips = set()
    for ip, timestamps in ip_activity.items():
        timestamps.sort()
        for i in range(len(timestamps)):
            if i + THRESHOLD_REQUESTS <= len(timestamps):
                if timestamps[i + THRESHOLD_REQUESTS - 1] - timestamps[i] <= TIME_WINDOW:
                    suspicious_ips.add(ip)
                    break
    
    repeated_failed_logins = {ip: count for ip, count in failed_logins.items() if count > THRESHOLD_LOGIN_ATTEMPTS}
    
    return suspicious_ips, repeated_failed_logins

def main():
    logs = parse_logs(LOG_FILE)
    ip_activity, failed_logins, critical_access = analyze_logs(logs)
    suspicious_ips, repeated_failed_logins = detect_suspicious_activity(ip_activity, failed_logins)

    print("\n=== Análisis de Seguridad ===")
    print(f"Sospechosas IPs con alta actividad: {suspicious_ips}")
    print(f"Sospechosas IPs con múltiples fallos de login: {repeated_failed_logins}")
    print(f"Accesos a rutas críticas:\n" + "\n".join(critical_access))

if __name__ == "__main__":
    main()
