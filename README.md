# Análisis de Logs de Seguridad

Este proyecto es un script en Python diseñado para analizar archivos de log desde una perspectiva de ciberseguridad. Permite detectar actividad sospechosa como múltiples intentos fallidos de inicio de sesión, IPs con alta actividad en períodos cortos de tiempo y accesos a rutas críticas.

## Características

- **Detección de IPs sospechosas:** Identifica direcciones IP que realizan demasiadas solicitudes en un período breve.
- **Intentos de login fallidos:** Identifica IPs con un número excesivo de intentos de inicio de sesión fallidos.
- **Acceso a rutas críticas:** Detecta accesos a rutas sensibles del sistema (por ejemplo, `/admin`, `/etc/passwd`).
- **Personalización de umbrales:** Permite configurar los límites de actividad sospechosa.

## Requisitos

- Python 3.7 o superior.

### Dependencias

El script utiliza únicamente bibliotecas estándar de Python, por lo que no requiere instalaciones adicionales.

## Uso

1. **Preparar el archivo de logs**
   - Asegúrate de tener un archivo de logs en formato de texto (por ejemplo, `server.log`). Este archivo debe incluir las direcciones IP y marcas de tiempo en el formato `YYYY-MM-DD HH:MM:SS`.

2. **Configurar parámetros**
   - En el script, puedes ajustar las siguientes configuraciones:
     - `LOG_FILE`: Nombre del archivo de logs.
     - `THRESHOLD_REQUESTS`: Número de solicitudes por IP en un período breve para considerarlas sospechosas.
     - `THRESHOLD_LOGIN_ATTEMPTS`: Número de intentos fallidos de inicio de sesión antes de marcarlos como sospechosos.
     - `TIME_WINDOW`: Ventana de tiempo para evaluar la actividad sospechosa.

3. **Ejecutar el script**
   ```bash
   python log_analyzer.py
   ```

4. **Resultados**
   El script imprimirá:
   - Direcciones IP con actividad sospechosa.
   - Direcciones IP con múltiples intentos fallidos de inicio de sesión.
   - Logs de accesos a rutas críticas.

## Ejemplo de salida

```
=== Análisis de Seguridad ===
Sospechosas IPs con alta actividad: {'192.168.1.100', '203.0.113.45'}
Sospechosas IPs con múltiples fallos de login: {'192.168.1.100': 6}
Accesos a rutas críticas:
2024-12-27 15:00:12 /admin - 192.168.1.200
```

## Posibles Mejoras

- Soporte para múltiples formatos de logs (Apache, Nginx, SSH, etc.).
- Análisis en tiempo real usando bibliotecas como `watchdog`.
- Exportación de resultados en JSON o CSV.
- Integración con sistemas de alerta como correos electrónicos o mensajes a través de Slack o Telegram.
- Conexión con herramientas avanzadas de análisis como Splunk o Elastic Stack.

## Aplicaciones

Este script es útil para:
- Monitoreo de servidores en tiempo real.
- Auditorías de seguridad.
- Análisis forense tras incidentes.
- Protección activa de sistemas mediante detección y respuesta.

## Licencia

Este proyecto está bajo la Licencia MIT. Puedes usar, modificar y distribuir libremente el código.

---

Si tienes preguntas o necesitas ayuda, no dudes en ponerte en contacto.
