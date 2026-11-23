---
name: Algo no funciona
about: Una tarjeta sale vacía, un error en api.php, un decoder que no extrae campos
labels: bug
---

**Qué esperabas y qué pasó**

**Versiones** (Zabbix, Wazuh, RouterOS, PHP):

**Pasos para reproducirlo**

**Evidencia** (sin IP reales ni nombres de equipos: reemplazalos por ejemplos)
- Resultado de `curl -s 'http://127.0.0.1/panel/api.php?view=meta'`
- Línea de log del MikroTik y salida de `wazuh-logtest`, si es un problema de decoder
