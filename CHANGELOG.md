# Changelog

## [1.0.0] · 2026-11
### Agregado
- Panel de decisiones: Resumen, Capacidad, Parches, Disponibilidad y Seguridad (Zabbix + Wazuh).
- Modo demostración (`?demo=1`), anónimo (`?anon=1`) y pantalla (`?tv=1`); temas claro y oscuro.
- Decoders y reglas de Wazuh para MikroTik RouterOS 7 (100800–100811) y bloque *Perímetro* del panel.
- Script RouterOS para enviar logs y registrar intentos TCP desde internet.
- Regla opcional 100900 para bajar a nivel 7 el ruido del detector de vulnerabilidades.
- Pruebas de decoders sin Wazuh, validación de higiene del repositorio y CI.
