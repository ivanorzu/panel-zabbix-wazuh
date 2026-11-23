# Cómo contribuir

¡Gracias por el interés! Este proyecto nació en un datacenter real y mejora con usos en otros entornos.

## Antes de abrir un issue o PR
- Probá el panel con `panel/index.html?demo=1` para separar problemas de datos de problemas de código.
- **Nunca pegues** IP reales, nombres de equipos, tokens ni claves. Reemplazalos por ejemplos (`192.168.10.x`, `203.0.113.x`).

## Desarrollo local
```bash
python3 tests/test_decoders.py     # decoders de MikroTik (sin Wazuh)
python3 tests/validate_repo.py     # XML, IDs de regla y datos sensibles
php -l panel/api.php
```
El panel es un único `index.html` sin dependencias ni paso de compilación, a propósito: se copia y funciona.

## Convenciones
- Decoders y reglas nuevas: ID dentro de 100000-120000, un caso nuevo en `tests/test_decoders.py` y una nota en `CHANGELOG.md`.
- El backend (`api.php`) es **solo lectura** y solo acepta GET. Un cambio que escriba en Zabbix o Wazuh no se acepta.
- Cada bloque de datos va dentro de `part()` para que el fallo de una fuente no tumbe el resto.
- Textos de la interfaz en español rioplatense neutro.
