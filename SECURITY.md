# Seguridad

## Reportar una vulnerabilidad
Si encontrás un problema de seguridad en este proyecto, **no abras un issue público**. Usá *Security → Report a vulnerability* de este repositorio (avisos privados de GitHub). Respondo lo antes posible.

## Recomendaciones de despliegue
- Usá solo cuentas **de solo lectura** en Zabbix y Wazuh, distintas de las de administración.
- Guardá `config.php` fuera del directorio web (`/etc/panel-decisiones/`), permisos 0640, grupo `www-data`.
- Restringí el acceso con Apache (`Require ip`) o detrás de VPN; ver `panel/apache.conf.sample`.
- Verificá el certificado de Wazuh con tu CA (`cafile` + `verify_tls`) en lugar de `verify_tls => false`.
- Si un secreto llegó a un chat, issue o commit: revocalo y regeneralo; borrar el commit no alcanza.
