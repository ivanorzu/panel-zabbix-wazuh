# Instalación y uso del panel

Una página que responde cuatro preguntas: **¿qué se llena?, ¿qué parcheo primero?, ¿qué se cae?, ¿qué está pasando en seguridad?**
Se aloja en la VM de Zabbix (Apache + PHP). El navegador solo habla con `api.php`; las claves quedan en el servidor.

Archivos (carpeta `panel/`): `index.html` (la página, un solo archivo), `api.php` (backend de solo lectura), `config.sample.php` (configuración).

> Probalo ya, sin instalar nada: abrí `index.html` en el navegador (o `index.html?demo=1`). Muestra **datos de ejemplo** con una franja amarilla que lo avisa.

## Qué hay en cada pestaña

- **Resumen**: la lista "Qué atender hoy" (ordenada por urgencia × importancia del equipo), 4 indicadores y la matriz de servidores. Es la única pantalla que necesitás abrir cada mañana.
- **Capacidad**: días hasta llenar cada disco, evolución con proyección punteada, RAM y CPU (pico típico), enlaces de internet con proyección hasta 80 % y 100 %.
- **Parches**: críticas y altas por servidor, orden de parcheo sugerido (menor impacto → archivos/Proxmox → DC de a uno → base de datos con imagen previa), CVE que afectan a más equipos, curva de vulnerabilidades en el tiempo.
- **Disponibilidad**: horas caído por equipo, problemas activos, estado de agentes Wazuh, días sin reiniciar, interfaces caídas.
- **Seguridad**: alertas importantes por día, inicios de sesión fallidos (por equipo, IP y usuario), bloqueos de cuenta, búfer saturado (regla 204), reglas que más se repiten.
  Más abajo tiene el bloque **Perímetro** (necesita el syslog del MikroTik, ver el apartado de abajo): conexiones nuevas desde internet por día, IP que más insisten, puertos más buscados y quién entra (o falla) en la administración del router.

Las proyecciones usan Theil–Sen (mediana de pendientes), que no se deja engañar por un pico aislado ni por una limpieza de disco. Cada proyección muestra su confianza (alta/media/baja según qué tan bien sigue una recta); con confianza baja la alerta no se dispara salvo que el disco ya esté al 90 %.

## Uso

- **Resumen**: el tablero de tarjetas muestra cada equipo con su semáforo; tocá una tarjeta (o una fila de la tabla) para abrir el **panel de detalle** (discos con proyección, RAM/CPU, vulnerabilidades, problemas, seguridad). `Esc` lo cierra.
- **Buscar** con la tecla `/` y **filtrar** por severidad en la fila de arriba (solo en Resumen).
- **Auto**: actualiza los datos solo cada 5 minutos.
- **Modo pantalla**: vista limpia a pantalla completa que rota entre pestañas cada 20 s, para dejar en un monitor. También con `?tv=1` en la dirección. Se sale con `Esc`.
- Para ocultar un equipo en baja: `'ignore' => true` en su línea de `meta.roles`.

## Instalación (≈ 20 minutos)

### 1. Copiar archivos (en la VM de Zabbix, 192.168.10.240)

```bash
sudo mkdir -p /var/www/html/panel
sudo cp panel/index.html panel/api.php /var/www/html/panel/
sudo install -d -m 0750 -o root -g www-data /etc/panel-decisiones
sudo install -m 0640 -o root -g www-data panel/config.sample.php /etc/panel-decisiones/config.php
sudo install -d -m 0750 -o www-data -g www-data /var/lib/panel-decisiones
```

PHP necesita `allow_url_fopen = On` (viene activado por defecto). No hace falta ninguna extensión extra.

### 2. Usuario de solo lectura en Zabbix + token

1. *Users → User groups*: crear **panel-lectura** con permiso **Solo lectura** sobre los grupos de hosts a mostrar.
2. *Users → Users*: crear **panel** (rol *User*, grupo panel-lectura).
3. *Users → API tokens*: crear token para **panel** y copiarlo a `zabbix.token` en `/etc/panel-decisiones/config.php`.
4. Ajustar `groups.servers` y `groups.network` con los nombres reales de tus grupos de hosts.

### 3. Usuarios de solo lectura en Wazuh

- **API (puerto 55000)**: Dashboard → *Server management → Security → Users*, crear `panel` con el rol **readonly**.
- **Indexer (puerto 9200)**: Dashboard → *Indexer management → Security*: crear un usuario interno `panel`, un rol con permisos de índice `read` y `indices:data/read/search` sobre `wazuh-alerts-*` y `wazuh-states-vulnerabilities-*`, y mapear el rol al usuario.
- Pegar ambas claves en `config.php`. Lo ideal es verificar el certificado con tu CA (`cafile` + `verify_tls => true`); mientras tanto queda `false`.

### 4. Restringir el acceso (importante)

Sin esto cualquiera de la red ve el estado de tu infraestructura. En Apache:

```apache
<Directory /var/www/html/panel>
    Require ip 192.168.10.0/24
</Directory>
```

Hay un ejemplo completo en `panel/apache.conf.sample` (restricción por IP, usuario y clave opcional, y cabeceras de seguridad). `api.php` solo acepta GET y nunca escribe nada en Zabbix ni Wazuh.

### 5. Registro diario de vulnerabilidades (para la curva de Parches)

```bash
echo '15 6 * * * www-data php /var/www/html/panel/api.php snapshot >> /var/log/panel-snapshot.log 2>&1' | sudo tee /etc/cron.d/panel-decisiones
```

Sin esto todo funciona igual; solo la curva de evolución queda vacía hasta juntar datos.

### 6. Probar

```bash
curl -s 'http://127.0.0.1/panel/api.php?view=meta'
curl -s 'http://127.0.0.1/panel/api.php?view=availability&days=30' | head -c 600
```

Después abrí `http://192.168.10.240/panel/`. Arriba a la derecha hay tres indicadores (Zabbix, Wazuh API, Wazuh índice): si uno falla, pasá el mouse y muestra el motivo. Si una fuente cae, el panel lo dice en vez de mostrar datos vacíos como si todo estuviera bien.

## Perímetro: MikroTik por syslog a Wazuh (opcional)

El bloque Perímetro de Seguridad lee alertas que Wazuh genera a partir del syslog del router. Sin esto el panel funciona igual y muestra un aviso "Todavía no llegan eventos del MikroTik".

- **Wazuh** (`/var/ossec/etc/ossec.conf`): un segundo bloque `<remote>` con `<connection>syslog</connection>`, puerto 514 UDP, `<allowed-ips>` con la IP del router.
- **Decoders y reglas locales** (carpeta `wazuh/` de este repo): `/var/ossec/etc/decoders/mikrotik_decoders.xml` y `/var/ossec/etc/rules/mikrotik_rules.xml` + `mikrotik_rules_fw.xml` (el nombre importa: Wazuh carga los archivos en orden alfabético y la segunda lista depende de la primera). Reglas: 100800 (base, nivel 0), 100801 (login fallido), 100802 (varios fallos de la misma IP), 100803 (login correcto), 100810 (conexión nueva desde internet), 100811 (misma IP insiste: 10 intentos en 5 min).
- **MikroTik** (RouterOS 7, script listo en `mikrotik/syslog-wazuh.rsc`): acción de log remota hacia Wazuh (UDP 514) con los temas `critical`, `error`, `warning`, `account` y `firewall`, y dos reglas de filtro en la cadena `input` que solo registran (`action=log`) los TCP SYN nuevos por cada interfaz pública, con `limit=2,10:packet`, colocadas antes de las reglas que descartan.
- El usuario `panel` del indexer ya lee `wazuh-alerts-*`, no necesita permisos nuevos.

## Ajustes en `config.php`

- `meta.roles`: rol e importancia (`weight`) de cada equipo. Define qué pesa más en "Qué atender hoy" y el orden de parcheo. Viene con nombres de ejemplo (AD, PMS, FILESERVER, ERP, PVE1/2, PBS, etc.): reemplazalos por los de tus equipos.
- `meta.aliases`: si un equipo se llama distinto en Zabbix y en Wazuh (`'nombre-zabbix' => 'nombre-wazuh'`). Los que no coinciden por nombre se cruzan por IP.
- `links`: tus enlaces de internet (host de Zabbix, texto de la interfaz, Mbps contratados). Ej.: `['host'=>'ROUTER-BORDE','match'=>'sfp-sfpplus1','label'=>'ISP principal','capacity_mbps'=>500]`.
- `ignore_ifaces` / `ignore_volumes`: puertos y volúmenes que no querés ver.

## Lo que NO pude comprobar

Se probó contra un simulador de Zabbix y Wazuh armado con las respuestas esperadas, y contra datos de ejemplo; **no contra tus servidores reales**. Los puntos que más probablemente necesiten un retoque:

- Nombres de campos de Wazuh 4.14 en el indexer: `vulnerability.severity`, `vulnerability.id`, `vulnerability.score.base`, `data.win.eventdata.ipAddress` / `targetUserName`. Si una tarjeta de Seguridad o Parches sale vacía, abrí un issue con una alerta de ejemplo (JSON, sin datos sensibles).
- Nombres de ítems de Zabbix: se buscan `vfs.fs.size[...,pused]`, `vm.memory.util`, `system.cpu.util`, `agent.ping`/`icmpping`, `system.uptime` y `net.if.in/out/status`. Son los de las plantillas oficiales; si usás plantillas propias con otras claves, no aparecerán.
- Un equipo con agente Wazuh pero sin Zabbix (o al revés) aparece con "Sin agente" / "Sin Zabbix".

## Seguridad

- Las claves nunca llegan al navegador y `config.php` está fuera del directorio web.
- Usá solo usuarios de solo lectura, distintos de tus administradores.
