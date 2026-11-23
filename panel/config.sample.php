<?php
/**
 * Configuracion del panel. Copiar a /etc/panel-decisiones/config.php
 * (fuera del directorio web) y completar. Permisos recomendados:
 *   sudo install -d -m 0750 -o root -g www-data /etc/panel-decisiones
 *   sudo install -m 0640 -o root -g www-data config.sample.php /etc/panel-decisiones/config.php
 *
 * Usar SIEMPRE usuarios de solo lectura. No reutilizar cuentas de administrador.
 */
return [
    'timezone' => 'America/Asuncion',
    'cache_ttl' => 300,                       // segundos que se reutiliza una consulta
    'snapshot_file' => '/var/lib/panel-decisiones/vulns-history.json',

    'zabbix' => [
        'url' => 'http://127.0.0.1/zabbix',   // la misma VM del Zabbix
        'token' => 'PEGAR_TOKEN_API_DE_SOLO_LECTURA',
        'verify_tls' => true,
    ],

    'wazuh' => [
        'api_url' => 'https://192.168.10.57:55000',
        'api_user' => 'panel',
        'api_pass' => 'PEGAR_CLAVE',
        'indexer_url' => 'https://192.168.10.57:9200',
        'indexer_user' => 'panel',
        'indexer_pass' => 'PEGAR_CLAVE',
        // Certificados autofirmados de Wazuh: lo ideal es verificar con el CA propio.
        //   'cafile' => '/etc/panel-decisiones/root-ca.pem',  + 'verify_tls' => true
        'verify_tls' => false,
        'alerts_index' => 'wazuh-alerts-4.x-*',
        'vuln_index' => 'wazuh-states-vulnerabilities-*',
    ],

    // Grupos de hosts de Zabbix que se consideran "servidores" y "red".
    'groups' => [
        'servers' => ['Servers', 'Windows Server', 'Linux servers', 'Proxmox', 'Backup', 'Zabbix servers'],
        'network' => ['Network Devices'],
    ],

    // Volumenes que NO se proyectan (regex PCRE sobre el nombre del volumen).
    'ignore_volumes' => '~^(/dev|/run|/sys|/proc|/snap|/boot/efi)~',
    // Interfaces de red a ignorar en la lista de "caidas" (puertos sin uso).
    'ignore_ifaces' => '~^(ether(1[0-9]|[2-9][0-9])|sfp-sfpplus[3-9])(\(.*\))?$~',

    // Enlaces a graficar con proyeccion (host de Zabbix, texto del nombre de la
    // interfaz, capacidad contratada). Dejar vacio [] si no se usa.
    'links' => [
        // ['host' => 'ROUTER-BORDE', 'match' => 'sfp-sfpplus1', 'label' => 'ISP principal', 'capacity_mbps' => 500],
    ],

    'meta' => [
        // Rol y peso de cada equipo. role: dc | db | file | app | infra | backup | monitor | other
        // El nombre es el de Zabbix (host) o el del agente de Wazuh, da igual.
        'roles' => [
            'AD'            => ['role' => 'dc',     'weight' => 3, 'label' => 'Controlador de dominio'],
            'AD2'           => ['role' => 'dc',     'weight' => 3, 'label' => 'Controlador de dominio (secundario)'],
            'PMS'           => ['role' => 'db',     'weight' => 5, 'label' => 'PMS / Oracle'],
            'FILESERVER'    => ['role' => 'file',   'weight' => 3, 'label' => 'Archivos'],
            'ERP'           => ['role' => 'app',    'weight' => 2, 'label' => 'ERP'],
            'INTEGRACIONES' => ['role' => 'app',    'weight' => 2, 'label' => 'Integraciones'],
            'ANTIVIRUS'     => ['role' => 'infra',  'weight' => 2, 'label' => 'Consola antivirus'],
            'PVE1'          => ['role' => 'infra',  'weight' => 4, 'label' => 'Proxmox'],
            'PVE2'          => ['role' => 'infra',  'weight' => 4, 'label' => 'Proxmox'],
            'PBS'           => ['role' => 'backup', 'weight' => 3, 'label' => 'Backups (PBS)'],
            'LINUX-BACKUP'  => ['role' => 'backup', 'weight' => 3, 'label' => 'Copias de la base'],
            'zabbix-server' => ['role' => 'monitor','weight' => 2, 'label' => 'Zabbix'],
            'wazuh-server'  => ['role' => 'monitor','weight' => 2, 'label' => 'Wazuh'],
            // 'ignore' => true oculta el equipo de todas las vistas (p. ej. un servidor dado de baja):
            // 'AD-VIEJO'   => ['role' => 'dc', 'weight' => 3, 'label' => 'Anterior', 'ignore' => true],
        ],
        // Si un equipo se llama distinto en Zabbix y en Wazuh: 'nombre-en-zabbix' => 'nombre-en-wazuh'
        'aliases' => [
            // 'ANTIVIRUS-ZBX' => 'ANTIVIRUS',   // nombre en Zabbix => nombre del agente en Wazuh
        ],
    ],
];
