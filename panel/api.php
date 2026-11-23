<?php
/**
 * Panel de decisiones - backend de solo lectura.
 *
 * Consulta Zabbix (API JSON-RPC) y Wazuh (API + indexer) desde el servidor,
 * de modo que las credenciales nunca viajan al navegador. Devuelve JSON ya
 * agregado para index.html.
 *
 *   GET api.php?view=meta
 *   GET api.php?view=capacity&days=60
 *   GET api.php?view=availability&days=60
 *   GET api.php?view=patches
 *   GET api.php?view=security&days=30
 *   CLI: php api.php snapshot     (cron diario: guarda el historial de vulnerabilidades)
 *
 * Solo hace consultas de lectura. No acepta parametros que lleguen a Zabbix o
 * Wazuh sin validar.
 */
declare(strict_types=1);

const PANEL_VERSION = '1.0';

class PanelError extends RuntimeException
{
    public string $source;
    public function __construct(string $source, string $message)
    {
        parent::__construct($message);
        $this->source = $source;
    }
}

/* ------------------------------------------------------------------ config */

$cfgFile = getenv('PANEL_CONFIG') ?: '';
if ($cfgFile === '') {
    $cfgFile = is_file('/etc/panel-decisiones/config.php') ? '/etc/panel-decisiones/config.php' : __DIR__ . '/config.php';
}
$CFG = is_file($cfgFile) ? require $cfgFile : [];

function cfg(string $path, $default = null)
{
    global $CFG;
    $cur = $CFG;
    foreach (explode('.', $path) as $k) {
        if (!is_array($cur) || !array_key_exists($k, $cur)) {
            return $default;
        }
        $cur = $cur[$k];
    }
    return $cur;
}

date_default_timezone_set((string) cfg('timezone', 'America/Asuncion'));

/* -------------------------------------------------------------------- http */

function http_request(string $source, string $method, string $url, array $headers, ?string $body, bool $verify, ?string $cafile = null, int $timeout = 40): array
{
    $ssl = ['verify_peer' => $verify, 'verify_peer_name' => $verify];
    if ($verify && $cafile) {
        $ssl['cafile'] = $cafile;
    }
    $opts = [
        'http' => ['method' => $method, 'header' => implode("\r\n", $headers), 'timeout' => $timeout, 'ignore_errors' => true],
        'ssl' => $ssl,
    ];
    if ($body !== null) {
        $opts['http']['content'] = $body;
    }
    $raw = @file_get_contents($url, false, stream_context_create($opts));
    if ($raw === false) {
        throw new PanelError($source, 'no se pudo conectar con ' . (parse_url($url, PHP_URL_HOST) ?: 'el servidor'));
    }
    $status = 0;
    if (isset($http_response_header[0]) && preg_match('#HTTP/\S+\s+(\d+)#', $http_response_header[0], $m)) {
        $status = (int) $m[1];
    }
    return ['status' => $status, 'body' => $raw];
}

/* ------------------------------------------------------------------ zabbix */

function zbx(string $method, array $params)
{
    static $id = 0;
    $id++;
    $url = rtrim((string) cfg('zabbix.url', 'http://127.0.0.1/zabbix'), '/') . '/api_jsonrpc.php';
    $token = (string) cfg('zabbix.token', '');
    if ($token === '') {
        throw new PanelError('zabbix', 'falta zabbix.token en la configuracion');
    }
    $res = http_request('zabbix', 'POST', $url, [
        'Content-Type: application/json-rpc',
        'Authorization: Bearer ' . $token,
    ], json_encode(['jsonrpc' => '2.0', 'method' => $method, 'params' => $params, 'id' => $id]), (bool) cfg('zabbix.verify_tls', true), cfg('zabbix.cafile'));
    $j = json_decode($res['body'], true);
    if (!is_array($j)) {
        throw new PanelError('zabbix', 'respuesta invalida (HTTP ' . $res['status'] . ')');
    }
    if (isset($j['error'])) {
        $e = $j['error'];
        throw new PanelError('zabbix', 'API: ' . ($e['data'] ?? $e['message'] ?? 'error'));
    }
    return $j['result'];
}

function zbx_hosts(array $groupNames): array
{
    if (!$groupNames) {
        return [];
    }
    $groups = zbx('hostgroup.get', ['output' => ['groupid', 'name'], 'filter' => ['name' => $groupNames]]);
    $ids = array_map('strval', array_column($groups, 'groupid'));
    if (!$ids) {
        return [];
    }
    $hosts = zbx('host.get', [
        'output' => ['hostid', 'host', 'name', 'status'],
        'groupids' => $ids,
        'selectHostGroups' => ['name'],
        'selectInterfaces' => ['type', 'available', 'ip', 'main'],
        'filter' => ['status' => 0],
    ]);
    $byId = [];
    foreach ($hosts as $h) {
        $byId[$h['hostid']] = $h;
    }
    return array_values($byId);
}

/** Agrupa trend.get (por hora) en puntos diarios [dia_ts, promedio, maximo]. */
function zbx_daily_trends(array $itemids, int $days): array
{
    $from = time() - $days * 86400;
    $acc = [];
    foreach (array_chunk(array_map('strval', $itemids), 25) as $chunk) {
        $rows = zbx('trend.get', ['output' => ['itemid', 'clock', 'num', 'value_avg', 'value_max'], 'itemids' => $chunk, 'time_from' => $from]);
        foreach ($rows as $r) {
            $day = (int) strtotime(date('Y-m-d', (int) $r['clock']) . ' 00:00:00');
            $n = max(1, (int) $r['num']);
            $k = $r['itemid'];
            if (!isset($acc[$k][$day])) {
                $acc[$k][$day] = ['s' => 0.0, 'n' => 0, 'mx' => -INF];
            }
            $acc[$k][$day]['s'] += (float) $r['value_avg'] * $n;
            $acc[$k][$day]['n'] += $n;
            $acc[$k][$day]['mx'] = max($acc[$k][$day]['mx'], (float) $r['value_max']);
        }
    }
    $out = [];
    foreach ($acc as $item => $perDay) {
        ksort($perDay);
        foreach ($perDay as $day => $a) {
            $out[$item][] = [$day, round($a['s'] / $a['n'], 3), round($a['mx'], 3)];
        }
    }
    return $out;
}

/* ------------------------------------------------------------------- wazuh */

function wazuh_token(): string
{
    static $token = null;
    if ($token !== null) {
        return $token;
    }
    $base = rtrim((string) cfg('wazuh.api_url', 'https://127.0.0.1:55000'), '/');
    $user = (string) cfg('wazuh.api_user', '');
    $pass = (string) cfg('wazuh.api_pass', '');
    if ($user === '' || $pass === '') {
        throw new PanelError('wazuh', 'faltan wazuh.api_user / wazuh.api_pass');
    }
    $res = http_request('wazuh', 'POST', $base . '/security/user/authenticate?raw=true', [
        'Authorization: Basic ' . base64_encode($user . ':' . $pass),
        'Content-Length: 0',
    ], '', (bool) cfg('wazuh.verify_tls', false), cfg('wazuh.cafile'));
    if ($res['status'] !== 200 || strlen(trim($res['body'])) < 20) {
        throw new PanelError('wazuh', 'autenticacion de la API rechazada (HTTP ' . $res['status'] . ')');
    }
    return $token = trim($res['body']);
}

function wazuh_get(string $path, array $query = []): array
{
    $base = rtrim((string) cfg('wazuh.api_url', 'https://127.0.0.1:55000'), '/');
    $url = $base . '/' . ltrim($path, '/') . ($query ? '?' . http_build_query($query) : '');
    $res = http_request('wazuh', 'GET', $url, ['Authorization: Bearer ' . wazuh_token()], null, (bool) cfg('wazuh.verify_tls', false), cfg('wazuh.cafile'));
    $j = json_decode($res['body'], true);
    if (!is_array($j) || $res['status'] >= 400) {
        throw new PanelError('wazuh', 'la API devolvio HTTP ' . $res['status']);
    }
    return $j;
}

function indexer_search(string $index, array $body): array
{
    $base = rtrim((string) cfg('wazuh.indexer_url', 'https://127.0.0.1:9200'), '/');
    $user = (string) cfg('wazuh.indexer_user', '');
    $pass = (string) cfg('wazuh.indexer_pass', '');
    if ($user === '' || $pass === '') {
        throw new PanelError('indexer', 'faltan wazuh.indexer_user / wazuh.indexer_pass');
    }
    $res = http_request('indexer', 'POST', $base . '/' . $index . '/_search', [
        'Authorization: Basic ' . base64_encode($user . ':' . $pass),
        'Content-Type: application/json',
    ], json_encode($body), (bool) cfg('wazuh.verify_tls', false), cfg('wazuh.cafile'));
    $j = json_decode($res['body'], true);
    if (!is_array($j)) {
        throw new PanelError('indexer', 'respuesta invalida (HTTP ' . $res['status'] . ')');
    }
    if (isset($j['error'])) {
        $why = is_array($j['error']) ? ($j['error']['reason'] ?? $j['error']['type'] ?? 'error') : (string) $j['error'];
        throw new PanelError('indexer', 'indexer: ' . $why);
    }
    return $j;
}

/* ------------------------------------------------------------------- views */

function part(callable $fn): array
{
    try {
        return ['ok' => true] + $fn();
    } catch (PanelError $e) {
        return ['ok' => false, 'error' => $e->getMessage()];
    } catch (Throwable $e) {
        return ['ok' => false, 'error' => 'error interno (' . get_class($e) . ')'];
    }
}

function view_meta(): array
{
    return [
        'version' => PANEL_VERSION,
        'generated' => time(),
        'timezone' => date_default_timezone_get(),
        'roles' => (object) cfg('meta.roles', []),
        'aliases' => (object) cfg('meta.aliases', []),
        'links' => array_map(static fn($l) => ['label' => $l['label'] ?? ($l['host'] ?? '?'), 'capacity_mbps' => $l['capacity_mbps'] ?? null], cfg('links', [])),
    ];
}

function view_capacity(int $days): array
{
    return [
        'generated' => time(),
        'days' => $days,
        'zabbix' => part(function () use ($days) {
            $hosts = zbx_hosts((array) cfg('groups.servers', ['Servers']));
            $names = [];
            foreach ($hosts as $h) {
                $names[$h['hostid']] = $h['host'];
            }
            $series = [];
            $ignore = (string) cfg('ignore_volumes', '~^(/dev|/run|/sys|/proc|/snap|/boot/efi)~');
            if ($hosts) {
                $items = zbx('item.get', [
                    'output' => ['itemid', 'hostid', 'name', 'key_', 'lastvalue', 'units'],
                    'hostids' => array_map('strval', array_keys($names)),
                    'search' => ['key_' => ['vfs.fs.size[', 'vfs.fs.dependent.size[', 'vm.memory.util', 'system.cpu.util']],
                    'searchByAny' => true,
                    'filter' => ['status' => 0],
                    'monitored' => true,
                ]);
                $wanted = [];
                foreach ($items as $it) {
                    $key = $it['key_'];
                    if (preg_match('~^vfs\.fs\.(?:dependent\.)?size\[(.+),pused\]$~', $key, $m)) {
                        if (@preg_match($ignore, $m[1]) === 1) {
                            continue;
                        }
                        $wanted[$it['itemid']] = [$it, 'disk', $m[1]];
                    } elseif (strpos($key, 'vm.memory.util') === 0) {
                        $wanted[$it['itemid']] = [$it, 'ram', ''];
                    } elseif ($key === 'system.cpu.util' || preg_match('~^system\.cpu\.util\[,?\]$~', $key)) {
                        $wanted[$it['itemid']] = [$it, 'cpu', ''];
                    }
                }
                $trends = $wanted ? zbx_daily_trends(array_map('strval', array_keys($wanted)), $days) : [];
                foreach ($wanted as $id => [$it, $kind, $label]) {
                    $series[] = [
                        'host' => $names[$it['hostid']] ?? $it['hostid'],
                        'kind' => $kind,
                        'label' => $label,
                        'now' => is_numeric($it['lastvalue']) ? round((float) $it['lastvalue'], 2) : null,
                        'pts' => $trends[$id] ?? [],
                    ];
                }
            }
            $links = [];
            foreach ((array) cfg('links', []) as $L) {
                $h = zbx('host.get', ['output' => ['hostid', 'host'], 'filter' => ['host' => [(string) ($L['host'] ?? '')]]]);
                if (!$h) {
                    continue;
                }
                $its = zbx('item.get', [
                    'output' => ['itemid', 'name', 'key_'],
                    'hostids' => [$h[0]['hostid']],
                    'search' => ['key_' => ['net.if.in[', 'net.if.out[']],
                    'searchByAny' => true,
                    'filter' => ['status' => 0],
                ]);
                $pick = ['in' => null, 'out' => null];
                foreach ($its as $it) {
                    if (stripos($it['name'], (string) ($L['match'] ?? '')) === false) {
                        continue;
                    }
                    $dir = strpos($it['key_'], 'net.if.in[') === 0 ? 'in' : 'out';
                    $pick[$dir] ??= $it['itemid'];
                }
                $ids = array_values(array_filter($pick));
                $tr = $ids ? zbx_daily_trends($ids, $days) : [];
                $conv = static function (array $pts): array {
                    return array_map(static fn($p) => [$p[0], round($p[1] / 1e6, 3), round($p[2] / 1e6, 3)], $pts);
                };
                $links[] = [
                    'label' => $L['label'] ?? $L['host'],
                    'capacity_mbps' => $L['capacity_mbps'] ?? null,
                    'in' => $pick['in'] ? $conv($tr[$pick['in']] ?? []) : [],
                    'out' => $pick['out'] ? $conv($tr[$pick['out']] ?? []) : [],
                ];
            }
            return ['series' => $series, 'links' => $links];
        }),
    ];
}

function view_availability(int $days): array
{
    return [
        'generated' => time(),
        'days' => $days,
        'zabbix' => part(function () use ($days) {
            $groups = array_values(array_unique(array_merge((array) cfg('groups.servers', ['Servers']), (array) cfg('groups.network', ['Network Devices']))));
            $hosts = zbx_hosts($groups);
            $netGroups = (array) cfg('groups.network', ['Network Devices']);
            $byId = [];
            foreach ($hosts as $h) {
                $byId[$h['hostid']] = $h;
            }
            $items = $hosts ? zbx('item.get', [
                'output' => ['itemid', 'hostid', 'name', 'key_', 'lastvalue', 'lastclock', 'state'],
                'hostids' => array_map('strval', array_keys($byId)),
                'search' => ['key_' => ['agent.ping', 'icmpping', 'system.uptime', 'net.if.status[']],
                'searchByAny' => true,
                'filter' => ['status' => 0],
                'monitored' => true,
            ]) : [];
            $ping = [];
            $icmp = [];
            $uptime = [];
            $ifaces = [];
            $ignoreIf = (string) cfg('ignore_ifaces', '');
            foreach ($items as $it) {
                $k = $it['key_'];
                $hid = $it['hostid'];
                if ($k === 'agent.ping') {
                    $ping[$hid] = $it;
                } elseif (strpos($k, 'icmpping') === 0) {
                    $icmp[$hid] = $it;
                } elseif (strpos($k, 'system.uptime') === 0) {
                    $uptime[$hid] = $it;
                } elseif (strpos($k, 'net.if.status[') === 0) {
                    $nm = trim(preg_replace('~^Interface\s+|:\s*Operational status$~i', '', $it['name']));
                    if ($ignoreIf !== '' && @preg_match($ignoreIf, $nm) === 1) {
                        continue;
                    }
                    $lv = (string) $it['lastvalue'];
                    // sin dato o ítem no soportado: no se puede afirmar que esté caída
                    if ($lv === '' || (string) ($it['state'] ?? '0') === '1') {
                        continue;
                    }
                    if ($lv === '1') {
                        $ifaces[] = ['host' => $byId[$hid]['host'] ?? $hid, 'name' => $nm, 'up' => true];
                    } elseif (in_array($lv, ['0', '2', '7'], true)) {
                        $ifaces[] = ['host' => $byId[$hid]['host'] ?? $hid, 'name' => $nm, 'up' => false];
                    }
                }
            }
            $availItems = [];
            foreach ($byId as $hid => $_) {
                $src = $ping[$hid] ?? ($icmp[$hid] ?? null);
                if ($src) {
                    $availItems[$hid] = $src['itemid'];
                }
            }
            $tr = $availItems ? zbx_daily_trends(array_map('strval', array_values($availItems)), $days) : [];
            $out = [];
            foreach ($byId as $hid => $h) {
                $avail = null;
                if (isset($availItems[$hid]) && !empty($tr[$availItems[$hid]])) {
                    $vals = array_column($tr[$availItems[$hid]], 1);
                    $avail = round(100 * array_sum($vals) / count($vals), 3);
                }
                $state = 'unknown';
                $ips = [];
                foreach ($h['interfaces'] ?? [] as $if) {
                    $ips[] = $if['ip'];
                    if ((string) $if['available'] === '1' && $state !== 'down') {
                        $state = 'up';
                    } elseif ((string) $if['available'] === '2') {
                        $state = 'down';
                    }
                }
                if ($state === 'unknown' && isset($ping[$hid]) && $ping[$hid]['lastvalue'] !== '') {
                    $state = (string) $ping[$hid]['lastvalue'] === '1' ? 'up' : 'down';
                }
                $gnames = array_column($h['hostgroups'] ?? [], 'name');
                $out[] = [
                    'host' => $h['host'],
                    'name' => $h['name'],
                    'ips' => array_values(array_unique($ips)),
                    'groups' => $gnames,
                    'network' => (bool) array_intersect($gnames, $netGroups),
                    'state' => $state,
                    'uptime_s' => isset($uptime[$hid]) && is_numeric($uptime[$hid]['lastvalue']) ? (int) $uptime[$hid]['lastvalue'] : null,
                    'avail_pct' => $avail,
                ];
            }
            $trg = zbx('trigger.get', [
                'output' => ['triggerid', 'description', 'priority', 'lastchange'],
                'selectHosts' => ['host'],
                'only_true' => 1,
                'monitored' => 1,
                'skipDependent' => 1,
                'min_severity' => 2,
                'expandDescription' => 1,
                'sortfield' => 'priority',
                'sortorder' => 'DESC',
                'limit' => 80,
                'filter' => ['value' => 1],
            ]);
            $problems = array_map(static fn($t) => [
                'host' => $t['hosts'][0]['host'] ?? '?',
                'name' => $t['description'],
                'severity' => (int) $t['priority'],
                'clock' => (int) $t['lastchange'],
            ], $trg);
            return ['hosts' => $out, 'problems' => $problems, 'ifaces' => $ifaces];
        }),
        'wazuh' => part(function () {
            $j = wazuh_get('agents', ['select' => 'id,name,ip,status,lastKeepAlive,os.name,os.version,version,group', 'limit' => 500]);
            $agents = [];
            foreach ($j['data']['affected_items'] ?? [] as $a) {
                if (($a['id'] ?? '') === '000') {
                    continue;
                }
                $agents[] = [
                    'id' => $a['id'],
                    'name' => $a['name'] ?? '?',
                    'ip' => $a['ip'] ?? '',
                    'status' => $a['status'] ?? 'unknown',
                    'last_keepalive' => isset($a['lastKeepAlive']) ? strtotime((string) $a['lastKeepAlive']) : null,
                    'os' => $a['os']['name'] ?? '',
                    'os_version' => $a['os']['version'] ?? '',
                    'agent_version' => $a['version'] ?? '',
                ];
            }
            return ['agents' => $agents];
        }),
    ];
}

function sev_key(string $s): string
{
    $s = strtolower($s);
    return in_array($s, ['critical', 'high', 'medium', 'low'], true) ? $s : 'low';
}

function vuln_snapshot_data(): array
{
    $idx = (string) cfg('wazuh.vuln_index', 'wazuh-states-vulnerabilities-*');
    $r = indexer_search($idx, [
        'size' => 0,
        'aggs' => [
            'by_agent' => ['terms' => ['field' => 'agent.name', 'size' => 300], 'aggs' => ['sev' => ['terms' => ['field' => 'vulnerability.severity', 'size' => 10]]]],
            'cves' => [
                'filter' => ['terms' => ['vulnerability.severity' => ['Critical', 'High']]],
                'aggs' => ['top' => [
                    'terms' => ['field' => 'vulnerability.id', 'size' => 40, 'order' => ['agents' => 'desc']],
                    'aggs' => [
                        'agents' => ['cardinality' => ['field' => 'agent.name']],
                        'names' => ['terms' => ['field' => 'agent.name', 'size' => 30]],
                        'sev' => ['terms' => ['field' => 'vulnerability.severity', 'size' => 1]],
                        'score' => ['max' => ['field' => 'vulnerability.score.base']],
                    ],
                ]],
            ],
        ],
    ]);
    $agents = [];
    foreach ($r['aggregations']['by_agent']['buckets'] ?? [] as $b) {
        $c = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0];
        foreach ($b['sev']['buckets'] as $s) {
            $c[sev_key((string) $s['key'])] += (int) $s['doc_count'];
        }
        $agents[(string) $b['key']] = $c;
    }
    $cves = [];
    foreach ($r['aggregations']['cves']['top']['buckets'] ?? [] as $b) {
        $cves[] = [
            'id' => (string) $b['key'],
            'severity' => sev_key((string) ($b['sev']['buckets'][0]['key'] ?? 'high')),
            'score' => isset($b['score']['value']) ? round((float) $b['score']['value'], 1) : null,
            'agents' => array_column($b['names']['buckets'], 'key'),
        ];
    }
    return ['agents' => $agents, 'cves' => $cves];
}

function snapshot_file(): string
{
    return (string) cfg('snapshot_file', '/var/lib/panel-decisiones/vulns-history.json');
}

function snapshot_read(): array
{
    $f = snapshot_file();
    if (!is_file($f)) {
        return [];
    }
    $j = json_decode((string) @file_get_contents($f), true);
    return is_array($j) ? $j : [];
}

function view_patches(): array
{
    return [
        'generated' => time(),
        'wazuh' => part(function () {
            $d = vuln_snapshot_data();
            $os = [];
            try {
                $j = wazuh_get('agents', ['select' => 'name,os.name,os.version', 'limit' => 500]);
                foreach ($j['data']['affected_items'] ?? [] as $a) {
                    $os[$a['name'] ?? ''] = trim(($a['os']['name'] ?? '') . ' ' . ($a['os']['version'] ?? ''));
                }
            } catch (PanelError $e) {
                // el detalle del SO es opcional
            }
            $agents = [];
            foreach ($d['agents'] as $name => $c) {
                $agents[] = ['name' => $name, 'os' => $os[$name] ?? '', 'counts' => $c];
            }
            $hist = array_map(static fn($h) => ['ts' => $h['ts'], 'totals' => $h['totals']], snapshot_read());
            return ['agents' => $agents, 'cves' => $d['cves'], 'history' => $hist];
        }),
    ];
}

function view_security(int $days): array
{
    return [
        'generated' => time(),
        'days' => $days,
        'wazuh' => part(function () use ($days) {
            $idx = (string) cfg('wazuh.alerts_index', 'wazuh-alerts-4.x-*');
            $tz = date_default_timezone_get();
            $sevFilters = [
                'filters' => [
                    'filters' => [
                        'high' => ['range' => ['rule.level' => ['gte' => 12]]],
                        'medium' => ['range' => ['rule.level' => ['gte' => 7, 'lt' => 12]]],
                        'low' => ['range' => ['rule.level' => ['lt' => 7]]],
                    ],
                ],
            ];
            $r = indexer_search($idx, [
                'size' => 0,
                'query' => ['range' => ['timestamp' => ['gte' => "now-{$days}d/d"]]],
                'aggs' => [
                    'by_day' => ['date_histogram' => ['field' => 'timestamp', 'calendar_interval' => 'day', 'time_zone' => $tz, 'min_doc_count' => 0], 'aggs' => ['sev' => $sevFilters]],
                    'last24' => ['filter' => ['range' => ['timestamp' => ['gte' => 'now-24h']]], 'aggs' => ['sev' => $sevFilters]],
                    'failed' => [
                        'filter' => ['term' => ['rule.id' => '60122']],
                        'aggs' => [
                            'by_day' => ['date_histogram' => ['field' => 'timestamp', 'calendar_interval' => 'day', 'time_zone' => $tz, 'min_doc_count' => 0]],
                            'by_agent' => ['terms' => ['field' => 'agent.name', 'size' => 10]],
                            'by_ip' => ['terms' => ['field' => 'data.win.eventdata.ipAddress', 'size' => 10]],
                            'by_user' => ['terms' => ['field' => 'data.win.eventdata.targetUserName', 'size' => 10]],
                        ],
                    ],
                    'lockouts' => ['filter' => ['term' => ['rule.id' => '60115']], 'aggs' => ['last24' => ['filter' => ['range' => ['timestamp' => ['gte' => 'now-24h']]]]]],
                    'flooded' => [
                        'filter' => ['term' => ['rule.id' => '204']],
                        'aggs' => ['by_agent' => ['terms' => ['field' => 'agent.name', 'size' => 20], 'aggs' => ['last' => ['max' => ['field' => 'timestamp']]]]],
                    ],
                    'top_rules' => [
                        'filter' => ['range' => ['rule.level' => ['gte' => 7]]],
                        'aggs' => ['r' => [
                            'terms' => ['field' => 'rule.id', 'size' => 12],
                            'aggs' => [
                                'd' => ['terms' => ['field' => 'rule.description', 'size' => 1]],
                                'l' => ['max' => ['field' => 'rule.level']],
                            ],
                        ]],
                    ],
                ],
            ]);
            $a = $r['aggregations'];
            $sevOf = static function (array $b): array {
                return [
                    'high' => (int) ($b['sev']['buckets']['high']['doc_count'] ?? 0),
                    'medium' => (int) ($b['sev']['buckets']['medium']['doc_count'] ?? 0),
                    'low' => (int) ($b['sev']['buckets']['low']['doc_count'] ?? 0),
                ];
            };
            $day = static fn($k) => (int) floor(((int) $k) / 1000);
            $byDay = [];
            foreach ($a['by_day']['buckets'] as $b) {
                $byDay[] = ['ts' => $day($b['key']), 'n' => (int) $b['doc_count']] + $sevOf($b);
            }
            $failedDay = [];
            foreach ($a['failed']['by_day']['buckets'] as $b) {
                $failedDay[] = [$day($b['key']), (int) $b['doc_count']];
            }
            $terms = static fn(array $agg) => array_map(static fn($b) => ['key' => (string) $b['key'], 'n' => (int) $b['doc_count']], $agg['buckets'] ?? []);
            $locks = indexer_search($idx, [
                'size' => 10,
                'sort' => [['timestamp' => 'desc']],
                '_source' => ['timestamp', 'agent.name', 'data.win.eventdata.targetUserName', 'data.win.eventdata.callerComputerName'],
                'query' => ['bool' => ['filter' => [['term' => ['rule.id' => '60115']], ['range' => ['timestamp' => ['gte' => "now-{$days}d/d"]]]]]],
            ]);
            $lockRows = [];
            foreach ($locks['hits']['hits'] ?? [] as $h) {
                $s = $h['_source'];
                $lockRows[] = [
                    'ts' => strtotime((string) ($s['timestamp'] ?? 'now')),
                    'user' => $s['data']['win']['eventdata']['targetUserName'] ?? '?',
                    'caller' => $s['data']['win']['eventdata']['callerComputerName'] ?? '',
                    'agent' => $s['agent']['name'] ?? '',
                ];
            }
            $rules = [];
            foreach ($a['top_rules']['r']['buckets'] ?? [] as $b) {
                $rules[] = [
                    'id' => (string) $b['key'],
                    'desc' => (string) ($b['d']['buckets'][0]['key'] ?? ''),
                    'level' => (int) ($b['l']['value'] ?? 0),
                    'n' => (int) $b['doc_count'],
                ];
            }
            $flooded = [];
            foreach ($a['flooded']['by_agent']['buckets'] ?? [] as $b) {
                $flooded[] = ['agent' => (string) $b['key'], 'n' => (int) $b['doc_count'], 'last' => isset($b['last']['value']) ? (int) floor($b['last']['value'] / 1000) : null];
            }
            return [
                'by_day' => $byDay,
                'last24' => $sevOf($a['last24']),
                'failed' => [
                    'by_day' => $failedDay,
                    'by_agent' => $terms($a['failed']['by_agent']),
                    'by_ip' => $terms($a['failed']['by_ip']),
                    'by_user' => $terms($a['failed']['by_user']),
                ],
                'lockouts' => ['total' => (int) $a['lockouts']['doc_count'], 'last24' => (int) $a['lockouts']['last24']['doc_count'], 'recent' => $lockRows],
                'top_rules' => $rules,
                'flooded' => $flooded,
            ];
        }),
        // Perímetro: alertas del MikroTik que llegan por syslog (reglas locales 100801-100803 y 100810-100811).
        // Es una fuente aparte: si todavía no hay datos o las reglas no existen, el resto de Seguridad sigue igual.
        'perimeter' => part(function () use ($days) {
            $idx = (string) cfg('wazuh.alerts_index', 'wazuh-alerts-4.x-*');
            $tz = date_default_timezone_get();
            $since = ['range' => ['timestamp' => ['gte' => "now-{$days}d/d"]]];
            $last24 = ['filter' => ['range' => ['timestamp' => ['gte' => 'now-24h']]]];
            $perDay = ['date_histogram' => ['field' => 'timestamp', 'calendar_interval' => 'day', 'time_zone' => $tz, 'min_doc_count' => 0]];
            $r = indexer_search($idx, [
                'size' => 0,
                'query' => ['bool' => ['filter' => [$since, ['terms' => ['rule.id' => ['100810', '100811', '100801', '100803']]]]]],
                'aggs' => [
                    'scan' => ['filter' => ['term' => ['rule.id' => '100810']], 'aggs' => [
                        'by_day' => $perDay,
                        'last24' => $last24,
                        'uniq' => ['cardinality' => ['field' => 'data.srcip']],
                        'top_ip' => ['terms' => ['field' => 'data.srcip', 'size' => 10], 'aggs' => [
                            'ports' => ['terms' => ['field' => 'data.dstport', 'size' => 4]],
                            'last' => ['max' => ['field' => 'timestamp']],
                        ]],
                        'top_port' => ['terms' => ['field' => 'data.dstport', 'size' => 10]],
                        'by_link' => ['terms' => ['field' => 'data.wan_link', 'size' => 5]],
                    ]],
                    'insist' => ['filter' => ['term' => ['rule.id' => '100811']], 'aggs' => [
                        'last24' => $last24,
                        'ips' => ['terms' => ['field' => 'data.srcip', 'size' => 10], 'aggs' => ['last' => ['max' => ['field' => 'timestamp']]]],
                    ]],
                    'fail' => ['filter' => ['term' => ['rule.id' => '100801']], 'aggs' => [
                        'last24' => $last24,
                        'by_ip' => ['terms' => ['field' => 'data.srcip', 'size' => 5]],
                        'by_user' => ['terms' => ['field' => 'data.dstuser', 'size' => 5]],
                    ]],
                    'ok' => ['filter' => ['term' => ['rule.id' => '100803']], 'aggs' => ['last24' => $last24]],
                ],
            ]);
            $a = $r['aggregations'] ?? [];
            $sec = static fn($ms) => (int) floor(((int) $ms) / 1000);
            $terms = static fn(array $agg) => array_map(static fn($b) => ['key' => (string) $b['key'], 'n' => (int) $b['doc_count']], $agg['buckets'] ?? []);
            $link = static fn(string $k) => ucfirst(strtolower((string) preg_replace('~^WANIN-~i', '', $k)));
            $scanDay = [];
            foreach ($a['scan']['by_day']['buckets'] ?? [] as $b) {
                $scanDay[] = ['ts' => $sec($b['key']), 'n' => (int) $b['doc_count']];
            }
            $topIp = [];
            foreach ($a['scan']['top_ip']['buckets'] ?? [] as $b) {
                $topIp[] = [
                    'ip' => (string) $b['key'],
                    'n' => (int) $b['doc_count'],
                    'ports' => $terms($b['ports'] ?? []),
                    'last' => isset($b['last']['value']) ? $sec($b['last']['value']) : null,
                ];
            }
            $insistIps = [];
            foreach ($a['insist']['ips']['buckets'] ?? [] as $b) {
                $insistIps[] = [
                    'ip' => (string) $b['key'],
                    'n' => (int) $b['doc_count'],
                    'last' => isset($b['last']['value']) ? $sec($b['last']['value']) : null,
                ];
            }
            $byLink = array_map(static fn($x) => ['key' => $link($x['key']), 'n' => $x['n']], $terms($a['scan']['by_link'] ?? []));
            $rec = indexer_search($idx, [
                'size' => 10,
                'sort' => [['timestamp' => 'desc']],
                '_source' => ['timestamp', 'rule.id', 'data.srcip', 'data.dstuser', 'data.protocol'],
                'query' => ['bool' => ['filter' => [$since, ['terms' => ['rule.id' => ['100801', '100803']]]]]],
            ]);
            $recent = [];
            foreach ($rec['hits']['hits'] ?? [] as $h) {
                $s = $h['_source'] ?? [];
                $recent[] = [
                    'ts' => strtotime((string) ($s['timestamp'] ?? 'now')),
                    'ok' => ((string) ($s['rule']['id'] ?? '')) === '100803',
                    'user' => (string) ($s['data']['dstuser'] ?? '?'),
                    'ip' => (string) ($s['data']['srcip'] ?? ''),
                    'via' => (string) ($s['data']['protocol'] ?? ''),
                ];
            }
            return [
                'scan' => [
                    'total' => (int) ($a['scan']['doc_count'] ?? 0),
                    'last24' => (int) ($a['scan']['last24']['doc_count'] ?? 0),
                    'unique_ips' => (int) ($a['scan']['uniq']['value'] ?? 0),
                    'by_day' => $scanDay,
                    'top_ip' => $topIp,
                    'top_port' => $terms($a['scan']['top_port'] ?? []),
                    'by_link' => $byLink,
                ],
                'insist' => [
                    'total' => (int) ($a['insist']['doc_count'] ?? 0),
                    'last24' => (int) ($a['insist']['last24']['doc_count'] ?? 0),
                    'ips' => $insistIps,
                ],
                'router' => [
                    'fail_total' => (int) ($a['fail']['doc_count'] ?? 0),
                    'fail_last24' => (int) ($a['fail']['last24']['doc_count'] ?? 0),
                    'ok_total' => (int) ($a['ok']['doc_count'] ?? 0),
                    'ok_last24' => (int) ($a['ok']['last24']['doc_count'] ?? 0),
                    'fail_by_ip' => $terms($a['fail']['by_ip'] ?? []),
                    'fail_by_user' => $terms($a['fail']['by_user'] ?? []),
                    'recent' => $recent,
                ],
            ];
        }),
    ];
}

/* ------------------------------------------------------------------ router */

function json_out($data, int $code = 200): void
{
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
}

function cached(string $key, callable $fn, bool $force): array
{
    $ttl = (int) cfg('cache_ttl', 300);
    $dir = (string) cfg('cache_dir', sys_get_temp_dir() . '/panel-decisiones');
    if (!is_dir($dir)) {
        @mkdir($dir, 0700, true);
    }
    $file = $dir . '/' . preg_replace('/[^a-z0-9_-]/i', '_', $key) . '.json';
    $age = is_file($file) ? time() - (int) filemtime($file) : PHP_INT_MAX;
    $fresh = $age < ($force ? 30 : $ttl);
    if ($fresh) {
        $j = json_decode((string) @file_get_contents($file), true);
        if (is_array($j)) {
            $j['cached_age_s'] = $age;
            return $j;
        }
    }
    $data = $fn();
    // no guardamos en cache un resultado donde falló alguna fuente
    $allOk = true;
    foreach ($data as $v) {
        if (is_array($v) && array_key_exists('ok', $v) && $v['ok'] === false) {
            $allOk = false;
        }
    }
    if ($allOk) {
        @file_put_contents($file, json_encode($data), LOCK_EX);
    }
    return $data;
}

function run_snapshot(): int
{
    $d = vuln_snapshot_data();
    $totals = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0];
    foreach ($d['agents'] as $c) {
        foreach ($c as $k => $v) {
            $totals[$k] += $v;
        }
    }
    $hist = snapshot_read();
    $hist[] = ['ts' => time(), 'totals' => $totals, 'agents' => $d['agents']];
    $hist = array_slice($hist, -400);
    $file = snapshot_file();
    @mkdir(dirname($file), 0750, true);
    if (@file_put_contents($file, json_encode($hist), LOCK_EX) === false) {
        fwrite(STDERR, "No se pudo escribir $file\n");
        return 1;
    }
    echo "Snapshot guardado: " . json_encode($totals) . "\n";
    return 0;
}

if (PHP_SAPI === 'cli') {
    if (($argv[1] ?? '') === 'snapshot') {
        try {
            exit(run_snapshot());
        } catch (Throwable $e) {
            fwrite(STDERR, 'Error: ' . $e->getMessage() . "\n");
            exit(1);
        }
    }
    fwrite(STDERR, "Uso: php api.php snapshot\n");
    exit(2);
}

set_exception_handler(static function (Throwable $e): void {
    json_out(['ok' => false, 'error' => 'error interno'], 500);
});

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'GET') {
    json_out(['ok' => false, 'error' => 'solo GET'], 405);
    exit;
}

$view = (string) ($_GET['view'] ?? '');
$days = max(7, min(180, (int) ($_GET['days'] ?? 60)));
$force = isset($_GET['fresh']);

switch ($view) {
    case 'meta':
        json_out(view_meta());
        break;
    case 'capacity':
        json_out(cached("capacity-$days", static fn() => view_capacity($days), $force));
        break;
    case 'availability':
        json_out(cached("availability-$days", static fn() => view_availability($days), $force));
        break;
    case 'patches':
        json_out(cached('patches', static fn() => view_patches(), $force));
        break;
    case 'security':
        json_out(cached("security-$days", static fn() => view_security($days), $force));
        break;
    default:
        json_out(['ok' => false, 'error' => 'vista desconocida'], 404);
}
