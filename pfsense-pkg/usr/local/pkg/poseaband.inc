<?php
/*
 * poseaband.inc - PoseaBand Bandwidth & QoS Engine for pfSense
 * Part of Posea Security Suite
 */

require_once("config.inc");
require_once("filter.inc");
require_once("shaper.inc");

define('POSEABAND_CONF_FILE', '/var/etc/poseafilter/poseaband_config.json');
define('POSEABAND_CONF_BACKUP', '/conf/poseaband_config.json');

function poseaband_get_default_config() {
    return [
        'enabled' => false, // Default is disabled (pasif)
        'default_download_mbps' => 5,
        'default_upload_mbps' => 5,
        'bypass_local_lan' => true,
        'auto_guest_limit' => true, // Automatically isolate/limit unauthenticated AD guest & mobile devices
        'profiles' => [
            [
                'id' => 'prof_vip',
                'name' => 'Yönetim & VIP',
                'down_mbps' => 25,
                'up_mbps' => 20,
                'descr' => 'Kritik birimler ve yöneticiler için yüksek hız',
                'badge' => 'label-success'
            ],
            [
                'id' => 'prof_standard',
                'name' => 'Standart Personel',
                'down_mbps' => 5,
                'up_mbps' => 5,
                'descr' => 'Standart ofis ve AD domain çalışan profili',
                'badge' => 'label-info'
            ],
            [
                'id' => 'prof_guest',
                'name' => 'Misafir & Wi-Fi',
                'down_mbps' => 2,
                'up_mbps' => 1,
                'descr' => 'Misafir Wi-Fi ve mobil cihazlar için otomatik korumalı hız',
                'badge' => 'label-warning'
            ],
            [
                'id' => 'prof_restricted',
                'name' => 'Kısıtlı / Kota Aşımı',
                'down_mbps' => 1,
                'up_mbps' => 0.5,
                'descr' => 'Aşırı bant genişliği tüketen cihazlar için minimum hız',
                'badge' => 'label-danger'
            ]
        ],
        'client_rules' => []
    ];
}

function poseaband_get_config() {
    $conf = null;
    if (file_exists(POSEABAND_CONF_FILE)) {
        $raw = @file_get_contents(POSEABAND_CONF_FILE);
        $conf = json_decode($raw, true);
    }
    if (!is_array($conf) && file_exists(POSEABAND_CONF_BACKUP)) {
        $raw = @file_get_contents(POSEABAND_CONF_BACKUP);
        $conf = json_decode($raw, true);
    }
    if (!is_array($conf)) {
        $conf = poseaband_get_default_config();
        poseaband_save_config($conf);
    }
    if (!isset($conf['client_rules']) || !is_array($conf['client_rules'])) {
        $conf['client_rules'] = [];
    }
    if (!isset($conf['auto_guest_limit'])) {
        $conf['auto_guest_limit'] = true;
    }
    return $conf;
}

function poseaband_save_config($conf) {
    if (!is_dir(dirname(POSEABAND_CONF_FILE))) {
        @mkdir(dirname(POSEABAND_CONF_FILE), 0755, true);
    }
    $json = json_encode($conf, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    @file_put_contents(POSEABAND_CONF_FILE, $json);
    @file_put_contents(POSEABAND_CONF_BACKUP, $json);
}

function poseaband_is_local_ip($ip) {
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        return false;
    }
    $long = ip2long($ip);
    if ($long === false) return false;
    // 10.0.0.0/8
    if (($long & 0xFF000000) === 0x0A000000) return true;
    // 172.16.0.0/12
    if (($long & 0xFFF00000) === 0xAC100000) return true;
    // 192.168.0.0/16
    if (($long & 0xFFFF0000) === 0xC0A80000) return true;
    return false;
}

function poseaband_kill_client_states($ip) {
    $ip = trim((string)$ip);
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        return false;
    }

    $esc_ip = preg_quote($ip, '/');
    exec("/sbin/pfctl -vvs states 2>/dev/null", $lines);
    $cur_state_is_target = false;
    $cur_state_is_mgmt = false;
    $target_ids = [];

    foreach ($lines as $line) {
        if (isset($line[0]) && $line[0] !== ' ' && $line[0] !== "\t") {
            // Match both LAN ("<- 192.168.2.13:port") and WAN NAT ("(192.168.2.13:port)")
            $cur_state_is_target = (preg_match("/(^|[\s<>\-\(])" . $esc_ip . "(:|\s|\)|$)/", $line) === 1);
            // Protect only actual pfSense WebGUI and SSH management ports to the firewall itself
            $cur_state_is_mgmt = (
                preg_match("/:(448|422)\b/", $line) === 1 && 
                (strpos($line, '192.168.1.1') !== false || strpos($line, '192.168.2.1') !== false || strpos($line, '185.189.54.89') !== false || strpos($line, 'ddm-ssl') !== false)
            );
            continue;
        }
        if ($cur_state_is_target && !$cur_state_is_mgmt) {
            if (preg_match('/id:\s*([0-9a-f]+)\s+creatorid:\s*([0-9a-f]+)/i', $line, $m)) {
                $target_ids[] = $m[1] . '/' . $m[2];
            }
        }
    }

    foreach ($target_ids as $tid) {
        @shell_exec("/sbin/pfctl -k id -k " . escapeshellarg($tid) . " 2>/dev/null");
    }

    return true;
}

function poseaband_kill_all_client_states($ips = []) {
    if (empty($ips)) {
        $conf = poseaband_get_config();
        foreach ($conf['client_rules'] ?? [] as $cr) {
            if (($cr['target_type'] ?? '') === 'ip' && !empty($cr['target_val'])) {
                $ips[] = $cr['target_val'];
            }
        }
    }
    $killed = 0;
    foreach (array_unique($ips) as $ip) {
        if (poseaband_kill_client_states($ip)) {
            $killed++;
        }
    }
    return $killed;
}

function poseaband_cidr_match($ip, $cidr) {
    if (strpos($cidr, '/') === false) {
        return $ip === $cidr;
    }
    list($subnet, $mask) = explode('/', $cidr);
    if ((ip2long($ip) & ~((1 << (32 - (int)$mask)) - 1)) == ip2long($subnet)) {
        return true;
    }
    return false;
}

function poseaband_resolve_alias_ips($alias_name) {
    global $config;
    $ips = [];
    if (!empty($config['aliases']['alias'])) {
        foreach ($config['aliases']['alias'] as $a) {
            if (strcasecmp($a['name'], $alias_name) === 0) {
                $raw = explode(' ', trim($a['address'] ?? ''));
                foreach ($raw as $entry) {
                    $entry = trim($entry);
                    if ($entry !== '') {
                        $ips[] = $entry;
                    }
                }
            }
        }
    }
    return $ips;
}

function poseaband_get_ad_metadata() {
    global $config;
    $cache_file = '/tmp/poseaband_ad_metadata.json';
    if (file_exists($cache_file) && (time() - filemtime($cache_file) < 300)) {
        $cached = @json_decode(file_get_contents($cache_file), true);
        if ($cached && !empty($cached['ad_groups'])) {
            return $cached;
        }
    }

    $res = [
        'aliases' => [],
        'ad_groups' => [],
        'ad_users' => [],
        'lan_clients' => []
    ];

    // 1. pfSense Host & Network Aliases
    if (isset($config['aliases']['alias']) && is_array($config['aliases']['alias'])) {
        foreach ($config['aliases']['alias'] as $a) {
            if (in_array($a['type'], ['host', 'network'])) {
                $res['aliases'][] = [
                    'name' => $a['name'],
                    'type' => $a['type'],
                    'descr' => $a['descr'] ?? '',
                    'address' => $a['address'] ?? ''
                ];
            }
        }
    }

    // 2. Active Directory Groups and Users
    $groups_found = [];
    $users_found = [];

    // Query active SSO sessions and bindings first (instant)
    if (file_exists('/usr/local/pkg/posea_ad_sso.inc')) {
        require_once('/usr/local/pkg/posea_ad_sso.inc');
        if (function_exists('posea_sso_get_sessions')) {
            $sessions = posea_sso_get_sessions();
            foreach ($sessions as $ip => $s) {
                if (!empty($s['groups']) && is_array($s['groups'])) {
                    foreach ($s['groups'] as $g) {
                        $groups_found[$g] = true;
                    }
                }
                if (!empty($s['department'])) {
                    $groups_found[$s['department']] = true;
                }
                if (!empty($s['username']) && $s['username'] !== 'anonymous') {
                    $users_found[$s['username']] = [
                        'username' => $s['username'],
                        'display_name' => $s['display_name'] ?? $s['username'],
                        'ip' => $ip,
                        'hostname' => $s['hostname'] ?? ''
                    ];
                }
            }
        }

        // Complete LDAP search for all groups & users
        if (function_exists('posea_sso_get_config') && function_exists('posea_sso_ldap_connect') && function_exists('posea_sso_ldap_bind')) {
            $cfg = posea_sso_get_config();
            $ldap = posea_sso_ldap_connect($cfg);
            if ($ldap && posea_sso_ldap_bind($ldap, $cfg['bind_user'] ?? '', $cfg['bind_password'] ?? '')) {
                // Query groups
                $sr = @ldap_search($ldap, $cfg['base_dn'], '(|(objectClass=group)(objectCategory=group))', ['cn']);
                if ($sr) {
                    $entries = @ldap_get_entries($ldap, $sr);
                    for ($i = 0; $i < ($entries['count'] ?? 0); $i++) {
                        $cn = $entries[$i]['cn'][0] ?? '';
                        if ($cn) $groups_found[$cn] = true;
                    }
                }

                // Query users
                $sr_u = @ldap_search($ldap, $cfg['base_dn'], '(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))', ['sAMAccountName', 'displayName']);
                if ($sr_u) {
                    $entries_u = @ldap_get_entries($ldap, $sr_u);
                    for ($i = 0; $i < ($entries_u['count'] ?? 0); $i++) {
                        $sam = $entries_u[$i]['samaccountname'][0] ?? '';
                        $dn = $entries_u[$i]['displayname'][0] ?? $sam;
                        if ($sam && !isset($users_found[$sam])) {
                            $users_found[$sam] = [
                                'username' => $sam,
                                'display_name' => $dn,
                                'ip' => '',
                                'hostname' => ''
                            ];
                        }
                    }
                }
                @ldap_close($ldap);
            }
        }
    }

    ksort($groups_found);
    uasort($users_found, function($a, $b) {
        return strcasecmp($a['username'], $b['username']);
    });

    $res['ad_groups'] = array_keys($groups_found);
    $res['ad_users'] = array_values($users_found);

    // 3. Current LAN active clients from ARP
    exec("/usr/sbin/arp -an 2>/dev/null", $arp_lines);
    $clients = [];
    foreach ($arp_lines as $l) {
        if (preg_match('/\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:]+)/i', $l, $m)) {
            $ip = $m[1];
            $mac = strtolower($m[2]);
            if ($mac === '(incomplete)' || $mac === 'ff:ff:ff:ff:ff:ff') continue;
            $name = 'Misafir Cihaz / Wi-Fi';
            $is_ad = false;
            if (isset($sessions[$ip]) && ($sessions[$ip]['status'] ?? '') === 'authenticated') {
                $name = ($sessions[$ip]['display_name'] ?? $sessions[$ip]['username']) . ' (' . ($sessions[$ip]['hostname'] ?? '') . ')';
                $is_ad = true;
            }
            $clients[] = [
                'ip' => $ip,
                'mac' => $mac,
                'name' => $name,
                'is_ad' => $is_ad
            ];
        }
    }
    $res['lan_clients'] = $clients;

    @file_put_contents($cache_file, json_encode($res, JSON_UNESCAPED_UNICODE));
    return $res;
}

function poseaband_get_ldap_enrichment() {
    $cache_file = '/tmp/poseaband_ldap_map.json';
    if (file_exists($cache_file) && (time() - filemtime($cache_file) < 300)) {
        $cached = @json_decode(@file_get_contents($cache_file), true);
        if (is_array($cached) && (!empty($cached['groups']) || !empty($cached['users']))) {
            return $cached;
        }
    }

    $res = ['groups' => [], 'users' => []];

    if (file_exists('/usr/local/pkg/posea_ad_sso.inc')) {
        require_once('/usr/local/pkg/posea_ad_sso.inc');
        if (function_exists('posea_sso_get_config') && function_exists('posea_sso_ldap_connect') && function_exists('posea_sso_ldap_bind')) {
            $cfg = posea_sso_get_config();
            $ldap = @posea_sso_ldap_connect($cfg);
            if ($ldap && @posea_sso_ldap_bind($ldap, $cfg['bind_user'] ?? '', $cfg['bind_password'] ?? '')) {
                $dn = $cfg['base_dn'] ?: 'DC=domain,DC=local';

                // 1. Query users
                $sr_u = @ldap_search($ldap, $dn, '(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))', ['samaccountname', 'displayname', 'department', 'memberof']);
                if ($sr_u) {
                    $u_entries = @ldap_get_entries($ldap, $sr_u);
                    for ($i = 0; $i < ($u_entries['count'] ?? 0); $i++) {
                        $e = $u_entries[$i];
                        $sam = strtolower($e['samaccountname'][0] ?? '');
                        if (!$sam) continue;

                        $u_groups = [];
                        for ($m = 0; $m < ($e['memberof']['count'] ?? 0); $m++) {
                            if (preg_match('/^CN=([^,]+)/i', $e['memberof'][$m], $cn_m)) {
                                $u_groups[] = strtolower($cn_m[1]);
                            }
                        }

                        $res['users'][$sam] = [
                            'sam' => $e['samaccountname'][0],
                            'display_name' => $e['displayname'][0] ?? '',
                            'department' => $e['department'][0] ?? '',
                            'groups' => $u_groups
                        ];
                    }
                }

                // 2. Query groups
                $sr_g = @ldap_search($ldap, $dn, '(|(objectClass=group)(objectCategory=group))', ['cn', 'samaccountname', 'member']);
                if ($sr_g) {
                    $g_entries = @ldap_get_entries($ldap, $sr_g);
                    for ($i = 0; $i < ($g_entries['count'] ?? 0); $i++) {
                        $g = $g_entries[$i];
                        $gname = strtolower($g['samaccountname'][0] ?? ($g['cn'][0] ?? ''));
                        if (!$gname) continue;

                        $members = [];
                        for ($m = 0; $m < ($g['member']['count'] ?? 0); $m++) {
                            if (preg_match('/^CN=([^,]+)/i', $g['member'][$m], $cn_m)) {
                                $cn_val = $cn_m[1];
                                $parts = preg_split('/[\s\-]+/', $cn_val);
                                if (!empty($parts[0])) {
                                    $members[strtolower($parts[0])] = true;
                                }
                                $members[strtolower($cn_val)] = true;
                            }
                        }
                        $res['groups'][$gname] = array_keys($members);
                    }
                }

                @ldap_close($ldap);
                @file_put_contents($cache_file, json_encode($res, JSON_UNESCAPED_UNICODE));
            }
        }
    }

    return $res;
}

function poseaband_resolve_client_identity($ip, $s, $ldap_enrichment = null) {
    if ($ldap_enrichment === null) {
        $ldap_enrichment = poseaband_get_ldap_enrichment();
    }
    $users = $ldap_enrichment['users'] ?? [];

    $u_user = trim($s['username'] ?? '');
    $u_host = trim($s['hostname'] ?? '');
    $u_disp = trim($s['display_name'] ?? '');
    $dept = trim($s['department'] ?? '');
    $groups = is_array($s['groups'] ?? null) ? $s['groups'] : [];

    // Candidate keys to match against LDAP users
    $candidates = [];
    if ($u_user && strcasecmp($u_user, 'anonymous') !== 0) $candidates[] = strtolower($u_user);
    if ($u_host) $candidates[] = strtolower($u_host);

    // Strip computer prefixes (e.g., PC-TERM15 -> term15)
    $strip_regex = '/^(pc[-_]|ws[-_]|laptop[-_]|nb[-_]|cl[-_]|desktop[-_])/i';
    if ($u_host) {
        $st = preg_replace($strip_regex, '', $u_host);
        if ($st && strcasecmp($st, $u_host) !== 0) $candidates[] = strtolower($st);
    }
    if ($u_user) {
        $st = preg_replace($strip_regex, '', $u_user);
        if ($st && strcasecmp($st, $u_user) !== 0) $candidates[] = strtolower($st);
    }

    $matched_u = null;
    foreach ($candidates as $cand) {
        if (isset($users[$cand])) {
            $matched_u = $users[$cand];
            break;
        }
    }

    if (!$matched_u && !empty($users)) {
        foreach ($users as $sam => $uinfo) {
            $patt = '/(^|[^a-z0-9])' . preg_quote($sam, '/') . '($|[^a-z0-9])/i';
            if (($u_host && preg_match($patt, $u_host)) || ($u_user && preg_match($patt, $u_user))) {
                $matched_u = $uinfo;
                break;
            }
        }
    }

    if ($matched_u) {
        $real_sam = $matched_u['sam'];
        $real_disp = $matched_u['display_name'];
        $disp_label = $real_sam . ($real_disp ? " ({$real_disp})" : "");
        $groups = array_unique(array_merge($groups, $matched_u['groups'] ?? []));

        // Auto-assign primary department from groups if blank or "Domain Computers"
        if (empty($dept) || strcasecmp($dept, 'Domain Computers') === 0) {
            if ($matched_u['department']) {
                $dept = $matched_u['department'];
            } elseif (in_array('muhasebe', $groups)) $dept = 'Muhasebe';
            elseif (in_array('yonetim', $groups)) $dept = 'Yonetim';
            elseif (in_array('yonetici', $groups)) $dept = 'Yonetici';
        }

        return [
            'username' => $real_sam,
            'hostname' => $u_host,
            'display_name' => $disp_label,
            'department' => $dept,
            'groups' => $groups,
            'is_ad' => true
        ];
    }

    return [
        'username' => $u_user ?: 'anonymous',
        'hostname' => $u_host,
        'display_name' => $u_disp ?: ($u_host ?: $ip),
        'department' => $dept,
        'groups' => $groups,
        'is_ad' => (!empty($u_user) && strcasecmp($u_user, 'anonymous') !== 0 && strpos($u_user, 'Misafir') === false)
    ];
}

function poseaband_find_client_profile($conf, $ip, $mac = '', $user = '', $dept = '', $groups = []) {
    $profiles_by_id = [];
    foreach ($conf['profiles'] ?? [] as $p) {
        $profiles_by_id[$p['id']] = $p;
    }

    $mac_clean = strtolower(trim($mac));
    $user_clean = strtolower(trim($user));
    $dept_clean = strtolower(trim($dept));
    if (!is_array($groups)) $groups = [];
    $groups_lower = array_map('strtolower', $groups);

    // 1. Check explicit client rules (highest precedence)
    foreach ($conf['client_rules'] ?? [] as $cr) {
        if (empty($cr['enabled'])) continue;
        $t_type = $cr['target_type'] ?? 'ip';
        $t_val = trim($cr['target_val'] ?? '');
        $t_clean = strtolower($t_val);
        $match = false;

        switch ($t_type) {
            case 'ip':
                if ($ip === $t_val) $match = true;
                break;
            case 'subnet':
                if (poseaband_cidr_match($ip, $t_val)) $match = true;
                break;
            case 'alias':
                $alias_ips = poseaband_resolve_alias_ips($t_val);
                foreach ($alias_ips as $a_ip) {
                    if ($ip === $a_ip || (strpos($a_ip, '/') !== false && poseaband_cidr_match($ip, $a_ip))) {
                        $match = true;
                        break;
                    }
                }
                break;
            case 'mac':
                if ($mac_clean && $mac_clean === $t_clean) $match = true;
                break;
            case 'user':
                $patt = '/(^|[^a-z0-9])' . preg_quote($t_clean, '/') . '($|[^a-z0-9])/i';
                if ($user_clean && (strcasecmp($user_clean, $t_clean) === 0 || preg_match($patt, $user_clean))) {
                    $match = true;
                }
                break;
            case 'group':
                if ($dept_clean && strcasecmp($dept_clean, $t_clean) === 0) {
                    $match = true;
                }
                if (!$match && in_array($t_clean, $groups_lower)) {
                    $match = true;
                }
                // Also check LDAP groups map if not matched yet
                if (!$match) {
                    $ldap_map = poseaband_get_ldap_enrichment();
                    $g_members = $ldap_map['groups'][$t_clean] ?? [];
                    if (!empty($g_members)) {
                        foreach ($g_members as $mem) {
                            $m_patt = '/(^|[^a-z0-9])' . preg_quote($mem, '/') . '($|[^a-z0-9])/i';
                            if ($user_clean && preg_match($m_patt, $user_clean)) {
                                $match = true;
                                break;
                            }
                        }
                    }
                }
                break;
        }

        if ($match && isset($profiles_by_id[$cr['profile_id']])) {
            $prof = $profiles_by_id[$cr['profile_id']];
            $prof['applied_by_rule'] = true;
            $prof['rule_id'] = $cr['id'] ?? '';
            $prof['rule_descr'] = $cr['descr'] ?: "Özel Kural ({$t_type}: {$t_val})";
            $prof['rule_target'] = $t_val;
            $prof['rule_type'] = $t_type;
            return $prof;
        }
    }

    // 2. Automatic AD vs Guest Classification
    $auto_guest = !isset($conf['auto_guest_limit']) || !empty($conf['auto_guest_limit']);
    
    // Check if device is authenticated in Active Directory
    $is_ad_authenticated = false;
    if (!empty($user) && $user !== 'anonymous' && strpos($user, 'Misafir') === false) {
        $is_ad_authenticated = true;
    }

    if ($auto_guest && !$is_ad_authenticated) {
        // UNMAPPED / GUEST / WI-FI DEVICE
        $guest = $profiles_by_id['prof_guest'] ?? null;
        if ($guest) {
            $guest['applied_by_rule'] = false;
            $guest['rule_descr'] = 'Otomatik AD / Misafir Koruması';
            $guest['rule_badge'] = 'label-warning';
            $guest['is_guest_auto'] = true;
            return $guest;
        }
    }

    // 3. Authenticated Staff or standard fallback
    $std = $profiles_by_id['prof_standard'] ?? null;
    if ($std) {
        $std['applied_by_rule'] = false;
        $std['rule_descr'] = $is_ad_authenticated ? 'AD Doğrulanmış Personel' : 'Varsayılan Standart Hız';
        $std['rule_badge'] = 'label-info';
        return $std;
    }

    $def_down = (float)($conf['default_download_mbps'] ?? 5);
    $def_up = (float)($conf['default_upload_mbps'] ?? 5);
    return [
        'id' => 'prof_standard',
        'name' => 'Standart (Varsayılan)',
        'down_mbps' => $def_down,
        'up_mbps' => $def_up,
        'badge' => 'label-info',
        'applied_by_rule' => false,
        'rule_descr' => 'Varsayılan Standart Hız'
    ];
}

function poseaband_sync_system($conf = null) {
    if ($conf === null) {
        $conf = poseaband_get_config();
    }
    global $config;

    $enabled = !empty($conf['enabled']);
    $bypass_lan = !empty($conf['bypass_local_lan']);
    $auto_guest = !isset($conf['auto_guest_limit']) || !empty($conf['auto_guest_limit']);

    if (!isset($config['dnshaper']) || !is_array($config['dnshaper'])) {
        $config['dnshaper'] = [];
    }
    if (!isset($config['filter']['rule']) || !is_array($config['filter']['rule'])) {
        $config['filter']['rule'] = [];
    }

    if ($enabled) {
        // 1. Build limiters for each profile
        $queues = [];
        $pipe_num = 1;

        foreach ($conf['profiles'] ?? [] as $p) {
            $pid = preg_replace('/[^a-zA-Z0-9_]/', '', $p['id']);
            $pdown = max(0.5, floatval($p['down_mbps'] ?? 5));
            $pup = max(0.5, floatval($p['up_mbps'] ?? 5));

            // Down pipe (mask dstaddress 32)
            $queues[] = [
                'name' => "Limiter_{$pid}_Down",
                'number' => $pipe_num++,
                'qlimit' => '100',
                'plr' => '',
                'description' => "PoseaBand {$p['name']} Down ({$pdown}M)",
                'bandwidth' => [
                    'item' => [[
                        'bw' => (string)$pdown,
                        'bwscale' => 'Mb',
                        'bwsched' => 'none'
                    ]]
                ],
                'enabled' => 'on',
                'buckets' => '',
                'mask' => 'dstaddress',
                'maskbits' => '32',
                'maskbitsv6' => '128',
                'delay' => '0',
                'sched' => 'fq_codel',
                'aqm' => 'codel'
            ];

            // Up pipe (mask srcaddress 32)
            $queues[] = [
                'name' => "Limiter_{$pid}_Up",
                'number' => $pipe_num++,
                'qlimit' => '100',
                'plr' => '',
                'description' => "PoseaBand {$p['name']} Up ({$pup}M)",
                'bandwidth' => [
                    'item' => [[
                        'bw' => (string)$pup,
                        'bwscale' => 'Mb',
                        'bwsched' => 'none'
                    ]]
                ],
                'enabled' => 'on',
                'buckets' => '',
                'mask' => 'srcaddress',
                'maskbits' => '32',
                'maskbitsv6' => '128',
                'delay' => '0',
                'sched' => 'fq_codel',
                'aqm' => 'codel'
            ];
        }

        // Backward-compatible generic 5M limiters
        $std_down = max(0.5, floatval($conf['default_download_mbps'] ?? 5));
        $std_up = max(0.5, floatval($conf['default_upload_mbps'] ?? 5));

        $queues[] = [
            'name' => 'Limiter_5M_Down',
            'number' => $pipe_num++,
            'qlimit' => '100',
            'plr' => '',
            'description' => "PoseaBand Default Download Limiter",
            'bandwidth' => [
                'item' => [[
                    'bw' => (string)$std_down,
                    'bwscale' => 'Mb',
                    'bwsched' => 'none'
                ]]
            ],
            'enabled' => 'on',
            'buckets' => '',
            'mask' => 'dstaddress',
            'maskbits' => '32',
            'maskbitsv6' => '128',
            'delay' => '0',
            'sched' => 'fq_codel',
            'aqm' => 'codel'
        ];

        $queues[] = [
            'name' => 'Limiter_5M_Up',
            'number' => $pipe_num++,
            'qlimit' => '100',
            'plr' => '',
            'description' => "PoseaBand Default Upload Limiter",
            'bandwidth' => [
                'item' => [[
                    'bw' => (string)$std_up,
                    'bwscale' => 'Mb',
                    'bwsched' => 'none'
                ]]
            ],
            'enabled' => 'on',
            'buckets' => '',
            'mask' => 'srcaddress',
            'maskbits' => '32',
            'maskbitsv6' => '128',
            'delay' => '0',
            'sched' => 'fq_codel',
            'aqm' => 'codel'
        ];

        $config['dnshaper']['queue'] = $queues;

        // 2. Read ARP & AD users
        $arp_map = [];
        exec("/usr/sbin/arp -an 2>/dev/null", $arp_lines);
        foreach ($arp_lines as $l) {
            if (preg_match('/\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:]+)/i', $l, $m)) {
                $arp_map[strtolower($m[2])] = $m[1];
            }
        }

        $ad_sessions = [];
        if (file_exists('/usr/local/pkg/posea_ad_sso.inc')) {
            require_once('/usr/local/pkg/posea_ad_sso.inc');
            if (function_exists('posea_sso_get_sessions')) {
                $ad_sessions = posea_sso_get_sessions();
            }
        }
        if (empty($ad_sessions) && file_exists('/var/etc/poseafilter/ad_users.json')) {
            $ad_sessions = @json_decode(file_get_contents('/var/etc/poseafilter/ad_users.json'), true) ?: [];
        }

        // Enrich AD sessions with real LDAP user accounts, display names, departments & groups
        $ldap_enrichment = poseaband_get_ldap_enrichment();
        $ldap_groups_map = $ldap_enrichment['groups'] ?? [];

        foreach ($ad_sessions as $u_ip => &$u_info) {
            $resolved = poseaband_resolve_client_identity($u_ip, $u_info, $ldap_enrichment);
            $u_info['username'] = $resolved['username'];
            $u_info['display_name'] = $resolved['display_name'];
            $u_info['department'] = $resolved['department'];
            $u_info['groups'] = $resolved['groups'];
        }
        unset($u_info);

        // Clean existing PoseaBand specific rules
        $cleaned_rules = [];
        foreach ($config['filter']['rule'] as $r) {
            if (is_array($r) && ($r['interface'] ?? '') === 'lan') {
                if (strpos($r['descr'] ?? '', 'PoseaBand Rule:') !== false) {
                    continue; // Skip old dynamic rules
                }
            }
            $cleaned_rules[] = $r;
        }

        // Ensure Local LAN Bypass rule exists at top
        $has_local_rule = false;
        foreach ($cleaned_rules as &$r) {
            if (is_array($r) && ($r['interface'] ?? '') === 'lan') {
                if (($r['descr'] ?? '') === 'Pass LAN to Local Subnets without Limiter') {
                    $has_local_rule = true;
                    if (!$bypass_lan) {
                        $r['disabled'] = 'yes';
                    } else {
                        unset($r['disabled']);
                    }
                    break;
                }
            }
        }
        unset($r);

        if (!$has_local_rule && $bypass_lan) {
            $local_lan_rule = [
                'id' => '',
                'tracker' => (string)(time() - 20),
                'type' => 'pass',
                'interface' => 'lan',
                'ipprotocol' => 'inet',
                'statetype' => 'keep state',
                'source' => ['any' => ''],
                'destination' => ['network' => 'lan'],
                'descr' => 'Pass LAN to Local Subnets without Limiter',
                'created' => ['time' => (string)time(), 'username' => 'admin (PoseaBand QoS Setup)']
            ];
            array_unshift($cleaned_rules, $local_lan_rule);
        }

        // Build specific client rules
        $generated_client_rules = [];
        $explicit_ips = [];
        $rule_seq = 1;
        foreach ($conf['client_rules'] ?? [] as $cr) {
            if (empty($cr['enabled'])) continue;
            $pid = preg_replace('/[^a-zA-Z0-9_]/', '', $cr['profile_id'] ?? '');
            if (!$pid) continue;

            $targets = [];
            $t_type = $cr['target_type'] ?? 'ip';
            $t_val = trim($cr['target_val'] ?? '');

            if ($t_type === 'ip') {
                $targets[] = ['address' => $t_val];
                $explicit_ips[$t_val] = true;
            } elseif ($t_type === 'subnet') {
                $targets[] = ['network' => $t_val];
            } elseif ($t_type === 'alias') {
                $targets[] = ['address' => $t_val];
            } elseif ($t_type === 'mac') {
                $m_ip = $arp_map[strtolower($t_val)] ?? null;
                if ($m_ip) {
                    $targets[] = ['address' => $m_ip];
                    $explicit_ips[$m_ip] = true;
                }
            } elseif ($t_type === 'user') {
                $t_clean = strtolower($t_val);
                $patt = '/(^|[^a-z0-9])' . preg_quote($t_clean, '/') . '($|[^a-z0-9])/i';
                foreach ($ad_sessions as $u_ip => $u_info) {
                    $u_user = strtolower(trim($u_info['username'] ?? ''));
                    $u_host = strtolower(trim($u_info['hostname'] ?? ''));
                    $u_disp = strtolower(trim($u_info['display_name'] ?? ''));
                    if ($u_user === $t_clean || $u_host === $t_clean || preg_match($patt, $u_user) || preg_match($patt, $u_host) || preg_match($patt, $u_disp)) {
                        $targets[] = ['address' => $u_ip];
                        $explicit_ips[$u_ip] = true;
                    }
                }
            } elseif ($t_type === 'group') {
                $g_key = strtolower($t_val);
                $g_members = $ldap_groups_map[$g_key] ?? [];

                foreach ($ad_sessions as $u_ip => $u_info) {
                    $g_match = false;
                    // 1. Direct department or group membership from session
                    if (strcasecmp($u_info['department'] ?? '', $t_val) === 0) {
                        $g_match = true;
                    }
                    if (!$g_match && !empty($u_info['groups']) && is_array($u_info['groups'])) {
                        foreach ($u_info['groups'] as $grp) {
                            if (strcasecmp($grp, $t_val) === 0) {
                                $g_match = true;
                                break;
                            }
                        }
                    }
                    // 2. Active Directory LDAP group membership resolution
                    if (!$g_match && !empty($g_members)) {
                        $u_user = strtolower(trim($u_info['username'] ?? ''));
                        $u_host = strtolower(trim($u_info['hostname'] ?? ''));
                        $u_disp = strtolower(trim($u_info['display_name'] ?? ''));

                        foreach ($g_members as $mem) {
                            $m_patt = '/(^|[^a-z0-9])' . preg_quote($mem, '/') . '($|[^a-z0-9])/i';
                            if (($u_host && preg_match($m_patt, $u_host)) || ($u_user && preg_match($m_patt, $u_user)) || ($u_disp && preg_match($m_patt, $u_disp))) {
                                $g_match = true;
                                break;
                            }
                        }
                    }

                    if ($g_match) {
                        $targets[] = ['address' => $u_ip];
                        $explicit_ips[$u_ip] = true;
                    }
                }
            }

            foreach ($targets as $src_def) {
                $generated_client_rules[] = [
                    'id' => '',
                    'tracker' => (string)(time() + ($rule_seq++)),
                    'type' => 'pass',
                    'interface' => 'lan',
                    'ipprotocol' => 'inet',
                    'statetype' => 'keep state',
                    'source' => $src_def,
                    'destination' => ['any' => ''],
                    'descr' => "PoseaBand Rule: " . ($cr['descr'] ?: "{$t_type} {$t_val}") . " [{$pid}]",
                    'dnpipe' => "Limiter_{$pid}_Up",
                    'pdnpipe' => "Limiter_{$pid}_Down",
                    'created' => ['time' => (string)time(), 'username' => 'admin (PoseaBand)']
                ];
            }
        }

        // 3. Auto Guest Limiting Rule via pfSense Alias
        if ($auto_guest) {
            $guest_ips = [];
            foreach ($arp_map as $mac => $ip) {
                if (!poseaband_is_local_ip($ip)) continue;
                if (isset($explicit_ips[$ip])) continue; // Exclude IPs with explicit QoS rules
                $is_ad = false;
                if (isset($ad_sessions[$ip]) && ($ad_sessions[$ip]['status'] ?? '') === 'authenticated') {
                    $is_ad = true;
                }
                if (!$is_ad) {
                    $guest_ips[] = $ip;
                }
            }

            if (empty($guest_ips)) {
                $guest_ips[] = '192.0.2.254';
            }

            // Sync PoseaBand_Guests alias in $config['aliases']['alias']
            if (!isset($config['aliases']['alias']) || !is_array($config['aliases']['alias'])) {
                $config['aliases']['alias'] = [];
            }
            $alias_idx = null;
            foreach ($config['aliases']['alias'] as $idx => $al) {
                if ($al['name'] === 'PoseaBand_Guests') {
                    $alias_idx = $idx;
                    break;
                }
            }
            $alias_obj = [
                'name' => 'PoseaBand_Guests',
                'type' => 'host',
                'descr' => 'PoseaBand Otomatik Misafir ve Mobil Cihazlar',
                'address' => implode(' ', $guest_ips),
                'detail' => implode('||', array_fill(0, count($guest_ips), 'Misafir Cihaz'))
            ];
            if ($alias_idx !== null) {
                $config['aliases']['alias'][$alias_idx] = $alias_obj;
            } else {
                $config['aliases']['alias'][] = $alias_obj;
            }

            // Add the Guest Limiter Rule
            $generated_client_rules[] = [
                'id' => '',
                'tracker' => (string)(time() + 1),
                'type' => 'pass',
                'interface' => 'lan',
                'ipprotocol' => 'inet',
                'statetype' => 'keep state',
                'source' => ['address' => 'PoseaBand_Guests'],
                'destination' => ['any' => ''],
                'descr' => "PoseaBand Rule: Otomatik Misafir & Wi-Fi Koruması (2M/1M)",
                'dnpipe' => 'Limiter_prof_guest_Up',
                'pdnpipe' => 'Limiter_prof_guest_Down',
                'created' => ['time' => (string)time(), 'username' => 'admin (PoseaBand)']
            ];
        }

        // Insert client rules before the default allow LAN rule
        $final_rules = [];
        $inserted = false;
        foreach ($cleaned_rules as $r) {
            if (is_array($r) && ($r['interface'] ?? '') === 'lan' && strpos($r['descr'] ?? '', 'Default allow LAN') !== false) {
                foreach ($generated_client_rules as $gcr) {
                    $final_rules[] = $gcr;
                }
                $inserted = true;
                // Attach default limiter to the default rule
                $r['dnpipe'] = 'Limiter_5M_Up';
                $r['pdnpipe'] = 'Limiter_5M_Down';
                $r['updated'] = ['time' => (string)time(), 'username' => 'admin (PoseaBand)'];
            }
            $final_rules[] = $r;
        }

        if (!$inserted) {
            foreach ($generated_client_rules as $gcr) {
                $final_rules[] = $gcr;
            }
        }

        $config['filter']['rule'] = $final_rules;

    } else {
        // Disabled: remove all limiters and PoseaBand rules
        $new_rules = [];
        foreach ($config['filter']['rule'] as $r) {
            if (is_array($r) && ($r['interface'] ?? '') === 'lan') {
                if (strpos($r['descr'] ?? '', 'PoseaBand Rule:') !== false) {
                    continue;
                }
                if (isset($r['dnpipe']) && strpos($r['dnpipe'], 'Limiter_') !== false) {
                    unset($r['dnpipe']);
                }
                if (isset($r['pdnpipe']) && strpos($r['pdnpipe'], 'Limiter_') !== false) {
                    unset($r['pdnpipe']);
                }
            }
            $new_rules[] = $r;
        }
        $config['filter']['rule'] = $new_rules;
    }

    write_config("PoseaBand: " . ($enabled ? "Synchronized QoS Profiles and Rules" : "Disabled QoS Limiting"));
    filter_configure();
    if ($enabled && !empty($explicit_ips)) {
        poseaband_kill_all_client_states(array_keys($explicit_ips));
        foreach (array_keys($explicit_ips) as $ex_ip) {
            if (filter_var($ex_ip, FILTER_VALIDATE_IP)) {
                @shell_exec("/sbin/pfctl -t PoseaBand_Guests -T delete " . escapeshellarg($ex_ip) . " 2>/dev/null");
            }
        }
    }
    return true;
}

function poseaband_install() {
    poseaband_get_config();
}

function poseaband_deinstall() {
    $conf = poseaband_get_config();
    $conf['enabled'] = false;
    poseaband_save_config($conf);
    poseaband_sync_system($conf);
    @unlink('/usr/local/www/widgets/include/poseaband.inc');
    @unlink('/usr/local/www/widgets/widgets/poseaband.widget.php');
}
