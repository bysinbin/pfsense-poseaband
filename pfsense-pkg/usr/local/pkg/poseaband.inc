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
                'descr' => 'Standart ofis ve çalışan profili',
                'badge' => 'label-info'
            ],
            [
                'id' => 'prof_guest',
                'name' => 'Misafir & Wi-Fi',
                'down_mbps' => 2,
                'up_mbps' => 1,
                'descr' => 'Misafir Wi-Fi ve mobil cihazlar için kısıtlı hız',
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

function poseaband_find_client_profile($conf, $ip, $mac = '', $user = '', $dept = '') {
    $profiles_by_id = [];
    foreach ($conf['profiles'] ?? [] as $p) {
        $profiles_by_id[$p['id']] = $p;
    }

    $mac_clean = strtolower(trim($mac));
    $user_clean = strtolower(trim($user));
    $dept_clean = strtolower(trim($dept));

    foreach ($conf['client_rules'] ?? [] as $cr) {
        if (empty($cr['enabled'])) continue;
        $t_type = $cr['target_type'] ?? 'ip';
        $t_val = trim($cr['target_val'] ?? '');
        $match = false;

        switch ($t_type) {
            case 'ip':
                if ($ip === $t_val) $match = true;
                break;
            case 'subnet':
                if (poseaband_cidr_match($ip, $t_val)) $match = true;
                break;
            case 'mac':
                if ($mac_clean && $mac_clean === strtolower($t_val)) $match = true;
                break;
            case 'user':
                if ($user_clean && $user_clean === strtolower($t_val)) $match = true;
                break;
            case 'group':
                if ($dept_clean && $dept_clean === strtolower($t_val)) $match = true;
                break;
        }

        if ($match && isset($profiles_by_id[$cr['profile_id']])) {
            $prof = $profiles_by_id[$cr['profile_id']];
            $prof['applied_by_rule'] = true;
            $prof['rule_id'] = $cr['id'] ?? '';
            $prof['rule_descr'] = $cr['descr'] ?? '';
            $prof['rule_target'] = $t_val;
            return $prof;
        }
    }

    // Default profile fallback
    $def_down = (float)($conf['default_download_mbps'] ?? 5);
    $def_up = (float)($conf['default_upload_mbps'] ?? 5);
    
    // Check if matching standard profile exists
    $std = $profiles_by_id['prof_standard'] ?? null;
    if ($std) {
        $std['applied_by_rule'] = false;
        $std['rule_descr'] = 'Varsayılan Standart Hız';
        return $std;
    }

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
    $down_speed = (int)($conf['default_download_mbps'] ?? 5);
    if ($down_speed <= 0) $down_speed = 5;
    $up_speed = (int)($conf['default_upload_mbps'] ?? 5);
    if ($up_speed <= 0) $up_speed = 5;
    $bypass_lan = !empty($conf['bypass_local_lan']);

    if (!isset($config['dnshaper']) || !is_array($config['dnshaper'])) {
        $config['dnshaper'] = [];
    }

    if ($enabled) {
        $queues = [];
        $pipe_num = 1;

        // 1. Build limiters for each profile
        foreach ($conf['profiles'] ?? [] as $p) {
            $pid = preg_replace('/[^a-zA-Z0-9_]/', '', $p['id']);
            $pdown = max(0.5, floatval($p['down_mbps'] ?? 5));
            $pup = max(0.5, floatval($p['up_mbps'] ?? 5));

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
        $queues[] = [
            'name' => 'Limiter_5M_Down',
            'number' => $pipe_num++,
            'qlimit' => '100',
            'plr' => '',
            'description' => "PoseaBand Default Download Limiter",
            'bandwidth' => [
                'item' => [[
                    'bw' => (string)$down_speed,
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
                    'bw' => (string)$up_speed,
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

        // 2. Read ARP & AD users for MAC / User / Group mapping
        $arp_map = [];
        exec("/usr/sbin/arp -an 2>/dev/null", $arp_lines);
        foreach ($arp_lines as $l) {
            if (preg_match('/\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:]+)/i', $l, $m)) {
                $arp_map[strtolower($m[2])] = $m[1];
            }
        }

        $ad_users = [];
        $ad_file = '/var/etc/poseafilter/ad_users.json';
        if (file_exists($ad_file)) {
            $ad_users = @json_decode(file_get_contents($ad_file), true) ?: [];
        }

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
        foreach ($conf['client_rules'] ?? [] as $cr) {
            if (empty($cr['enabled'])) continue;
            $pid = preg_replace('/[^a-zA-Z0-9_]/', '', $cr['profile_id'] ?? '');
            if (!$pid) continue;

            $targets = [];
            $t_type = $cr['target_type'] ?? 'ip';
            $t_val = trim($cr['target_val'] ?? '');

            if ($t_type === 'ip') {
                $targets[] = ['address' => $t_val];
            } elseif ($t_type === 'subnet') {
                $targets[] = ['network' => $t_val];
            } elseif ($t_type === 'mac') {
                $m_ip = $arp_map[strtolower($t_val)] ?? null;
                if ($m_ip) {
                    $targets[] = ['address' => $m_ip];
                }
            } elseif ($t_type === 'user' || $t_type === 'group') {
                foreach ($ad_users as $u_ip => $u_info) {
                    if ($t_type === 'user' && strcasecmp($u_info['username'] ?? '', $t_val) === 0) {
                        $targets[] = ['address' => $u_ip];
                    } elseif ($t_type === 'group' && strcasecmp($u_info['department'] ?? '', $t_val) === 0) {
                        $targets[] = ['address' => $u_ip];
                    }
                }
            }

            foreach ($targets as $src_def) {
                $generated_client_rules[] = [
                    'id' => '',
                    'tracker' => (string)time(),
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
    return true;
}
