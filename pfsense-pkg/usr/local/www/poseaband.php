<?php
/*
 * poseaband.php - PoseaBand Bandwidth & QoS Engine for pfSense
 * Part of Posea Security Suite
 */

require_once("guiconfig.inc");
require_once("/usr/local/pkg/poseafilter.inc");
require_once("/usr/local/pkg/poseaband.inc");

$conf = poseaband_get_config();
$savemsg = "";

// Handle AJAX live traffic query
if (isset($_GET['ajax_traffic'])) {
    session_write_close();
    header('Content-Type: application/json; charset=utf-8');
    
    $cache_file = '/tmp/poseaband_cache.json';
    if (file_exists($cache_file) && (time() - filemtime($cache_file) < 3)) {
        $cached = @file_get_contents($cache_file);
        if ($cached) {
            echo $cached;
            exit;
        }
    }
    
    // Read AD users & sessions
    $ad_users = [];
    if (file_exists('/usr/local/pkg/posea_ad_sso.inc')) {
        require_once('/usr/local/pkg/posea_ad_sso.inc');
        if (function_exists('posea_sso_get_sessions')) {
            $ad_users = posea_sso_get_sessions();
        }
    }
    if (empty($ad_users) && file_exists('/var/etc/poseafilter/ad_users.json')) {
        $ad_users = @json_decode(file_get_contents('/var/etc/poseafilter/ad_users.json'), true) ?: [];
    }
    
    // Read ARP
    $arp_map = [];
    exec("/usr/sbin/arp -an 2>/dev/null", $arp_lines);
    foreach ($arp_lines as $l) {
        if (preg_match('/\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:]+)/i', $l, $m)) {
            $arp_map[$m[1]] = strtolower($m[2]);
        }
    }
    
    // Run iftop short sample (1s fast mode)
    $iftop_raw = shell_exec("/usr/local/sbin/iftop -t -s 1 -n -N -i vtnet1 2>/dev/null");
    $lines = explode("\n", (string)$iftop_raw);
    
    function pb_parse_rate($str) {
        $str = trim($str);
        if (!$str) return 0.0;
        $mult = 1.0;
        if (str_ends_with($str, 'Kb')) {
            $mult = 1.0 / 1024.0;
            $val = substr($str, 0, -2);
        } elseif (str_ends_with($str, 'Mb')) {
            $mult = 1.0;
            $val = substr($str, 0, -2);
        } elseif (str_ends_with($str, 'Gb')) {
            $mult = 1024.0;
            $val = substr($str, 0, -2);
        } elseif (str_ends_with($str, 'b')) {
            $mult = 1.0 / (1024.0 * 1024.0);
            $val = substr($str, 0, -1);
        } else {
            return 0.0;
        }
        return floatval($val) * $mult;
    }
    
    $rates = [];
    $count = count($lines);
    for ($i = 0; $i < $count; $i++) {
        $line = $lines[$i];
        if (preg_match('/^\s*\d+\s+([0-9a-z\.\-_]+)\s+=>\s+([0-9\.]+[A-Za-z]+)\s+([0-9\.]+[A-Za-z]+)/', $line, $m1)) {
            if ($i + 1 < $count) {
                $line2 = $lines[$i + 1];
                if (preg_match('/^\s*([0-9a-z\.\-_]+)\s+<=\s+([0-9\.]+[A-Za-z]+)\s+([0-9\.]+[A-Za-z]+)/', $line2, $m2)) {
                    $host_a = $m1[1];
                    $host_b = $m2[1];
                    $down = pb_parse_rate($m1[2]);
                    $up = pb_parse_rate($m2[2]);
                    
                    $lan_ip = null;
                    $remote = null;
                    if (str_starts_with($host_b, '192.168.')) {
                        $lan_ip = $host_b;
                        $remote = $host_a;
                    } elseif (str_starts_with($host_a, '192.168.')) {
                        $lan_ip = $host_a;
                        $remote = $host_b;
                    }
                    
                    if ($lan_ip) {
                        if (!isset($rates[$lan_ip])) {
                            $rates[$lan_ip] = ['down' => 0.0, 'up' => 0.0, 'remote' => $remote];
                        }
                        $rates[$lan_ip]['down'] += $down;
                        $rates[$lan_ip]['up'] += $up;
                    }
                }
            }
        }
    }
    
    uasort($rates, function($a, $b) {
        return $b['down'] <=> $a['down'];
    });
    
    $result = [];
    foreach ($rates as $ip => $data) {
        $u_name = "Misafir Cihaz / Wi-Fi";
        $dept = "Misafir";
        $groups = [];
        $is_ad_auth = false;

        if (isset($ad_users[$ip])) {
            $u = $ad_users[$ip];
            if (!empty($u['username']) && $u['username'] !== 'anonymous' && ($u['status'] ?? '') === 'authenticated') {
                $u_name = $u['display_name'] ?? ($u['username'] ?? 'Domain User');
                $dept = $u['department'] ?? 'Domain Computers';
                $groups = $u['groups'] ?? [];
                $is_ad_auth = true;
            }
        }
        $mac = $arp_map[$ip] ?? '';

        // Match applied QoS profile
        $applied = poseaband_find_client_profile($conf, $ip, $mac, $u_name, $dept, $groups);

        $badge = 'label-info';
        if ($applied['down_mbps'] >= 20) $badge = 'label-success';
        elseif ($applied['down_mbps'] <= 1) $badge = 'label-danger';
        elseif ($applied['down_mbps'] <= 2) $badge = 'label-warning';

        $result[] = [
            'ip' => $ip,
            'user' => $u_name,
            'dept' => $dept,
            'is_ad' => $is_ad_auth,
            'mac' => $mac ?: 'Bilinmiyor',
            'down_mbps' => round($data['down'], 2),
            'up_mbps' => round($data['up'], 2),
            'remote' => $data['remote'] ?: '-',
            'profile_id' => $applied['id'] ?? 'prof_standard',
            'profile_name' => $applied['name'] ?? 'Standart',
            'profile_down' => $applied['down_mbps'] ?? 5,
            'profile_up' => $applied['up_mbps'] ?? 5,
            'profile_badge' => $badge,
            'applied_by_rule' => !empty($applied['applied_by_rule']),
            'rule_descr' => $applied['rule_descr'] ?? ''
        ];
    }
    
    $json_out = json_encode([
        'enabled' => !empty($conf['enabled']),
        'total_clients' => count($result),
        'clients' => array_slice($result, 0, 25)
    ], JSON_UNESCAPED_UNICODE);

    @file_put_contents($cache_file, $json_out);
    echo $json_out;
    exit;
}

// Handle Form Submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['act'] ?? '';

    if ($action === 'save_settings') {
        $conf['enabled'] = !empty($_POST['enabled']);
        $conf['default_download_mbps'] = max(0.5, floatval($_POST['default_download_mbps'] ?? 5));
        $conf['default_upload_mbps'] = max(0.5, floatval($_POST['default_upload_mbps'] ?? 5));
        $conf['bypass_local_lan'] = !empty($_POST['bypass_local_lan']);
        $conf['auto_guest_limit'] = !empty($_POST['auto_guest_limit']);

        poseaband_save_config($conf);
        poseaband_sync_system($conf);
        $savemsg = "PoseaBand yapılandırması başarıyla kaydedildi ve uygulandı.";

    } elseif ($action === 'save_profile') {
        $p_id = trim($_POST['prof_id'] ?? '');
        $p_name = trim($_POST['prof_name'] ?? '');
        $p_down = max(0.1, floatval($_POST['prof_down'] ?? 5));
        $p_up = max(0.1, floatval($_POST['prof_up'] ?? 5));
        $p_descr = trim($_POST['prof_descr'] ?? '');

        if ($p_name) {
            $found = false;
            if ($p_id) {
                foreach ($conf['profiles'] as &$p) {
                    if (($p['id'] ?? '') === $p_id) {
                        $p['name'] = $p_name;
                        $p['down_mbps'] = $p_down;
                        $p['up_mbps'] = $p_up;
                        $p['descr'] = $p_descr;
                        $found = true;
                        break;
                    }
                }
                unset($p);
            }
            if (!$found) {
                $p_id = 'prof_' . substr(md5(uniqid()), 0, 6);
                $conf['profiles'][] = [
                    'id' => $p_id,
                    'name' => $p_name,
                    'down_mbps' => $p_down,
                    'up_mbps' => $p_up,
                    'descr' => $p_descr,
                    'badge' => 'label-primary'
                ];
                $savemsg = "Yeni hız profili ('{$p_name}') başarıyla eklendi.";
            } else {
                $savemsg = "Hız profili ('{$p_name}') başarıyla güncellendi.";
            }
            poseaband_save_config($conf);
            poseaband_sync_system($conf);
        }

    } elseif ($action === 'del_profile') {
        $p_id = trim($_POST['prof_id'] ?? '');
        if (in_array($p_id, ['prof_vip', 'prof_standard', 'prof_guest'])) {
            $savemsg = "Varsayılan sistem profilleri silinemez (ancak hızlarını düzenleyebilirsiniz).";
        } else {
            $conf['profiles'] = array_values(array_filter($conf['profiles'], function($p) use ($p_id) {
                return ($p['id'] ?? '') !== $p_id;
            }));
            poseaband_save_config($conf);
            poseaband_sync_system($conf);
            $savemsg = "Hız profili başarıyla silindi.";
        }

    } elseif ($action === 'save_client_rule') {
        $r_id = trim($_POST['rule_id'] ?? '');
        $t_type = trim($_POST['target_type'] ?? 'ip');
        $t_val = trim($_POST['target_val'] ?? '');
        $prof_id = trim($_POST['target_profile'] ?? 'prof_standard');
        $descr = trim($_POST['rule_descr'] ?? '');

        if ($t_val) {
            $found = false;
            if ($r_id) {
                foreach ($conf['client_rules'] as &$r) {
                    if (($r['id'] ?? '') === $r_id) {
                        $r['target_type'] = $t_type;
                        $r['target_val'] = $t_val;
                        $r['profile_id'] = $prof_id;
                        $r['descr'] = $descr;
                        $r['enabled'] = true;
                        $found = true;
                        break;
                    }
                }
                unset($r);
            }
            if (!$found) {
                $r_id = 'crule_' . substr(md5(uniqid()), 0, 6);
                $conf['client_rules'][] = [
                    'id' => $r_id,
                    'target_type' => $t_type,
                    'target_val' => $t_val,
                    'profile_id' => $prof_id,
                    'descr' => $descr,
                    'enabled' => true
                ];
                $savemsg = "Özel hız atama kuralı ('{$t_val}') başarıyla eklendi ve uygulandı.";
            } else {
                $savemsg = "Hız atama kuralı ('{$t_val}') başarıyla güncellendi.";
            }
            poseaband_save_config($conf);
            poseaband_sync_system($conf);
        }

    } elseif ($action === 'del_client_rule') {
        $r_id = trim($_POST['rule_id'] ?? '');
        $conf['client_rules'] = array_values(array_filter($conf['client_rules'], function($r) use ($r_id) {
            return ($r['id'] ?? '') !== $r_id;
        }));
        poseaband_save_config($conf);
        poseaband_sync_system($conf);
        $savemsg = "İstemci hız kuralı başarıyla silindi.";

    } elseif ($action === 'kill_host_states') {
        $kill_ip = escapeshellarg(trim($_POST['kill_ip'] ?? ''));
        if (!empty($kill_ip)) {
            shell_exec("/sbin/pfctl -k {$kill_ip} 2>/dev/null");
            $savemsg = "{$kill_ip} için aktif tüm oturumlar sıfırlandı.";
        }
    }
}

// Fetch AD & pfSense Aliases Metadata
$meta = poseaband_get_ad_metadata();
$meta_aliases = $meta['aliases'] ?? [];
$meta_groups = $meta['ad_groups'] ?? [];
$meta_users = $meta['ad_users'] ?? [];
$meta_clients = $meta['lan_clients'] ?? [];

$pgtitle = array(gettext("Services"), gettext("PoseaBand (Bant Genişliği & QoS)"));
include("head.inc");

$tab_array = array();
$tab_array[] = array(gettext("PoseaBand (QoS)"), true, "/poseaband.php");
$tab_array[] = array(gettext("PoseaInsight"), false, "/poseainsight.php");
$tab_array[] = array(gettext("PoseaApp"), false, "/poseaapp.php");
$tab_array[] = array(gettext("PoseaAccess"), false, "/poseaaccess.php");
display_top_tabs($tab_array);

if ($savemsg) {
    print_info_box($savemsg, 'success');
}

// Build profile lookup map for table renders
$profiles_map = [];
foreach ($conf['profiles'] ?? [] as $p) {
    $profiles_map[$p['id']] = $p;
}
?>

<div class="panel panel-default">
    <div class="panel-heading">
        <h2 class="panel-title">
            <i class="fa fa-dashboard"></i> PoseaBand &bull; Kurumsal Bant Genişliği &amp; QoS Hız Yöneticisi
        </h2>
    </div>
    <div class="panel-body">
        <p class="text-muted">
            PoseaBand, ağdaki tekil kullanıcıların veya misafir cihazların kurumsal internet hattını kilitlemesini önler. 
            Active Directory ile tam entegre çalışır; doğrulanmış personele ayrı, misafir ve mobil cihazlara otomatik ayrı hız limitleri tanımlar.
        </p>

        <!-- FORM 1: Settings Form -->
        <form method="post" id="settingsForm" class="form-horizontal" novalidate>
            <input type="hidden" name="act" value="save_settings">

            <div class="alert <?=!empty($conf['enabled']) ? 'alert-success' : 'alert-warning'?>" style="display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; padding:12px 18px; border-radius:6px;">
                <div style="font-size:14px;">
                    <strong><i class="fa fa-power-off"></i> PoseaBand Çalışma Durumu:</strong>
                    <?php if (!empty($conf['enabled'])): ?>
                        <span class="badge" style="background-color:#16a34a; font-size:13px; margin-left:8px; padding:6px 12px;">AKTİF (Hız Limitleri Uygulanıyor)</span>
                    <?php else: ?>
                        <span class="badge" style="background-color:#64748b; font-size:13px; margin-left:8px; padding:6px 12px;">PASİF (Limitler Devre Dışı)</span>
                    <?php endif; ?>
                </div>
                <div class="checkbox" style="margin:0;">
                    <label style="font-weight:700; color:#0f172a; cursor:pointer; font-size:13px;">
                        <input type="checkbox" name="enabled" value="1" <?=!empty($conf['enabled']) ? 'checked' : ''?> onchange="this.form.submit();" style="transform:scale(1.2); margin-right:8px;">
                        PoseaBand Servisini Etkinleştir
                    </label>
                </div>
            </div>

            <!-- ROW 1: Default Speeds & Defined Profiles -->
            <div class="row" style="margin-top:20px;">
                <div class="col-md-6">
                    <div class="panel panel-info">
                        <div class="panel-heading"><strong><i class="fa fa-download"></i> Varsayılan Kişi Başı İnternet Hızı</strong></div>
                        <div class="panel-body">
                            <div class="form-group">
                                <label class="col-sm-5 control-label">Varsayılan İndirme (Download):</label>
                                <div class="col-sm-7">
                                    <div class="input-group">
                                        <input type="number" class="form-control" name="default_download_mbps" value="<?=htmlspecialchars((string)($conf['default_download_mbps'] ?? 5))?>" min="0.5" max="1000" step="0.5">
                                        <span class="input-group-addon">Mbit/s</span>
                                    </div>
                                    <span class="help-block">Özel kural atanmamış AD domain kullanıcılarına uygulanacak standart maksimum indirme hızı.</span>
                                </div>
                            </div>

                            <div class="form-group">
                                <label class="col-sm-5 control-label">Varsayılan Yükleme (Upload):</label>
                                <div class="col-sm-7">
                                    <div class="input-group">
                                        <input type="number" class="form-control" name="default_upload_mbps" value="<?=htmlspecialchars((string)($conf['default_upload_mbps'] ?? 5))?>" min="0.5" max="1000" step="0.5">
                                        <span class="input-group-addon">Mbit/s</span>
                                    </div>
                                    <span class="help-block">Özel kural atanmamış AD domain kullanıcılarına uygulanacak standart maksimum yükleme hızı.</span>
                                </div>
                            </div>

                            <div class="form-group">
                                <div class="col-sm-offset-5 col-sm-7">
                                    <div class="checkbox">
                                        <label>
                                            <input type="checkbox" name="bypass_local_lan" value="1" <?=!empty($conf['bypass_local_lan']) ? 'checked' : ''?>>
                                            <strong>Yerel Ağ (LAN-LAN) İstisnası:</strong> Şirket içi sunucular, dosya paylaşımı ve yazıcılar sınırsız (1 Gbps) çalışsın.
                                        </label>
                                    </div>
                                    <div class="checkbox" style="margin-top:8px;">
                                        <label>
                                            <input type="checkbox" name="auto_guest_limit" value="1" <?=!empty($conf['auto_guest_limit'] ?? true) ? 'checked' : ''?>>
                                            <strong>Akıllı AD &amp; Misafir Ayrımı:</strong> Active Directory'de doğrulanmamış misafir ve mobil cihazlara otomatik olarak <strong>Misafir &amp; Wi-Fi Profili (2M/1M)</strong> uygulansın.
                                        </label>
                                    </div>
                                </div>
                            </div>

                            <div class="form-group">
                                <div class="col-sm-offset-5 col-sm-7">
                                    <button type="submit" class="btn btn-primary"><i class="fa fa-save"></i> Yapılandırmayı Kaydet &amp; Uygula</button>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
        </form> <!-- CLOSE settingsForm -->

                <!-- ROW 1 Right: Defined Profiles -->
                <div class="col-md-6">
                    <div class="panel panel-success">
                        <div class="panel-heading" style="display:flex; justify-content:space-between; align-items:center;">
                            <strong><i class="fa fa-sliders"></i> Tanımlı Hız Profilleri</strong>
                            <button type="button" class="btn btn-xs btn-default" onclick="openNewProfileForm();"><i class="fa fa-plus"></i> Yeni Profil Ekle</button>
                        </div>
                        <div class="panel-body">
                            <!-- Dark Add/Edit Profile Collapse Panel with its OWN Form -->
                            <div id="newProfilePanel" class="collapse" style="background:#1e293b; color:#f1f5f9; padding:18px; border-radius:8px; margin-bottom:15px; border:1px solid #3b82f6; box-shadow:0 4px 6px -1px rgba(0,0,0,0.3);">
                                <form method="post" id="profileForm" class="form-horizontal" novalidate onsubmit="return validateProfileForm();">
                                    <input type="hidden" name="act" value="save_profile">
                                    <input type="hidden" name="prof_id" id="prof_id_input" value="">

                                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px; border-bottom:1px solid #334155; padding-bottom:8px;">
                                        <h4 style="color:#60a5fa; margin:0; font-weight:700;"><i class="fa fa-tachometer"></i> <span id="profFormTitle">Yeni Hız Profili Tanımla</span></h4>
                                        <button type="button" class="btn btn-xs btn-default" onclick="$('#newProfilePanel').collapse('hide');" style="color:#94a3b8;"><i class="fa fa-times"></i> Kapat</button>
                                    </div>
                                    
                                    <div class="form-group" style="margin-bottom:12px;">
                                        <label class="col-sm-4 control-label" style="color:#cbd5e1; font-weight:600;">Profil Adı:</label>
                                        <div class="col-sm-8">
                                            <input type="text" name="prof_name" id="prof_name_input" class="form-control" placeholder="Örn: Muhasebe &amp; Finans" style="background:#0f172a; color:#fff; border:1px solid #475569;">
                                        </div>
                                    </div>

                                    <div class="form-group" style="margin-bottom:12px;">
                                        <label class="col-sm-4 control-label" style="color:#cbd5e1; font-weight:600;">İndirme (Download):</label>
                                        <div class="col-sm-8">
                                            <div class="input-group">
                                                <input type="number" name="prof_down" id="prof_down_input" class="form-control" value="10" min="0.1" max="1000" step="0.5" style="background:#0f172a; color:#fff; border:1px solid #475569;">
                                                <span class="input-group-addon" style="background:#334155; color:#cbd5e1; border:1px solid #475569;">Mbit/s</span>
                                            </div>
                                        </div>
                                    </div>

                                    <div class="form-group" style="margin-bottom:12px;">
                                        <label class="col-sm-4 control-label" style="color:#cbd5e1; font-weight:600;">Yükleme (Upload):</label>
                                        <div class="col-sm-8">
                                            <div class="input-group">
                                                <input type="number" name="prof_up" id="prof_up_input" class="form-control" value="5" min="0.1" max="1000" step="0.5" style="background:#0f172a; color:#fff; border:1px solid #475569;">
                                                <span class="input-group-addon" style="background:#334155; color:#cbd5e1; border:1px solid #475569;">Mbit/s</span>
                                            </div>
                                        </div>
                                    </div>

                                    <div class="form-group" style="margin-bottom:12px;">
                                        <label class="col-sm-4 control-label" style="color:#cbd5e1; font-weight:600;">Açıklama:</label>
                                        <div class="col-sm-8">
                                            <input type="text" name="prof_descr" id="prof_descr_input" class="form-control" placeholder="Bu profilin kullanım amacı" style="background:#0f172a; color:#fff; border:1px solid #475569;">
                                        </div>
                                    </div>

                                    <div class="form-group" style="margin-bottom:0;">
                                        <div class="col-sm-offset-4 col-sm-8 text-right">
                                            <button type="button" class="btn btn-default btn-sm" onclick="$('#newProfilePanel').collapse('hide');" style="margin-right:6px;"><i class="fa fa-times"></i> Vazgeç</button>
                                            <button type="submit" id="profSubmitBtn" class="btn btn-primary btn-sm"><i class="fa fa-check"></i> Profili Kaydet</button>
                                        </div>
                                    </div>
                                </form>
                            </div>

                            <table class="table table-hover table-striped">
                                <thead>
                                    <tr style="background:#0f172a; color:#fff;">
                                        <th>Profil Adı</th>
                                        <th>İndirme (Down)</th>
                                        <th>Yükleme (Up)</th>
                                        <th>Açıklama</th>
                                        <th style="text-align:right; width:110px;">İşlemler</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($conf['profiles'] as $p): 
                                        $is_sys = in_array($p['id'], ['prof_vip', 'prof_standard', 'prof_guest']);
                                    ?>
                                    <tr>
                                        <td><strong><?=htmlspecialchars($p['name'])?></strong></td>
                                        <td><span class="label label-info" style="font-size:11px;"><?=htmlspecialchars((string)$p['down_mbps'])?> Mbit/s</span></td>
                                        <td><span class="label label-warning" style="font-size:11px;"><?=htmlspecialchars((string)$p['up_mbps'])?> Mbit/s</span></td>
                                        <td><small class="text-muted"><?=htmlspecialchars($p['descr'])?></small></td>
                                        <td style="text-align:right; white-space:nowrap;">
                                            <button type="button" class="btn btn-xs btn-primary" onclick='editProfile(<?=json_encode($p, JSON_UNESCAPED_UNICODE)?>)' title="Profili ve Hızları Düzenle">
                                                <i class="fa fa-pencil"></i> Düzenle
                                            </button>
                                            <?php if (!$is_sys): ?>
                                                <button type="button" onclick="deleteProfile('<?=htmlspecialchars($p['id'], ENT_QUOTES, 'UTF-8')?>', '<?=htmlspecialchars($p['name'], ENT_QUOTES, 'UTF-8')?>')" class="btn btn-xs btn-danger" title="Profili Sil" style="margin-left:4px;">
                                                    <i class="fa fa-trash"></i>
                                                </button>
                                            <?php endif; ?>
                                        </td>
                                    </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div> <!-- close row 1 -->

            <!-- ROW 2: Client & Group QoS Rules -->
            <div class="panel panel-warning" style="margin-top:20px;">
                <div class="panel-heading" style="display:flex; justify-content:space-between; align-items:center;">
                    <strong style="font-size:14px;"><i class="fa fa-users"></i> İstemci &amp; Grup Özel Hız Atamaları (QoS Kuralları)</strong>
                    <button type="button" class="btn btn-xs btn-success" onclick="openNewRuleForm();"><i class="fa fa-plus"></i> Yeni İstemci / Grup Kuralı Ata</button>
                </div>
                <div class="panel-body">
                    <p class="text-muted">
                        pfSense Alias'larına, Active Directory kullanıcı veya gruplarına, tekil IP veya MAC adreslerine özel hız profili atayabilirsiniz. 
                        Burada tanımlanan kurallar genel varsayılan hızın önüne geçer.
                    </p>

                    <!-- Dark Add/Edit Client Rule Collapse Panel with its OWN Form -->
                    <div id="newRulePanel" class="collapse" style="background:#1e293b; color:#f1f5f9; padding:20px; border-radius:8px; margin-bottom:20px; border:1px solid #10b981; box-shadow:0 4px 6px -1px rgba(0,0,0,0.3);">
                        <form method="post" id="ruleForm" novalidate onsubmit="return validateRuleForm();">
                            <input type="hidden" name="act" value="save_client_rule">
                            <input type="hidden" name="rule_id" id="rule_id_input" value="">
                            <input type="hidden" name="target_val" id="rule_target_val" value="">

                            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px; border-bottom:1px solid #334155; padding-bottom:8px;">
                                <h4 style="color:#34d399; margin:0; font-weight:700;">
                                    <i class="fa fa-tag"></i> <span id="ruleFormTitle">Yeni Hız Kuralı Ata</span>
                                </h4>
                                <button type="button" class="btn btn-xs btn-default" onclick="$('#newRulePanel').collapse('hide');" style="color:#94a3b8;"><i class="fa fa-times"></i> Kapat</button>
                            </div>

                            <div class="row">
                                <div class="col-md-3">
                                    <div class="form-group" style="margin-bottom:12px;">
                                        <label class="control-label" style="color:#cbd5e1; font-weight:600;">Hedef Tipi:</label>
                                        <select name="target_type" id="rule_target_type" class="form-control" style="background:#0f172a; color:#fff; border:1px solid #475569;" onchange="onTargetTypeChange();">
                                            <option value="alias">📋 pfSense Alias (IP / Host / Ağ Listesi)</option>
                                            <option value="group">👥 Active Directory Grubu / Departman</option>
                                            <option value="user">👤 Active Directory Kullanıcısı / Bilgisayar</option>
                                            <option value="ip" selected>💻 Tekil İstemci IP Adresi</option>
                                            <option value="mac">🏷️ Cihaz MAC Adresi</option>
                                            <option value="subnet">🌐 IP Alt Ağı (Subnet / CIDR)</option>
                                        </select>
                                    </div>
                                </div>

                                <div class="col-md-4">
                                    <div class="form-group" style="margin-bottom:12px;">
                                        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
                                            <label class="control-label" style="color:#cbd5e1; font-weight:600; margin:0;">Hedef Değer:</label>
                                            <a href="javascript:void(0)" onclick="toggleManualTargetInput();" style="color:#38bdf8; font-size:11px; text-decoration:none;"><i class="fa fa-keyboard-o"></i> <span id="manualToggleLabel">Elle Yaz</span></a>
                                        </div>

                                        <!-- Alias Select -->
                                        <div id="wrap_alias" class="target-field-wrap" style="display:none;">
                                            <select id="sel_alias" class="form-control" style="background:#0f172a; color:#fff; border:1px solid #475569;" onchange="syncTargetVal(this.value)">
                                                <option value="">-- pfSense Alias Seçiniz (<?=count($meta_aliases)?> Alias) --</option>
                                                <?php foreach ($meta_aliases as $als): ?>
                                                    <option value="<?=htmlspecialchars($als['name'])?>"><?=htmlspecialchars($als['name'])?> (<?=htmlspecialchars($als['type'])?>: <?=htmlspecialchars(mb_substr($als['address'], 0, 30))?>)</option>
                                                <?php endforeach; ?>
                                            </select>
                                        </div>

                                        <!-- AD Group Select -->
                                        <div id="wrap_group" class="target-field-wrap" style="display:none;">
                                            <select id="sel_group" class="form-control" style="background:#0f172a; color:#fff; border:1px solid #475569;" onchange="syncTargetVal(this.value)">
                                                <option value="">-- AD Grubu / Departman Seçiniz (<?=count($meta_groups)?> Grup) --</option>
                                                <?php foreach ($meta_groups as $grp): ?>
                                                    <option value="<?=htmlspecialchars($grp)?>"><?=htmlspecialchars($grp)?></option>
                                                <?php endforeach; ?>
                                            </select>
                                        </div>

                                        <!-- AD User Select -->
                                        <div id="wrap_user" class="target-field-wrap" style="display:none;">
                                            <select id="sel_user" class="form-control" style="background:#0f172a; color:#fff; border:1px solid #475569;" onchange="syncTargetVal(this.value)">
                                                <option value="">-- AD Kullanıcısı / PC Seçiniz (<?=count($meta_users)?> Kullanıcı) --</option>
                                                <?php foreach ($meta_users as $usr): ?>
                                                    <option value="<?=htmlspecialchars($usr['username'])?>"><?=htmlspecialchars($usr['username'])?> <?=!empty($usr['display_name']) && $usr['display_name'] !== $usr['username'] ? '('.htmlspecialchars($usr['display_name']).')' : ''?></option>
                                                <?php endforeach; ?>
                                            </select>
                                        </div>

                                        <!-- IP Input with LAN Clients Datalist -->
                                        <div id="wrap_ip" class="target-field-wrap">
                                            <input type="text" id="sel_ip" class="form-control" list="dl_lan_ips" placeholder="Örn: 192.168.2.226" style="background:#0f172a; color:#fff; border:1px solid #475569;" oninput="syncTargetVal(this.value)">
                                            <datalist id="dl_lan_ips">
                                                <?php foreach ($meta_clients as $cli): ?>
                                                    <option value="<?=htmlspecialchars($cli['ip'])?>"><?=htmlspecialchars($cli['name'])?> (<?=htmlspecialchars($cli['mac'])?>)</option>
                                                <?php endforeach; ?>
                                            </datalist>
                                        </div>

                                        <!-- MAC Input with LAN MACs Datalist -->
                                        <div id="wrap_mac" class="target-field-wrap" style="display:none;">
                                            <input type="text" id="sel_mac" class="form-control" list="dl_lan_macs" placeholder="Örn: a6:73:5a:e1:34:c1" style="background:#0f172a; color:#fff; border:1px solid #475569;" oninput="syncTargetVal(this.value)">
                                            <datalist id="dl_lan_macs">
                                                <?php foreach ($meta_clients as $cli): ?>
                                                    <option value="<?=htmlspecialchars($cli['mac'])?>"><?=htmlspecialchars($cli['ip'])?> - <?=htmlspecialchars($cli['name'])?></option>
                                                <?php endforeach; ?>
                                            </datalist>
                                        </div>

                                        <!-- Subnet Input -->
                                        <div id="wrap_subnet" class="target-field-wrap" style="display:none;">
                                            <input type="text" id="sel_subnet" class="form-control" placeholder="Örn: 192.168.2.0/24" style="background:#0f172a; color:#fff; border:1px solid #475569;" oninput="syncTargetVal(this.value)">
                                        </div>

                                        <!-- Fallback Manual Input -->
                                        <div id="wrap_manual" class="target-field-wrap" style="display:none;">
                                            <input type="text" id="sel_manual" class="form-control" placeholder="Özel Değer Yazınız..." style="background:#0f172a; color:#fff; border:1px solid #475569;" oninput="syncTargetVal(this.value)">
                                        </div>
                                    </div>
                                </div>

                                <div class="col-md-2">
                                    <div class="form-group" style="margin-bottom:12px;">
                                        <label class="control-label" style="color:#cbd5e1; font-weight:600;">Uygulanacak Profil:</label>
                                        <select name="target_profile" id="rule_target_profile" class="form-control" style="background:#0f172a; color:#fff; border:1px solid #475569;">
                                            <?php foreach ($conf['profiles'] as $p): ?>
                                                <option value="<?=htmlspecialchars($p['id'])?>">
                                                    <?=htmlspecialchars($p['name'])?> (<?=htmlspecialchars((string)$p['down_mbps'])?>M / <?=htmlspecialchars((string)$p['up_mbps'])?>M)
                                                </option>
                                            <?php endforeach; ?>
                                        </select>
                                    </div>
                                </div>

                                <div class="col-md-3">
                                    <div class="form-group" style="margin-bottom:12px;">
                                        <label class="control-label" style="color:#cbd5e1; font-weight:600;">Açıklama / Not:</label>
                                        <input type="text" name="rule_descr" id="rule_descr" class="form-control" placeholder="Örn: Muhasebe Müdürü PC" style="background:#0f172a; color:#fff; border:1px solid #475569;">
                                    </div>
                                </div>
                            </div>

                            <div class="text-right" style="border-top:1px solid #334155; padding-top:12px; margin-top:10px;">
                                <button type="button" class="btn btn-default btn-sm" onclick="$('#newRulePanel').collapse('hide');" style="margin-right:6px;"><i class="fa fa-times"></i> Vazgeç</button>
                                <button type="submit" id="ruleSubmitBtn" class="btn btn-success btn-sm"><i class="fa fa-check"></i> Kuralı Kaydet &amp; Uygula</button>
                            </div>
                        </form>
                    </div>

                    <!-- Client Rules Table -->
                    <table class="table table-hover table-striped">
                        <thead>
                            <tr style="background:#090d16; color:#f8fafc;">
                                <th>Hedef Değer</th>
                                <th>Hedef Tipi</th>
                                <th>Atanan Hız Profili</th>
                                <th>Tanımlı Hız Limiti</th>
                                <th>Açıklama</th>
                                <th style="text-align:right; width:130px;">İşlemler</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php if (empty($conf['client_rules'])): ?>
                                <tr>
                                    <td colspan="6" class="text-center text-muted" style="padding:20px;">
                                        <i class="fa fa-info-circle"></i> Henüz özel bir kural tanımlanmadı. Ağınız "Varsayılan Hız" ve "Akıllı AD/Misafir Ayrımı" kuralları ile otomatik yönetiliyor.
                                    </td>
                                </tr>
                            <?php else: ?>
                                <?php foreach ($conf['client_rules'] as $cr): 
                                    $prof = $profiles_map[$cr['profile_id']] ?? null;
                                    $prof_name = $prof['name'] ?? 'Bilinmeyen Profil';
                                    $p_down = $prof['down_mbps'] ?? 5;
                                    $p_up = $prof['up_mbps'] ?? 5;
                                    $type_labels = [
                                        'alias' => '<span class="label label-primary"><i class="fa fa-list"></i> pfSense Alias</span>',
                                        'group' => '<span class="label label-success"><i class="fa fa-users"></i> AD Grubu</span>',
                                        'user' => '<span class="label label-warning"><i class="fa fa-user"></i> AD Kullanıcı</span>',
                                        'ip' => '<span class="label label-default"><i class="fa fa-desktop"></i> IP Adresi</span>',
                                        'mac' => '<span class="label label-info"><i class="fa fa-barcode"></i> MAC Adresi</span>',
                                        'subnet' => '<span class="label label-info"><i class="fa fa-sitemap"></i> Subnet</span>'
                                    ];
                                ?>
                                <tr>
                                    <td><strong style="color:#f8fafc; font-size:13px;"><?=htmlspecialchars($cr['target_val'])?></strong></td>
                                    <td><?=$type_labels[$cr['target_type']] ?? '<span class="label label-default">'.htmlspecialchars($cr['target_type']).'</span>'?></td>
                                    <td><strong><?=htmlspecialchars($prof_name)?></strong></td>
                                    <td>
                                        <span class="label label-info" style="font-size:11px;"><?=htmlspecialchars((string)$p_down)?> Mbit/s Down</span>
                                        <span class="label label-warning" style="font-size:11px; margin-left:3px;"><?=htmlspecialchars((string)$p_up)?> Mbit/s Up</span>
                                    </td>
                                    <td><small class="text-muted"><?=htmlspecialchars($cr['descr'])?></small></td>
                                    <td style="text-align:right; white-space:nowrap;">
                                        <button type="button" class="btn btn-xs btn-primary" onclick='editClientRule(<?=json_encode($cr, JSON_UNESCAPED_UNICODE)?>)' title="Kuralı Düzenle">
                                            <i class="fa fa-pencil"></i> Düzenle
                                        </button>
                                        <button type="button" onclick="deleteClientRule('<?=htmlspecialchars($cr['id'], ENT_QUOTES, 'UTF-8')?>', '<?=htmlspecialchars($cr['target_val'], ENT_QUOTES, 'UTF-8')?>')" class="btn btn-xs btn-danger" title="Kuralı Sil" style="margin-left:4px;">
                                            <i class="fa fa-trash"></i>
                                        </button>
                                    </td>
                                </tr>
                                <?php endforeach; ?>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>
            </div>

        <hr style="margin:25px 0; border-color:#334155;">

        <!-- ROW 3: Live Traffic Monitor Card -->
        <div class="panel panel-primary">
            <div class="panel-heading" style="display:flex; justify-content:space-between; align-items:center;">
                <strong><i class="fa fa-line-chart"></i> PoseaBand Canlı Hat &amp; İstemci Hız İzleyici (vtnet1 LAN)</strong>
                <div>
                    <span id="pbStatusBadge" class="badge" style="background-color:#1e293b;">Yükleniyor...</span>
                    <button type="button" class="btn btn-xs btn-default" onclick="refreshBandTraffic();" style="margin-left:8px;"><i class="fa fa-refresh"></i> Yenile</button>
                </div>
            </div>
            <div class="panel-body" style="overflow-x:auto;">
                <table class="table table-hover table-striped" id="pbTrafficTable">
                    <thead>
                        <tr style="background:#0f172a; color:#fff;">
                            <th>İstemci IP Adresi</th>
                            <th>Active Directory / Cihaz Adı</th>
                            <th>Departman / Durum</th>
                            <th>MAC Adresi</th>
                            <th>Anlık İndirme (Download)</th>
                            <th>Anlık Yükleme (Upload)</th>
                            <th>Uygulanan QoS Profili &amp; Limit</th>
                            <th>Aktif Bağlantı Hedefi</th>
                            <th style="text-align:right; width:150px;">Müdahale</th>
                        </tr>
                    </thead>
                    <tbody id="pbTrafficTbody">
                        <tr><td colspan="9" class="text-center text-muted" style="padding:25px;"><i class="fa fa-spinner fa-spin"></i> Canlı ağ verisi taranıyor...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

    </div>
</div>

<!-- Dedicated Action Form for Deletions and Killing States -->
<form method="post" id="actionForm" style="display:none;" novalidate>
    <input type="hidden" name="act" id="action_act" value="">
    <input type="hidden" name="prof_id" id="action_prof_id" value="">
    <input type="hidden" name="rule_id" id="action_rule_id" value="">
    <input type="hidden" name="kill_ip" id="action_kill_ip" value="">
</form>

<script>
// Profile Management JS
function validateProfileForm() {
    var name = document.getElementById('prof_name_input').value.trim();
    var down = parseFloat(document.getElementById('prof_down_input').value);
    var up = parseFloat(document.getElementById('prof_up_input').value);
    if (!name) {
        alert('Lütfen bir profil adı giriniz.');
        document.getElementById('prof_name_input').focus();
        return false;
    }
    if (isNaN(down) || down <= 0) {
        alert('Lütfen geçerli bir indirme hızı (Mbit/s) giriniz.');
        document.getElementById('prof_down_input').focus();
        return false;
    }
    if (isNaN(up) || up <= 0) {
        alert('Lütfen geçerli bir yükleme hızı (Mbit/s) giriniz.');
        document.getElementById('prof_up_input').focus();
        return false;
    }
    return true;
}

function openNewProfileForm() {
    document.getElementById('profFormTitle').innerText = 'Yeni Hız Profili Tanımla';
    document.getElementById('prof_id_input').value = '';
    document.getElementById('prof_name_input').value = '';
    document.getElementById('prof_down_input').value = '10';
    document.getElementById('prof_up_input').value = '5';
    document.getElementById('prof_descr_input').value = '';
    document.getElementById('profSubmitBtn').innerHTML = '<i class="fa fa-check"></i> Profili Kaydet';
    $('#newProfilePanel').collapse('show');
    setTimeout(function() { document.getElementById('prof_name_input').focus(); }, 150);
}

function editProfile(p) {
    document.getElementById('profFormTitle').innerText = 'Profili Düzenle: ' + p.name;
    document.getElementById('prof_id_input').value = p.id;
    document.getElementById('prof_name_input').value = p.name;
    document.getElementById('prof_down_input').value = p.down_mbps;
    document.getElementById('prof_up_input').value = p.up_mbps;
    document.getElementById('prof_descr_input').value = p.descr || '';
    document.getElementById('profSubmitBtn').innerHTML = '<i class="fa fa-check"></i> Değişiklikleri Güncelle';
    $('#newProfilePanel').collapse('show');
    setTimeout(function() { document.getElementById('prof_down_input').focus(); }, 150);
}

function deleteProfile(id, name) {
    if (!confirm("'" + name + "' profilini silmek istediğinize emin misiniz?")) return;
    var f = document.getElementById('actionForm');
    document.getElementById('action_act').value = 'del_profile';
    document.getElementById('action_prof_id').value = id;
    f.submit();
}

// Client Rule Target Type & Field Dynamic Switcher
var isManualMode = false;
function syncTargetVal(val) {
    document.getElementById('rule_target_val').value = (val || '').trim();
}

function onTargetTypeChange() {
    var type = document.getElementById('rule_target_type').value;
    isManualMode = false;
    document.getElementById('manualToggleLabel').innerText = 'Elle Yaz';

    var wraps = document.querySelectorAll('.target-field-wrap');
    for (var i = 0; i < wraps.length; i++) {
        wraps[i].style.display = 'none';
    }

    var targetWrap = document.getElementById('wrap_' + type);
    if (targetWrap) {
        targetWrap.style.display = 'block';
        var inputElem = targetWrap.querySelector('input, select');
        if (inputElem) {
            syncTargetVal(inputElem.value);
            inputElem.focus();
        }
    }
}

function toggleManualTargetInput() {
    isManualMode = !isManualMode;
    var wraps = document.querySelectorAll('.target-field-wrap');
    for (var i = 0; i < wraps.length; i++) {
        wraps[i].style.display = 'none';
    }

    if (isManualMode) {
        document.getElementById('manualToggleLabel').innerText = 'Listeden Seç';
        document.getElementById('wrap_manual').style.display = 'block';
        var m = document.getElementById('sel_manual');
        m.value = document.getElementById('rule_target_val').value;
        m.focus();
    } else {
        document.getElementById('manualToggleLabel').innerText = 'Elle Yaz';
        onTargetTypeChange();
    }
}

function validateRuleForm() {
    var val = document.getElementById('rule_target_val').value.trim();
    if (!val) {
        alert('Lütfen kural için bir hedef değer (IP, Alias, AD Grubu vb.) seçiniz veya giriniz.');
        return false;
    }
    return true;
}

function openNewRuleForm() {
    document.getElementById('ruleFormTitle').innerText = 'Yeni Hız Kuralı Ata';
    document.getElementById('rule_id_input').value = '';
    document.getElementById('rule_target_type').value = 'ip';
    document.getElementById('rule_target_val').value = '';
    document.getElementById('rule_target_profile').selectedIndex = 0;
    document.getElementById('rule_descr').value = '';
    document.getElementById('ruleSubmitBtn').innerHTML = '<i class="fa fa-check"></i> Kuralı Kaydet &amp; Uygula';
    onTargetTypeChange();
    $('#newRulePanel').collapse('show');
}

function editClientRule(r) {
    document.getElementById('ruleFormTitle').innerText = 'Kuralı Düzenle: ' + r.target_val;
    document.getElementById('rule_id_input').value = r.id;
    document.getElementById('rule_target_type').value = r.target_type;
    document.getElementById('rule_target_val').value = r.target_val;
    document.getElementById('rule_target_profile').value = r.profile_id;
    document.getElementById('rule_descr').value = r.descr || '';
    document.getElementById('ruleSubmitBtn').innerHTML = '<i class="fa fa-check"></i> Değişiklikleri Güncelle';
    
    onTargetTypeChange();

    var wrap = document.getElementById('wrap_' + r.target_type);
    if (wrap) {
        var input = wrap.querySelector('input, select');
        if (input) {
            input.value = r.target_val;
            if (input.tagName === 'SELECT' && input.value !== r.target_val) {
                toggleManualTargetInput();
                document.getElementById('sel_manual').value = r.target_val;
            }
        }
    }

    $('#newRulePanel').collapse('show');
}

function deleteClientRule(id, target) {
    if (!confirm("'" + target + "' için tanımlı hız kuralını kaldırmak istediğinize emin misiniz?")) return;
    var f = document.getElementById('actionForm');
    document.getElementById('action_act').value = 'del_client_rule';
    document.getElementById('action_rule_id').value = id;
    f.submit();
}

// Quick Assign from Live Table
function quickAssignProfile(ip, mac, user, currentProfId) {
    openNewRuleForm();
    document.getElementById('rule_target_type').value = 'ip';
    onTargetTypeChange();
    document.getElementById('sel_ip').value = ip;
    syncTargetVal(ip);
    if (currentProfId && document.getElementById('rule_target_profile')) {
        document.getElementById('rule_target_profile').value = currentProfId;
    }
    document.getElementById('rule_descr').value = (user ? user + ' için ' : '') + 'Özel Hız Limiti';
    document.getElementById('rule_target_profile').focus();
}

// Kill State Function
function killHostState(ip) {
    if (!confirm(ip + ' için aktif oturumları sıfırlamak istediğinize emin misiniz?')) return;
    var f = document.getElementById('actionForm');
    document.getElementById('action_act').value = 'kill_host_states';
    document.getElementById('action_kill_ip').value = ip;
    f.submit();
}

// Live Traffic Polling
var isFetchingBand = false;
function refreshBandTraffic() {
    if (isFetchingBand) return;
    isFetchingBand = true;

    var tbody = document.getElementById('pbTrafficTbody');
    var badge = document.getElementById('pbStatusBadge');
    if (badge) badge.innerHTML = '<i class="fa fa-spinner fa-spin"></i> Taranıyor...';
    
    fetch('/poseaband.php?ajax_traffic=1')
        .then(function(res) { return res.json(); })
        .then(function(data) {
            isFetchingBand = false;
            if (badge) badge.innerText = data.total_clients + ' Aktif Cihaz (' + new Date().toLocaleTimeString() + ')';
            tbody.innerHTML = '';
            
            if (!data.clients || data.clients.length === 0) {
                tbody.innerHTML = '<tr><td colspan="9" class="text-center text-muted" style="padding:25px;"><i class="fa fa-info-circle fa-2x" style="margin-bottom:8px;"></i><br>Şu anda yüksek tüketim yapan istemci yok (Trafik sakin).</td></tr>';
                return;
            }
            
            data.clients.forEach(function(c) {
                var tr = document.createElement('tr');
                var downColor = c.down_mbps >= 4.5 ? 'color:#ef4444; font-weight:bold;' : (c.down_mbps >= 2.0 ? 'color:#f59e0b; font-weight:bold;' : 'color:#10b981;');
                
                var ruleTag = '';
                if (c.applied_by_rule) {
                    ruleTag = '<br><small class="text-muted"><i class="fa fa-tag text-success"></i> ' + (c.rule_descr || 'Özel Kural') + '</small>';
                } else if (c.profile_id === 'prof_guest') {
                    ruleTag = '<br><small class="text-warning"><i class="fa fa-magic"></i> ' + (c.rule_descr || 'Otomatik Misafir Limiti') + '</small>';
                } else {
                    ruleTag = '<br><small class="text-info"><i class="fa fa-id-badge"></i> ' + (c.rule_descr || 'AD Doğrulanmış Cihaz') + '</small>';
                }

                var deptBadge = c.is_ad 
                    ? '<span class="label label-primary"><i class="fa fa-building-o"></i> ' + (c.dept || 'Domain Computers') + '</span>'
                    : '<span class="label label-default"><i class="fa fa-wifi"></i> Misafir</span>';

                tr.innerHTML = '<td><strong>' + c.ip + '</strong></td>' +
                    '<td><strong>' + c.user + '</strong></td>' +
                    '<td>' + deptBadge + '</td>' +
                    '<td><small class="text-muted font-monospace">' + c.mac + '</small></td>' +
                    '<td style="' + downColor + '"><i class="fa fa-arrow-down"></i> ' + c.down_mbps.toFixed(2) + ' Mbit/s</td>' +
                    '<td><i class="fa fa-arrow-up text-muted"></i> ' + c.up_mbps.toFixed(2) + ' Mbit/s</td>' +
                    '<td>' +
                        '<span class="label ' + c.profile_badge + '" style="font-size:11px; padding:3px 7px;"><i class="fa fa-tachometer"></i> ' + c.profile_name + ' (' + c.profile_down + 'M/' + c.profile_up + 'M)</span>' +
                        ruleTag +
                    '</td>' +
                    '<td><small class="text-muted">' + (c.remote || '-') + '</small></td>' +
                    '<td style="text-align:right; white-space:nowrap;">' +
                        '<button type="button" class="btn btn-xs btn-info" onclick="quickAssignProfile(\'' + c.ip + '\', \'' + (c.mac === "Bilinmiyor" ? "" : c.mac) + '\', \'' + c.user.replace(/'/g, "") + '\', \'' + c.profile_id + '\')" title="Bu Cihaza Özel Hız Profili Ata" style="margin-right:4px;"><i class="fa fa-bolt"></i> Hız Ata</button>' +
                        '<button type="button" class="btn btn-xs btn-danger" onclick="killHostState(\'' + c.ip + '\')" title="Oturumu Kes"><i class="fa fa-cut"></i> Kes</button>' +
                    '</td>';
                tbody.appendChild(tr);
            });
        })
        .catch(function(err) {
            isFetchingBand = false;
            if (badge) badge.innerText = 'Hata';
            tbody.innerHTML = '<tr><td colspan="9" class="text-danger text-center" style="padding:20px;">Veri alınamadı: ' + err + '</td></tr>';
        });
}

// Auto-refresh every 5 seconds
setInterval(refreshBandTraffic, 5000);
refreshBandTraffic();
</script>

<?php include("foot.inc"); ?>
