<?php
/*
 * poseaband.widget.php
 *
 * Part of PoseaBand for pfSense (QoS & Bandwidth Manager)
 * pfSense Dashboard Widget
 */

require_once("guiconfig.inc");
require_once("/usr/local/pkg/poseaband.inc");

$widgetkey = isset($widgetkey) ? $widgetkey : 'poseaband';
$pb_conf = poseaband_get_config();
$pb_enabled = !empty($pb_conf['enabled']);
?>

<!-- PoseaBand Widget Settings Panel (pfSense Wrench Icon) -->
<div id="<?=htmlspecialchars($widgetkey)?>-settings" class="widgetconfigdiv" style="display:none; padding: 10px; background: rgba(0,0,0,0.02); border-bottom: 1px solid #ddd; margin-bottom: 10px;">
    <form id="<?=htmlspecialchars($widgetkey)?>-settings-form" class="form-horizontal">
        <div class="form-group" style="margin-bottom: 8px;">
            <label class="col-sm-6 control-label" style="font-size: 11px;">Görüntülenecek İstemci Sayısı:</label>
            <div class="col-sm-6">
                <select id="<?=htmlspecialchars($widgetkey)?>-cfg-limit" class="form-control input-sm">
                    <option value="5">İlk 5 İstemci</option>
                    <option value="10" selected>İlk 10 İstemci</option>
                    <option value="15">İlk 15 İstemci</option>
                    <option value="25">İlk 25 İstemci</option>
                </select>
            </div>
        </div>
        <div class="form-group" style="margin-bottom: 8px;">
            <label class="col-sm-6 control-label" style="font-size: 11px;">Otomatik Yenileme Aralığı:</label>
            <div class="col-sm-6">
                <select id="<?=htmlspecialchars($widgetkey)?>-cfg-interval" class="form-control input-sm">
                    <option value="2000">Her 2 saniyede bir (Çok Hızlı)</option>
                    <option value="4000" selected>Her 4 saniyede bir (Önerilen)</option>
                    <option value="8000">Her 8 saniyede bir</option>
                    <option value="0">Otomatik Yenileme Kapalı</option>
                </select>
            </div>
        </div>
        <div class="text-right">
            <button type="button" id="<?=htmlspecialchars($widgetkey)?>-cfg-save" class="btn btn-primary btn-xs">
                <i class="fa fa-save"></i> Ayarları Uygula
            </button>
        </div>
    </form>
</div>

<!-- PoseaBand Widget Main Container -->
<div id="<?=htmlspecialchars($widgetkey)?>-container" style="padding: 6px 4px 4px 4px;">

    <!-- Top Action & Status Bar -->
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; flex-wrap: wrap; gap: 6px;">
        <div style="display: flex; align-items: center; gap: 6px;">
            <span id="<?=htmlspecialchars($widgetkey)?>-badge" class="label <?= $pb_enabled ? 'label-success' : 'label-default' ?>" style="font-size: 11px; padding: 4px 8px; border-radius: 3px; font-weight: 600;">
                <i id="<?=htmlspecialchars($widgetkey)?>-status-icon" class="fa <?= $pb_enabled ? 'fa-check-circle' : 'fa-pause-circle' ?>"></i>
                <span id="<?=htmlspecialchars($widgetkey)?>-status-text"><?= $pb_enabled ? 'QoS Aktif' : 'QoS Pasif' ?></span>
            </span>
            <span class="text-muted hidden-xs" style="font-size: 11px;">
                <i class="fa fa-filter"></i> Per-Host Limiter
            </span>
        </div>

        <div class="btn-group btn-group-xs">
            <button type="button" class="btn btn-default" id="<?=htmlspecialchars($widgetkey)?>-toggle-btn" title="Servisi Aç / Kapa">
                <i id="<?=htmlspecialchars($widgetkey)?>-toggle-icon" class="fa fa-power-off"></i>
                <span id="<?=htmlspecialchars($widgetkey)?>-toggle-label"><?= $pb_enabled ? 'Durdur' : 'Başlat' ?></span>
            </button>
            <button type="button" class="btn btn-default" id="<?=htmlspecialchars($widgetkey)?>-refresh-btn" title="Verileri Şimdi Yenile">
                <i id="<?=htmlspecialchars($widgetkey)?>-refresh-icon" class="fa fa-refresh"></i>
            </button>
            <a href="/poseaband.php" class="btn btn-primary" title="PoseaBand Yönetim Konsolunu Aç" style="font-weight: 500;">
                <i class="fa fa-external-link"></i> Yönetim
            </a>
        </div>
    </div>

    <!-- 3 Mini Summary KPI Cards -->
    <div class="row" style="margin-left: -4px; margin-right: -4px; margin-bottom: 8px;">
        <div class="col-xs-4" style="padding: 0 4px;">
            <div style="background: rgba(0,0,0,0.03); border: 1px solid rgba(0,0,0,0.08); border-radius: 4px; padding: 5px 6px; text-align: center;">
                <div style="font-size: 9px; color: #777; text-transform: uppercase; font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">
                    <i class="fa fa-arrow-down text-success"></i> İndirme
                </div>
                <div id="<?=htmlspecialchars($widgetkey)?>-tot-down" style="font-size: 13px; font-weight: 700; margin-top: 2px; color: #2e6da4;">
                    0.0 Mbps
                </div>
            </div>
        </div>
        <div class="col-xs-4" style="padding: 0 4px;">
            <div style="background: rgba(0,0,0,0.03); border: 1px solid rgba(0,0,0,0.08); border-radius: 4px; padding: 5px 6px; text-align: center;">
                <div style="font-size: 9px; color: #777; text-transform: uppercase; font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">
                    <i class="fa fa-arrow-up text-primary"></i> Yükleme
                </div>
                <div id="<?=htmlspecialchars($widgetkey)?>-tot-up" style="font-size: 13px; font-weight: 700; margin-top: 2px; color: #337ab7;">
                    0.0 Mbps
                </div>
            </div>
        </div>
        <div class="col-xs-4" style="padding: 0 4px;">
            <div style="background: rgba(0,0,0,0.03); border: 1px solid rgba(0,0,0,0.08); border-radius: 4px; padding: 5px 6px; text-align: center;">
                <div style="font-size: 9px; color: #777; text-transform: uppercase; font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">
                    <i class="fa fa-users text-info"></i> Aktif İstemci
                </div>
                <div id="<?=htmlspecialchars($widgetkey)?>-tot-clients" style="font-size: 13px; font-weight: 700; margin-top: 2px; color: #468847;">
                    0 Cihaz
                </div>
            </div>
        </div>
    </div>

    <!-- Live Clients Table -->
    <div class="table-responsive" style="margin-bottom: 4px;">
        <table class="table table-striped table-condensed table-hover" style="font-size: 11px; margin-bottom: 0;">
            <thead>
                <tr style="background: rgba(0,0,0,0.03);">
                    <th>İstemci / Cihaz</th>
                    <th style="width: 105px;">Profil &amp; Limit</th>
                    <th style="min-width: 110px;">Download (Hız)</th>
                    <th style="width: 65px;">Upload</th>
                    <th style="width: 30px; text-align: center;">Kes</th>
                </tr>
            </thead>
            <tbody id="<?=htmlspecialchars($widgetkey)?>-tbody">
                <tr>
                    <td colspan="5" class="text-center text-muted" style="padding: 12px;">
                        <i class="fa fa-spinner fa-spin"></i> Canlı trafik verileri alınıyor...
                    </td>
                </tr>
            </tbody>
        </table>
    </div>

    <!-- Footer Status & Timestamp -->
    <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 4px; font-size: 10px; color: #999; padding: 2px 2px 0 2px;">
        <span><i class="fa fa-clock-o"></i> <span id="<?=htmlspecialchars($widgetkey)?>-last-sync">-</span></span>
        <span>
            <a href="/poseaband.php" style="color: inherit; text-decoration: none;" title="PoseaBand QoS Modülü">
                <i class="fa fa-tachometer"></i> PoseaBand
            </a>
        </span>
    </div>
</div>

<script type="text/javascript">
//<![CDATA[
(function() {
    var key = "<?=htmlspecialchars($widgetkey)?>";
    var limitKey = "pb_wlimit_" + key;
    var intervalKey = "pb_winterval_" + key;

    var displayLimit = parseInt(localStorage.getItem(limitKey) || "10", 10);
    var refreshInterval = parseInt(localStorage.getItem(intervalKey) || "4000", 10);
    var pollTimer = null;
    var isPolling = false;

    // UI Element references
    var elTbody = document.getElementById(key + "-tbody");
    var elBadge = document.getElementById(key + "-badge");
    var elStatusIcon = document.getElementById(key + "-status-icon");
    var elStatusText = document.getElementById(key + "-status-text");
    var elToggleBtn = document.getElementById(key + "-toggle-btn");
    var elToggleIcon = document.getElementById(key + "-toggle-icon");
    var elToggleLabel = document.getElementById(key + "-toggle-label");
    var elRefreshBtn = document.getElementById(key + "-refresh-btn");
    var elRefreshIcon = document.getElementById(key + "-refresh-icon");
    var elTotDown = document.getElementById(key + "-tot-down");
    var elTotUp = document.getElementById(key + "-tot-up");
    var elTotClients = document.getElementById(key + "-tot-clients");
    var elLastSync = document.getElementById(key + "-last-sync");

    // Init config dropdown values
    var elCfgLimit = document.getElementById(key + "-cfg-limit");
    var elCfgInterval = document.getElementById(key + "-cfg-interval");
    var elCfgSave = document.getElementById(key + "-cfg-save");

    if (elCfgLimit) elCfgLimit.value = displayLimit;
    if (elCfgInterval) elCfgInterval.value = refreshInterval;

    if (elCfgSave) {
        elCfgSave.addEventListener("click", function() {
            displayLimit = parseInt(elCfgLimit.value, 10);
            refreshInterval = parseInt(elCfgInterval.value, 10);
            localStorage.setItem(limitKey, displayLimit);
            localStorage.setItem(intervalKey, refreshInterval);
            
            // Hide settings panel
            var panel = document.getElementById(key + "-settings");
            if (panel) panel.style.display = "none";

            // Restart interval & fetch immediately
            startPolling();
            fetchTrafficData();
        });
    }

    function escapeHtml(str) {
        if (!str) return "";
        return String(str)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    function formatTime(d) {
        var h = String(d.getHours()).padStart(2, "0");
        var m = String(d.getMinutes()).padStart(2, "0");
        var s = String(d.getSeconds()).padStart(2, "0");
        return h + ":" + m + ":" + s;
    }

    function updateServiceStateUI(isEnabled) {
        if (!elBadge) return;
        if (isEnabled) {
            elBadge.className = "label label-success";
            elStatusIcon.className = "fa fa-check-circle";
            elStatusText.textContent = "QoS Aktif";
            if (elToggleLabel) elToggleLabel.textContent = "Durdur";
            if (elToggleBtn) elToggleBtn.className = "btn btn-default";
        } else {
            elBadge.className = "label label-default";
            elStatusIcon.className = "fa fa-pause-circle";
            elStatusText.textContent = "QoS Pasif";
            if (elToggleLabel) elToggleLabel.textContent = "Başlat";
            if (elToggleBtn) elToggleBtn.className = "btn btn-success";
        }
    }

    function fetchTrafficData() {
        if (isPolling) return;
        isPolling = true;

        if (elRefreshIcon) elRefreshIcon.classList.add("fa-spin");

        $.ajax({
            url: "/poseaband.php?ajax_traffic=1",
            type: "GET",
            dataType: "json",
            cache: false,
            timeout: 6000
        }).done(function(data) {
            if (!data) return;

            updateServiceStateUI(data.enabled);

            // Update KPI totals
            var totDown = (typeof data.total_down_mbps !== 'undefined') ? parseFloat(data.total_down_mbps) : 0;
            var totUp = (typeof data.total_up_mbps !== 'undefined') ? parseFloat(data.total_up_mbps) : 0;
            var totClients = data.total_clients || (data.clients ? data.clients.length : 0);

            if (elTotDown) elTotDown.textContent = totDown.toFixed(1) + " Mbps";
            if (elTotUp) elTotUp.textContent = totUp.toFixed(1) + " Mbps";
            if (elTotClients) elTotClients.textContent = totClients + " Cihaz";
            if (elLastSync) elLastSync.textContent = "Güncellendi: " + formatTime(new Date());

            // Render clients table
            var clients = data.clients || [];
            if (!data.enabled) {
                elTbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted" style="padding: 14px;">' +
                    '<i class="fa fa-info-circle text-warning"></i> PoseaBand QoS servisi şu an pasif durumda. ' +
                    '<a href="javascript:void(0)" id="' + key + '-inline-enable" style="text-decoration: underline; font-weight: bold;">Etkinleştirmek için tıklayın</a>' +
                    '</td></tr>';
                var inlineEn = document.getElementById(key + "-inline-enable");
                if (inlineEn) inlineEn.addEventListener("click", toggleService);
                return;
            }

            if (clients.length === 0) {
                elTbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted" style="padding: 14px;">' +
                    '<i class="fa fa-check-circle text-success"></i> İnternet trafiği tüketen aktif istemci bulunmuyor (Tüm bant genişliği serbest).' +
                    '</td></tr>';
                return;
            }

            var visibleClients = clients.slice(0, displayLimit);
            var html = "";

            visibleClients.forEach(function(c) {
                var down = parseFloat(c.down_mbps || 0);
                var up = parseFloat(c.up_mbps || 0);
                var pDown = parseFloat(c.profile_down || 5);
                var pUp = parseFloat(c.profile_up || 5);

                var pct = Math.min(100, Math.round((down / (pDown || 1)) * 100));
                var barClass = "progress-bar-success";
                if (pct >= 85) barClass = "progress-bar-danger";
                else if (pct >= 60) barClass = "progress-bar-warning";

                var userLabel = c.user || "Misafir Cihaz";
                var isAd = c.is_ad;
                var badgeClass = c.profile_badge || "label-info";

                var userHtml = '<div style="font-weight: 600; font-family: monospace;">' + escapeHtml(c.ip) + '</div>';
                if (isAd) {
                    userHtml += '<div style="font-size: 10px; color: #555; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 140px;" title="' + escapeHtml(userLabel) + '">' +
                        '<i class="fa fa-user text-primary"></i> ' + escapeHtml(userLabel) + '</div>';
                } else {
                    userHtml += '<div style="font-size: 10px; color: #888;" title="Misafir Wi-Fi / Mobil Cihaz">' +
                        '<span class="label label-default" style="font-size: 9px; padding: 1px 4px;">Misafir</span> ' + escapeHtml(c.mac && c.mac !== "Bilinmiyor" ? c.mac.substring(0, 8) + '...' : '') + '</div>';
                }

                html += '<tr>';
                // 1. Client / User
                html += '<td style="vertical-align: middle;">' + userHtml + '</td>';

                // 2. Profile Badge
                html += '<td style="vertical-align: middle;">' +
                    '<span class="label ' + escapeHtml(badgeClass) + '" style="font-size: 10px; padding: 2px 5px;" title="' + escapeHtml(c.rule_descr || '') + '">' +
                    escapeHtml(c.profile_name || 'Standart') +
                    '</span>' +
                    '<div style="font-size: 9px; color: #777; margin-top: 2px;">Limit: ' + pDown + 'M / ' + pUp + 'M</div>' +
                    '</td>';

                // 3. Download + Mini Progress Bar
                html += '<td style="vertical-align: middle;">' +
                    '<div style="display: flex; justify-content: space-between; font-weight: 600; font-size: 11px;">' +
                    '<span>' + down.toFixed(2) + ' <small>Mbps</small></span>' +
                    '<span style="font-size: 10px; color: #777;">%' + pct + '</span>' +
                    '</div>' +
                    '<div class="progress" style="height: 6px; margin: 3px 0 0 0; background-color: #eee; border-radius: 3px;">' +
                    '<div class="progress-bar ' + barClass + '" role="progressbar" style="width: ' + pct + '%;"></div>' +
                    '</div>' +
                    '</td>';

                // 4. Upload
                html += '<td style="vertical-align: middle; font-size: 11px;">' +
                    '<span style="color: #337ab7; font-weight: 600;">' + up.toFixed(2) + '</span> <small style="color: #888;">Mbps</small>' +
                    '</td>';

                // 5. Kill Action
                html += '<td style="vertical-align: middle; text-align: center;">' +
                    '<button type="button" class="btn btn-xs btn-danger pb-kill-btn" data-ip="' + escapeHtml(c.ip) + '" title="Bağlantıyı Kes (Kill State)" style="padding: 1px 5px;">' +
                    '<i class="fa fa-times"></i>' +
                    '</button>' +
                    '</td>';

                html += '</tr>';
            });

            elTbody.innerHTML = html;

            // Bind Kill State buttons
            var killBtns = elTbody.querySelectorAll(".pb-kill-btn");
            killBtns.forEach(function(b) {
                b.addEventListener("click", function() {
                    var ip = this.getAttribute("data-ip");
                    killClientState(ip);
                });
            });

        }).fail(function() {
            if (elLastSync) elLastSync.textContent = "Bağlantı hatası (" + formatTime(new Date()) + ")";
        }).always(function() {
            isPolling = false;
            if (elRefreshIcon) elRefreshIcon.classList.remove("fa-spin");
        });
    }

    function toggleService() {
        if (!confirm("PoseaBand QoS servisi durumunu değiştirmek istediğinize emin misiniz?")) return;
        if (elRefreshIcon) elRefreshIcon.classList.add("fa-spin");

        $.ajax({
            url: "/poseaband.php?ajax_toggle_service=1",
            type: "GET",
            dataType: "json",
            timeout: 10000
        }).done(function(res) {
            if (res && typeof res.enabled !== "undefined") {
                updateServiceStateUI(res.enabled);
            }
            fetchTrafficData();
        }).fail(function() {
            alert("Servis durumu değiştirilirken bir hata oluştu.");
            if (elRefreshIcon) elRefreshIcon.classList.remove("fa-spin");
        });
    }

    function killClientState(ip) {
        if (!ip) return;
        if (!confirm("İstemcinin (" + ip + ") tüm aktif bağlantıları sıfırlansın mı?")) return;
        if (elRefreshIcon) elRefreshIcon.classList.add("fa-spin");

        $.ajax({
            url: "/poseaband.php?ajax_kill_state=1&ip=" + encodeURIComponent(ip),
            type: "GET",
            dataType: "json",
            timeout: 8000
        }).done(function(res) {
            setTimeout(fetchTrafficData, 400);
        }).fail(function() {
            alert("Bağlantı kesilemedi.");
            if (elRefreshIcon) elRefreshIcon.classList.remove("fa-spin");
        });
    }

    function startPolling() {
        if (pollTimer) clearInterval(pollTimer);
        if (refreshInterval > 0) {
            pollTimer = setInterval(function() {
                // If browser tab is hidden, skip to save router CPU
                if (document.hidden) return;
                fetchTrafficData();
            }, refreshInterval);
        }
    }

    // Attach button listeners
    if (elRefreshBtn) {
        elRefreshBtn.addEventListener("click", function() {
            fetchTrafficData();
        });
    }
    if (elToggleBtn) {
        elToggleBtn.addEventListener("click", function() {
            toggleService();
        });
    }

    // Initial trigger
    function initWidget() {
        fetchTrafficData();
        startPolling();
    }

    if (typeof events !== 'undefined' && Array.isArray(events)) {
        events.push(initWidget);
    } else {
        $(document).ready(initWidget);
    }
})();
//]]>
</script>
