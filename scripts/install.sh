#!/bin/sh
set -e
echo "=== Installing PoseaBand (QoS & Bandwidth Manager) for pfSense ==="
if [ "$(id -u)" -ne 0 ]; then
    echo "[!] Error: Run as root."
    exit 1
fi
SCRIPT_DIR="$(cd "$(dirname "$0")/.." 2>/dev/null && pwd)"
if [ ! -d "${SCRIPT_DIR}/pfsense-pkg" ]; then
    TMP_DIR="/tmp/poseaband_install"
    rm -rf "${TMP_DIR}"
    mkdir -p "${TMP_DIR}"
    fetch -q -o "${TMP_DIR}/main.tar.gz" "https://github.com/bysinbin/pfsense-poseaband/archive/refs/heads/main.tar.gz"
    tar -xzf "${TMP_DIR}/main.tar.gz" -C "${TMP_DIR}"
    SCRIPT_DIR="${TMP_DIR}/pfsense-poseaband-main"
fi

mkdir -p /usr/local/pkg /usr/local/www /var/etc/poseafilter /usr/local/www/widgets/include /usr/local/www/widgets/widgets
cp "${SCRIPT_DIR}/pfsense-pkg/usr/local/pkg/poseaband.inc" /usr/local/pkg/poseaband.inc
cp "${SCRIPT_DIR}/pfsense-pkg/usr/local/pkg/poseaband.xml" /usr/local/pkg/poseaband.xml
cp "${SCRIPT_DIR}/pfsense-pkg/usr/local/www/poseaband.php" /usr/local/www/poseaband.php
cp "${SCRIPT_DIR}/pfsense-pkg/usr/local/www/widgets/include/poseaband.inc" /usr/local/www/widgets/include/poseaband.inc
cp "${SCRIPT_DIR}/pfsense-pkg/usr/local/www/widgets/widgets/poseaband.widget.php" /usr/local/www/widgets/widgets/poseaband.widget.php

php -r '
require_once("/etc/inc/config.inc");
global $config;
$found = false;
foreach ($config["installedpackages"]["package"] ?? [] as $p) {
    if (($p["name"] ?? "") === "poseaband") { $found = true; break; }
}
if (!$found) {
    $config["installedpackages"]["package"][] = [
        "name" => "poseaband",
        "descr" => "PoseaBand QoS & Bandwidth Manager for pfSense",
        "website" => "https://github.com/bysinbin/pfsense-poseaband",
        "version" => "1.0.0",
        "status" => "Stable",
        "configurationfile" => "poseaband.xml"
    ];
}
$mfound = false;
foreach ($config["installedpackages"]["menu"] ?? [] as $m) {
    if (($m["name"] ?? "") === "PoseaBand (QoS)") { $mfound = true; break; }
}
if (!$mfound) {
    $config["installedpackages"]["menu"][] = [
        "name" => "PoseaBand (QoS)",
        "section" => "Services",
        "url" => "/poseaband.php"
    ];
}
write_config("Installed PoseaBand package");
'
echo "[+] PoseaBand successfully installed!"
