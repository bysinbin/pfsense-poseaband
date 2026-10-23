# PoseaBand for pfSense &bull; Kurumsal Bant Genişliği & QoS Hız Yöneticisi

PoseaBand, ağdaki tekil kullanıcıların veya misafir cihazların (video akışı, dosya indirme vb.) kurumsal internet hattını kilitlemesini önleyen, kişi başı dinamik bant genişliği havuzu (Per-Host Limiter) atayan bağımsız bir pfSense paketidir.

## 🚀 Özellikler
- **Kişi Başı Dinamik Hız Sınırı:** Her istemciye bağımsız Download ve Upload limiti tanımlama (Varsayılan: 5 Mbps).
- **Hız Profilleri:** Yönetim/VIP (25M), Standart Personel (5M), Misafir Wi-Fi (2M), Kısıtlı (1M).
- **Yerel Ağ İstisnası (LAN Bypass):** Şirket içi yerel sunucu ve dosya paylaşımlarının tam 1 Gbps gigabit hızında çalışmasını garanti eder.
- **Canlı Ağ & Hız Monitörü:** Ağdaki tüm istemcilerin anlık tüketimini gösterir ve tek tıkla oturum kesme (`Kill State`) imkanı sunar.
- **Aç/Kapa Anahtarı:** İçindeki enable seçeneği ile dilediğiniz zaman tek tıkla aktif veya pasif edilebilir.

## 📦 Kurulum (Tek Komut)
pfSense SSH konsolunda root olarak çalıştırın:
```sh
curl -sSL https://raw.githubusercontent.com/bysinbin/pfsense-poseaband/main/scripts/install.sh | sh
```
Kurulum tamamlandığında pfSense WebGUI üzerinde **Services > PoseaBand (QoS)** menüsü belirecektir.
