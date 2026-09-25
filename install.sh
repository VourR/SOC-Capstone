#!/bin/bash

set -e

# ==================================================
# Web-IDS Capstone - Complete Installation Script
# ==================================================
# Auto-detects installation directory and configures
# all components: Filebeat, Zeek, FlowMeter, ML Worker,
# Malware Monitor, and Command Logging

# ==================================================
# Auto-detect BASE_DIR from script location
# ==================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$SCRIPT_DIR"

echo "======================================"
echo " Installing Web-IDS Capstone"
echo " Installation directory: $BASE_DIR"
echo "======================================"

# ==================================================
# Validasi Root
# ==================================================
if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] Jalankan script ini dengan sudo:"
    echo "sudo $SCRIPT_DIR/install.sh"
    exit 1
fi

# ==================================================
# Deteksi OS
# ==================================================
if [ -f /etc/os-release ]; then
    . /etc/os-release
else
    echo "[ERROR] /etc/os-release tidak ditemukan. OS tidak bisa dideteksi."
    exit 1
fi

OS_ID="${ID}"
OS_VERSION="${VERSION_ID}"

echo "[INFO] OS terdeteksi: $PRETTY_NAME"

# ==================================================
# Tanya user: mau install ML Inference Worker atau tidak?
# ==================================================
# Ini KHUSUS untuk komponen ML inference worker (model scoring: pandas,
# scikit-learn, joblib, artifacts.zip, proses inference_worker.py).
# Zeek, FlowMeter, Filebeat, file monitor, dan command logging TETAP
# terinstall apa pun jawabannya - itu bukan bagian dari "ML inferencing".
#
# Bisa juga di-skip interaktifnya pakai flag:
#   ./install.sh --with-ml   -> langsung install ML tanpa nanya
#   ./install.sh --no-ml     -> langsung skip ML tanpa nanya
INSTALL_ML=true
ML_FLAG=""
for arg in "$@"; do
    case "$arg" in
        --with-ml) ML_FLAG="yes" ;;
        --no-ml) ML_FLAG="no" ;;
    esac
done

if [ -n "$ML_FLAG" ]; then
    if [ "$ML_FLAG" = "yes" ]; then
        INSTALL_ML=true
        echo "[INFO] ML Inference Worker: diinstall (via flag --with-ml)."
    else
        INSTALL_ML=false
        echo "[INFO] ML Inference Worker: di-skip (via flag --no-ml)."
    fi
elif [ -t 0 ]; then
    echo ""
    read -r -p "Install ML Inference Worker (model scoring pandas/scikit-learn)? [Y/n]: " ML_ANSWER
    case "$ML_ANSWER" in
        [nN]|[nN][oO])
            INSTALL_ML=false
            echo "[INFO] ML Inference Worker akan di-skip."
            ;;
        *)
            INSTALL_ML=true
            echo "[INFO] ML Inference Worker akan diinstall."
            ;;
    esac
    echo ""
else
    # stdin bukan terminal (misal dijalankan lewat pipe/cron/CI) - default
    # install ML supaya behavior tetap sama seperti versi sebelumnya kalau
    # tidak ada interaksi sama sekali. Pakai --with-ml/--no-ml eksplisit
    # untuk kontrol pasti di mode non-interaktif.
    echo "[INFO] Mode non-interaktif terdeteksi, ML Inference Worker default: diinstall."
    echo "[INFO] Gunakan --no-ml untuk skip ML tanpa prompt."
fi

# ==================================================
# Flag untuk skip instalasi ML (inference worker, Zeek, FlowMeter)
# ==================================================
SKIP_ML=false
if [ "$OS_ID" = "centos" ]; then
    SKIP_ML=true
    echo "[INFO] $PRETTY_NAME terdeteksi - instalasi ML (inference worker, Zeek, FlowMeter) akan di-skip."
    echo "[INFO] File monitoring juga akan di-skip (inotify-tools tidak tersedia)."
    echo "[INFO] Fitur lain (Filebeat, command logging) tetap akan diinstall."
fi

# ==================================================
# Fungsi Umum
# ==================================================
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# ==================================================
# Enable EPEL (untuk RHEL-family: AlmaLinux, RHEL, CentOS)
# ==================================================
# PENTING: sebelumnya EPEL cuma di-"set-enabled" di dalam
# install_zeek_from_epel() - itu jalan SETELAH install_basic_dependencies_yum,
# dan cuma mengasumsikan file /etc/yum.repos.d/epel.repo SUDAH ADA. Di sistem
# yang benar-benar fresh, paket "epel-release" itu sendiri belum pernah
# terinstall, jadi repo epel.repo tidak ada sama sekali - akibatnya paket
# "inotify-tools" (yang cuma tersedia via EPEL) tidak ketemu, dan karena itu
# digabung dalam satu transaksi dnf/yum bareng paket kritikal lain (curl,
# python3, gcc, dst), SELURUH transaksi gagal -> seluruh script mati (set -e).
#
# Fix: install epel-release di awal, SEBELUM install dependency dasar apa pun,
# supaya inotify-tools (dan zeek-zkg nantinya) sudah bisa ketemu dari awal.
enable_epel() {
    if rpm -q epel-release &>/dev/null; then
        echo "[INFO] epel-release sudah terinstall."
        return
    fi

    echo "[INFO] Menginstall epel-release..."
    if command_exists dnf; then
        dnf install -y epel-release || echo "[WARNING] Gagal install epel-release via dnf, lanjut tanpa EPEL."
    elif command_exists yum; then
        yum install -y epel-release || echo "[WARNING] Gagal install epel-release via yum, lanjut tanpa EPEL."
    fi
}

install_basic_dependencies_apt() {
    echo "[INFO] Install dependency dasar..."
    apt-get update
    apt-get install -y curl wget gnupg gpg apt-transport-https ca-certificates git \
        python3 python3-pip python3-venv python3-dev \
        build-essential swig libssl-dev \
        inotify-tools libimage-exiftool-perl \
        lsb-release unzip

    echo "[INFO] Install build dependencies untuk Zeek..."
    apt-get install -y cmake flex bison libpcap-dev zlib1g-dev
}

install_basic_dependencies_yum() {
    echo "[INFO] Install dependency dasar..."
    yum install -y curl wget gnupg ca-certificates git \
        python3 python3-pip python3-devel \
        gcc gcc-c++ make openssl-devel \
        yum-utils unzip

    # inotify-tools dipisah dari transaksi utama - cuma tersedia via EPEL,
    # dan kalau EPEL gagal/tidak ketemu, ini best-effort saja supaya paket
    # kritikal di atas tetap terinstall (tidak ikut gagal semua gara-gara
    # satu paket ini tidak ketemu). Kalau tetap gagal, file monitor otomatis
    # fallback ke polling mode (lihat setup_file_monitor).
    if ! yum install -y inotify-tools; then
        echo "[WARNING] inotify-tools tidak ketemu (EPEL mungkin belum aktif)."
        echo "[WARNING] File monitor akan pakai polling mode, bukan real-time inotify."
    fi

    # Optional packages - jika tidak ada, skip
    echo "[INFO] Install optional packages..."
    yum install -y perl-Image-ExifTool || true
    yum install -y swig || true
}

install_basic_dependencies_dnf() {
    echo "[INFO] Install dependency dasar..."
    dnf install -y curl wget gnupg ca-certificates git \
        python3 python3-pip python3-devel \
        gcc gcc-c++ make openssl-devel \
        dnf-plugins-core unzip

    # inotify-tools dipisah - lihat catatan di install_basic_dependencies_yum
    if ! dnf install -y inotify-tools; then
        echo "[WARNING] inotify-tools tidak ketemu (EPEL mungkin belum aktif)."
        echo "[WARNING] File monitor akan pakai polling mode, bukan real-time inotify."
    fi

    echo "[INFO] Install build dependencies untuk Zeek..."
    dnf install -y cmake flex bison libpcap-devel zlib-devel

    # Optional packages - jika tidak ada, skip
    echo "[INFO] Install optional packages..."
    dnf install -y perl-Image-ExifTool || true
    dnf install -y swig || true
}

# ==================================================
# Setup Python Environment
# ==================================================
setup_python_environment() {
    # Ensure valid working directory for pip operations
    cd /tmp
    
    echo "[INFO] Mengecek Python 3 dan pip..."

    if ! command_exists python3; then
        echo "[ERROR] python3 tidak ditemukan."
        exit 1
    fi

    if ! command_exists pip3; then
        echo "[ERROR] pip3 tidak ditemukan."
        exit 1
    fi

    PYTHON_VERSION=$(python3 --version | awk '{print $2}')
    echo "[OK] Python 3 terinstall: $PYTHON_VERSION"

    echo "[INFO] Upgrade pip, setuptools, dan wheel..."
    pip3 install --upgrade pip setuptools wheel

    if [ "$SKIP_ML" = true ] || [ "$INSTALL_ML" = false ]; then
        echo "[INFO] SKIP: dependency ML inference worker (pandas, scikit-learn, joblib) di-skip."
    else
        echo "[INFO] Install Python dependencies untuk ML inference worker..."
        
        # Detect Python version untuk compatibility
        PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
        echo "[INFO] Python version terdeteksi: $PYTHON_VERSION"
        
        # Install sesuai Python version
        if [ "$PYTHON_VERSION" = "3.9" ]; then
            echo "[INFO] Python 3.9 - install scikit-learn 1.6.x (compatible)"
            pip3 install pandas==2.3.0 scikit-learn==1.6.1 joblib==1.5.1 psycopg2-binary python-dotenv
        elif [ "$PYTHON_VERSION" = "3.10" ]; then
            echo "[INFO] Python 3.10 - install scikit-learn 1.7.x (compatible)"
            pip3 install pandas==2.3.0 scikit-learn==1.7.0 joblib==1.5.1 psycopg2-binary python-dotenv
        else
            # Python 3.11+ atau yang lain - gunakan latest compatible
            echo "[INFO] Python $PYTHON_VERSION - install latest compatible versions"
            pip3 install pandas scikit-learn joblib psycopg2-binary python-dotenv
        fi
    fi

    echo "[INFO] Install Python dependencies untuk malware file monitor..."
    pip3 install PyExifTool==0.5.5 pypdf==5.0.0

    if [ "$SKIP_ML" = false ]; then
        echo "[INFO] Install Python dependencies untuk Zeek..."
        pip3 install websockets>=11.0 || true
    fi

    echo "[OK] Python environment sudah siap."
}

# ==================================================
# Generate config.json
# ==================================================
generate_config_json() {
    echo "[INFO] Generate config.json dengan paths yang benar..."

    cat > "$BASE_DIR/config/config.json" <<EOF
{
  "artifacts_dir": "$BASE_DIR/artifacts",
  "conn_log_path": "/opt/zeek/logs/current/conn.log",
  "flowmeter_log_path": "/opt/zeek/logs/current/flowmeter.log",
  "output_jsonl": "/var/log/Capstone/predictions.jsonl",
  "worker_log_path": "/var/log/Capstone/inference_worker.log",
  "state_dir": "$BASE_DIR/state",
  "poll_interval_seconds": 1.0,
  "batch_size": 500,
  "conn_cache_ttl_seconds": 900,
  "pending_flow_ttl_seconds": 600,
  "start_at_end": true,
  "model_name": "RF-WEBIDS23",
  "model_version": "2.0.0",
  "internal_networks": [
    "192.168.1.0/24",
    "10.0.0.0/8"
  ],
  "direction_labels": {
    "inbound": "inbound",
    "outbound": "outbound",
    "internal": "internal",
    "external": "external",
    "unknown": "Unknown"
  },
  "log_level": "INFO"
}
EOF

    echo "[OK] config.json berhasil dibuat: $BASE_DIR/config/config.json"
}

# ==================================================
# Generate/Update filebeat.yml
# ==================================================
generate_filebeat_yml() {
    echo "[INFO] Generate filebeat.yml dengan konfigurasi Capstone..."

    FILEBEAT_YML="/etc/filebeat/filebeat.yml"
    FILEBEAT_BACKUP="/etc/filebeat/filebeat.yml.backup-$(date +%Y%m%d-%H%M%S)"

    # Backup original config
    if [ -f "$FILEBEAT_YML" ]; then
        cp "$FILEBEAT_YML" "$FILEBEAT_BACKUP"
        echo "[INFO] Backup original filebeat.yml: $FILEBEAT_BACKUP"
    fi

    # Generate clean filebeat.yml (overwrite completely)
    cat > "$FILEBEAT_YML" <<'EOFFILEBEAT'
# Filebeat configuration - generated by Capstone installer
# Do not edit manually - changes will be overwritten

# ========================================
# Capstone Web-IDS inputs
# ========================================
filebeat.inputs:
- type: filestream
  id: webids-predictions
  enabled: true
  paths:
    - /var/log/Capstone/predictions.jsonl
  parsers:
    - ndjson:
        target: ""
        add_error_key: true
  fields:
    log_type: webids_prediction
  fields_under_root: true

- type: filestream
  id: file-content-scan
  enabled: true
  paths:
    - /var/log/file-content-scan.log
  parsers:
    - ndjson:
        target: ""
        add_error_key: true
  fields:
    log_type: file_content_scan
  fields_under_root: true

- type: filestream
  id: linux-commands
  enabled: true
  paths:
    - /var/log/commands.log
  fields:
    log_type: linux_commands
  fields_under_root: true
  pipeline: "capstone-linux-commands"

# ========================================
# Kibana setup
# ========================================
setup.kibana:
  host: "10.70.128.26:5601"
  protocol: "https"
  username: "elastic"
  password: "ScfJtJGKnw8irv*V5_NI"
  ssl.verification_mode: "none"

# ========================================
# Elasticsearch output
# ========================================
output.elasticsearch:
  hosts: ["10.70.128.26:9200"]
  protocol: "https"
  username: "elastic"
  password: "ScfJtJGKnw8irv*V5_NI"
  ssl.verification_mode: "none"

# ========================================
# Processors
# ========================================
processors:
  - add_host_metadata:
      when.not.contains.tags: forwarded
  - add_cloud_metadata: ~
  - add_docker_metadata: ~
  - add_kubernetes_metadata: ~
  - script:
      lang: javascript
      id: extract_command_name
      source: >
        function process(event) {
          var cmd = event.Get("linux.command");
          if (cmd) {
            cmd = cmd.replace(/^\s+|\s+$/g, "");
            if (cmd.length > 0) {
              var parts = cmd.split(/\s+/);
              event.Put("linux.command_name", parts[0]);
            }
          }
        }

# ========================================
# Logging
# ========================================
logging.level: info

# ========================================
# Template settings
# ========================================
setup.template.settings:
  index.number_of_shards: 1
EOFFILEBEAT

    chmod 600 "$FILEBEAT_YML"
    echo "[OK] filebeat.yml berhasil dibuat: $FILEBEAT_YML"

    # Test config
    echo "[INFO] Testing filebeat config..."
    if filebeat test config -c "$FILEBEAT_YML" > /dev/null 2>&1; then
        echo "[OK] Filebeat config valid"
    else
        echo "[ERROR] Filebeat config invalid!"
        echo "[INFO] Running detailed test..."
        filebeat test config -c "$FILEBEAT_YML"
        return 1
    fi

    echo "[INFO] Backup tersimpan di: $FILEBEAT_BACKUP"
}


# ==================================================
# Install Filebeat
# ==================================================
install_filebeat_apt() {
    if command_exists filebeat; then
        echo "[OK] Filebeat sudah terinstall: $(filebeat version)"
        return
    fi

    echo "[INFO] Menambahkan repository Elastic untuk Filebeat..."

    curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor -o /usr/share/keyrings/elastic-keyring.gpg

    echo "deb [signed-by=/usr/share/keyrings/elastic-keyring.gpg] https://artifacts.elastic.co/packages/9.x/apt stable main" \
        > /etc/apt/sources.list.d/elastic-9.x.list

    apt-get update
    apt-get install -y filebeat

    systemctl enable filebeat

    echo "[OK] Filebeat berhasil diinstall."
}

install_filebeat_yum_or_dnf() {
    if command_exists filebeat; then
        echo "[OK] Filebeat sudah terinstall: $(filebeat version)"
        return
    fi

    echo "[INFO] Menambahkan repository Elastic untuk Filebeat..."

    rpm --import https://artifacts.elastic.co/GPG-KEY-elasticsearch

    cat > /etc/yum.repos.d/elastic-9.x.repo <<EOF
[elastic-9.x]
name=Elastic repository for 9.x packages
baseurl=https://artifacts.elastic.co/packages/9.x/yum
gpgcheck=1
gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
enabled=1
autorefresh=1
type=rpm-md
EOF

    if command_exists dnf; then
        dnf install -y filebeat
    else
        yum install -y filebeat
    fi

    systemctl enable filebeat

    echo "[OK] Filebeat berhasil diinstall."
}

# ==================================================
# Install Zeek
# ==================================================
get_zeek_repo_name_apt() {
    case "$OS_ID:$OS_VERSION" in
        ubuntu:22.04)
            echo "xUbuntu_22.04"
            ;;
        ubuntu:24.04)
            echo "xUbuntu_24.04"
            ;;
        ubuntu:25.04)
            echo "xUbuntu_25.04"
            ;;
        debian:12)
            echo "Debian_12"
            ;;
        debian:13)
            echo "Debian_13"
            ;;
        *)
            echo ""
            ;;
    esac
}

install_zeek_apt() {
    if [ -x /opt/zeek/bin/zeek ]; then
        echo "[OK] Zeek sudah terinstall: $(/opt/zeek/bin/zeek --version)"
        return
    fi

    ZEEK_REPO_NAME="$(get_zeek_repo_name_apt)"

    if [ -z "$ZEEK_REPO_NAME" ]; then
        echo "[ERROR] OS ini belum ditangani otomatis untuk repository Zeek."
        echo "[INFO] OS terdeteksi: $PRETTY_NAME"
        echo "[INFO] Script ini mendukung Ubuntu 22.04, Ubuntu 24.04, Ubuntu 25.04, Debian 12, dan Debian 13."
        exit 1
    fi

    echo "[INFO] Menambahkan repository Zeek: $ZEEK_REPO_NAME"

    echo "deb http://download.opensuse.org/repositories/security:/zeek/$ZEEK_REPO_NAME/ /" \
        > /etc/apt/sources.list.d/security:zeek.list

    curl -fsSL "https://download.opensuse.org/repositories/security:zeek/$ZEEK_REPO_NAME/Release.key" \
        | gpg --dearmor \
        > /etc/apt/trusted.gpg.d/security_zeek.gpg

    apt-get update
    apt-get install -y zeek

    echo "[OK] Zeek berhasil diinstall."
}

# ==================================================
# Install Zeek dari EPEL Repository (AlmaLinux/RHEL)
# ==================================================
install_zeek_from_epel() {
    # PENTING: sebelumnya function ini langsung "return" di sini kalau Zeek
    # SUDAH terinstall (misal dari run install.sh sebelumnya) - akibatnya
    # install_flowmeter_epel() di bagian bawah TIDAK PERNAH terpanggil sama
    # sekali pada run kedua dan seterusnya, walaupun FlowMeter belum pernah
    # berhasil ter-load. Ini penyebab utama "@load flowmeter" tidak pernah
    # muncul di local.zeek meski script "sukses" tanpa error.
    #
    # Fix: kalau Zeek sudah terinstall, skip instalasi paket Zeek saja,
    # tapi tetap lanjut cek/instal FlowMeter di bawah.
    ZEEK_ALREADY_INSTALLED=false
    if command -v zeek &> /dev/null; then
        echo "[OK] Zeek sudah terinstall: $(zeek --version)"
        ZEEK_ALREADY_INSTALLED=true
    fi

    if [ "$ZEEK_ALREADY_INSTALLED" = false ]; then
        echo "[INFO] Install Zeek dari EPEL repository..."

        # Enable EPEL if not already
        if ! grep -q "^enabled=1" /etc/yum.repos.d/epel.repo 2>/dev/null; then
            echo "[INFO] Enabling EPEL repository..."
            if command -v dnf &> /dev/null; then
                sudo dnf config-manager --set-enabled epel || true
            else
                sudo yum-config-manager --enable epel || true
            fi
        fi

        # Install zeek packages dari EPEL
        echo "[INFO] Menginstall zeek-core, zeekctl, dan zeek-zkg dari EPEL..."
        if command -v dnf &> /dev/null; then
            dnf install -y zeek-core zeekctl zeek-zkg
        else
            yum install -y zeek-core zeekctl zeek-zkg
        fi

        # Fix EPEL paths (bukan /opt/zeek tapi /var/spool/zeek dan /var/log/zeek)
        echo "[INFO] Fix permission untuk Zeek directories (EPEL paths)..."
        sudo chown -R root:root /var/spool/zeek 2>/dev/null || true
        sudo chmod -R 755 /var/spool/zeek 2>/dev/null || true
        sudo chown -R root:root /var/log/zeek 2>/dev/null || true
        sudo chmod -R 755 /var/log/zeek 2>/dev/null || true

        # Auto-configure network interface untuk EPEL
        echo "[INFO] Mengkonfigurasi Zeek network interface..."
        configure_zeek_epel

        echo "[OK] Zeek berhasil diinstall dari EPEL."
    fi

    # Install FlowMeter plugin - SELALU dicek/dijalankan, baik Zeek baru
    # diinstall maupun sudah ada dari sebelumnya. install_flowmeter_epel()
    # sendiri sudah idempotent (skip kalau sudah ke-load di local.zeek).
    echo "[INFO] Install FlowMeter plugin via zkg..."
    install_flowmeter_epel
}

# ==================================================
# Install FlowMeter untuk EPEL Zeek
# ==================================================
install_flowmeter_epel() {
    echo "[INFO] Installing FlowMeter plugin..."

    # Cari binary zkg - bisa di PATH biasa atau di lokasi umum lainnya
    ZKG_BIN=""
    if command -v zkg &> /dev/null; then
        ZKG_BIN="$(command -v zkg)"
    elif [ -x /opt/zeek/bin/zkg ]; then
        ZKG_BIN="/opt/zeek/bin/zkg"
    elif [ -x /usr/bin/zkg ]; then
        ZKG_BIN="/usr/bin/zkg"
    fi

    if [ -z "$ZKG_BIN" ]; then
        echo "[WARNING] zkg tidak ditemukan (dicek di PATH, /opt/zeek/bin, /usr/bin). FlowMeter skip."
        return
    fi
    echo "[INFO] zkg ditemukan: $ZKG_BIN"

    # Paket "zeek-zkg" dari EPEL tidak membawa dependency Python-nya sendiri
    # (GitPython, semantic-version) - tanpa ini, zkg langsung error dengan
    # "ModuleNotFoundError: No module named 'git'" begitu dipanggil.
    if ! "$ZKG_BIN" --version &> /dev/null; then
        echo "[INFO] Install Python dependencies untuk zkg (GitPython, semantic-version)..."
        pip3 install GitPython semantic-version || {
            echo "[WARNING] Gagal install dependency zkg. FlowMeter kemungkinan tetap gagal."
        }
    fi

    if ! "$ZKG_BIN" --version &> /dev/null; then
        echo "[ERROR] zkg masih tidak bisa jalan setelah install dependency. FlowMeter skip."
        "$ZKG_BIN" --version || true
        return
    fi

    # zkg butuh konfigurasi (state_dir/script_dir/plugin_dir) sebelum bisa install.
    # Paket zeek-zkg dari EPEL biasanya sudah punya config bawaan, tapi kalau belum
    # ada sama sekali, jalankan autoconfig dulu supaya tidak macet/gagal aneh.
    if [ ! -f "$HOME/.zkg/config" ] && [ ! -f /etc/zkg/config ] && [ ! -f /root/.zkg/config ]; then
        echo "[INFO] zkg belum ada konfigurasi, menjalankan '$ZKG_BIN autoconfig --force'..."
        "$ZKG_BIN" autoconfig --force || true
    fi

    # Install FlowMeter via zkg menggunakan GitHub URL (tidak ada di zkg search index).
    #
    # PENTING - dua bug yang bikin FlowMeter GAGAL ter-load sebelumnya:
    #   1. "zkg install ... | tail -3" -> exit status yang dicek oleh "if" adalah
    #      punya "tail", BUKAN punya "zkg install". Jadi blok "berhasil" selalu
    #      jalan meskipun instalasi FlowMeter aslinya gagal.
    #   2. "zkg install" tanpa "--force" akan menampilkan prompt konfirmasi
    #      interaktif (Y/n). Karena outputnya di-pipe ke "tail", prompt itu
    #      tidak pernah terlihat di layar -> script seolah "diam"/hang, padahal
    #      sebenarnya sedang menunggu input yang tidak pernah datang.
    #
    # Fix: output ditulis ke log file (bukan di-pipe langsung), exit code diambil
    # dari zkg langsung, dan "--force" dipakai supaya tidak ada prompt interaktif.
    echo "[INFO] Installing FlowMeter dari GitHub..."
    ZKG_LOG="/tmp/zkg_flowmeter_install.log"
    "$ZKG_BIN" install --force https://github.com/zeek-flowmeter/zeek-flowmeter > "$ZKG_LOG" 2>&1
    ZKG_STATUS=$?

    echo "[INFO] --- output zkg install (20 baris terakhir) ---"
    tail -20 "$ZKG_LOG"
    echo "[INFO] --- log lengkap: $ZKG_LOG ---"

    if [ "$ZKG_STATUS" -eq 0 ]; then
        echo "[OK] FlowMeter berhasil diinstall"

        # Add @load directive ke local.zeek untuk load FlowMeter
        load_flowmeter_in_local_zeek "$ZKG_BIN"
    else
        echo "[WARNING] FlowMeter installation gagal (exit code $ZKG_STATUS). Lihat $ZKG_LOG untuk detail."
    fi
}

# ==================================================
# Load FlowMeter di local.zeek
# ==================================================
load_flowmeter_in_local_zeek() {
    local ZKG_BIN="${1:-zkg}"

    # Detect path based on OS
    if [ "$OS_ID" = "almalinux" ]; then
        LOCAL_ZEEK="/usr/share/zeek/site/local.zeek"  # EPEL package path
    else
        LOCAL_ZEEK="/opt/zeek/etc/local.zeek"  # Build-from-source path (Ubuntu/Debian/RHEL/CentOS)
    fi

    # Check jika file ada
    if [ ! -f "$LOCAL_ZEEK" ]; then
        echo "[WARNING] local.zeek tidak ditemukan di $LOCAL_ZEEK"
        return
    fi

    # Check jika FlowMeter sudah di-load (anchor ^ supaya tidak ke-skip gara-gara komentar
    # yang kebetulan mengandung teks yang sama)
    if grep -qE '^[[:space:]]*@load[[:space:]]+flowmeter[[:space:]]*$' "$LOCAL_ZEEK"; then
        echo "[INFO] FlowMeter sudah di-load di local.zeek"
        return
    fi

    echo "[INFO] Adding FlowMeter @load directive ke local.zeek..."
    echo "[INFO] Path: $LOCAL_ZEEK"

    # Backup. Script ini sudah divalidasi berjalan sebagai root (EUID=0) di awal,
    # jadi tidak perlu "sudo" lagi di sini - "sudo" di dalam script yang sudah
    # root justru jadi titik gagal baru kalau paket sudo tidak terinstall.
    cp "$LOCAL_ZEEK" "$LOCAL_ZEEK.backup.$(date +%s)"

    {
        echo ""
        echo "# Added by Web-IDS Capstone installer"
        echo "@load flowmeter"
    } >> "$LOCAL_ZEEK"

    if grep -qE '^[[:space:]]*@load[[:space:]]+flowmeter[[:space:]]*$' "$LOCAL_ZEEK"; then
        echo "[OK] FlowMeter @load directive berhasil ditambahkan ke local.zeek"
    else
        echo "[ERROR] Gagal menambahkan FlowMeter @load directive ke local.zeek"
        return
    fi

    # Validasi konfigurasi Zeek setelah perubahan, supaya ketahuan dari sekarang
    # kalau ada masalah (misalnya paket FlowMeter tidak benar-benar ke-copy ke
    # ZEEKPATH), bukan baru ketahuan saat zeekctl start di akhir instalasi.
    if command -v zeekctl &> /dev/null; then
        echo "[INFO] Validasi konfigurasi Zeek via 'zeekctl check'..."
        if zeekctl check; then
            echo "[OK] Konfigurasi Zeek valid, FlowMeter siap dipakai."
        else
            echo "[WARNING] 'zeekctl check' melaporkan masalah setelah penambahan FlowMeter."
            echo "[INFO] Cek manual: zeekctl check   |   cat $LOCAL_ZEEK"
        fi
    fi
}

# ==================================================
# Configure Zeek Interface untuk EPEL Package (AlmaLinux)
# ==================================================
# Path: /etc/zeek/node.cfg (EPEL location)
configure_zeek_epel() {
    ZEEK_NODE_CONFIG="/etc/zeek/node.cfg"

    if [ ! -f "$ZEEK_NODE_CONFIG" ]; then
        echo "[WARNING] node.cfg tidak ditemukan"
        return
    fi

    # Find active network interface (exclude lo, docker, etc)
    INTERFACE=$(ip route | grep '^default' | awk '{print $5}' | head -1)

    if [ -z "$INTERFACE" ]; then
        # Fallback: gunakan interface pertama yang up (bukan loopback)
        INTERFACE=$(ip link show | grep "^[0-9]" | grep "UP" | awk '{print $2}' | sed 's/:$//' | grep -v "^lo$" | head -1)
    fi

    if [ -z "$INTERFACE" ]; then
        echo "[WARNING] Tidak bisa menemukan network interface aktif"
        echo "[INFO] Edit manual: $ZEEK_NODE_CONFIG"
        echo "[INFO] Set interface= ke interface yang ingin di-monitor"
        return
    fi

    echo "[INFO] Network interface terdeteksi: $INTERFACE"

    # Update node.cfg dengan interface
    if grep -q "^interface=" "$ZEEK_NODE_CONFIG"; then
        sudo sed -i "s/^interface=.*/interface=$INTERFACE/" "$ZEEK_NODE_CONFIG"
    else
        sudo sed -i "/^\[manager\]/a interface=$INTERFACE" "$ZEEK_NODE_CONFIG"
    fi

    echo "[OK] Zeek dikonfigurasi untuk interface: $INTERFACE"
}

# ==================================================
# Install Zeek (CentOS/RHEL - Build from Source)
# ==================================================
install_zeek_yum_or_dnf() {
    if [ -x /opt/zeek/bin/zeek ]; then
        echo "[OK] Zeek sudah terinstall: $(/opt/zeek/bin/zeek --version)"
        return
    fi

    echo "[INFO] Menambahkan repository Zeek untuk $PRETTY_NAME..."

    # Tentukan repository path berdasarkan OS dan versi
    if [ "$OS_ID" = "centos" ]; then
        if [ "$OS_VERSION" = "10" ]; then
            ZEEK_REPO_PATH="CentOS_Stream_10"
        elif [ "$OS_VERSION" = "9" ]; then
            ZEEK_REPO_PATH="CentOS_Stream_9"
        else
            ZEEK_REPO_PATH="CentOS_CentOS-$OS_VERSION"
        fi
    elif [ "$OS_ID" = "rhel" ]; then
        ZEEK_REPO_PATH="RHEL_$OS_VERSION"
    else
        ZEEK_REPO_PATH="CentOS_Stream_10"
    fi

    ZEEK_REPO_URL="https://download.opensuse.org/repositories/security:zeek/$ZEEK_REPO_PATH/"
    echo "[INFO] Zeek repository: $ZEEK_REPO_URL"

    # Try package installation
    if command_exists dnf; then
        echo "[INFO] Menggunakan dnf..."
        dnf config-manager --add-repo "${ZEEK_REPO_URL}security:zeek.repo" 2>/dev/null || true
        dnf install -y zeek 2>/dev/null && return
    else
        echo "[INFO] Menggunakan yum..."
        cat > /etc/yum.repos.d/security:zeek.repo <<EOF
[security:zeek]
name=Zeek repository for RHEL/CentOS/AlmaLinux
baseurl=$ZEEK_REPO_URL
gpgcheck=0
enabled=1
EOF
        yum install -y zeek 2>/dev/null && return
    fi

    # Fallback: Build from source
    echo "[WARNING] Package installation gagal. Building Zeek dari source..."
    build_zeek_from_source
}

# ==================================================
# Build Zeek from Source
# ==================================================
build_zeek_from_source() {
    echo "[INFO] Install build dependencies..."

    if command_exists dnf; then
        dnf install -y cmake make gcc gcc-c++ flex bison openssl-devel || true

        # Try alternative package names for libpcap
        dnf install -y libpcap-devel 2>/dev/null || \
        dnf install -y libpcap-dev 2>/dev/null || \
        dnf install -y libpcap 2>/dev/null || true
    else
        yum install -y cmake make gcc gcc-c++ flex bison openssl-devel || true

        # Try alternative package names for libpcap
        yum install -y libpcap-devel 2>/dev/null || \
        yum install -y libpcap-dev 2>/dev/null || \
        yum install -y libpcap 2>/dev/null || true
    fi

    # Verify cmake is installed
    if ! command_exists cmake; then
        echo "[ERROR] cmake tidak terinstall. Install manual:"
        echo "  sudo dnf install cmake"
        echo "  atau"
        echo "  sudo yum install cmake"
        return 1
    fi

    echo "[INFO] Download Zeek LTS source code..."
    cd /tmp

    # Download latest LTS version
    ZEEK_VERSION="8.0.8"  # LTS version
    ZEEK_FILE="zeek-$ZEEK_VERSION.tar.gz"
    ZEEK_URL="https://download.zeek.org/$ZEEK_FILE"

    if [ -f "$ZEEK_FILE" ]; then
        echo "[INFO] Source sudah ada: $ZEEK_FILE"
    else
        echo "[INFO] Downloading dari: $ZEEK_URL"
        curl -L -o "$ZEEK_FILE" "$ZEEK_URL" || {
            echo "[ERROR] Gagal download Zeek source"
            return 1
        }
    fi

    echo "[INFO] Extract source code..."
    tar -xzf "$ZEEK_FILE"
    cd "zeek-$ZEEK_VERSION"

    echo "[INFO] Build Zeek (ini bisa memakan waktu 10-30 menit)..."
    mkdir -p build
    cd build
    cmake .. -DCMAKE_INSTALL_PREFIX=/opt/zeek || {
        echo "[ERROR] CMake failed"
        echo "[INFO] Pastikan semua build dependencies terinstall:"
        echo "  - cmake"
        echo "  - gcc/gcc-c++"
        echo "  - flex, bison"
        echo "  - openssl-devel"
        echo "  - libpcap-devel (atau libpcap)"
        return 1
    }

    make -j $(nproc) || {
        echo "[ERROR] Build failed"
        return 1
    }

    echo "[INFO] Install Zeek..."
    make install || {
        echo "[ERROR] Install failed"
        return 1
    }

    echo "[OK] Zeek berhasil diinstall dari source di /opt/zeek"
}

setup_zeek_path() {
    echo "[INFO] Menambahkan Zeek ke PATH..."

    cat > /etc/profile.d/zeek.sh <<EOF
export PATH=/opt/zeek/bin:\$PATH
EOF

    chmod +x /etc/profile.d/zeek.sh

    ln -sf /opt/zeek/bin/zeek /usr/local/bin/zeek
    ln -sf /opt/zeek/bin/zeekctl /usr/local/bin/zeekctl

    if [ -x /opt/zeek/bin/zkg ]; then
        ln -sf /opt/zeek/bin/zkg /usr/local/bin/zkg
    fi

    export PATH="/opt/zeek/bin:$PATH"

    echo "[OK] PATH Zeek sudah disiapkan."
}

# ==================================================
# Configure Zeek Network Interface
# ==================================================
configure_zeek() {
    echo "[INFO] Mengkonfigurasi Zeek network interface..."

    export PATH="/opt/zeek/bin:$PATH"

    # Fix permission untuk Zeek spool dan logs directory
    # Path: /opt/zeek/ (build-from-source location)
    echo "[INFO] Fix permission untuk Zeek directories..."
    sudo chown -R root:root /opt/zeek/spool 2>/dev/null || true
    sudo chmod -R 755 /opt/zeek/spool 2>/dev/null || true
    sudo chown -R root:root /opt/zeek/logs 2>/dev/null || true
    sudo chmod -R 755 /opt/zeek/logs 2>/dev/null || true

    ZEEK_NODE_CONFIG="/opt/zeek/etc/node.cfg"

    if [ ! -f "$ZEEK_NODE_CONFIG" ]; then
        echo "[WARNING] node.cfg tidak ditemukan"
        return
    fi

    # Find active network interface (exclude lo, docker, etc)
    INTERFACE=$(ip route | grep '^default' | awk '{print $5}' | head -1)

    if [ -z "$INTERFACE" ]; then
        # Fallback: gunakan interface pertama yang up (bukan loopback)
        INTERFACE=$(ip link show | grep "^[0-9]" | grep "UP" | awk '{print $2}' | sed 's/:$//' | grep -v "^lo$" | head -1)
    fi

    if [ -z "$INTERFACE" ]; then
        echo "[WARNING] Tidak bisa menemukan network interface aktif"
        echo "[INFO] Edit manual: $ZEEK_NODE_CONFIG"
        echo "[INFO] Set interface= ke interface yang ingin di-monitor"
        return
    fi

    echo "[INFO] Network interface terdeteksi: $INTERFACE"

    # Update node.cfg dengan interface
    if grep -q "^interface=" "$ZEEK_NODE_CONFIG"; then
        sed -i "s/^interface=.*/interface=$INTERFACE/" "$ZEEK_NODE_CONFIG"
    else
        sed -i "/^\[manager\]/a interface=$INTERFACE" "$ZEEK_NODE_CONFIG"
    fi

    echo "[OK] Zeek dikonfigurasi untuk interface: $INTERFACE"
    echo "[INFO] Deploy Zeek..."

    sudo zeekctl deploy

    echo "[OK] Zeek berhasil di-deploy"
}

# ==================================================
# Install Zeek FlowMeter
# ==================================================
install_zeek_flowmeter() {
    echo "[INFO] Mengecek Zeek FlowMeter..."

    export PATH="/opt/zeek/bin:$PATH"

    if ! command_exists zeek; then
        echo "[ERROR] zeek tidak ditemukan."
        exit 1
    fi

    if ! command_exists zeekctl; then
        echo "[ERROR] zeekctl tidak ditemukan."
        exit 1
    fi

    if ! command_exists zkg; then
        echo "[ERROR] zkg tidak ditemukan."
        echo "[INFO] Pastikan paket Zeek yang terinstall menyertakan zkg."
        exit 1
    fi

    pip3 install --upgrade gitpython semantic-version

    FLOWMETER_SRC="/opt/zeek-flowmeter"

    if [ ! -d "$FLOWMETER_SRC" ]; then
        echo "[INFO] Clone repository Zeek FlowMeter..."
        git clone https://github.com/zeek-flowmeter/zeek-flowmeter.git "$FLOWMETER_SRC"
    else
        echo "[INFO] Repository FlowMeter sudah ada. Melakukan update..."
        cd "$FLOWMETER_SRC"
        git pull || true
    fi

    cd "$FLOWMETER_SRC"

    echo "[INFO] Install FlowMeter menggunakan zkg..."
    zkg install --force . || {
        echo "[WARNING] Instalasi via zkg gagal. Mencoba metode manual..."

        ZEEK_SCRIPT_DIR="$(zeekctl config | grep zeekscriptdir | awk '{print $3}')"

        if [ -z "$ZEEK_SCRIPT_DIR" ]; then
            echo "[ERROR] Tidak bisa membaca zeekscriptdir dari zeekctl config."
            exit 1
        fi

        mkdir -p "$ZEEK_SCRIPT_DIR/site/flowmeter"
        cp -a "$FLOWMETER_SRC/scripts/." "$ZEEK_SCRIPT_DIR/site/flowmeter/"

        echo "[OK] FlowMeter berhasil dipasang secara manual ke $ZEEK_SCRIPT_DIR/site/flowmeter"
    }

    ZEEK_LOCAL_FILE="/opt/zeek/share/zeek/site/local.zeek"

    if [ ! -f "$ZEEK_LOCAL_FILE" ]; then
        echo "[INFO] Membuat file local.zeek..."
        mkdir -p "$(dirname "$ZEEK_LOCAL_FILE")"
        touch "$ZEEK_LOCAL_FILE"
    fi

    # Hapus konfigurasi Capstone lama jika ada (untuk idempotency)
    sed -i '/# Capstone FlowMeter START/,/# Capstone FlowMeter END/d' "$ZEEK_LOCAL_FILE"

    # Append konfigurasi Capstone yang baru dengan marker
    cat >> "$ZEEK_LOCAL_FILE" <<'EOFZEEK'

# Capstone FlowMeter START
# Load Zeek FlowMeter for capstone ML feature extraction
@load flowmeter
# Capstone FlowMeter END
EOFZEEK

    echo "[OK] @load flowmeter ditambahkan ke $ZEEK_LOCAL_FILE"
}

# ==================================================
# Setup File Monitor (select inotify or polling version)
# ==================================================
setup_file_monitor() {
    echo "[INFO] Setup file monitor..."

    MALWARE_DIR="$BASE_DIR/malware-file-monitor"
    WATCH_UPLOADS="$MALWARE_DIR/watch_uploads.sh"
    WATCH_UPLOADS_INOTIFY="$MALWARE_DIR/watch_uploads_inotify.sh"
    WATCH_UPLOADS_POLLING="$MALWARE_DIR/watch_uploads_polling.sh"

    # Check if source files exist
    if [ ! -f "$WATCH_UPLOADS_INOTIFY" ] && [ ! -f "$WATCH_UPLOADS_POLLING" ]; then
        echo "[WARNING] watch_uploads source files tidak ditemukan"
        echo "[INFO] File monitor tidak disetup otomatis."
        return
    fi

    # Check if inotify-tools is available
    if command_exists inotifywait; then
        echo "[INFO] inotifywait tersedia - menggunakan real-time mode (inotify)"
        if [ -f "$WATCH_UPLOADS_INOTIFY" ]; then
            cp "$WATCH_UPLOADS_INOTIFY" "$WATCH_UPLOADS"
            echo "[OK] Menggunakan: watch_uploads_inotify.sh"
        else
            echo "[WARNING] watch_uploads_inotify.sh tidak ditemukan"
            return
        fi
    else
        echo "[INFO] inotifywait tidak tersedia - menggunakan polling mode"
        if [ -f "$WATCH_UPLOADS_POLLING" ]; then
            cp "$WATCH_UPLOADS_POLLING" "$WATCH_UPLOADS"
            echo "[OK] Menggunakan: watch_uploads_polling.sh"
        else
            echo "[WARNING] watch_uploads_polling.sh tidak ditemukan"
            return
        fi
    fi

    # PENTING: baris "cp" di atas cuma copy file apa adanya. Source file
    # (watch_uploads_inotify.sh / watch_uploads_polling.sh, keduanya di-track
    # di git) punya baris SCANNER="..." yang di-hardcode ke path development
    # lama (misal /opt/webids-capstone/... atau /home/agent5/Capstone/...),
    # bukan path instalasi yang sebenarnya. Kalau tidak diperbaiki, scanner
    # tidak akan ketemu file_content_scanner.py di server manapun selain
    # mesin development aslinya.
    #
    # Fix: timpa baris SCANNER= supaya selalu mengarah ke
    # $BASE_DIR/malware-file-monitor/file_content_scanner.py sesuai lokasi
    # instalasi saat ini. Ini dilakukan di DUA tempat:
    #   1. Source template-nya sendiri (watch_uploads_inotify.sh /
    #      watch_uploads_polling.sh) - supaya kalau file monitor mode
    #      berganti nanti (inotify <-> polling) atau script di-copy manual,
    #      path-nya tetap benar.
    #   2. File aktif yang dipakai (watch_uploads.sh) - hasil cp di atas.
    SCANNER_PATH="$MALWARE_DIR/file_content_scanner.py"
    for f in "$WATCH_UPLOADS_INOTIFY" "$WATCH_UPLOADS_POLLING" "$WATCH_UPLOADS"; do
        if [ -f "$f" ] && grep -q '^SCANNER=' "$f"; then
            sed -i "s|^SCANNER=.*|SCANNER=\"$SCANNER_PATH\"|" "$f"
            echo "[OK] SCANNER path di $(basename "$f") disesuaikan ke: $SCANNER_PATH"
        fi
    done

    if [ ! -f "$SCANNER_PATH" ]; then
        echo "[WARNING] $SCANNER_PATH tidak ditemukan - file monitor akan gagal saat dijalankan."
    fi

    # WATCH_DIR (direktori yang dipantau, misal /var/www/) tetap dari source
    # file apa adanya, karena itu memang harus disesuaikan manual per server
    # (tidak ada cara otomatis mendeteksi direktori upload aplikasi target).
    # Tampilkan nilainya di sini supaya user sadar dan bisa cek/ubah kalau perlu.
    if grep -q '^WATCH_DIR=' "$WATCH_UPLOADS"; then
        CURRENT_WATCH_DIR="$(grep '^WATCH_DIR=' "$WATCH_UPLOADS" | head -1 | cut -d'"' -f2)"
        echo "[INFO] WATCH_DIR saat ini: $CURRENT_WATCH_DIR"
        echo "[INFO] Kalau direktori upload aplikasi kamu beda, edit manual:"
        echo "       $WATCH_UPLOADS"
    fi

    chmod +x "$WATCH_UPLOADS"
    echo "[OK] File monitor berhasil disetup."
}

# ==================================================
# Setup Command Monitoring
# ==================================================
setup_command_monitoring() {
    echo "[INFO] Setup command monitoring..."

    if [ ! -f "$BASE_DIR/command-monitoring.sh" ]; then
        echo "[WARNING] command-monitoring.sh tidak ditemukan di $BASE_DIR"
        echo "[INFO] Command monitoring tidak disetup otomatis."
        return
    fi

    chmod +x "$BASE_DIR/command-monitoring.sh"
    bash "$BASE_DIR/command-monitoring.sh"

    echo "[OK] Command monitoring berhasil disetup."
}

# ==================================================
# Setup Project Directories
# ==================================================
setup_project_directories() {
    echo "[INFO] Membuat direktori project..."

    mkdir -p "$BASE_DIR/artifacts"
    mkdir -p "$BASE_DIR/state"

    chmod 755 "$BASE_DIR/artifacts"
    chmod 755 "$BASE_DIR/state"

    echo "[OK] Direktori project sudah siap."
}

# ==================================================
# Validate Project Files
# ==================================================
validate_project_files() {
    echo "[INFO] Validasi file project..."

    if [ ! -f "$BASE_DIR/app/inference_worker.py" ]; then
        echo "[ERROR] app/inference_worker.py tidak ditemukan"
        exit 1
    fi

    if [ ! -f "$BASE_DIR/malware-file-monitor/file_content_scanner.py" ]; then
        echo "[ERROR] malware-file-monitor/file_content_scanner.py tidak ditemukan"
        exit 1
    fi

    # PENTING: watch_uploads.sh BELUM ADA di titik ini - file itu baru dibuat
    # belakangan oleh setup_file_monitor() (hasil copy dari salah satu
    # template di bawah). Validasi yang benar di sini adalah source
    # template-nya, bukan hasil generate-nya.
    if [ ! -f "$BASE_DIR/malware-file-monitor/watch_uploads_inotify.sh" ] && \
       [ ! -f "$BASE_DIR/malware-file-monitor/watch_uploads_polling.sh" ]; then
        echo "[ERROR] watch_uploads_inotify.sh / watch_uploads_polling.sh tidak ditemukan di malware-file-monitor/"
        exit 1
    fi

    echo "[OK] Semua file project ditemukan."
}

# ==================================================
# Main Installer
# ==================================================
case "$OS_ID" in
    ubuntu|debian)
        install_basic_dependencies_apt
        setup_python_environment
        install_filebeat_apt
        install_zeek_apt
        ;;
    centos|rhel)
        enable_epel
        install_basic_dependencies_yum
        setup_python_environment
        install_filebeat_yum_or_dnf
        install_zeek_yum_or_dnf
        ;;
    almalinux)
        enable_epel
        install_basic_dependencies_yum
        setup_python_environment
        install_filebeat_yum_or_dnf
        install_zeek_from_epel
        ;;
    fedora)
        enable_epel
        install_basic_dependencies_dnf
        setup_python_environment
        install_filebeat_yum_or_dnf
        install_zeek_yum_or_dnf
        ;;
    *)
        echo "[ERROR] OS belum didukung otomatis oleh script ini: $PRETTY_NAME"
        exit 1
        ;;
esac

if [ "$SKIP_ML" = true ]; then
    echo "[INFO] SKIP: setup PATH Zeek dan instalasi FlowMeter di-skip untuk $PRETTY_NAME."
elif [ "$OS_ID" = "almalinux" ]; then
    echo "[INFO] AlmaLinux EPEL Zeek sudah otomatis di-configure. Skip setup_zeek_path & configure_zeek."
else
    setup_zeek_path
    configure_zeek
    install_zeek_flowmeter
fi
setup_project_directories
validate_project_files
generate_config_json
generate_filebeat_yml
setup_command_monitoring

# ==================================================
# Setup System Log & PID Directories
# ==================================================
setup_log_directories() {
    echo "[INFO] Membuat direktori system logs dan PID..."

    mkdir -p /var/log/Capstone
    mkdir -p /var/run/Capstone

    chmod 755 /var/log/Capstone
    chmod 755 /var/run/Capstone

    echo "[OK] Direktori system sudah siap."
}

# ==================================================
# Check & Extract ML Artifacts
# ==================================================
artifacts_ready() {
    [ -f "$BASE_DIR/artifacts/model.joblib" ] &&
    [ -f "$BASE_DIR/artifacts/scaler.joblib" ] &&
    [ -f "$BASE_DIR/artifacts/label_encoder.joblib" ] &&
    [ -f "$BASE_DIR/artifacts/feature_names.joblib" ] &&
    [ -f "$BASE_DIR/artifacts/preprocess_config.joblib" ]
}

extract_artifacts() {
    if [ "$SKIP_ML" = true ]; then
        echo "[INFO] SKIP: ekstraksi ML artifacts di-skip untuk CentOS."
        return
    fi
    if [ "$INSTALL_ML" = false ]; then
        echo "[INFO] SKIP: ekstraksi ML artifacts di-skip (ML Inference Worker tidak dipilih)."
        return
    fi

    echo "[INFO] Mengecek ML artifacts..."

    if artifacts_ready; then
        echo "[OK] Artifacts sudah tersedia di $BASE_DIR/artifacts"
        return
    fi

    ARTIFACTS_ZIP="$BASE_DIR/artifacts.zip"

    if [ ! -f "$ARTIFACTS_ZIP" ]; then
        echo "[WARNING] artifacts.zip tidak ditemukan di $ARTIFACTS_ZIP"
        echo "[INFO] File model tidak lengkap. Inference worker mungkin tidak jalan."
        echo "[INFO] Untuk menjalankan inference, upload artifacts.zip ke project directory."
        return
    fi

    echo "[INFO] Extract artifacts dari artifacts.zip..."

    ARTIFACTS_TMP="$BASE_DIR/.artifacts_extract_tmp"
    rm -rf "$ARTIFACTS_TMP"
    mkdir -p "$ARTIFACTS_TMP" "$BASE_DIR/artifacts"

    unzip -q "$ARTIFACTS_ZIP" -d "$ARTIFACTS_TMP"

    if [ -d "$ARTIFACTS_TMP/artifacts" ]; then
        cp -a "$ARTIFACTS_TMP/artifacts/." "$BASE_DIR/artifacts/"
    else
        cp -a "$ARTIFACTS_TMP/." "$BASE_DIR/artifacts/"
    fi

    rm -rf "$ARTIFACTS_TMP"

    if artifacts_ready; then
        echo "[OK] artifacts.zip berhasil diextract"
    else
        echo "[WARNING] Extract selesai, tapi file model belum lengkap."
        ls -lah "$BASE_DIR/artifacts"
    fi
}

# ==================================================
# Start Services
# ==================================================
start_services() {
    echo ""
    echo "======================================"
    echo " Memulai Capstone Services"
    echo "======================================"

    # Start Filebeat
    echo "[INFO] Menjalankan Filebeat..."
    if ! systemctl start filebeat; then
        echo "[ERROR] Gagal start Filebeat!"
        echo "[INFO] Checking Filebeat status..."
        systemctl status filebeat || true
        return 1
    fi

    sleep 2

    if systemctl is-active --quiet filebeat; then
        echo "[OK] Filebeat berhasil dijalankan"
        systemctl --no-pager status filebeat
    else
        echo "[ERROR] Filebeat tidak running!"
        echo "[INFO] Checking logs..."
        journalctl -u filebeat -n 20 || true
        return 1
    fi

    # Start Zeek
    if [ "$SKIP_ML" = true ]; then
        echo "[INFO] SKIP: Zeek tidak dijalankan (CentOS)."
    else
        echo "[INFO] Menjalankan Zeek..."
        if command_exists zeekctl; then
            zeekctl start || zeekctl deploy
        elif [ -x "/opt/zeek/bin/zeekctl" ]; then
            /opt/zeek/bin/zeekctl start || /opt/zeek/bin/zeekctl deploy
        else
            echo "[ERROR] zeekctl tidak ditemukan."
            return 1
        fi
        echo "[OK] Zeek berhasil dijalankan."
    fi

    # Start ML Inference Worker
    if [ "$SKIP_ML" = true ]; then
        echo "[INFO] SKIP: ML inference worker tidak dijalankan (CentOS)."
    elif [ "$INSTALL_ML" = false ]; then
        echo "[INFO] SKIP: ML inference worker tidak dijalankan (tidak dipilih saat instalasi)."
    elif artifacts_ready; then
        echo "[INFO] Menjalankan ML inference worker..."
        CONFIG_FILE="$BASE_DIR/config/config.json"
        INFERENCE_LOG="/var/log/Capstone/inference_worker.log"
        INFERENCE_PID="/var/run/Capstone/inference_worker.pid"
        APP_DIR="$BASE_DIR/app"

        if [ -f "$INFERENCE_PID" ] && kill -0 "$(cat "$INFERENCE_PID")" 2>/dev/null; then
            echo "[INFO] inference_worker.py sudah berjalan dengan PID $(cat "$INFERENCE_PID")"
        else
            cd "$APP_DIR"
            nohup python3 inference_worker.py "$CONFIG_FILE" > "$INFERENCE_LOG" 2>&1 &
            echo $! > "$INFERENCE_PID"
            echo "[OK] inference_worker.py berjalan dengan PID $(cat "$INFERENCE_PID")"
            echo "[INFO] Log: $INFERENCE_LOG"
        fi
    else
        echo "[WARNING] ML artifacts tidak tersedia. Inference worker tidak dijalankan."
    fi

    # Start Malware Monitor (always run, adaptive mode: inotify or polling)
    echo "[INFO] Menjalankan File Malware Monitor..."
    MALWARE_DIR="$BASE_DIR/malware-file-monitor"
    WATCH_UPLOADS="$MALWARE_DIR/watch_uploads.sh"
    MALWARE_LOG="/var/log/Capstone/malware_monitor.log"
    MALWARE_PID="/var/run/Capstone/malware_monitor.pid"

    if [ ! -f "$WATCH_UPLOADS" ] || [ ! -x "$WATCH_UPLOADS" ]; then
        echo "[WARNING] watch_uploads.sh tidak ditemukan atau tidak executable"
        echo "[INFO] File monitor tidak dijalankan."
    else
        # PENTING: selalu restart (kill proses lama, start baru) alih-alih
        # skip kalau sudah jalan. Alasannya: setup_file_monitor() di atas
        # tadi bisa saja memperbaiki isi watch_uploads.sh (misal path
        # SCANNER=), tapi proses lama yang sudah jalan tetap memakai
        # variabel versi lama yang sudah ter-load ke memorinya - perbaikan
        # di disk baru kepakai setelah proses-nya benar-benar direstart.
        if [ -f "$MALWARE_PID" ] && kill -0 "$(cat "$MALWARE_PID")" 2>/dev/null; then
            OLD_PID="$(cat "$MALWARE_PID")"
            echo "[INFO] watch_uploads.sh sedang jalan (PID $OLD_PID) - restart supaya pakai script/path terbaru..."
            kill "$OLD_PID" 2>/dev/null || true
            # inotifywait/loop child process kadang tidak ikut mati langsung
            # dari kill parent-nya - pastikan benar-benar berhenti dulu.
            pkill -P "$OLD_PID" 2>/dev/null || true
            sleep 1
        fi

        cd "$MALWARE_DIR"
        nohup "$WATCH_UPLOADS" > "$MALWARE_LOG" 2>&1 &
        echo $! > "$MALWARE_PID"
        echo "[OK] watch_uploads.sh berjalan dengan PID $(cat "$MALWARE_PID")"
        echo "[INFO] Log: $MALWARE_LOG"
    fi

    echo "======================================"
    echo " Semua services sudah dijalankan!"
    echo "======================================"
}

# ==================================================
# Call all functions
# ==================================================
setup_log_directories
setup_file_monitor
extract_artifacts
start_services

echo ""
echo "======================================"
echo " ✅ Instalasi dan startup selesai!"
echo "======================================"
echo ""

if [ "$SKIP_ML" = true ]; then
    echo "[INFO] ⚠️  $PRETTY_NAME Mode - fitur yang di-skip:"
    echo "  - ML Inference Worker (Zeek, FlowMeter)"
    echo ""
    echo "[INFO] Fitur yang aktif:"
    echo "  - Filebeat untuk log collection"
    echo "  - File Malware Monitor (polling mode, no inotify)"
    echo "  - Command logging"
    echo ""
else
    if [ "$OS_ID" = "almalinux" ]; then
        echo "[INFO] $PRETTY_NAME - status fitur:"
        echo "  - Zeek untuk network IDS (versi 4.2.0)"
        echo "  - FlowMeter untuk network metrics (via zkg)"
        if [ "$INSTALL_ML" = true ]; then
            echo "  - ML Inference Worker"
        else
            echo "  - ML Inference Worker: DI-SKIP (tidak dipilih saat instalasi)"
        fi
        echo "  - Filebeat untuk log collection"
        echo "  - File Malware Monitor (real-time inotify mode)"
        echo "  - Command logging"
        echo ""
    else
        echo "[INFO] $PRETTY_NAME - status fitur:"
        echo "  - Zeek untuk network IDS"
        echo "  - FlowMeter untuk network metrics"
        if [ "$INSTALL_ML" = true ]; then
            echo "  - ML Inference Worker"
        else
            echo "  - ML Inference Worker: DI-SKIP (tidak dipilih saat instalasi)"
        fi
        echo "  - Filebeat untuk log collection"
        echo "  - File Malware Monitor (real-time inotify mode)"
        echo "  - Command logging"
        echo ""
    fi
    
    # Info tentang Zeek installation method
    if [ "$OS_ID" = "almalinux" ]; then
        echo "[INFO] Zeek installation: dari EPEL repository (binary packages - ready to use)"
        echo "[INFO] Zeek location: /usr/bin/zeek, /usr/bin/zeekctl (sudah di PATH)"
        echo "[INFO] Config location: /etc/zeek/node.cfg (auto-configured)"
        echo "[INFO] Network interface: otomatis terdeteksi & dikonfigurasi"
        echo "[INFO] Logs location: /var/log/zeek/"
        echo "[INFO] FlowMeter: installed via zkg (zeek package manager)"
    elif [ "$OS_ID" = "ubuntu" ] || [ "$OS_ID" = "debian" ]; then
        echo "[INFO] Zeek installation: build dari source (custom compilation)"
        echo "[INFO] Zeek location: /opt/zeek/bin/"
        echo "[INFO] Network interface: otomatis terdeteksi & dikonfigurasi"
    else
        echo "[INFO] Zeek installation: build dari source (custom compilation)"
        echo "[INFO] Zeek location: /opt/zeek/bin/"
        echo "[INFO] Network interface: otomatis terdeteksi & dikonfigurasi"
    fi
    echo ""
fi

echo "[INFO] File Monitor Mode:"
if command_exists inotifywait; then
    echo "  ✓ watch_uploads_inotify.sh (real-time via inotify)"
else
    echo "  ✓ watch_uploads_polling.sh (polling mode, every 5s)"
fi
echo ""

echo "[INFO] Cek status services:"
echo "  - Filebeat: systemctl status filebeat"
if [ "$SKIP_ML" = false ]; then
    if [ "$OS_ID" = "almalinux" ]; then
        echo "  - Zeek (EPEL): zeekctl (sudah siap - tinggal deploy)"
    else
        echo "  - Zeek: zeekctl status"
    fi
fi
echo ""
echo "[INFO] Lihat logs:"
echo "  - Filebeat: tail -f /var/log/filebeat/filebeat.log"
if [ "$SKIP_ML" = false ] && [ "$INSTALL_ML" = true ]; then
    echo "  - Inference: tail -f /var/log/Capstone/inference_worker.log"
fi
echo "  - Malware Monitor: tail -f /var/log/Capstone/malware_monitor.log"
echo "  - Commands: tail -f /var/log/commands.log"
echo ""
echo "[INFO] Cek konfigurasi:"
echo "  - config.json: cat $BASE_DIR/config/config.json"
echo "  - filebeat.yml: cat /etc/filebeat/filebeat.yml"
echo "  - file monitor: cat $BASE_DIR/malware-file-monitor/watch_uploads.sh | head -5"
echo ""

if [ "$SKIP_ML" = false ] && [ "$OS_ID" = "almalinux" ]; then
    echo "[INFO] Zeek Deployment Instructions (AlmaLinux EPEL):"
    echo "  1. Deploy Zeek: sudo zeekctl deploy"
    echo "  2. Start Zeek: sudo zeekctl start"
    echo "  3. Check status: sudo zeekctl status"
    echo "  4. View logs: sudo tail -f /var/log/zeek/current/zeek.log"
    echo "  5. Monitor traffic: sudo tail -f /var/log/zeek/current/conn.log"
    echo ""
fi

echo "======================================"