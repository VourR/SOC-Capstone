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
# Flag untuk skip instalasi ML (inference worker, Zeek, FlowMeter)
# ==================================================
SKIP_ML=false
if [ "$OS_ID" = "centos" ]; then
    SKIP_ML=true
    echo "[INFO] CentOS terdeteksi - instalasi ML (inference worker, Zeek, FlowMeter) akan di-skip."
    echo "[INFO] File monitoring juga akan di-skip (inotify-tools tidak tersedia di CentOS 7)."
    echo "[INFO] Fitur lain (Filebeat, command logging) tetap akan diinstall."
fi

# ==================================================
# Fungsi Umum
# ==================================================
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

install_basic_dependencies_apt() {
    echo "[INFO] Install dependency dasar..."
    apt-get update
    apt-get install -y curl wget gnupg gpg apt-transport-https ca-certificates git \
        python3 python3-pip python3-venv python3-dev \
        build-essential swig libssl-dev \
        inotify-tools libimage-exiftool-perl \
        lsb-release unzip
}

install_basic_dependencies_yum() {
    echo "[INFO] Install dependency dasar..."
    yum install -y curl wget gnupg ca-certificates git \
        python3 python3-pip python3-devel \
        gcc gcc-c++ make openssl-devel \
        yum-utils unzip

    # Optional packages - jika tidak ada, skip
    echo "[INFO] Install optional packages..."
    yum install -y inotify-tools || true
    yum install -y perl-Image-ExifTool || true
    yum install -y swig || true
}

install_basic_dependencies_dnf() {
    echo "[INFO] Install dependency dasar..."
    dnf install -y curl wget gnupg ca-certificates git \
        python3 python3-pip python3-devel \
        gcc gcc-c++ make openssl-devel \
        dnf-plugins-core unzip

    # Optional packages - jika tidak ada, skip
    echo "[INFO] Install optional packages..."
    dnf install -y inotify-tools || true
    dnf install -y perl-Image-ExifTool || true
    dnf install -y swig || true
}

# ==================================================
# Setup Python Environment
# ==================================================
setup_python_environment() {
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

    if [ "$SKIP_ML" = true ]; then
        echo "[INFO] SKIP: dependency ML inference worker (pandas, scikit-learn, joblib) di-skip untuk CentOS."
    else
        echo "[INFO] Install Python dependencies untuk ML inference worker..."
        pip3 install pandas==2.3.0 scikit-learn==1.7.0 joblib==1.5.1 psycopg2-binary python-dotenv
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

install_zeek_yum_or_dnf() {
    if [ -x /opt/zeek/bin/zeek ]; then
        echo "[OK] Zeek sudah terinstall: $(/opt/zeek/bin/zeek --version)"
        return
    fi

    echo "[INFO] Menambahkan repository Zeek untuk CentOS/RHEL..."

    # Tentukan repository path berdasarkan versi
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
name=Zeek repository for CentOS/RHEL
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

    if [ ! -f "$BASE_DIR/malware-file-monitor/watch_uploads.sh" ]; then
        echo "[ERROR] malware-file-monitor/watch_uploads.sh tidak ditemukan"
        exit 1
    fi

    chmod +x "$BASE_DIR/malware-file-monitor/watch_uploads.sh"

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
        install_basic_dependencies_yum
        setup_python_environment
        install_filebeat_yum_or_dnf
        if [ "$SKIP_ML" = true ]; then
            echo "[INFO] SKIP: instalasi Zeek di-skip untuk CentOS."
        else
            install_zeek_yum_or_dnf
        fi
        ;;
    fedora)
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
    echo "[INFO] SKIP: setup PATH Zeek dan instalasi FlowMeter di-skip untuk CentOS."
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
    elif [ -f "$MALWARE_PID" ] && kill -0 "$(cat "$MALWARE_PID")" 2>/dev/null; then
        echo "[INFO] watch_uploads.sh sudah berjalan dengan PID $(cat "$MALWARE_PID")"
    else
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
    echo "[INFO] ⚠️  CentOS Mode - fitur yang di-skip:"
    echo "  - ML Inference Worker (Zeek, FlowMeter)"
    echo ""
    echo "[INFO] Fitur yang aktif:"
    echo "  - Filebeat untuk log collection"
    echo "  - File Malware Monitor (polling mode, no inotify)"
    echo "  - Command logging"
    echo ""
else
    echo "[INFO] Ubuntu/Debian Mode - semua fitur aktif"
    echo "  - ML Inference Worker (Zeek, FlowMeter)"
    echo "  - File Malware Monitor (real-time inotify mode)"
    echo "  - Filebeat untuk log collection"
    echo "  - Command logging"
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
    echo "  - Zeek: zeekctl status"
fi
echo ""
echo "[INFO] Lihat logs:"
echo "  - Filebeat: tail -f /var/log/filebeat/filebeat.log"
if [ "$SKIP_ML" = false ]; then
    echo "  - Inference: tail -f /var/log/Capstone/inference_worker.log"
fi
echo "  - Malware Monitor: tail -f /var/log/Capstone/malware_monitor.log"
echo "  - Commands: tail -f /var/log/commands.log"
echo ""
echo "[INFO] Cek konfigurasi:"
echo "  - config.json: cat $BASE_DIR/config/config.json"
echo "  - filebeat.yml: cat /etc/filebeat/filebeat.yml"
echo "  - file monitor: cat $BASE_DIR/malware-file-monitor/watch_uploads.sh | head -5"
echo "======================================"