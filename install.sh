#!/bin/bash

set -e

# ==================================================
# Web-IDS Capstone - Complete Installation Script
# ==================================================
# Auto-detects installation directory and configures
# all components: Filebeat, Zeek, FlowMeter, ML Worker,
# Malware Monitor, and Command Logging
#
# Python dependencies are installed inside:
#   $BASE_DIR/.venv
#
# This avoids PEP 668 / externally-managed-environment
# errors on modern Ubuntu/Debian systems.
# ==================================================


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
# Flag untuk skip instalasi ML
# ==================================================
SKIP_ML=false

if [ "$OS_ID" = "centos" ]; then
    SKIP_ML=true

    echo "[INFO] $PRETTY_NAME terdeteksi."
    echo "[INFO] Instalasi ML (inference worker, Zeek, FlowMeter) akan di-skip."
    echo "[INFO] File monitoring juga akan menggunakan mode fallback."
    echo "[INFO] Fitur lain (Filebeat, command logging) tetap akan diinstall."
fi


# ==================================================
# Fungsi Umum
# ==================================================

command_exists() {
    command -v "$1" >/dev/null 2>&1
}


zeek_is_installed() {
    if command_exists zeek; then
        return 0
    elif [ -x /opt/zeek/bin/zeek ]; then
        return 0
    else
        return 1
    fi
}


# ==================================================
# Install Basic Dependencies - APT
# ==================================================

install_basic_dependencies_apt() {
    echo "[INFO] Install dependency dasar..."

    apt-get update

    apt-get install -y \
        curl \
        wget \
        gnupg \
        gpg \
        apt-transport-https \
        ca-certificates \
        git \
        python3 \
        python3-pip \
        python3-venv \
        python3-dev \
        build-essential \
        swig \
        libssl-dev \
        inotify-tools \
        libimage-exiftool-perl \
        lsb-release \
        unzip

    # Only install Zeek build dependencies if Zeek is not installed
    if zeek_is_installed; then
        echo "[OK] Zeek sudah terinstall - skip build dependencies"
    else
        echo "[INFO] Install build dependencies untuk Zeek..."

        apt-get install -y \
            cmake \
            flex \
            bison \
            libpcap-dev \
            zlib1g-dev
    fi
}


# ==================================================
# Install Basic Dependencies - YUM
# ==================================================

install_basic_dependencies_yum() {
    echo "[INFO] Install dependency dasar..."

    yum install -y \
        curl \
        wget \
        gnupg \
        ca-certificates \
        git \
        python3 \
        python3-pip \
        python3-devel \
        gcc \
        gcc-c++ \
        make \
        openssl-devel \
        yum-utils \
        unzip \
        inotify-tools

    echo "[INFO] Install optional packages..."

    yum install -y perl-Image-ExifTool || true
    yum install -y swig || true
}


# ==================================================
# Install Basic Dependencies - DNF
# ==================================================

install_basic_dependencies_dnf() {
    echo "[INFO] Install dependency dasar..."

    dnf install -y \
        curl \
        wget \
        gnupg \
        ca-certificates \
        git \
        python3 \
        python3-pip \
        python3-devel \
        gcc \
        gcc-c++ \
        make \
        openssl-devel \
        dnf-plugins-core \
        unzip \
        inotify-tools

    if zeek_is_installed; then
        echo "[OK] Zeek sudah terinstall - skip build dependencies"
    else
        echo "[INFO] Install build dependencies untuk Zeek..."

        dnf install -y \
            cmake \
            flex \
            bison \
            libpcap-devel \
            zlib-devel
    fi

    echo "[INFO] Install optional packages..."

    dnf install -y perl-Image-ExifTool || true
    dnf install -y swig || true
}


# ==================================================
# Setup Python Virtual Environment
# ==================================================

setup_python_environment() {

    echo ""
    echo "======================================"
    echo " Setup Python Virtual Environment"
    echo "======================================"

    if ! command_exists python3; then
        echo "[ERROR] python3 tidak ditemukan."
        exit 1
    fi

    PYTHON_SYSTEM_VERSION=$(python3 --version | awk '{print $2}')

    echo "[OK] System Python: $PYTHON_SYSTEM_VERSION"

    # --------------------------------------------------
    # Check venv module
    # --------------------------------------------------

    if ! python3 -c "import venv" >/dev/null 2>&1; then

        echo "[ERROR] Python venv module tidak tersedia."

        case "$OS_ID" in

            ubuntu|debian)
                echo "[INFO] Install dengan:"
                echo "       apt-get install -y python3-venv python3-full"
                ;;

            centos|rhel|almalinux|fedora)
                echo "[INFO] Pastikan package Python virtual environment tersedia."
                ;;

        esac

        exit 1
    fi


    # --------------------------------------------------
    # Create VENV
    # --------------------------------------------------

    VENV_DIR="$BASE_DIR/.venv"

    if [ ! -x "$VENV_DIR/bin/python" ]; then

        echo "[INFO] Membuat Python virtual environment..."
        echo "[INFO] Location: $VENV_DIR"

        python3 -m venv "$VENV_DIR"

    else

        echo "[OK] Python virtual environment sudah tersedia:"
        echo "     $VENV_DIR"

    fi


    # --------------------------------------------------
    # Define Python/Pip
    # --------------------------------------------------

    PYTHON="$VENV_DIR/bin/python"
    PIP="$VENV_DIR/bin/pip"

    if [ ! -x "$PYTHON" ]; then
        echo "[ERROR] Python virtual environment tidak valid."
        exit 1
    fi

    if [ ! -x "$PIP" ]; then
        echo "[ERROR] pip pada virtual environment tidak ditemukan."
        exit 1
    fi


    echo "[INFO] VENV Python:"
    "$PYTHON" --version

    echo "[INFO] VENV pip:"
    "$PIP" --version


    # --------------------------------------------------
    # Upgrade pip
    # --------------------------------------------------

    echo "[INFO] Upgrade pip, setuptools, dan wheel..."

    "$PIP" install --upgrade \
        pip \
        setuptools \
        wheel


    # --------------------------------------------------
    # ML Dependencies
    # --------------------------------------------------

    if [ "$SKIP_ML" = true ]; then

        echo "[INFO] SKIP: dependency ML inference worker."
        echo "[INFO] OS: $PRETTY_NAME"

    else

        echo "[INFO] Install Python dependencies untuk ML inference worker..."

        PYTHON_VERSION=$(
            "$PYTHON" -c \
            'import sys; print(".".join(map(str, sys.version_info[:2])))'
        )

        echo "[INFO] Python version terdeteksi: $PYTHON_VERSION"


        if [ "$PYTHON_VERSION" = "3.9" ]; then

            echo "[INFO] Python 3.9 - install scikit-learn 1.6.x"

            "$PIP" install \
                pandas==2.3.0 \
                scikit-learn==1.6.1 \
                joblib==1.5.1 \
                psycopg2-binary \
                python-dotenv


        elif [ "$PYTHON_VERSION" = "3.10" ]; then

            echo "[INFO] Python 3.10 - install scikit-learn 1.7.x"

            "$PIP" install \
                pandas==2.3.0 \
                scikit-learn==1.7.0 \
                joblib==1.5.1 \
                psycopg2-binary \
                python-dotenv


        else

            echo "[INFO] Python $PYTHON_VERSION - install compatible latest versions"

            "$PIP" install \
                pandas \
                scikit-learn \
                joblib \
                psycopg2-binary \
                python-dotenv

        fi

    fi


    # --------------------------------------------------
    # Malware File Monitor Dependencies
    # --------------------------------------------------

    echo "[INFO] Install Python dependencies untuk malware file monitor..."

    "$PIP" install \
        PyExifTool==0.5.5 \
        pypdf==5.0.0


    # --------------------------------------------------
    # Zeek Python Dependencies
    # --------------------------------------------------

    if [ "$SKIP_ML" = false ]; then

        echo "[INFO] Install Python dependencies untuk Zeek..."

        "$PIP" install "websockets>=11.0"

        echo "[INFO] Install dependencies untuk FlowMeter/zkg..."

        "$PIP" install \
            --upgrade \
            gitpython \
            semantic-version

    fi


    echo ""
    echo "[OK] Python environment sudah siap."
    echo "[OK] Semua Python package berada di:"
    echo "     $VENV_DIR"
    echo ""

}


# ==================================================
# Generate config.json
# ==================================================

generate_config_json() {

    echo "[INFO] Generate config.json dengan paths yang benar..."

    ZEEK_LOG_BASE="/opt/zeek/logs/current"

    echo "[INFO] Using Zeek log base: $ZEEK_LOG_BASE"


    mkdir -p "$BASE_DIR/config"


    cat > "$BASE_DIR/config/config.json" <<EOF
{
  "artifacts_dir": "$BASE_DIR/artifacts",
  "conn_log_path": "$ZEEK_LOG_BASE/conn.log",
  "flowmeter_log_path": "$ZEEK_LOG_BASE/flowmeter.log",
  "http_log_path": "$ZEEK_LOG_BASE/http.log",
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
  "log_level": "INFO",
  "db_enabled": true,
  "ml_db_host": "10.70.128.26",
  "ml_db_port": 5432,
  "ml_db_name": "capstone_ict",
  "ml_db_user": "postgres",
  "skip_local_noise": true,
  "write_only_non_benign": true,
  "skip_external_external": false
}
EOF


    echo "[OK] config.json berhasil dibuat:"
    echo "     $BASE_DIR/config/config.json"
}


# ==================================================
# Generate / Update Filebeat
# ==================================================

generate_filebeat_yml() {

    echo "[INFO] Generate filebeat.yml dengan konfigurasi Capstone..."

    FILEBEAT_YML="/etc/filebeat/filebeat.yml"

    FILEBEAT_BACKUP="/etc/filebeat/filebeat.yml.backup-$(date +%Y%m%d-%H%M%S)"


    if [ -f "$FILEBEAT_YML" ]; then

        cp "$FILEBEAT_YML" "$FILEBEAT_BACKUP"

        echo "[INFO] Backup original filebeat.yml:"
        echo "       $FILEBEAT_BACKUP"

    fi


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

    echo "[OK] filebeat.yml berhasil dibuat:"
    echo "     $FILEBEAT_YML"


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


    echo "[INFO] Backup tersimpan di:"
    echo "       $FILEBEAT_BACKUP"
}


# ==================================================
# Install Filebeat - APT
# ==================================================

install_filebeat_apt() {

    if command_exists filebeat; then

        echo "[OK] Filebeat sudah terinstall:"
        filebeat version

        return

    fi


    echo "[INFO] Menambahkan repository Elastic untuk Filebeat..."


    curl -fsSL \
        https://artifacts.elastic.co/GPG-KEY-elasticsearch \
        | gpg --dearmor \
        -o /usr/share/keyrings/elastic-keyring.gpg


    echo "deb [signed-by=/usr/share/keyrings/elastic-keyring.gpg] https://artifacts.elastic.co/packages/9.x/apt stable main" \
        > /etc/apt/sources.list.d/elastic-9.x.list


    apt-get update

    apt-get install -y filebeat

    systemctl enable filebeat


    echo "[OK] Filebeat berhasil diinstall."
}


# ==================================================
# Install Filebeat - YUM / DNF
# ==================================================

install_filebeat_yum_or_dnf() {

    if command_exists filebeat; then

        echo "[OK] Filebeat sudah terinstall:"
        filebeat version

        return

    fi


    echo "[INFO] Menambahkan repository Elastic untuk Filebeat..."


    rpm --import \
        https://artifacts.elastic.co/GPG-KEY-elasticsearch


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
# Zeek Repository - APT
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


# ==================================================
# Install Zeek - APT
# ==================================================

install_zeek_apt() {

    if zeek_is_installed; then

        ZEEK_VERSION=$(zeek --version 2>/dev/null || echo "unknown")

        echo "[OK] Zeek sudah terinstall: $ZEEK_VERSION"

        return

    fi


    ZEEK_REPO_NAME="$(get_zeek_repo_name_apt)"


    if [ -z "$ZEEK_REPO_NAME" ]; then

        echo "[ERROR] OS ini belum ditangani otomatis untuk repository Zeek."

        echo "[INFO] OS terdeteksi: $PRETTY_NAME"

        echo "[INFO] Script ini mendukung:"
        echo "       Ubuntu 22.04"
        echo "       Ubuntu 24.04"
        echo "       Ubuntu 25.04"
        echo "       Debian 12"
        echo "       Debian 13"

        exit 1

    fi


    echo "[INFO] Menambahkan repository Zeek:"
    echo "       $ZEEK_REPO_NAME"


    echo "deb http://download.opensuse.org/repositories/security:/zeek/$ZEEK_REPO_NAME/ /" \
        > /etc/apt/sources.list.d/security:zeek.list


    curl -fsSL \
        "https://download.opensuse.org/repositories/security:zeek/$ZEEK_REPO_NAME/Release.key" \
        | gpg --dearmor \
        > /etc/apt/trusted.gpg.d/security_zeek.gpg


    apt-get update

    apt-get install -y zeek


    echo "[OK] Zeek berhasil diinstall."
}


# ==================================================
# Install Zeek dari EPEL - AlmaLinux
# ==================================================

install_zeek_from_epel() {

    if command -v zeek >/dev/null 2>&1; then

        echo "[OK] Zeek sudah terinstall:"
        zeek --version

        return

    fi


    echo "[INFO] Install Zeek dari EPEL repository..."


    if ! grep -q "^enabled=1" /etc/yum.repos.d/epel.repo 2>/dev/null; then

        echo "[INFO] Enabling EPEL repository..."

        if command -v dnf >/dev/null 2>&1; then

            dnf config-manager --set-enabled epel || true

        else

            yum-config-manager --enable epel || true

        fi

    fi


    echo "[INFO] Menginstall Zeek packages dari EPEL..."


    if command -v dnf >/dev/null 2>&1; then

        dnf install -y \
            zeek-core \
            zeekctl \
            zeek-zkg

    else

        yum install -y \
            zeek-core \
            zeekctl \
            zeek-zkg

    fi


    echo "[INFO] Fix permission untuk Zeek directories..."


    chown -R root:root /var/spool/zeek 2>/dev/null || true
    chmod -R 755 /var/spool/zeek 2>/dev/null || true

    chown -R root:root /var/log/zeek 2>/dev/null || true
    chmod -R 755 /var/log/zeek 2>/dev/null || true


    echo "[INFO] Mengkonfigurasi Zeek network interface..."

    configure_zeek_epel


    echo "[INFO] Install FlowMeter plugin via zkg..."

    install_flowmeter_epel


    echo "[OK] Zeek berhasil diinstall dari EPEL."
}


# ==================================================
# Install FlowMeter - EPEL
# ==================================================

install_flowmeter_epel() {

    echo "[INFO] Installing FlowMeter plugin..."


    if ! command -v zkg >/dev/null 2>&1; then

        echo "[WARNING] zkg tidak ditemukan."
        echo "[WARNING] FlowMeter skip."

        return

    fi


    echo "[INFO] Installing FlowMeter dari GitHub..."


    if zkg install https://github.com/zeek-flowmeter/zeek-flowmeter 2>&1 | tail -3; then

        echo "[OK] FlowMeter berhasil diinstall"

        load_flowmeter_in_local_zeek

    else

        echo "[WARNING] FlowMeter installation gagal"

    fi
}


# ==================================================
# Load FlowMeter di local.zeek
# ==================================================

load_flowmeter_in_local_zeek() {

    if [ "$OS_ID" = "almalinux" ]; then

        LOCAL_ZEEK="/usr/share/zeek/site/local.zeek"

    else

        LOCAL_ZEEK="/opt/zeek/etc/local.zeek"

    fi


    if [ ! -f "$LOCAL_ZEEK" ]; then

        echo "[WARNING] local.zeek tidak ditemukan:"
        echo "          $LOCAL_ZEEK"

        return

    fi


    if grep -q "@load flowmeter" "$LOCAL_ZEEK"; then

        echo "[INFO] FlowMeter sudah di-load di local.zeek"

        return

    fi


    echo "[INFO] Adding FlowMeter @load directive..."

    echo "[INFO] Path: $LOCAL_ZEEK"


    cp "$LOCAL_ZEEK" \
        "$LOCAL_ZEEK.backup.$(date +%s)"


    if echo "@load flowmeter" | tee -a "$LOCAL_ZEEK" >/dev/null; then

        echo "[OK] FlowMeter @load directive added"

    else

        echo "[ERROR] Failed to add FlowMeter @load directive"

    fi
}


# ==================================================
# Configure Zeek Interface - EPEL
# ==================================================

configure_zeek_epel() {

    ZEEK_NODE_CONFIG="/etc/zeek/node.cfg"


    if [ ! -f "$ZEEK_NODE_CONFIG" ]; then

        echo "[WARNING] node.cfg tidak ditemukan:"
        echo "          $ZEEK_NODE_CONFIG"

        return

    fi


    INTERFACE=$(
        ip route |
        grep '^default' |
        awk '{print $5}' |
        head -1
    )


    if [ -z "$INTERFACE" ]; then

        INTERFACE=$(
            ip link show |
            grep "^[0-9]" |
            grep "UP" |
            awk '{print $2}' |
            sed 's/:$//' |
            grep -v "^lo$" |
            head -1
        )

    fi


    if [ -z "$INTERFACE" ]; then

        echo "[WARNING] Tidak bisa menemukan network interface aktif"

        echo "[INFO] Edit manual:"
        echo "       $ZEEK_NODE_CONFIG"

        return

    fi


    echo "[INFO] Network interface terdeteksi: $INTERFACE"


    if grep -q "^interface=" "$ZEEK_NODE_CONFIG"; then

        sed -i \
            "s/^interface=.*/interface=$INTERFACE/" \
            "$ZEEK_NODE_CONFIG"

    else

        sed -i \
            "/^\[manager\]/a interface=$INTERFACE" \
            "$ZEEK_NODE_CONFIG"

    fi


    echo "[OK] Zeek dikonfigurasi untuk interface: $INTERFACE"
}


# ==================================================
# Install Zeek - YUM / DNF
# ==================================================

install_zeek_yum_or_dnf() {

    if zeek_is_installed; then

        ZEEK_VERSION=$(zeek --version 2>/dev/null || echo "unknown")

        echo "[OK] Zeek sudah terinstall: $ZEEK_VERSION"

        return

    fi


    echo "[INFO] Menambahkan repository Zeek untuk $PRETTY_NAME..."


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


    echo "[INFO] Zeek repository:"
    echo "       $ZEEK_REPO_URL"


    if command_exists dnf; then

        echo "[INFO] Menggunakan dnf..."

        dnf config-manager \
            --add-repo "${ZEEK_REPO_URL}security:zeek.repo" \
            2>/dev/null || true


        if dnf install -y zeek 2>/dev/null; then
            return
        fi

    else

        echo "[INFO] Menggunakan yum..."

        cat > /etc/yum.repos.d/security:zeek.repo <<EOF
[security:zeek]
name=Zeek repository for RHEL/CentOS/AlmaLinux
baseurl=$ZEEK_REPO_URL
gpgcheck=0
enabled=1
EOF


        if yum install -y zeek 2>/dev/null; then
            return
        fi

    fi


    echo "[WARNING] Package installation gagal."
    echo "[INFO] Building Zeek dari source..."

    build_zeek_from_source
}


# ==================================================
# Build Zeek from Source
# ==================================================

build_zeek_from_source() {

    echo "[INFO] Install build dependencies..."


    if command_exists dnf; then

        dnf install -y \
            cmake \
            make \
            gcc \
            gcc-c++ \
            flex \
            bison \
            openssl-devel || true


        dnf install -y libpcap-devel 2>/dev/null || \
        dnf install -y libpcap-dev 2>/dev/null || \
        dnf install -y libpcap 2>/dev/null || true

    else

        yum install -y \
            cmake \
            make \
            gcc \
            gcc-c++ \
            flex \
            bison \
            openssl-devel || true


        yum install -y libpcap-devel 2>/dev/null || \
        yum install -y libpcap-dev 2>/dev/null || \
        yum install -y libpcap 2>/dev/null || true

    fi


    if ! command_exists cmake; then

        echo "[ERROR] cmake tidak terinstall."

        return 1

    fi


    echo "[INFO] Download Zeek LTS source code..."


    cd /tmp


    ZEEK_VERSION="8.0.8"

    ZEEK_FILE="zeek-$ZEEK_VERSION.tar.gz"

    ZEEK_URL="https://download.zeek.org/$ZEEK_FILE"


    if [ -f "$ZEEK_FILE" ]; then

        echo "[INFO] Source sudah ada: $ZEEK_FILE"

    else

        echo "[INFO] Downloading dari:"
        echo "       $ZEEK_URL"

        curl -L \
            -o "$ZEEK_FILE" \
            "$ZEEK_URL" || {

            echo "[ERROR] Gagal download Zeek source"

            return 1
        }

    fi


    echo "[INFO] Extract source code..."

    tar -xzf "$ZEEK_FILE"

    cd "zeek-$ZEEK_VERSION"


    echo "[INFO] Build Zeek..."
    echo "[INFO] Ini bisa memakan waktu 10-30 menit."


    mkdir -p build

    cd build


    cmake .. \
        -DCMAKE_INSTALL_PREFIX=/opt/zeek || {

        echo "[ERROR] CMake failed"

        return 1
    }


    make -j "$(nproc)" || {

        echo "[ERROR] Build failed"

        return 1
    }


    echo "[INFO] Install Zeek..."


    make install || {

        echo "[ERROR] Install failed"

        return 1
    }


    echo "[OK] Zeek berhasil diinstall:"
    echo "     /opt/zeek"

}


# ==================================================
# Setup Zeek PATH
# ==================================================

setup_zeek_path() {

    echo "[INFO] Menambahkan Zeek ke PATH..."


    cat > /etc/profile.d/zeek.sh <<EOF
export PATH=/opt/zeek/bin:\$PATH
EOF


    chmod +x /etc/profile.d/zeek.sh


    ln -sf \
        /opt/zeek/bin/zeek \
        /usr/local/bin/zeek


    ln -sf \
        /opt/zeek/bin/zeekctl \
        /usr/local/bin/zeekctl


    if [ -x /opt/zeek/bin/zkg ]; then

        ln -sf \
            /opt/zeek/bin/zkg \
            /usr/local/bin/zkg

    fi


    export PATH="/opt/zeek/bin:$PATH"


    echo "[OK] PATH Zeek sudah disiapkan."
}


# ==================================================
# Configure Zeek
# ==================================================

configure_zeek() {

    echo "[INFO] Mengkonfigurasi Zeek network interface..."


    export PATH="/opt/zeek/bin:$PATH"


    echo "[INFO] Fix permission untuk Zeek directories..."


    chown -R root:root \
        /opt/zeek/spool \
        2>/dev/null || true


    chmod -R 755 \
        /opt/zeek/spool \
        2>/dev/null || true


    chown -R root:root \
        /opt/zeek/logs \
        2>/dev/null || true


    chmod -R 755 \
        /opt/zeek/logs \
        2>/dev/null || true


    ZEEK_NODE_CONFIG="/opt/zeek/etc/node.cfg"


    if [ ! -f "$ZEEK_NODE_CONFIG" ]; then

        echo "[WARNING] node.cfg tidak ditemukan"

        return

    fi


    INTERFACE=$(
        ip route |
        grep '^default' |
        awk '{print $5}' |
        head -1
    )


    if [ -z "$INTERFACE" ]; then

        INTERFACE=$(
            ip link show |
            grep "^[0-9]" |
            grep "UP" |
            awk '{print $2}' |
            sed 's/:$//' |
            grep -v "^lo$" |
            head -1
        )

    fi


    if [ -z "$INTERFACE" ]; then

        echo "[WARNING] Tidak bisa menemukan network interface aktif"

        echo "[INFO] Edit manual:"
        echo "       $ZEEK_NODE_CONFIG"

        return

    fi


    echo "[INFO] Network interface terdeteksi: $INTERFACE"


    if grep -q "^interface=" "$ZEEK_NODE_CONFIG"; then

        sed -i \
            "s/^interface=.*/interface=$INTERFACE/" \
            "$ZEEK_NODE_CONFIG"

    else

        sed -i \
            "/^\[manager\]/a interface=$INTERFACE" \
            "$ZEEK_NODE_CONFIG"

    fi


    echo "[OK] Zeek dikonfigurasi untuk interface: $INTERFACE"


    echo "[INFO] Deploy Zeek..."


    zeekctl deploy


    echo "[OK] Zeek berhasil di-deploy."
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

        echo "[INFO] Pastikan paket Zeek menyertakan zkg."

        exit 1

    fi


    # ==================================================
    # IMPORTANT:
    # Use Capstone virtual environment
    # ==================================================

    PIP="$BASE_DIR/.venv/bin/pip"


    if [ ! -x "$PIP" ]; then

        echo "[ERROR] Virtual environment pip tidak ditemukan:"
        echo "        $PIP"

        exit 1

    fi


    echo "[INFO] Install/update Python dependencies untuk zkg..."

    "$PIP" install \
        --upgrade \
        gitpython \
        semantic-version


    FLOWMETER_SRC="/opt/zeek-flowmeter"


    if [ ! -d "$FLOWMETER_SRC" ]; then

        echo "[INFO] Clone repository Zeek FlowMeter..."

        git clone \
            https://github.com/zeek-flowmeter/zeek-flowmeter.git \
            "$FLOWMETER_SRC"

    else

        echo "[INFO] Repository FlowMeter sudah ada."

        echo "[INFO] Melakukan update..."

        cd "$FLOWMETER_SRC"

        git pull || true

    fi


    cd "$FLOWMETER_SRC"


    echo "[INFO] Install FlowMeter menggunakan zkg..."


    zkg install --force . || {

        echo "[WARNING] Instalasi via zkg gagal."
        echo "[INFO] Mencoba metode manual..."


        ZEEK_SCRIPT_DIR=$(
            zeekctl config |
            grep zeekscriptdir |
            awk '{print $3}'
        )


        if [ -z "$ZEEK_SCRIPT_DIR" ]; then

            echo "[ERROR] Tidak bisa membaca zeekscriptdir dari zeekctl config."

            exit 1

        fi


        mkdir -p \
            "$ZEEK_SCRIPT_DIR/site/flowmeter"


        cp -a \
            "$FLOWMETER_SRC/scripts/." \
            "$ZEEK_SCRIPT_DIR/site/flowmeter/"


        echo "[OK] FlowMeter berhasil dipasang secara manual."

    }


    ZEEK_LOCAL_FILE="/opt/zeek/share/zeek/site/local.zeek"


    if [ ! -f "$ZEEK_LOCAL_FILE" ]; then

        echo "[INFO] Membuat file local.zeek..."

        mkdir -p \
            "$(dirname "$ZEEK_LOCAL_FILE")"

        touch "$ZEEK_LOCAL_FILE"

    fi


    # Remove old Capstone FlowMeter config

    sed -i \
        '/# Capstone FlowMeter START/,/# Capstone FlowMeter END/d' \
        "$ZEEK_LOCAL_FILE"


    # Append new config

    cat >> "$ZEEK_LOCAL_FILE" <<'EOFZEEK'

# Capstone FlowMeter START
# Load Zeek FlowMeter for capstone ML feature extraction
@load flowmeter
# Capstone FlowMeter END

EOFZEEK


    echo "[OK] @load flowmeter ditambahkan ke:"
    echo "     $ZEEK_LOCAL_FILE"
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


    mkdir -p \
        "$BASE_DIR/artifacts"


    mkdir -p \
        "$BASE_DIR/state"


    chmod 755 \
        "$BASE_DIR/artifacts"


    chmod 755 \
        "$BASE_DIR/state"


    echo "[OK] Direktori project sudah siap."
}


# ==================================================
# Validate Project Files
# ==================================================
# NOTE:
#   Fungsi ini TIDAK boleh memvalidasi watch_uploads.sh karena file itu
#   di-generate oleh setup_file_monitor(), yang HARUS dijalankan lebih dulu.
#   Di sini hanya validasi file statis yang memang ada di repo.
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


    # watch_uploads.sh sengaja TIDAK divalidasi di sini.
    # File itu dibuat oleh setup_file_monitor() yang dijalankan sebelumnya.


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

        install_zeek_yum_or_dnf

        ;;


    almalinux)

        install_basic_dependencies_yum

        setup_python_environment

        install_filebeat_yum_or_dnf

        install_zeek_from_epel

        ;;


    fedora)

        install_basic_dependencies_dnf

        setup_python_environment

        install_filebeat_yum_or_dnf

        install_zeek_yum_or_dnf

        ;;


    *)

        echo "[ERROR] OS belum didukung otomatis:"
        echo "       $PRETTY_NAME"

        exit 1

        ;;

esac


# ==================================================
# Configure Zeek
# ==================================================

if [ "$SKIP_ML" = true ]; then

    echo "[INFO] SKIP: setup PATH Zeek dan FlowMeter."

elif [ "$OS_ID" = "almalinux" ]; then

    echo "[INFO] AlmaLinux EPEL Zeek sudah otomatis di-configure."

else

    setup_zeek_path

    configure_zeek

    install_zeek_flowmeter

fi


# ==================================================
# Project Setup
# ==================================================
# IMPORTANT ORDER:
#   1. setup_project_directories  -> bikin artifacts/, state/
#   2. setup_file_monitor         -> bikin watch_uploads.sh (copy dari template)
#   3. validate_project_files     -> cek file statis (inference_worker.py, dll)
#   4. generate_config_json       -> tulis config/config.json
#   5. generate_filebeat_yml      -> tulis /etc/filebeat/filebeat.yml
#   6. setup_command_monitoring   -> jalankan command-monitoring.sh
# ==================================================

setup_project_directories

setup_file_monitor

validate_project_files

generate_config_json

generate_filebeat_yml

setup_command_monitoring


# ==================================================
# Setup System Log & PID Directories
# ==================================================

setup_log_directories() {

    echo "[INFO] Membuat direktori system logs dan PID..."


    mkdir -p \
        /var/log/Capstone


    mkdir -p \
        /var/run/Capstone


    chmod 755 \
        /var/log/Capstone


    chmod 755 \
        /var/run/Capstone


    echo "[OK] Direktori system sudah siap."
}


# ==================================================
# ML Artifacts
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

        echo "[INFO] SKIP: ekstraksi ML artifacts."

        return

    fi


    echo "[INFO] Mengecek ML artifacts..."


    if artifacts_ready; then

        echo "[OK] Artifacts sudah tersedia:"
        echo "     $BASE_DIR/artifacts"

        return

    fi


    ARTIFACTS_ZIP="$BASE_DIR/artifacts.zip"


    if [ ! -f "$ARTIFACTS_ZIP" ]; then

        echo "[WARNING] artifacts.zip tidak ditemukan:"
        echo "          $ARTIFACTS_ZIP"

        echo "[INFO] File model tidak lengkap."

        echo "[INFO] Inference worker mungkin tidak jalan."

        return

    fi


    echo "[INFO] Extract artifacts dari artifacts.zip..."


    ARTIFACTS_TMP="$BASE_DIR/.artifacts_extract_tmp"


    rm -rf "$ARTIFACTS_TMP"


    mkdir -p \
        "$ARTIFACTS_TMP" \
        "$BASE_DIR/artifacts"


    unzip -q \
        "$ARTIFACTS_ZIP" \
        -d "$ARTIFACTS_TMP"


    if [ -d "$ARTIFACTS_TMP/artifacts" ]; then

        cp -a \
            "$ARTIFACTS_TMP/artifacts/." \
            "$BASE_DIR/artifacts/"

    else

        cp -a \
            "$ARTIFACTS_TMP/." \
            "$BASE_DIR/artifacts/"

    fi


    rm -rf \
        "$ARTIFACTS_TMP"


    if artifacts_ready; then

        echo "[OK] artifacts.zip berhasil diextract."

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


    # ==================================================
    # Filebeat
    # ==================================================

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


    # ==================================================
    # Zeek
    # ==================================================

    if [ "$SKIP_ML" = true ]; then

        echo "[INFO] SKIP: Zeek tidak dijalankan."

    else

        echo "[INFO] Menjalankan Zeek..."


        if command_exists zeekctl; then

            zeekctl start || zeekctl deploy

        elif [ -x "/opt/zeek/bin/zeekctl" ]; then

            /opt/zeek/bin/zeekctl start ||
            /opt/zeek/bin/zeekctl deploy

        else

            echo "[ERROR] zeekctl tidak ditemukan."

            return 1

        fi


        echo "[OK] Zeek berhasil dijalankan."

    fi


    # ==================================================
    # ML Inference Worker
    # ==================================================

    if [ "$SKIP_ML" = true ]; then

        echo "[INFO] SKIP: ML inference worker."

    elif artifacts_ready; then

        echo "[INFO] Menjalankan ML inference worker..."


        CONFIG_FILE="$BASE_DIR/config/config.json"

        INFERENCE_LOG="/var/log/Capstone/inference_worker.log"

        INFERENCE_PID="/var/run/Capstone/inference_worker.pid"

        APP_DIR="$BASE_DIR/app"

        PYTHON="$BASE_DIR/.venv/bin/python"


        if [ ! -x "$PYTHON" ]; then

            echo "[ERROR] Python virtual environment tidak ditemukan:"
            echo "        $PYTHON"

            return 1

        fi


        if [ -f "$INFERENCE_PID" ] &&
           kill -0 "$(cat "$INFERENCE_PID")" 2>/dev/null; then

            echo "[INFO] inference_worker.py sudah berjalan."

            echo "[INFO] PID: $(cat "$INFERENCE_PID")"

        else

            cd "$APP_DIR"


            echo "[INFO] Python:"
            echo "       $PYTHON"


            nohup "$PYTHON" \
                inference_worker.py \
                "$CONFIG_FILE" \
                > "$INFERENCE_LOG" \
                2>&1 &


            echo $! > "$INFERENCE_PID"


            echo "[OK] inference_worker.py berjalan."

            echo "[INFO] PID: $(cat "$INFERENCE_PID")"

            echo "[INFO] Log:"
            echo "       $INFERENCE_LOG"

        fi

    else

        echo "[WARNING] ML artifacts tidak tersedia."

        echo "[WARNING] Inference worker tidak dijalankan."

    fi


    # ==================================================
    # Malware Monitor
    # ==================================================

    echo "[INFO] Menjalankan File Malware Monitor..."


    MALWARE_DIR="$BASE_DIR/malware-file-monitor"

    WATCH_UPLOADS="$MALWARE_DIR/watch_uploads.sh"

    MALWARE_LOG="/var/log/Capstone/malware_monitor.log"

    MALWARE_PID="/var/run/Capstone/malware_monitor.pid"


    if [ ! -f "$WATCH_UPLOADS" ] ||
       [ ! -x "$WATCH_UPLOADS" ]; then

        echo "[WARNING] watch_uploads.sh tidak ditemukan atau tidak executable."

        echo "[INFO] File monitor tidak dijalankan."

    elif [ -f "$MALWARE_PID" ] &&
         kill -0 "$(cat "$MALWARE_PID")" 2>/dev/null; then

        echo "[INFO] watch_uploads.sh sudah berjalan."

        echo "[INFO] PID: $(cat "$MALWARE_PID")"

    else

        cd "$MALWARE_DIR"


        nohup "$WATCH_UPLOADS" \
            > "$MALWARE_LOG" \
            2>&1 &


        echo $! > "$MALWARE_PID"


        echo "[OK] watch_uploads.sh berjalan."

        echo "[INFO] PID: $(cat "$MALWARE_PID")"

        echo "[INFO] Log:"
        echo "       $MALWARE_LOG"

    fi


    echo "======================================"
    echo " Semua services sudah dijalankan!"
    echo "======================================"
}


# ==================================================
# Call Functions
# ==================================================

setup_log_directories

setup_file_monitor

extract_artifacts

start_services


# ==================================================
# Installation Summary
# ==================================================

echo ""

echo "======================================"
echo " ✅ Instalasi dan startup selesai!"
echo "======================================"

echo ""


if [ "$SKIP_ML" = true ]; then

    echo "[INFO] ⚠️  $PRETTY_NAME Mode"

    echo "[INFO] Fitur yang di-skip:"
    echo "  - ML Inference Worker"
    echo "  - Zeek"
    echo "  - FlowMeter"

    echo ""

    echo "[INFO] Fitur yang aktif:"
    echo "  - Filebeat"
    echo "  - File Malware Monitor"
    echo "  - Command logging"

    echo ""

else

    if [ "$OS_ID" = "almalinux" ]; then

        echo "[INFO] $PRETTY_NAME - semua fitur aktif (FULL STACK)"

        echo "  - Zeek Network IDS"
        echo "  - FlowMeter"
        echo "  - ML Inference Worker"
        echo "  - Filebeat"
        echo "  - File Malware Monitor"
        echo "  - Command logging"

    else

        echo "[INFO] $PRETTY_NAME - semua fitur aktif (FULL STACK)"

        echo "  - Zeek Network IDS"
        echo "  - FlowMeter"
        echo "  - ML Inference Worker"
        echo "  - Filebeat"
        echo "  - File Malware Monitor"
        echo "  - Command logging"

    fi

    echo ""


    # ==================================================
    # Zeek Installation Information
    # ==================================================

    if [ "$OS_ID" = "almalinux" ]; then

        echo "[INFO] Zeek installation:"
        echo "       EPEL repository"

        echo "[INFO] Zeek location:"
        echo "       /usr/bin/zeek"
        echo "       /usr/bin/zeekctl"

        echo "[INFO] Config:"
        echo "       /etc/zeek/node.cfg"

        echo "[INFO] Logs:"
        echo "       /var/log/zeek/"

        echo "[INFO] FlowMeter:"
        echo "       installed via zkg"

    elif [ "$OS_ID" = "ubuntu" ] ||
         [ "$OS_ID" = "debian" ]; then

        echo "[INFO] Zeek installation:"
        echo "       package repository"

        echo "[INFO] Zeek location:"
        echo "       /opt/zeek/bin/"

    else

        echo "[INFO] Zeek installation:"
        echo "       package repository/source fallback"

        echo "[INFO] Zeek location:"
        echo "       /opt/zeek/bin/"

    fi

    echo ""

fi


# ==================================================
# Python Environment Information
# ==================================================

echo "[INFO] Python Environment:"
echo "  - System Python: $(python3 --version)"

if [ -x "$BASE_DIR/.venv/bin/python" ]; then

    echo "  - Capstone Python:"
    "$BASE_DIR/.venv/bin/python" --version

    echo "  - Virtual environment:"
    echo "    $BASE_DIR/.venv"

fi

echo ""


# ==================================================
# File Monitor Mode
# ==================================================

echo "[INFO] File Monitor Mode:"

if command_exists inotifywait; then

    echo "  ✓ watch_uploads_inotify.sh"
    echo "    real-time via inotify"

else

    echo "  ✓ watch_uploads_polling.sh"
    echo "    polling mode"

fi

echo ""


# ==================================================
# Service Status
# ==================================================

echo "[INFO] Cek status services:"

echo "  - Filebeat:"
echo "    systemctl status filebeat"


if [ "$SKIP_ML" = false ]; then

    if [ "$OS_ID" = "almalinux" ]; then

        echo "  - Zeek:"
        echo "    sudo zeekctl status"

    else

        echo "  - Zeek:"
        echo "    sudo zeekctl status"

    fi

fi


if [ "$SKIP_ML" = false ]; then

    echo "  - Inference Worker:"
    echo "    cat /var/run/Capstone/inference_worker.pid"

fi

echo ""


# ==================================================
# Logs
# ==================================================

echo "[INFO] Lihat logs:"

echo "  - Filebeat:"
echo "    tail -f /var/log/filebeat/filebeat.log"


if [ "$SKIP_ML" = false ]; then

    echo "  - Inference:"
echo "    tail -f /var/log/Capstone/inference_worker.log"

fi


echo "  - Malware Monitor:"
echo "    tail -f /var/log/Capstone/malware_monitor.log"


echo "  - Commands:"
echo "    tail -f /var/log/commands.log"


if [ "$SKIP_ML" = false ]; then

    echo "  - Zeek:"
    echo "    tail -f /opt/zeek/logs/current/conn.log"

fi

echo ""


# ==================================================
# Configuration
# ==================================================

echo "[INFO] Cek konfigurasi:"

echo "  - config.json:"
echo "    cat $BASE_DIR/config/config.json"


echo "  - filebeat.yml:"
echo "    cat /etc/filebeat/filebeat.yml"


echo "  - Python venv:"
echo "    $BASE_DIR/.venv/bin/python"


echo "  - Python packages:"
echo "    $BASE_DIR/.venv/bin/pip list"


echo "  - file monitor:"
echo "    cat $BASE_DIR/malware-file-monitor/watch_uploads.sh | head -5"


echo ""


# ==================================================
# AlmaLinux Zeek Instructions
# ==================================================

if [ "$SKIP_ML" = false ] &&
   [ "$OS_ID" = "almalinux" ]; then

    echo "[INFO] Zeek Deployment Instructions (AlmaLinux EPEL):"

    echo "  1. Deploy Zeek:"
    echo "     sudo zeekctl deploy"

    echo "  2. Start Zeek:"
    echo "     sudo zeekctl start"

    echo "  3. Check status:"
    echo "     sudo zeekctl status"

    echo "  4. View Zeek logs:"
    echo "     sudo tail -f /var/log/zeek/current/zeek.log"

    echo "  5. Monitor traffic:"
    echo "     sudo tail -f /var/log/zeek/current/conn.log"

    echo ""

fi


echo "======================================"
echo " Installation completed."
echo "======================================"