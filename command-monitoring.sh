
set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

ok()   { echo -e "      ${GREEN}[OK]${NC}   $1"; }
skip() { echo -e "      ${YELLOW}[SKIP]${NC} $1"; }
info() { echo -e "      [INFO] $1"; }
err()  { echo -e "      ${RED}[ERROR]${NC} $1"; }

# --------------------------------------------------------
# Pastikan dijalankan sebagai root
# --------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[ERROR]${NC} Script ini harus dijalankan sebagai root."
    echo "        Gunakan: sudo bash $0"
    exit 1
fi

# --------------------------------------------------------
# Deteksi OS
# --------------------------------------------------------
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS_ID="${ID,,}"
        OS_ID_LIKE="${ID_LIKE,,}"
    else
        OS_ID=""
        OS_ID_LIKE=""
    fi

    if [[ -f /etc/debian_version ]] || [[ "$OS_ID" == "ubuntu" ]] || [[ "$OS_ID" == "debian" ]] || [[ "$OS_ID_LIKE" == *"debian"* ]]; then
        echo "debian"
    elif [[ -f /etc/redhat-release ]] || command -v rpm &>/dev/null || [[ "$OS_ID_LIKE" == *"rhel"* ]] || [[ "$OS_ID_LIKE" == *"fedora"* ]]; then
        echo "rpm"
    else
        echo "unknown"
    fi
}

OS_TYPE=$(detect_os)

case "$OS_TYPE" in
    debian)
        OS_LABEL="Ubuntu / Debian"
        ;;
    rpm)
        OS_LABEL="CentOS / RHEL / RPM-based"
        ;;
    *)
        echo -e "${RED}[ERROR]${NC} OS tidak dikenali. Script ini hanya mendukung Ubuntu/Debian dan CentOS/RHEL."
        exit 1
        ;;
esac

echo "========================================"
echo " Setup Command Logging via rsyslog"
echo -e " Target: ${CYAN}${OS_LABEL}${NC}"
echo "========================================"
echo ""

PROMPT_MARKER="LinuxCommandsWazuh"

# ============================================================
# UBUNTU / DEBIAN
# ============================================================
if [[ "$OS_TYPE" == "debian" ]]; then

    BASHRC_FILE="/etc/bash.bashrc"
    RSYSLOG_CONF="/etc/rsyslog.d/bash.conf"
    DEFAULT_CONF="/etc/rsyslog.d/50-default.conf"
    TOTAL_STEPS=5

    # Step 1: PROMPT_COMMAND ke /etc/bash.bashrc
    echo "[1/${TOTAL_STEPS}] Menambahkan PROMPT_COMMAND ke $BASHRC_FILE ..."
    if grep -qF "$PROMPT_MARKER" "$BASHRC_FILE"; then
        skip "PROMPT_COMMAND sudah ada di $BASHRC_FILE"
    else
        cat >> "$BASHRC_FILE" <<'EOF'

# Command logging untuk rsyslog (LinuxCommandsWazuh)
export PROMPT_COMMAND='RETRN_VAL=$?;logger -t LinuxCommandsWazuh -p local6.debug "User $(whoami) [$$]: $(history 1 | sed "s/^[ ]*[0-9]\+[ ]*//" )"'
EOF
        ok "PROMPT_COMMAND berhasil ditambahkan ke $BASHRC_FILE"
    fi

    # Step 2: Buat /etc/rsyslog.d/bash.conf
    echo "[2/${TOTAL_STEPS}] Membuat $RSYSLOG_CONF ..."
    if [[ -f "$RSYSLOG_CONF" ]]; then
        skip "$RSYSLOG_CONF sudah ada"
    else
        cat > "$RSYSLOG_CONF" <<'EOF'
# Log semua command user (local6) ke file commands.log
local6.* /var/log/commands.log
EOF
        ok "$RSYSLOG_CONF berhasil dibuat"
    fi

    # Step 3: Exclude local6 dari syslog
    echo "[3/${TOTAL_STEPS}] Mengecualikan local6 dari syslog di $DEFAULT_CONF ..."
    if [[ ! -f "$DEFAULT_CONF" ]]; then
        err "$DEFAULT_CONF tidak ditemukan. Lewati langkah ini."
    elif grep -q "local6.none" "$DEFAULT_CONF"; then
        skip "local6.none sudah ada di $DEFAULT_CONF"
    else
        cp "$DEFAULT_CONF" "${DEFAULT_CONF}.bak"
        info "Backup disimpan: ${DEFAULT_CONF}.bak"
        sed -i 's|\(\*\.\*;auth,authpriv\.none\)|\1,local6.none|g' "$DEFAULT_CONF"
        if grep -q "local6.none" "$DEFAULT_CONF"; then
            ok "local6.none berhasil ditambahkan ke $DEFAULT_CONF"
        else
            err "Baris '*.*;auth,authpriv.none' tidak ditemukan di $DEFAULT_CONF"
            echo "        Edit manual: ubah baris tersebut menjadi:"
            echo "        *.*;auth,authpriv.none,local6.none -/var/log/syslog"
        fi
    fi

    # Step 4: Log rotation
    echo "[4/${TOTAL_STEPS}] Mengatur log rotation untuk /var/log/commands.log ..."
    if grep -q "commands.log" /etc/logrotate.d/rsyslog 2>/dev/null; then
        skip "commands.log sudah ada di /etc/logrotate.d/rsyslog"
    else
        cat > /etc/logrotate.d/commands <<'EOF'
/var/log/commands.log
{
    rotate 7
    daily
    missingok
    notifempty
    compress
    delaycompress
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
}
EOF
        ok "Log rotation dibuat: /etc/logrotate.d/commands"
    fi

    # Step 5: Restart rsyslog
    echo "[5/${TOTAL_STEPS}] Merestart rsyslog ..."
    if systemctl restart rsyslog; then
        ok "rsyslog berhasil direstart"
    else
        err "Gagal merestart rsyslog. Cek log: journalctl -xe"
        exit 1
    fi

    echo ""
    echo "========================================"
    echo " Konfigurasi selesai!"
    echo "========================================"
    echo ""
    echo " Log tersimpan di : /var/log/commands.log"
    echo " Bash config      : $BASHRC_FILE"
    echo " rsyslog config   : $RSYSLOG_CONF"
    echo " Log rotation     : /etc/logrotate.d/commands"

# ============================================================
# CENTOS / RHEL / RPM
# ============================================================
elif [[ "$OS_TYPE" == "rpm" ]]; then

    BASHRC_FILE="/etc/bashrc"
    RSYSLOG_CONF="/etc/rsyslog.d/10-linux-commands.conf"
    TOTAL_STEPS=3

    # Step 1: Buat /etc/rsyslog.d/10-linux-commands.conf
    echo "[1/${TOTAL_STEPS}] Membuat $RSYSLOG_CONF ..."
    if [[ -f "$RSYSLOG_CONF" ]]; then
        skip "$RSYSLOG_CONF sudah ada"
    else
        cat > "$RSYSLOG_CONF" <<'EOF'
# Log semua command user (local6) ke file commands.log
local6.* /var/log/commands.log
& stop
EOF
        ok "$RSYSLOG_CONF berhasil dibuat"
    fi

    # Step 2: Restart rsyslog
    echo "[2/${TOTAL_STEPS}] Merestart rsyslog ..."
    if systemctl restart rsyslog; then
        ok "rsyslog berhasil direstart"
    else
        err "Gagal merestart rsyslog. Cek log: journalctl -xe"
        exit 1
    fi

    # Step 3: PROMPT_COMMAND ke /etc/bashrc
    echo "[3/${TOTAL_STEPS}] Menambahkan PROMPT_COMMAND ke $BASHRC_FILE ..."
    if grep -qF "$PROMPT_MARKER" "$BASHRC_FILE"; then
        skip "PROMPT_COMMAND sudah ada di $BASHRC_FILE"
    else
        cat >> "$BASHRC_FILE" <<'EOF'

# Command logging untuk rsyslog (LinuxCommandsWazuh)
export PROMPT_COMMAND='LAST_CMD=$(fc -ln -1 | tr "\t" " " | sed "s/^[[:space:]]*//; s/[[:space:]]*$//"); logger -t LinuxCommandsWazuh -p local6.debug "User $USER [$$]: $LAST_CMD"'
EOF
        ok "PROMPT_COMMAND berhasil ditambahkan ke $BASHRC_FILE"
    fi

    echo ""
    echo "========================================"
    echo " Konfigurasi selesai!"
    echo "========================================"
    echo ""
    echo " Log tersimpan di : /var/log/commands.log"
    echo " Bash config      : $BASHRC_FILE"
    echo " rsyslog config   : $RSYSLOG_CONF"

fi

echo ""
echo " PENTING: Logout dan login kembali agar PROMPT_COMMAND aktif,"
echo "          atau jalankan: source $BASHRC_FILE"
echo ""