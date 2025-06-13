#!/bin/bash

# WireGuard + MTProto Proxy Setup - All-in-One Script
# Version 2.0 - Single File Solution - Ubuntu Only
# Chỉ cần 1 file duy nhất để chạy trên VPS Ubuntu

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Header đẹp
show_header() {
    clear
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║                                                               ║"
    echo "║    🔥 WireGuard + MTProto Proxy Setup 🔥                    ║"
    echo "║                                                               ║"
    echo "║    ⚡ All-in-One Solution - Ubuntu Only ⚡                  ║"
    echo "║                                                               ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
}

# Kiểm tra quyền root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}❌ Script này cần chạy với quyền root!${NC}"
        echo -e "${YELLOW}💡 Sử dụng: sudo bash wg.sh${NC}"
        exit 1
    fi
}

# Kiểm tra Ubuntu
check_ubuntu() {
    if ! grep -qi ubuntu /etc/os-release; then
        echo -e "${RED}❌ Script này chỉ hỗ trợ Ubuntu!${NC}"
        exit 1
    fi
}

# Thu thập thông tin MTProto với validation
collect_mtproto_input() {
    echo -e "${BLUE}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║                   CẤU HÌNH MTPROTO PROXY                     ║${NC}"
    echo -e "${BLUE}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # Port
    while true; do
        read -p "$(echo -e "${GREEN}🔌 Port cho MTProto ${YELLOW}[2443]${NC}: ")" MTPROTO_PORT
        MTPROTO_PORT=${MTPROTO_PORT:-2443}
        if [[ "$MTPROTO_PORT" =~ ^[0-9]+$ ]] && [ "$MTPROTO_PORT" -ge 1 ] && [ "$MTPROTO_PORT" -le 65535 ]; then
            break
        fi
        echo -e "${RED}❌ Port không hợp lệ! Phải là số từ 1-65535.${NC}"
    done
    
    # Username
    while true; do
        read -p "$(echo -e "${GREEN}👤 Username cho MTProto ${YELLOW}[MTSecret1]${NC}: ")" MTPROTO_USER
        MTPROTO_USER=${MTPROTO_USER:-MTSecret1}
        [[ ${#MTPROTO_USER} -ge 3 ]] && break
        echo -e "${RED}❌ Username phải có ít nhất 3 ký tự!${NC}"
    done
    
    # Secret (tự động tạo hoặc nhập thủ công)
    echo -e "${GREEN}🔐 Tạo secret:${NC}"
    echo "  1) Tự động tạo random secret"
    echo "  2) Nhập thủ công (32 ký tự hex)"
    while true; do
        read -p "$(echo -e "${GREEN}Lựa chọn ${YELLOW}[1]${NC}: ")" secret_choice
        secret_choice=${secret_choice:-1}
        case $secret_choice in
            1)
                MTPROTO_SECRET=$(hexdump -vn "16" -e ' /1 "%02x"' /dev/urandom)
                echo -e "${GREEN}✅ Secret được tạo: ${YELLOW}$MTPROTO_SECRET${NC}"
                break
                ;;
            2)
                while true; do
                    read -p "$(echo -e "${GREEN}🔐 Nhập secret (32 ký tự hex)${NC}: ")" MTPROTO_SECRET
                    MTPROTO_SECRET=$(echo "$MTPROTO_SECRET" | tr '[A-Z]' '[a-z]')
                    if [[ $MTPROTO_SECRET =~ ^[0-9a-f]{32}$ ]]; then
                        break
                    fi
                    echo -e "${RED}❌ Secret phải có đúng 32 ký tự hex (0-9, a-f)!${NC}"
                done
                break
                ;;
            *)
                echo -e "${RED}❌ Lựa chọn không hợp lệ!${NC}"
                ;;
        esac
    done
    
    # TLS Domain
    read -p "$(echo -e "${GREEN}🌐 TLS Domain ${YELLOW}[www.cloudflare.com]${NC}: ")" TLS_DOMAIN
    TLS_DOMAIN=${TLS_DOMAIN:-www.cloudflare.com}
    
    # Giới hạn kết nối
    echo -e "${GREEN}📊 Giới hạn kết nối:${NC}"
    echo "  1) Không giới hạn"
    echo "  2) Giới hạn số kết nối"
    while true; do
        read -p "$(echo -e "${GREEN}Lựa chọn ${YELLOW}[1]${NC}: ")" limit_choice
        limit_choice=${limit_choice:-1}
        case $limit_choice in
            1)
                MTPROTO_LIMIT=""
                break
                ;;
            2)
                while true; do
                    read -p "$(echo -e "${GREEN}Số kết nối tối đa${NC}: ")" MTPROTO_LIMIT
                    if [[ "$MTPROTO_LIMIT" =~ ^[0-9]+$ ]] && [ "$MTPROTO_LIMIT" -gt 0 ]; then
                        MTPROTO_LIMIT=$((MTPROTO_LIMIT * 8))  # Multiply by 8 as per original script
                        break
                    fi
                    echo -e "${RED}❌ Phải là số nguyên dương!${NC}"
                done
                break
                ;;
            *)
                echo -e "${RED}❌ Lựa chọn không hợp lệ!${NC}"
                ;;
        esac
    done
    
    # Xác nhận
    echo ""
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                     XÁC NHẬN CẤU HÌNH                        ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo -e "${GREEN}📊 Port: ${YELLOW}$MTPROTO_PORT${NC}"
    echo -e "${GREEN}📊 Username: ${YELLOW}$MTPROTO_USER${NC}"
    echo -e "${GREEN}📊 Secret: ${YELLOW}$MTPROTO_SECRET${NC}"
    echo -e "${GREEN}📊 TLS Domain: ${YELLOW}$TLS_DOMAIN${NC}"
    if [[ -n "$MTPROTO_LIMIT" ]]; then
        echo -e "${GREEN}📊 Giới hạn kết nối: ${YELLOW}$((MTPROTO_LIMIT / 8)) người dùng${NC}"
    else
        echo -e "${GREEN}📊 Giới hạn kết nối: ${YELLOW}Không giới hạn${NC}"
    fi
    echo ""
    
    while true; do
        read -p "$(echo -e "${GREEN}✅ Xác nhận cấu hình? ${YELLOW}(y/N)${NC}: ")" confirm
        case $confirm in
            [yY][eE][sS]|[yY]) 
                export MTPROTO_PORT MTPROTO_USER MTPROTO_SECRET TLS_DOMAIN MTPROTO_LIMIT
                return 0
                ;;
            [nN][oO]|[nN]|"") 
                return 1
                ;;
            *) 
                echo -e "${RED}❌ Vui lòng nhập y hoặc n${NC}"
                ;;
        esac
    done
}

# Menu chính
show_menu() {
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                  CHỌN PHƯƠNG THỨC CÀI ĐẶT                    ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}1.${NC} ${GREEN}📝 Interactive Setup${NC} - Nhập thông tin chi tiết (khuyến nghị)"
    echo -e "${CYAN}2.${NC} ${YELLOW}⚡ Quick Setup${NC} - Cấu hình mặc định nhanh"
    echo -e "${CYAN}3.${NC} ${RED}❌ Thoát${NC}"
    echo ""
}

# Quick Setup
quick_setup() {
    show_header
    echo -e "${YELLOW}⚡ Quick Setup - Cấu hình mặc định${NC}"
    echo ""
    echo -e "${GREEN}🔌 Port: ${YELLOW}2443${NC}"
    echo -e "${GREEN}👤 Username: ${YELLOW}MTSecret1${NC}"
    echo -e "${GREEN}🔐 Secret: ${YELLOW}Tự động tạo${NC}"
    echo -e "${GREEN}🌐 TLS Domain: ${YELLOW}www.cloudflare.com${NC}"
    echo -e "${GREEN}📊 Giới hạn: ${YELLOW}Không giới hạn${NC}"
    echo ""
    
    read -p "$(echo -e "${GREEN}🚀 Xác nhận? ${YELLOW}(y/N)${NC}: ")" confirm
    if [[ "$confirm" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        export MTPROTO_PORT="2443"
        export MTPROTO_USER="MTSecret1"
        export MTPROTO_SECRET=$(hexdump -vn "16" -e ' /1 "%02x"' /dev/urandom)
        export TLS_DOMAIN="www.cloudflare.com"
        export MTPROTO_LIMIT=""
        run_installation
    fi
}

# Interactive Setup
interactive_setup() {
    show_header
    echo -e "${BLUE}📝 Interactive Setup - Cấu hình chi tiết${NC}"
    echo ""
    
    if collect_mtproto_input; then
        run_installation
    else
        echo -e "${YELLOW}⚠️  Hủy bỏ cài đặt.${NC}"
    fi
}

# Chạy cài đặt - TẤT CẢ CODE CÀI ĐẶT ĐƯỢC TÍCH HỢP VÀO ĐÂY
run_installation() {
    echo -e "${GREEN}🚀 Bắt đầu cài đặt WireGuard + MTProto Proxy...${NC}"
    echo ""
    
    # Tạo log file
    LOG_FILE="/var/log/wireguard_mtproto_install.log"
    
    # Function logging
    log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"; }
    error() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1" | tee -a "$LOG_FILE"; exit 1; }
    
    log "=== BẮT ĐẦU CÀI ĐẶT ==="
    log "MTProto Port: $MTPROTO_PORT, Username: $MTPROTO_USER"
    log "TLS Domain: $TLS_DOMAIN"
    
    # 1. Fix repository và cài đặt packages
    log "🔧 Cập nhật repository và cài đặt packages..."
    apt update || true
    
    # Cài đặt Python trước tiên (bắt buộc cho MTProto)
    log "🐍 Kiểm tra và cài đặt Python..."
    if ! command -v python3 &> /dev/null; then
        log "📦 Cài đặt Python3..."
        apt install -y python3 python3-minimal || error "Không thể cài đặt Python3"
    fi
    
    # Kiểm tra phiên bản Python
    PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    log "✅ Python version: $PYTHON_VERSION"
    
    # Cài đặt pip nếu chưa có
    if ! command -v pip3 &> /dev/null; then
        log "📦 Cài đặt pip3..."
        apt install -y python3-pip || error "Không thể cài đặt pip3"
    fi
    
    # Cài đặt các packages khác
    log "📦 Cài đặt các packages hệ thống..."
    apt install -y wget curl net-tools ufw wireguard sed git jq ca-certificates build-essential --fix-missing || true
    
    # Enable NTP for accurate time
    timedatectl set-ntp on 2>/dev/null || true
    
    # 2. Cài đặt Python dependencies cho MTProto
    log "📦 Cài đặt Python dependencies..."
    
    # Thử cài đặt qua apt trước (Ubuntu packages)
    log "🔧 Cài đặt Python packages qua apt..."
    apt install -y python3-cryptography python3-dev python3-setuptools python3-wheel 2>/dev/null || true
    
    # Kiểm tra và cài đặt uvloop
    if ! python3 -c "import uvloop" 2>/dev/null; then
        log "�� Cài đặt uvloop..."
        # Thử pip3 với --break-system-packages cho Ubuntu 22.04+
        pip3 install uvloop --break-system-packages 2>/dev/null || \
        pip3 install uvloop --user 2>/dev/null || \
        apt install -y python3-uvloop 2>/dev/null || \
        log "⚠️  Không thể cài uvloop, sẽ dùng asyncio thay thế"
    fi
    
    # Kiểm tra và cài đặt cryptography nếu cần
    if ! python3 -c "import cryptography" 2>/dev/null; then
        log "📦 Cài đặt cryptography..."
        pip3 install cryptography --break-system-packages 2>/dev/null || \
        pip3 install cryptography --user 2>/dev/null || \
        log "⚠️  Cryptography đã được cài qua apt"
    fi
    
    log "✅ Python dependencies đã sẵn sàng"
    
    # 3. Cài đặt wgcf
    if ! command -v wgcf &> /dev/null; then
        log "📥 Cài đặt wgcf..."
        curl -L -o /usr/local/bin/wgcf https://github.com/ViRb3/wgcf/releases/download/v2.2.26/wgcf_2.2.26_linux_amd64
        chmod +x /usr/local/bin/wgcf
    fi
    
    # 4. Dừng services cũ
    log "🛑 Dừng services cũ..."
    systemctl stop wg-quick@wg0 2>/dev/null || true
    systemctl stop telegram-routing 2>/dev/null || true
    systemctl stop mtprotoproxy 2>/dev/null || true
    ip link delete wg0 2>/dev/null || true
    
    # 5. Cấu hình WireGuard
    log "🔧 Cấu hình WireGuard..."
    cd /etc/wireguard
    rm -f wgcf-account.toml wgcf-profile.conf wg0.conf
    
    wgcf register --accept-tos || error "Không thể đăng ký WARP"
    wgcf generate || error "Không thể tạo profile"
    
    PRIVATE_KEY=$(grep "PrivateKey" wgcf-profile.conf | cut -d' ' -f3)
    ADDRESS=$(grep "Address" wgcf-profile.conf | cut -d' ' -f3 | cut -d',' -f1)
    PUBLIC_KEY=$(grep "PublicKey" wgcf-profile.conf | cut -d' ' -f3)
    ENDPOINT=$(grep "Endpoint" wgcf-profile.conf | cut -d' ' -f3)
    
    cat > wg0.conf << EOF
[Interface]
PrivateKey = $PRIVATE_KEY
Address = $ADDRESS
MTU = 1280

[Peer]
PublicKey = $PUBLIC_KEY
AllowedIPs = 149.154.160.0/20, 149.154.164.0/22, 149.154.168.0/22, 149.154.172.0/22, 91.108.4.0/22, 91.108.8.0/22, 91.108.12.0/22, 91.108.16.0/22, 91.108.20.0/22, 91.108.56.0/22, 95.161.64.0/20
Endpoint = $ENDPOINT
EOF
    
    # 6. Khởi động WireGuard
    log "🚀 Khởi động WireGuard..."
    systemctl start wg-quick@wg0 && systemctl enable wg-quick@wg0
    sleep 3
    
    # 7. Cấu hình routing cho Telegram qua WireGuard
    log "🔧 Cấu hình routing Telegram qua WireGuard..."
    echo "200 telegram" >> /etc/iproute2/rt_tables 2>/dev/null || true
    
    cat > /usr/local/bin/telegram-routing.sh << 'EOF'
#!/bin/bash
TELEGRAM_CIDRS=("149.154.160.0/20" "149.154.164.0/22" "149.154.168.0/22" "149.154.172.0/22" "91.108.4.0/22" "91.108.8.0/22" "91.108.12.0/22" "91.108.16.0/22" "91.108.20.0/22" "91.108.56.0/22" "95.161.64.0/20")
case "$1" in
    start) 
        for cidr in "${TELEGRAM_CIDRS[@]}"; do 
            ip rule add to $cidr table telegram 2>/dev/null || true
            ip route add $cidr dev wg0 table telegram 2>/dev/null || true
        done
        ;;
    stop) 
        ip rule flush table telegram 2>/dev/null || true
        ip route flush table telegram 2>/dev/null || true
        ;;
esac
EOF
    chmod +x /usr/local/bin/telegram-routing.sh
    
    cat > /etc/systemd/system/telegram-routing.service << 'EOF'
[Unit]
Description=Telegram Routing via WireGuard
After=wg-quick@wg0.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/telegram-routing.sh start
ExecStop=/usr/local/bin/telegram-routing.sh stop
[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload && systemctl enable telegram-routing && systemctl start telegram-routing
    
    # 8. Cài đặt MTProto Proxy
    log "🔧 Cài đặt MTProto Proxy..."
    
    # Tạo thư mục nếu chưa có
    mkdir -p /opt
    cd /opt
    
    # Xóa thư mục cũ nếu có
    rm -rf mtprotoproxy
    
    # Clone MTProto proxy
    git clone https://github.com/alexbers/mtprotoproxy.git || error "Không thể clone MTProto proxy"
    cd mtprotoproxy || error "Không thể vào thư mục mtprotoproxy"
    
    # Tạo config file
    chmod 0777 config.py
    
    # Tạo cấu hình MTProto
    cat > config.py << EOF
PORT = $MTPROTO_PORT
USERS = { "$MTPROTO_USER": "$MTPROTO_SECRET" }
TLS_DOMAIN = "$TLS_DOMAIN"
MODES = { "classic": False, "secure": False, "tls": True }
EOF
    
    # Thêm giới hạn kết nối nếu có
    if [[ -n "$MTPROTO_LIMIT" ]]; then
        echo "USER_MAX_TCP_CONNS = { \"$MTPROTO_USER\": $MTPROTO_LIMIT }" >> config.py
    fi
    
    # Tạo các file cần thiết
    echo "{}" > limits_date.json
    echo "{}" > limits_quota.json
    echo "" > limits_bash.txt
    
    # 9. Tạo systemd service cho MTProto
    log "⚙️  Tạo systemd service cho MTProto..."
    
    # Kiểm tra cuối cùng trước khi tạo service
    log "🔍 Kiểm tra Python và dependencies..."
    if ! python3 -c "import sys; print('Python OK')" 2>/dev/null; then
        error "Python3 không hoạt động đúng"
    fi
    
    # Kiểm tra có thể import các module cần thiết
    python3 -c "
try:
    import socket, asyncio, hashlib, struct, time, random, binascii
    print('Core modules: OK')
except ImportError as e:
    print(f'Missing core module: {e}')
    exit(1)
" || error "Thiếu Python core modules"
    
    log "✅ Python environment sẵn sàng"
    
    cat > /etc/systemd/system/mtprotoproxy.service << 'EOF'
[Unit]
Description=MTProto Proxy Service
After=network.target telegram-routing.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/mtprotoproxy/mtprotoproxy.py
WorkingDirectory=/opt/mtprotoproxy
StartLimitBurst=0
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable mtprotoproxy
    
    # Thử khởi động và kiểm tra
    log "🚀 Khởi động MTProto service..."
    if systemctl start mtprotoproxy; then
        sleep 3
        if systemctl is-active mtprotoproxy >/dev/null; then
            log "✅ MTProto service khởi động thành công"
        else
            log "⚠️  MTProto service không stable, kiểm tra logs: journalctl -u mtprotoproxy"
        fi
    else
        error "Không thể khởi động MTProto service"
    fi
    
    # 10. Cấu hình firewall
    log "🔧 Cấu hình firewall..."
    ufw allow 22/tcp 2>/dev/null || true
    ufw allow ${MTPROTO_PORT}/tcp 2>/dev/null || true
    ufw --force enable 2>/dev/null || true
    
    # 11. Tạo management scripts
    log "📝 Tạo management scripts..."
    cat > /usr/local/bin/telegram-proxy-status << 'EOFSTATUS'
#!/bin/bash
echo "=== TELEGRAM PROXY STATUS ==="
systemctl is-active wg-quick@wg0 && echo "✅ WireGuard: Running" || echo "❌ WireGuard: Stopped"
systemctl is-active mtprotoproxy && echo "✅ MTProto: Running" || echo "❌ MTProto: Stopped"
systemctl is-active telegram-routing && echo "✅ Routing: Running" || echo "❌ Routing: Stopped"
PUBLIC_IP=$(curl -s ifconfig.me 2>/dev/null || echo "Unknown")
echo "📊 Public IP: $PUBLIC_IP"
EOFSTATUS
    chmod +x /usr/local/bin/telegram-proxy-status
    
    sleep 5
    
    # 12. Hiển thị kết quả
    PUBLIC_IP=$(curl -s --connect-timeout 5 ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
    
    echo ""
    log "=== ✅ CÀI ĐẶT HOÀN TẤT ==="
    echo ""
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                   THÔNG TIN MTPROTO PROXY                    ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo -e "${GREEN}🌐 Server: ${YELLOW}$PUBLIC_IP${NC}"
    echo -e "${GREEN}🔌 Port: ${YELLOW}$MTPROTO_PORT${NC}"
    echo -e "${GREEN}👤 Username: ${YELLOW}$MTPROTO_USER${NC}"
    echo -e "${GREEN}🔐 Secret: ${YELLOW}$MTPROTO_SECRET${NC}"
    echo -e "${GREEN}🌐 TLS Domain: ${YELLOW}$TLS_DOMAIN${NC}"
    echo ""
    
    # Tạo connection link
    ENCODED_SECRET=$(python3 -c "print(\"ee\" + \"$MTPROTO_SECRET\" + \"$TLS_DOMAIN\".encode().hex())")
    CONNECTION_LINK="tg://proxy?server=$PUBLIC_IP&port=$MTPROTO_PORT&secret=$ENCODED_SECRET"
    
    echo -e "${BLUE}📱 Connection Link:${NC}"
    echo -e "${YELLOW}$CONNECTION_LINK${NC}"
    echo ""
    echo -e "${BLUE}📱 Cách sử dụng:${NC}"
    echo -e "${BLUE}1. Mở Telegram${NC}"
    echo -e "${BLUE}2. Click vào link trên hoặc copy-paste vào trình duyệt${NC}"
    echo -e "${BLUE}3. Telegram sẽ tự động kết nối proxy${NC}"
    echo ""
    echo -e "${GREEN}🔧 Quản lý:${NC}"
    echo -e "${GREEN}telegram-proxy-status${NC} - Kiểm tra trạng thái"
    echo -e "${GREEN}systemctl restart mtprotoproxy${NC} - Restart MTProto"
    echo -e "${GREEN}systemctl restart wg-quick@wg0${NC} - Restart WireGuard"
    echo -e "${GREEN}systemctl restart telegram-routing${NC} - Restart Routing"
    echo ""
    
    log "🎉 Hệ thống đã sẵn sàng! Telegram sẽ được route qua WireGuard."
}

# Main function
main() {
    show_header
    check_root
    check_ubuntu
    
    while true; do
        show_menu
        read -p "$(echo -e "${GREEN}🎯 Lựa chọn [1-3]${NC}: ")" choice
        echo ""
        
        case $choice in
            1) interactive_setup; break;;
            2) quick_setup; break;;
            3) echo -e "${GREEN}👋 Tạm biệt!${NC}"; exit 0;;
            *) echo -e "${RED}❌ Lựa chọn không hợp lệ!${NC}"; sleep 1;;
        esac
    done
}

main "$@" 
