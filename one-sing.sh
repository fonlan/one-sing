#!/bin/bash

# one-sing.sh - sing-box服务端管理脚本
# 支持下载、更新、卸载sing-box，以及添加SS2022、VLESS Reality和AnyTLS协议

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # 无颜色

# 基本配置
WORK_DIR="/etc/one-sing"
SING_SERVICE="one-sing.service"
SING_CONFIG="$WORK_DIR/config.json"
SING_BIN="$WORK_DIR/sing-box"
GITHUB_API="https://api.github.com/repos/SagerNet/sing-box/releases"

# 确保root权限
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}错误: 此脚本必须以root权限运行${NC}"
        exit 1
    fi
}

# 检查系统是否为Debian
check_system() {
    if [ ! -f /etc/debian_version ]; then
        echo -e "${RED}错误: 此脚本仅支持Debian系统${NC}"
        exit 1
    fi
    
    # 检查架构是否为amd64
    ARCH=$(dpkg --print-architecture)
    if [ "$ARCH" != "amd64" ]; then
        echo -e "${RED}错误: 此脚本仅支持amd64架构${NC}"
        exit 1
    fi
}

# 检查依赖工具
check_dependencies() {
    local deps=("curl" "jq" "unzip" "openssl")
    local missing=()
    
    for dep in "${deps[@]}"; do
        if ! command -v $dep &> /dev/null; then
            missing+=("$dep")
        fi
    done
    
    if [ ${#missing[@]} -ne 0 ]; then
        echo -e "${YELLOW}安装缺少的依赖: ${missing[*]}${NC}"
        apt update
        apt install -y ${missing[@]}
    fi
}

# 创建工作目录
setup_work_dir() {
    mkdir -p "$WORK_DIR"
}

# 随机生成未被占用的端口
generate_random_port() {
    local min=10000
    local max=65535
    local port
    while true; do
        port=$(( RANDOM % (max - min + 1) + min ))
        # 检查端口是否被占用（tcp/udp都检查）
        if ! ss -tuln | awk '{print $5}' | grep -q ":$port$"; then
            echo $port
            return
        fi
    done
}

# 获取服务器IP地址
get_server_ip() {
    curl -s4 ip.sb || curl -s4 ifconfig.io || echo "服务器IP"
}

# 获取证书指纹
get_cert_fingerprint() {
    local cert_file=$1
    if [ -f "$cert_file" ]; then
        openssl x509 -in "$cert_file" -noout -fingerprint -sha256 | cut -d= -f2
    fi
}

# 下载最新开发版sing-box
download_sing_box() {
    echo -e "${BLUE}正在获取sing-box最新版本...${NC}"
    
    # 获取最新版本信息
    local latest_version_info
    latest_version_info=$(curl -s $GITHUB_API | jq -r '[.[] | select(.prerelease==true)][0]')
    if [ -z "$latest_version_info" ]; then
        echo -e "${RED}无法获取最新版本信息${NC}"
        return 1
    fi
    
    local version
    version=$(echo "$latest_version_info" | jq -r '.tag_name')
    echo -e "${GREEN}找到最新版本: $version${NC}"
    
    # 获取下载URL
    local download_url=""
    
    # 首先尝试获取linux-amd64.tar.gz文件
    download_url=$(echo "$latest_version_info" | jq -r '.assets[] | select(.name | contains("linux-amd64") and contains(".tar.gz")) | .browser_download_url')
    local is_tar=true
    
    # 如果没有找到tar.gz文件，尝试找zip文件
    if [ -z "$download_url" ]; then
        download_url=$(echo "$latest_version_info" | jq -r '.assets[] | select(.name | contains("linux-amd64") and contains(".zip")) | .browser_download_url')
        is_tar=false
    fi
    
    # 如果都没有找到，尝试任何包含linux-amd64的文件
    if [ -z "$download_url" ]; then
        download_url=$(echo "$latest_version_info" | jq -r '.assets[] | select(.name | contains("linux-amd64")) | .browser_download_url')
        
        # 根据文件扩展名判断是tar还是zip
        if [[ "$download_url" == *".tar.gz" ]]; then
            is_tar=true
        elif [[ "$download_url" == *".zip" ]]; then
            is_tar=false
        else
            echo -e "${RED}未知的文件格式: $download_url${NC}"
            return 1
        fi
    fi
    
    if [ -z "$download_url" ]; then
        echo -e "${RED}无法找到适用于linux-amd64的下载链接${NC}"
        return 1
    fi
    
    # 下载sing-box
    echo -e "${BLUE}正在下载 sing-box: $download_url${NC}"
    local temp_file=""
    
    if [ "$is_tar" = true ]; then
        temp_file="$WORK_DIR/sing-box.tar.gz"
    else
        temp_file="$WORK_DIR/sing-box.zip"
    fi
    
    curl -L "$download_url" -o "$temp_file"
    
    # 解压并安装
    echo -e "${BLUE}正在安装 sing-box...${NC}"
    
    # 创建临时目录用于解压
    local extract_dir="$WORK_DIR/sing-box-temp"
    mkdir -p "$extract_dir"
    
    # 根据文件类型解压
    if [ "$is_tar" = true ]; then
        tar -xzf "$temp_file" -C "$extract_dir"
    else
        unzip -o "$temp_file" -d "$extract_dir" || {
            echo -e "${RED}解压失败，尝试直接下载二进制文件...${NC}"
            # 下载可能是直接的二进制文件而非压缩包
            mv "$temp_file" "$SING_BIN"
            chmod +x "$SING_BIN"
            echo -e "${GREEN}sing-box $version 安装成功${NC}"
            return 0
        }
    fi
    
    # 查找并复制sing-box二进制文件
    local binary_path
    binary_path=$(find "$extract_dir" -name "sing-box" -type f | head -n 1)
    
    if [ -n "$binary_path" ]; then
        cp "$binary_path" "$SING_BIN"
        chmod +x "$SING_BIN"
        echo -e "${GREEN}sing-box $version 安装成功${NC}"
    else
        echo -e "${RED}无法找到sing-box二进制文件${NC}"
        return 1
    fi
    
    # 清理临时文件
    rm -f "$temp_file"
    rm -rf "$extract_dir"
    
    return 0
}

# 创建systemd服务
create_systemd_service() {
    echo -e "${BLUE}正在创建systemd服务...${NC}"
    
    cat > "/etc/systemd/system/$SING_SERVICE" << EOF
[Unit]
Description=one-sing service
After=network.target nss-lookup.target

[Service]
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
ExecStart=$SING_BIN run -c $SING_CONFIG
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable $SING_SERVICE
    
    echo -e "${GREEN}systemd服务创建成功${NC}"
}

# 更新sing-box
update_sing_box() {
    echo -e "${BLUE}正在更新sing-box...${NC}"
    
    # 停止服务
    systemctl stop $SING_SERVICE
    
    # 下载新版本
    if download_sing_box; then
        # 重启服务
        systemctl start $SING_SERVICE
        echo -e "${GREEN}sing-box更新并重启成功${NC}"
    else
        echo -e "${RED}sing-box更新失败${NC}"
    fi
}

# 卸载sing-box
uninstall_sing_box() {
    echo -e "${YELLOW}正在卸载sing-box...${NC}"
    
    # 停止并禁用服务
    systemctl stop $SING_SERVICE
    systemctl disable $SING_SERVICE
    
    # 删除服务文件
    rm -f "/etc/systemd/system/$SING_SERVICE"
    systemctl daemon-reload
    
    # 删除二进制文件
    rm -f "$SING_BIN"
    
    # 删除工作目录
    echo -e "${YELLOW}是否要删除配置文件和工作目录 $WORK_DIR? [y/N]${NC}"
    read -r confirm
    if [[ $confirm =~ ^[Yy]$ ]]; then
        rm -rf "$WORK_DIR"
        echo -e "${GREEN}工作目录已删除${NC}"
    fi
    
    echo -e "${GREEN}sing-box已成功卸载${NC}"
}

# 创建基本配置结构
create_base_config() {
    if [ ! -f "$SING_CONFIG" ]; then
        echo -e "${BLUE}创建基本配置结构...${NC}"
        cat > "$SING_CONFIG" << EOF
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "ntp": {
    "enabled": true,
    "server": "time.apple.com"
  },
  "inbounds": [],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    }
  ]
}
EOF
    fi
}

# 生成SS2022协议配置
add_ss2022() {
    local port
    port=$(generate_random_port)
    local password
    password=$(openssl rand -base64 16)
    
    echo -e "${BLUE}正在添加SS2022协议...${NC}"
    
    # 检查是否已有配置文件
    create_base_config
    
    # 添加SS2022配置
    local method="2022-blake3-aes-128-gcm"
    local temp_config
    temp_config=$(mktemp)
    jq '.inbounds += [{
      "type": "shadowsocks",
      "tag": "ss2022-in-'"$port"'",
      "listen": "::",
      "listen_port": '"$port"',
      "method": "'"$method"'",
      "password": "'"$password"'"
    }]' "$SING_CONFIG" > "$temp_config"
    mv "$temp_config" "$SING_CONFIG"
    
    # 生成SS URL
    local ip
    ip=$(get_server_ip)
    local ss_url
    ss_url="ss://$(echo -n "${method}:${password}" | base64 | tr -d '\n')@${ip}:${port}#${ip}:${port}-ss2022"
    
    echo -e "${GREEN}SS2022协议添加成功${NC}"
    echo -e "${CYAN}连接信息:${NC}"
    echo -e "${CYAN}协议: SS2022${NC}"
    echo -e "${CYAN}端口: $port${NC}"
    echo -e "${CYAN}密码: $password${NC}"
    echo -e "${CYAN}加密方式: $method${NC}"
    echo -e "${GREEN}URL: $ss_url${NC}"
    
    # 重启服务
    if ! restart_service; then
        rollback_last_config "SS2022" "$port"
    fi
}

# 生成VLESS Reality协议配置
add_vless() {
    local port
    port=$(generate_random_port)
    local uuid
    uuid=$(cat /proc/sys/kernel/random/uuid)
    
    # 随机选择一个SNI
    local sni_list=(
        "www.microsoft.com"
        "www.apple.com"
        "www.cloudflare.com"
        "www.amazon.com"
        "www.tesla.com"
        "www.nvidia.com"
        "www.bing.com"
        "www.yahoo.com"
    )
    
    local random_index=$(( RANDOM % ${#sni_list[@]} ))
    local server_name=${sni_list[$random_index]}
    
    echo -e "${BLUE}正在添加VLESS Reality协议...${NC}"
    
    # 生成密钥对
    local key_output
    key_output=$($SING_BIN generate reality-keypair)
    local private_key
    private_key=$(echo "$key_output" | grep "PrivateKey" | awk '{print $2}')
    local public_key
    public_key=$(echo "$key_output" | grep "PublicKey" | awk '{print $2}')
    
    # 检查是否已有配置文件
    create_base_config
    
    # 添加VLESS Reality配置
    local temp_config
    temp_config=$(mktemp)
    jq '.inbounds += [{
      "type": "vless",
      "tag": "vless-in-'"$port"'",
      "listen": "::",
      "listen_port": '"$port"',
      "users": [
        {
          "uuid": "'"$uuid"'",
          "flow": "xtls-rprx-vision"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "'"$server_name"'",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "'"$server_name"'",
            "server_port": 443
          },
          "private_key": "'"$private_key"'",
          "short_id": [""]
        }
      }
    }]' "$SING_CONFIG" > "$temp_config"
    mv "$temp_config" "$SING_CONFIG"
    
    # 生成VLESS URL
    local ip
    ip=$(get_server_ip)
    local flow="xtls-rprx-vision"
    local vless_url
    vless_url="vless://${uuid}@${ip}:${port}?security=reality&sni=${server_name}&fp=chrome&pbk=${public_key}&flow=${flow}&type=tcp#${ip}:${port}-vless"

    echo -e "${GREEN}VLESS Reality协议添加成功${NC}"
    echo -e "${CYAN}连接信息:${NC}"
    echo -e "${CYAN}协议: VLESS${NC}"
    echo -e "${CYAN}端口: $port${NC}"
    echo -e "${CYAN}UUID: $uuid${NC}"
    echo -e "${CYAN}SNI: $server_name${NC}"
    echo -e "${CYAN}Public Key: $public_key${NC}"
    echo -e "${CYAN}Flow: $flow${NC}"
    echo -e "${GREEN}URL: $vless_url${NC}"
    
    # 重启服务
    if ! restart_service; then
        rollback_last_config "VLESS" "$port"
    fi
}

# 生成AnyTLS协议配置
add_anytls() {
    local port
    port=$(generate_random_port)
    local password
    password=$(tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c 16)
    
    echo -e "${BLUE}正在添加AnyTLS协议...${NC}"
    
    # 检查证书目录和证书文件
    local cert_dir="$WORK_DIR/cert"
    local cert_file="$cert_dir/cert.crt"
    local key_file="$cert_dir/private.key"
    
    # 创建证书目录
    mkdir -p "$cert_dir"
    
    # 检查证书是否已存在
    if [ -f "$cert_file" ] && [ -f "$key_file" ]; then
        echo -e "${YELLOW}检测到已存在的证书，将直接使用...${NC}"
    else
        echo -e "${YELLOW}生成新的自签名证书...${NC}"
        # 生成私钥和证书
        openssl req -x509 -newkey rsa:4096 -keyout "$key_file" -out "$cert_file" -days 3650 -nodes -subj "/CN=example.com"
    fi
    
    # 检查是否已有配置文件
    create_base_config
    
    # 添加AnyTLS配置
    local temp_config
    temp_config=$(mktemp)
    jq '.inbounds += [{
      "type": "anytls",
      "tag": "anytls-in-'"$port"'",
      "listen": "::",
      "listen_port": '"$port"',
      "users": [
        {
          "password": "'"$password"'"
        }
      ],
      "tls": {
        "enabled": true,
        "certificate_path": "'"$cert_file"'",
        "key_path": "'"$key_file"'"
      }
    }]' "$SING_CONFIG" > "$temp_config"
    mv "$temp_config" "$SING_CONFIG"
    
    # 获取证书指纹
    local cert_fingerprint
    cert_fingerprint=$(get_cert_fingerprint "$cert_file")
    
    # 生成AnyTLS URL
    local ip
    ip=$(get_server_ip)
    local anytls_url
    anytls_url="anytls://${password}@${ip}:${port}?insecure=1#${ip}:${port}-anytls"

    echo -e "${GREEN}AnyTLS协议添加成功${NC}"
    echo -e "${CYAN}连接信息:${NC}"
    echo -e "${CYAN}协议: AnyTLS${NC}"
    echo -e "${CYAN}端口: $port${NC}"
    echo -e "${CYAN}密码: $password${NC}"
    echo -e "${CYAN}证书指纹: $cert_fingerprint${NC}"
    echo -e "${GREEN}URL: $anytls_url${NC}"
    
    # 重启服务
    if ! restart_service; then
        rollback_last_config "AnyTLS" "$port"
    fi
}

# 重启sing-box服务
restart_service() {
    echo -e "${BLUE}正在校验配置文件...${NC}"
    # 先验证配置文件
    if ! $SING_BIN check -c "$SING_CONFIG"; then
        echo -e "${RED}配置文件验证失败，无法启动服务${NC}"
        return 1
    fi
    
    echo -e "${BLUE}配置验证通过，正在重启sing-box服务...${NC}"
    systemctl restart $SING_SERVICE
    sleep 2
    
    if systemctl is-active --quiet $SING_SERVICE; then
        echo -e "${GREEN}sing-box服务已成功重启${NC}"
        return 0
    else
        echo -e "${RED}sing-box服务重启失败${NC}"
        echo -e "${YELLOW}查看日志: journalctl -u $SING_SERVICE -n 50 --no-pager${NC}"
        return 1
    fi
}

# 回滚最近的协议配置
rollback_last_config() {
    local protocol_type=$1
    local protocol_port=$2
    
    echo -e "${YELLOW}检测到服务启动失败，正在回滚 $protocol_type 协议配置...${NC}"
    
    # 从配置文件中删除该协议
    local temp_config=$(mktemp)
    jq '.inbounds = [.inbounds[] | select(.listen_port != '"$protocol_port"')]' "$SING_CONFIG" > "$temp_config"
    mv "$temp_config" "$SING_CONFIG"
    
    # 尝试重新启动服务
    systemctl restart $SING_SERVICE
    sleep 2
    
    if systemctl is-active --quiet $SING_SERVICE; then
        echo -e "${GREEN}回滚成功，服务已恢复正常${NC}"
    else
        echo -e "${RED}回滚后服务仍然无法启动，请检查日志排查问题${NC}"
        echo -e "${YELLOW}查看日志: journalctl -u $SING_SERVICE -n 50 --no-pager${NC}"
    fi
}

# 查看服务状态
check_status() {
    echo -e "${BLUE}sing-box服务状态:${NC}"
    systemctl status $SING_SERVICE --no-pager
    
    echo -e "\n${BLUE}配置信息:${NC}"
    if [ -f "$SING_CONFIG" ]; then
        jq '.inbounds[] | {type, tag, listen_port}' "$SING_CONFIG"
    else
        echo -e "${YELLOW}配置文件不存在${NC}"
    fi
}

# 删除指定协议
delete_inbound() {
    if [ ! -f "$SING_CONFIG" ]; then
        echo -e "${YELLOW}配置文件不存在，还没有添加任何协议${NC}"
        return
    fi
    
    # 从配置文件中获取所有协议信息
    local inbounds=$(jq -r '.inbounds[] | "\(.type)|\(.listen_port)"' "$SING_CONFIG")
    if [ -z "$inbounds" ]; then
        echo -e "${YELLOW}还没有添加任何协议${NC}"
        return
    fi
    
    # 列出所有协议
    echo -e "${BLUE}已添加的协议列表:${NC}"
    local count=0
    local protocols=()
    
    while IFS='|' read -r protocol port; do
        count=$((count+1))
        protocols+=("$protocol|$port")
        # 根据协议类型显示更友好的名称
        case "$protocol" in
            "shadowsocks") protocol_name="SS2022" ;;
            "vless") protocol_name="VLESS Reality" ;;
            "anytls") protocol_name="AnyTLS" ;;
            *) protocol_name="$protocol" ;;
        esac
        echo -e "${YELLOW}[$count] $protocol_name 协议 (端口: $port)${NC}"
    done <<< "$inbounds"
    
    # 选择要删除的协议
    echo -ne "\n${YELLOW}请输入要删除的协议编号 [1-$count] (输入0取消): ${NC}"
    read -r select
    
    if [[ ! $select =~ ^[0-9]+$ ]] || [ $select -lt 1 ] || [ $select -gt $count ]; then
        if [ "$select" == "0" ]; then
            echo -e "${YELLOW}取消删除操作${NC}"
        else
            echo -e "${RED}无效选择${NC}"
        fi
        return
    fi
    
    # 获取要删除的协议信息
    local selected_protocol=${protocols[$select-1]}
    local protocol_type=${selected_protocol%|*}
    local protocol_port=${selected_protocol#*|}
    
    # 显示友好的协议名称
    case "$protocol_type" in
        "shadowsocks") protocol_name="SS2022" ;;
        "vless") protocol_name="VLESS" ;;
        "anytls") protocol_name="AnyTLS" ;;
        *) protocol_name="$protocol_type" ;;
    esac
    
    # 从配置文件中删除该协议
    local temp_config=$(mktemp)
    jq '.inbounds = [.inbounds[] | select(.listen_port != '"$protocol_port"')]' "$SING_CONFIG" > "$temp_config"
    mv "$temp_config" "$SING_CONFIG"
    
    echo -e "${GREEN}成功删除 $protocol_name 协议 (端口: $protocol_port)${NC}"
    
    # 询问是否要重启服务
    echo -ne "${YELLOW}是否要重启sing-box服务以应用更改? [Y/n]: ${NC}"
    read -r restart
    if [[ ! $restart =~ ^[Nn]$ ]]; then
        restart_service
    fi
}

# 查看所有配置及URL
list_inbounds() {
    echo -e "${BLUE}已添加的协议列表:${NC}"
    
    if [ ! -f "$SING_CONFIG" ]; then
        echo -e "${YELLOW}配置文件不存在，还没有添加任何协议${NC}"
        return
    fi
    
    # 从配置文件中获取所有协议信息
    local inbounds=$(jq -r '.inbounds[]' "$SING_CONFIG")
    if [ -z "$inbounds" ]; then
        echo -e "${YELLOW}还没有添加任何协议${NC}"
        return
    fi
    
    # 获取服务器IP
    local ip
    ip=$(get_server_ip)
    local count=0
    
    # 处理每个入站协议
    # 使用管道前先计算有多少个入站协议
    count=$(jq '.inbounds | length' "$SING_CONFIG")
    
    if [ "$count" -eq 0 ]; then
        echo -e "${YELLOW}还没有添加任何协议${NC}"
        return
    fi
    
    # 处理每个入站协议
    local idx=1
    jq -c '.inbounds[]' "$SING_CONFIG" | while read -r inbound; do
        local protocol=$(echo "$inbound" | jq -r '.type')
        local port=$(echo "$inbound" | jq -r '.listen_port')
        
        # 根据协议类型显示不同信息
        case "$protocol" in
            "shadowsocks")
                local method=$(echo "$inbound" | jq -r '.method')
                local password=$(echo "$inbound" | jq -r '.password')
                local ss_url="ss://$(echo -n "${method}:${password}" | base64 | tr -d '\n')@${ip}:${port}#${ip}:${port}-ss2022"
                
                echo -e "\n${YELLOW}[$idx] SS2022 协议${NC}"
                echo -e "${CYAN}端口: $port${NC}"
                echo -e "${CYAN}密码: $password${NC}"
                echo -e "${CYAN}加密方式: $method${NC}"
                echo -e "${GREEN}URL: $ss_url${NC}"
                ;;
            
            "vless")
                local uuid=$(echo "$inbound" | jq -r '.users[0].uuid')
                local flow=$(echo "$inbound" | jq -r '.users[0].flow')
                local server_name=$(echo "$inbound" | jq -r '.tls.server_name')
                
                local vless_url="vless://${uuid}@${ip}:${port}?security=reality&sni=${server_name}&fp=chrome&pbk=${public_key}&flow=${flow}&type=tcp#${ip}:${port}-vless"
                
                echo -e "\n${YELLOW}[$idx] VLESS 协议${NC}"
                echo -e "${CYAN}端口: $port${NC}"
                echo -e "${CYAN}UUID: $uuid${NC}"
                echo -e "${CYAN}SNI: $server_name${NC}"
                echo -e "${CYAN}Flow: $flow${NC}"
                echo -e "${GREEN}URL: $vless_url${NC}"
                ;;
            
            "anytls")
                local password=$(echo "$inbound" | jq -r '.users[0].password')
                local cert_path=$(echo "$inbound" | jq -r '.tls.certificate_path')
                local cert_fingerprint=""
                
                # 如果证书文件存在，获取指纹
                cert_fingerprint=$(get_cert_fingerprint "$cert_path")
                
                local anytls_url="anytls://${password}@${ip}:${port}?insecure=1#${ip}:${port}-anytls"
                
                echo -e "\n${YELLOW}[$idx] AnyTLS 协议${NC}"
                echo -e "${CYAN}端口: $port${NC}"
                echo -e "${CYAN}密码: $password${NC}"
                if [ -n "$cert_fingerprint" ]; then
                    echo -e "${CYAN}证书指纹: $cert_fingerprint${NC}"
                fi
                echo -e "${GREEN}URL: $anytls_url${NC}"
                ;;
            
            *)
                echo -e "\n${YELLOW}[$idx] $protocol 协议${NC}"
                echo -e "${CYAN}端口: $port${NC}"
                ;;
        esac
        
        # 递增索引
        idx=$((idx+1))
    done
}

# 显示菜单
show_menu() {
    echo -e "\n${PURPLE}=== One-Sing 管理脚本 ===${NC}"
    echo -e "${CYAN}1.${NC} 添加 SS2022 配置"
    echo -e "${CYAN}2.${NC} 添加 VLESS  配置"
    echo -e "${CYAN}3.${NC} 添加 AnyTLS 配置"
    echo -e "${CYAN}4.${NC} 查看已添加的配置"
    echo -e "${CYAN}5.${NC} 删除已添加的配置"
    echo -e "------------------------------${NC}"
    echo -e "${CYAN}6.${NC} 更新内核"
    echo -e "${CYAN}7.${NC} 卸载服务"
    echo -e "${CYAN}8.${NC} 重启服务"
    echo -e "${CYAN}9.${NC} 查看服务"
    echo -e "------------------------------${NC}"
    echo -e "${CYAN}0.${NC} 退出脚本"
    echo -e "------------------------------${NC}"
    echo -ne "\n${YELLOW}请输入选项 [0-9]:${NC} "
    read -r choice
    
    case "$choice" in
        1)
            check_root
            ensure_sing_box_installed
            add_ss2022
            ;;
        2)
            check_root
            ensure_sing_box_installed
            add_vless
            ;;
        3)
            check_root
            ensure_sing_box_installed
            add_anytls
            ;;
        4)
            check_root
            list_inbounds
            ;;
        5)
            check_root
            delete_inbound
            ;;
        6)
            check_root
            # 确保已安装sing-box，才能执行更新
            if [ -f "$SING_BIN" ]; then
                update_sing_box
            else
                echo -e "${YELLOW}sing-box尚未安装，请先添加一个协议配置以自动安装sing-box${NC}"
            fi
            ;;
        7)
            check_root
            uninstall_sing_box
            ;;
        8)
            check_root
            restart_service
            ;;
        9)
            check_root
            check_status
            ;;
        0)
            echo -e "${GREEN}感谢使用，再见!${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}无效选项，请重新选择${NC}"
            ;;
    esac
    
    # 如果不是退出选项，在操作完成后暂停一下，让用户查看结果
    if [ "$choice" != "0" ]; then
        echo -e "\n${YELLOW}按回车键返回主菜单...${NC}"
        read -r
    fi
}

# 检查并确保sing-box已安装
ensure_sing_box_installed() {
    if [ ! -f "$SING_BIN" ]; then
        echo -e "${YELLOW}检测到sing-box尚未安装，正在执行安装流程...${NC}"
        check_system
        check_dependencies
        setup_work_dir
        download_sing_box
        create_systemd_service
        echo -e "${GREEN}sing-box安装完成${NC}"
    fi
}

# 主函数
main() {
    while true; do
        show_menu
    done
}

# 执行主函数
main
