#!/bin/bash
# sing-box-onekey 一键安装脚本
# Author: yuehen7

plain='\033[0m'
red='\033[0;31m'
blue='\033[1;34m'
pink='\033[1;35m'
green='\033[0;32m'
yellow='\033[0;33m'

#os
OS_RELEASE=''

#arch
OS_ARCH=''

#sing-box version
SING_BOX_VERSION=''

#script version
SING_BOX_ONEKEY_VERSION='1.0.13'

#package download path
DOWNLAOD_PATH='/usr/local/sing-box'

#scritp install path
SCRIPT_FILE_PATH='/usr/local/sbin/sing-box'

#config install path
CONFIG_FILE_PATH='/usr/local/etc/sing-box'

#binary install path
BINARY_FILE_PATH='/usr/local/bin/sing-box'

#service install path
SERVICE_FILE_PATH='/etc/systemd/system/sing-box.service'

#log file save path
DEFAULT_LOG_FILE_SAVE_PATH='/usr/local/sing-box/sing-box.log'

#sing-box status define
declare -r SING_BOX_STATUS_RUNNING=1
declare -r SING_BOX_STATUS_NOT_RUNNING=0
declare -r SING_BOX_STATUS_NOT_INSTALL=255

#log file size which will trigger log clear
#here we set it as 25M
declare -r DEFAULT_LOG_FILE_DELETE_TRIGGER=25

#utils
function LOGE() {
  echo -e "${red}[ERR] $* ${plain}"
}

function LOGI() {
  echo -e "${green}[INFO] $* ${plain}"
}

function LOGD() {
  echo -e "${yellow}[DEG] $* ${plain}"
}

confirm() {
  if [[ $# > 1 ]]; then
    echo && read -p "$1 [默认$2]: " temp
    if [[ x"${temp}" == x"" ]]; then
      temp=$2
    fi
  else
    read -p "$1 [y/n]: " temp
  fi
  
  if [[ x"${temp}" == x"y" || x"${temp}" == x"Y" ]]; then
    return 0
  else
    return 1
  fi
}

[[ $EUID -ne 0 ]] && LOGE "Silakan jalankan skrip sebagai pengguna root" && exit 1

os_check() {
  LOGI "Periksa sistem saat ini..."
  if [[ -f /etc/redhat-release ]]; then
    OS_RELEASE="centos"
  elif cat /etc/issue | grep -Eqi "debian"; then
    OS_RELEASE="debian"
  elif cat /etc/issue | grep -Eqi "ubuntu"; then
    OS_RELEASE="ubuntu"
  elif cat /etc/issue | grep -Eqi "centos|red hat|redhat"; then
    OS_RELEASE="centos"
  elif cat /proc/version | grep -Eqi "debian"; then
    OS_RELEASE="debian"
  elif cat /proc/version | grep -Eqi "ubuntu"; then
    OS_RELEASE="ubuntu"
  elif cat /proc/version | grep -Eqi "centos|red hat|redhat"; then
    OS_RELEASE="centos"
  else
    LOGE "Kesalahan deteksi sistem, silakan hubungi penulis skrip!" && exit 1
  fi
  LOGI "Deteksi sistem selesai, sistem saat ini adalah:${OS_RELEASE}"
}

arch_check() {
  LOGI "Periksa arsitektur sistem saat ini..."
  OS_ARCH=$(arch)
  LOGI "Arsitektur sistem saat ini adalah ${OS_ARCH}"
  if [[ ${OS_ARCH} == "x86_64" || ${OS_ARCH} == "x64" || ${OS_ARCH} == "amd64" ]]; then
    OS_ARCH="amd64"
  elif [[ ${OS_ARCH} == "aarch64" || ${OS_ARCH} == "arm64" ]]; then
    OS_ARCH="arm64"
  else
    OS_ARCH="amd64"
    LOGE "Gagal mendeteksi arsitektur sistem, gunakan arsitektur default: ${OS_ARCH}"
  fi
  LOGI "Deteksi arsitektur sistem selesai, arsitektur sistem saat ini adalah:${OS_ARCH}"
}

status_check() {
  if [[ ! -f "${SERVICE_FILE_PATH}" ]]; then
    return ${SING_BOX_STATUS_NOT_INSTALL}
  fi
  temp=$(systemctl status sing-box | grep Active | awk '{print $3}' | cut -d "(" -f2 | cut -d ")" -f1)
  if [[ x"${temp}" == x"running" ]]; then
    return ${SING_BOX_STATUS_RUNNING}
  else
    return ${SING_BOX_STATUS_NOT_RUNNING}
  fi
}

config_check() {
  if [[ ! -f "${CONFIG_FILE_PATH}/config.json" ]]; then
    LOGE "${CONFIG_FILE_PATH}/config.json tidak ada, pemeriksaan konfigurasi gagal"
    return
  else
    info=$(${BINARY_FILE_PATH} check -c ${CONFIG_FILE_PATH}/config.json)
    if [[ $? -ne 0 ]]; then
      LOGE "Pemeriksaan konfigurasi gagal, harap periksa log"
    else
      LOGI "Selamat: pemeriksaan konfigurasi berhasil"
    fi
  fi
}

show_status() {
  status_check
  case $? in
  0)
    show_sing_box_version
    echo -e "[INFO] Status sing-box: ${yellow}Tidak Berjalan${plain}"
    show_enable_status
    LOGI "Path file konfigurasi:${CONFIG_FILE_PATH}/config.json"
    LOGI "Path file yang dapat dieksekusi:${BINARY_FILE_PATH}"
    ;;
  1)
    show_sing_box_version
    echo -e "[INFO] Status sing-box: ${green}Berjalan${plain}"
    show_enable_status
    show_running_status
    LOGI "Path file konfigurasi:${CONFIG_FILE_PATH}/config.json"
    LOGI "Path file yang dapat dieksekusi:${BINARY_FILE_PATH}"
    ;;
  255)
    echo -e "[INFO] Status sing-box: ${red}Tidak terpasang${plain}"
    ;;
  esac
}

show_running_status() {
  status_check
  if [[ $? == ${SING_BOX_STATUS_RUNNING} ]]; then
    local pid=$(pidof sing-box)
    local runTime=$(systemctl status sing-box | grep Active | awk '{for (i=5;i<=NF;i++)printf("%s ", $i);print ""}')
    local memCheck=$(cat /proc/${pid}/status | grep -i vmrss | awk '{print $2,$3}')
    LOGI "#####################"
    LOGI "Process ID:${pid}"
    LOGI "Waktu Berjalan：${runTime}"
    LOGI "️Penggunaan memori:${memCheck}"
    LOGI "#####################"
  else
    LOGE "sing-box tidak berjalan"
  fi
}

show_sing_box_version() {
  LOGI "Informasi Versi:$(${BINARY_FILE_PATH} version)"
}

show_enable_status() {
  local temp=$(systemctl is-enabled sing-box)
  if [[ x"${temp}" == x"enabled" ]]; then
    echo -e "[INFO] Apakah sing-box dimulai secara otomatis: ${green}Ya${plain}"
  else
    echo -e "[INFO] Apakah sing-box dimulai secara otomatis: ${red}Tidak${plain}"
  fi
}

create_or_delete_path() {
  if [[ $# -ne 1 ]]; then
    LOGE "invalid input,should be one paremete,and can be 0 or 1"
    exit 1
  fi
  if [[ "$1" == "1" ]]; then
    LOGI "Will create ${DOWNLAOD_PATH} and ${CONFIG_FILE_PATH} for sing-box..."
    rm -rf ${DOWNLAOD_PATH} ${CONFIG_FILE_PATH}
    mkdir -p ${DOWNLAOD_PATH} ${CONFIG_FILE_PATH}
    if [[ $? -ne 0 ]]; then
      LOGE "create ${DOWNLAOD_PATH} and ${CONFIG_FILE_PATH} for sing-box failed"
      exit 1
    else
      LOGI "create ${DOWNLAOD_PATH} adn ${CONFIG_FILE_PATH} for sing-box success"
    fi
  elif [[ "$1" == "0" ]]; then
    LOGI "Will delete ${DOWNLAOD_PATH} and ${CONFIG_FILE_PATH}..."
    rm -rf ${DOWNLAOD_PATH} ${CONFIG_FILE_PATH}
    if [[ $? -ne 0 ]]; then
      LOGE "delete ${DOWNLAOD_PATH} and ${CONFIG_FILE_PATH} failed"
      exit 1
    else
      LOGI "delete ${DOWNLAOD_PATH} and ${CONFIG_FILE_PATH} success"
    fi
  fi
}

install_base() {
  if [[ ${OS_RELEASE} == "ubuntu" || ${OS_RELEASE} == "debian" ]]; then
    apt clean all
    apt update -y
    apt install wget tar unzip vim gcc openssl -y
    apt install net-tools -y 
    apt install libssl-dev g++ -y
  elif [[ ${OS_RELEASE} == "centos" ]]; then
    yum install wget tar unzip vim gcc openssl -y
    yum install net-tools -y 
  fi

  res=`which unzip 2>/dev/null`
  if [[ $? -ne 0 ]]; then
    LOGE " Instalasi unzip gagal, silakan periksa jaringan${plain}"
    exit 1
  fi
}

download_sing-box() {
  LOGD "Mulai Unduh sing-box..."
  os_check && arch_check && install_base

  local SING_BOX_VERSION_TEMP=$(curl -Ls "https://api.github.com/repos/SagerNet/sing-box/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
  SING_BOX_VERSION=${SING_BOX_VERSION_TEMP:1}

  LOGI "Versi yang akan digunakan:${SING_BOX_VERSION}"
  local DOWANLOAD_URL="https://github.com/SagerNet/sing-box/releases/download/${SING_BOX_VERSION_TEMP}/sing-box-${SING_BOX_VERSION}-linux-${OS_ARCH}.tar.gz"

  #here we need create directory for sing-box
  create_or_delete_path 1
  wget -N --no-check-certificate -O ${DOWNLAOD_PATH}/sing-box-${SING_BOX_VERSION}-linux-${OS_ARCH}.tar.gz ${DOWANLOAD_URL}

  if [[ $? -ne 0 ]]; then
    LOGE "Download sing-box failed,plz be sure that your network work properly and can access github"
    create_or_delete_path 0
    exit 1
  else
    LOGI "Unduh sing-box berhasil"
  fi
}

update_sing-box() {
  LOGD "Mulai perbarui sing-box..."
  if [[ ! -f "${SERVICE_FILE_PATH}" ]]; then
    LOGE "system did not install sing-box,please install it firstly"
    show_menu
  fi

  systemctl stop sing-box
  os_check && arch_check

  local SING_BOX_VERSION_TEMP=$(curl -Ls "https://api.github.com/repos/SagerNet/sing-box/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
  SING_BOX_VERSION=${SING_BOX_VERSION_TEMP:1}

  LOGI "Versi yang akan digunakan:${SING_BOX_VERSION}"
  local DOWANLOAD_URL="https://github.com/SagerNet/sing-box/releases/download/${SING_BOX_VERSION_TEMP}/sing-box-${SING_BOX_VERSION}-linux-${OS_ARCH}.tar.gz"

  rm -rf ${DOWNLAOD_PATH}  
  mkdir -p ${DOWNLAOD_PATH}  

  wget -N --no-check-certificate -O ${DOWNLAOD_PATH}/sing-box-${SING_BOX_VERSION}-linux-${OS_ARCH}.tar.gz ${DOWANLOAD_URL}

  cd ${DOWNLAOD_PATH}
  tar -xvf sing-box-${SING_BOX_VERSION}-linux-${OS_ARCH}.tar.gz && cd sing-box-${SING_BOX_VERSION}-linux-${OS_ARCH}

  if [[ $? -ne 0 ]]; then
    clear_sing_box
    OGE "Unzip paket instalasi sing-box gagal, keluar dari skrip"
    exit 1
  else
    LOGI "Dekompresi paket instalasi sing-box berhasil"
  fi

  install -m 755 sing-box ${BINARY_FILE_PATH}

  if ! systemctl restart sing-box; then
    LOGE "update sing-box failed,please check logs"
    show_menu
  else
    LOGI "update sing-box success"
  fi
}

clear_sing_box() {
  LOGD "Mulai bersihkan sing-box..."
  create_or_delete_path 0 && rm -rf ${SERVICE_FILE_PATH} && rm -rf ${BINARY_FILE_PATH} && rm -rf ${SCRIPT_FILE_PATH}
  LOGD "Sing-box dihapus"
}

uninstall_Nginx() {
  LOGI "Mulai mencopot pemasangan nginx..."
  systemctl stop nginx
  sleep 2s
  if [[ ${OS_RELEASE} == "ubuntu" || ${OS_RELEASE} == "debian" ]]; then
    apt autoremove nginx-common -y
    apt autoremove nginx -y
  elif [[ ${OS_RELEASE} == "centos" ]]; then
    yum remove nginx -y
  fi

  rm -rf /etc/nginx/nginx.conf
  if [[ -f /etc/nginx/nginx.conf.bak ]]; then
    mv /etc/nginx/nginx.conf.bak /etc/nginx/nginx.conf
  fi

  ~/.acme.sh/acme.sh --uninstall
  rm -rf /etc/nginx/conf.d/alone.conf && rm -rf /usr/share/nginx && rm -rf ~/.acme.sh
  LOGI "Penghapusan instalasi nginx dan acme.sh selesai."
}

uninstall_sing-box() {
  uninstall_Nginx
  echo ""
  LOGD "Mulai mencopot pemasangan sing-box..."
  pidOfsing_box=$(pidof sing-box)
  if [ -n ${pidOfsing_box} ]; then
        stop_sing-box
  fi
  clear_sing_box

  if [ $? -ne 0 ]; then
    LOGE "Gagal uninstall sing-box, harap periksa log"
    exit 1
  else
    LOGI "Uninstall sing-box berhasil"
  fi
}

start_sing-box() {
  if [ -f "${SERVICE_FILE_PATH}" ]; then
    systemctl start sing-box
    sleep 1s
    status_check
    if [ $? == ${SING_BOX_STATUS_NOT_RUNNING} ]; then
      LOGE "start sing-box service failed,exit"
      exit 1
    elif [ $? == ${SING_BOX_STATUS_RUNNING} ]; then
      LOGI "start sing-box service success"
    fi
  else
    LOGE "${SERVICE_FILE_PATH} does not exist,can not start service"
    exit 1
  fi
}

restart_sing-box() {
  if [ -f "${SERVICE_FILE_PATH}" ]; then
    systemctl restart sing-box
    sleep 1s
    status_check
    if [ $? == 0 ]; then
      LOGE "restart sing-box service failed,exit"
      exit 1
    elif [ $? == 1 ]; then
      LOGI "restart sing-box service success"
    fi
  else
    LOGE "${SERVICE_FILE_PATH} does not exist,can not restart service"
    exit 1
  fi
}

stop_sing-box() {
  LOGD "Menghentikan layanan sing-box..."
  status_check
  if [ $? == ${SING_BOX_STATUS_NOT_INSTALL} ]; then
    LOGE "sing-box did not install,can not stop it"
    exit 1
  elif [ $? == ${SING_BOX_STATUS_NOT_RUNNING} ]; then
    LOGI "sing-box already stoped,no need to stop it again"
    exit 1
  elif [ $? == ${SING_BOX_STATUS_RUNNING} ]; then
    if ! systemctl stop sing-box; then
      LOGE "stop sing-box service failed,plz check logs"
      exit 1
    fi
  fi
  LOGD "Hentikan layanan sing-box dengan sukses"
}

install_sing-box() {
  LOGD "Mulai instal kotak bernyanyi..."
  if [[ $# -ne 0 ]]; then
    download_sing-box $1
  else
    download_sing-box
  fi

  config_sing-box
  setFirewall

  if [[ ! -f "${DOWNLAOD_PATH}/sing-box-${SING_BOX_VERSION}-linux-${OS_ARCH}.tar.gz" ]]; then
    clear_sing_box
    LOGE "could not find sing-box packages,plz check dowanload sing-box whether suceess"
    exit 1
  fi
  cd ${DOWNLAOD_PATH}

  tar -xvf sing-box-${SING_BOX_VERSION}-linux-${OS_ARCH}.tar.gz && cd sing-box-${SING_BOX_VERSION}-linux-${OS_ARCH}

  if [[ $? -ne 0 ]]; then
    clear_sing_box
    OGE "Unzip paket instalasi sing-box gagal, keluar dari skrip"
    exit 1
  else
    LOGI "Dekompresi paket instalasi sing-box berhasil"
  fi

  install -m 755 sing-box ${BINARY_FILE_PATH}

  if [[ $? -ne 0 ]]; then
    LOGE "install sing-box failed,exit"
    exit 1
  else
    LOGI "install sing-box suceess"
  fi
  install_systemd_service && enable_sing-box && start_sing-box
  LOGI "Instalasi sing-box berhasil, dan dimulai dengan sukses"
}

install_systemd_service() {
  LOGD "Mulai instal layanan systemd sing-box..."
  if [ -f "${SERVICE_FILE_PATH}" ]; then
    rm -rf ${SERVICE_FILE_PATH}
  fi
  touch ${SERVICE_FILE_PATH}
  if [ $? -ne 0 ]; then
    LOGE "create service file failed,exit"
    exit 1
  else
    LOGI "create service file success..."
  fi
  cat >${SERVICE_FILE_PATH} <<EOF
[Unit]
Description=sing-box Service
Documentation=https://sing-box.sagernet.org/
After=network.target nss-lookup.target
Wants=network.target
[Service]
Type=simple
ExecStart=${BINARY_FILE_PATH} run -c ${CONFIG_FILE_PATH}/config.json
Restart=on-failure
RestartSec=30s
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000
[Install]
WantedBy=multi-user.target
EOF
  chmod 644 ${SERVICE_FILE_PATH}
  systemctl daemon-reload
  LOGD "Layanan systemd sing-box berhasil diinstal"
}

enable_sing-box() {
  systemctl enable sing-box
  if [[ $? == 0 ]]; then
    LOGI "Atur sing-box untuk memulai otomatis saat boot sukses"
  else
    LOGE "Gagal menyetel sing-box untuk memulai secara otomatis"
  fi
}

create_Cert() {
  LOGD "Memulai..."
  sleep 2s
  res=`ss -ntlp| grep -E ':80 |:443 '`
  if [[ "${res}" != "" ]]; then
    LOGE "Proses lain menempati port 80 atau 443, harap tutup terlebih dahulu lalu jalankan skrip${plain}"
    LOGE "Informasi port adalah sebagai berikut:："
    LOGE ${res}
    exit 1
  fi

  if [[ ${OS_RELEASE} == "ubuntu" || ${OS_RELEASE} == "debian" ]]; then
    apt install -y socat openssl cron
    systemctl start cron
    systemctl enable cron
  elif [[ ${OS_RELEASE} == "centos" ]]; then
    yum install -y socat openssl cronie
    systemctl start crond
    systemctl enable crond
  fi

  curl -sL https://get.acme.sh | sh -s email=hijk.pw@protonmail.ch
  source ~/.bashrc
  ~/.acme.sh/acme.sh --upgrade  --auto-upgrade
  ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt
  ~/.acme.sh/acme.sh --force --issue -d $domain --keylength ec-256 --pre-hook "systemctl stop nginx" --post-hook "systemctl restart nginx"  --standalone

  [[ -f ~/.acme.sh/${domain}_ecc/ca.cer ]] || {
    LOGE " Gagal mendapatkan sertifikat!"
    exit 1
  }

  CERT_FILE="${CONFIG_FILE_PATH}/${domain}.pem"
  KEY_FILE="${CONFIG_FILE_PATH}/${domain}.key"
  ~/.acme.sh/acme.sh --install-cert -d $domain --ecc \
    --key-file       $KEY_FILE  \
    --fullchain-file $CERT_FILE \
    --reloadcmd     "service nginx force-reload"
  [[ -f $CERT_FILE && -f $KEY_FILE ]] || {
    LOGE "Gagal mendapatkan sertifikat!"
    exit 1
  }
}

install_Nginx() {
  LOGI " Mulai instal nginx..."
  if [[ ${OS_RELEASE} == "ubuntu" || ${OS_RELEASE} == "debian" ]]; then
    apt install nginx -y
    if [[ "$?" != "0" ]]; then
      LOGE " Instalasi Nginx gagal！"
      exit 1
    fi
  elif [[ ${OS_RELEASE} == "centos" ]]; then
    yum install epel-release -y
    if [[ "$?" != "0" ]]; then
      echo '[nginx-stable]
name=nginx stable repo
baseurl=http://nginx.org/packages/centos/$releasever/$basearch/
gpgcheck=1
enabled=1
gpgkey=https://nginx.org/keys/nginx_signing.key
module_hotfixes=true' > /etc/yum.repos.d/nginx.repo
    fi
    yum install nginx -y
    if [[ "$?" != "0" ]]; then
      LOGE " Instalasi Nginx gagal！"
      exit 1
    fi
  fi
  systemctl enable nginx
}

config_Nginx() {
  LOGD "Mulai konfigurasi nginx..."
  systemctl stop nginx

  LOGD "Konfigurasikan Stasiun Masquerade(???)..."
  rm -rf /usr/share/nginx/html
  mkdir -p /usr/share/nginx/html
  wget -c -P /usr/share/nginx "https://raw.githubusercontent.com/mack-a/v2ray-agent/master/fodder/blog/unable/html8.zip" >/dev/null
  unzip -o "/usr/share/nginx/html8.zip" -d /usr/share/nginx/html >/dev/null
  rm -f "/usr/share/nginx/html8.zip*"

  echo 'User-Agent: *' > /usr/share/nginx/html/robots.txt
  echo 'Disallow: /' >> /usr/share/nginx/html/robots.txt
  ROBOT_CONFIG="    location = /robots.txt {}"

  if [[ ! -f /etc/nginx/nginx.conf.bak ]]; then
    mv /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak
  fi
  
  res=`id nginx 2>/dev/null`
  if [[ "$?" != "0" ]]; then
    user="www-data"
  else
    user="nginx"
  fi
  cat > /etc/nginx/nginx.conf<<-EOF
user $user;
worker_processes auto;
error_log /var/log/nginx/error.log;
pid /run/nginx.pid;
# Load dynamic modules. See /usr/share/doc/nginx/README.dynamic.
include /usr/share/nginx/modules/*.conf;
events {
    worker_connections 1024;
}
http {
    log_format  main  '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                      '\$status \$body_bytes_sent "\$http_referer" '
                      '"\$http_user_agent" "\$http_x_forwarded_for"';
    access_log  /var/log/nginx/access.log  main;
    server_tokens off;
    sendfile            on;
    tcp_nopush          on;
    tcp_nodelay         on;
    keepalive_timeout   65;
    types_hash_max_size 2048;
    gzip                on;
    include             /etc/nginx/mime.types;
    default_type        application/octet-stream;
    # Load modular configuration files from the /etc/nginx/conf.d directory.
    # See http://nginx.org/en/docs/ngx_core_module.html#include
    # for more information.
    include /etc/nginx/conf.d/*.conf;
}
EOF

  mkdir -p /etc/nginx/conf.d

  if [[ "${tlsFlag}" == "y" ]]; then
    cat > /etc/nginx/conf.d/alone.conf <<-EOF
server {
  listen 80;
  listen [::]:80;
  server_name ${domain};
  rewrite ^(.*)$ https://${domain}:${port}$1 permanent;
}

server {
  listen ${port} ssl;
  server_name ${domain};

  ssl_certificate ${CERT_FILE};
  ssl_certificate_key ${KEY_FILE};
  ssl_session_timeout 15m;
  ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE:ECDH:AES:HIGH:!NULL:!aNULL:!MD5:!ADH:!RC4;
  ssl_protocols TLSv1.2 TLSv1.3;
  ssl_prefer_server_ciphers on;

  root /usr/share/nginx/html;

  location /vmess {
    proxy_redirect off;
    proxy_pass http://127.0.0.1:33210;
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host \$http_host;
    proxy_read_timeout 300s;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
  }

  location /trojan {
    proxy_redirect off;
    proxy_pass http://127.0.0.1:33211;
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host \$http_host;
    proxy_read_timeout 300s;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
  }
}
EOF
  else
    cat > /etc/nginx/conf.d/alone.conf <<-EOF
server {
  listen ${port};
  listen [::]:${port};
  server_name ${domain};
  root /usr/share/nginx/html;

  location /vmess {
    proxy_redirect off;
    proxy_pass http://127.0.0.1:33210;
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host \$http_host;
    proxy_read_timeout 300s;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
  }

  location /trojan {
    proxy_redirect off;
    proxy_pass http://127.0.0.1:33211;
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host \$http_host;
    proxy_read_timeout 300s;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
  }
}    
EOF
  fi
  LOGD "konfigurasi nginx selesai..."
  systemctl restart nginx
}

config_sing-box(){
  LOGD "Mulai konfigurasi sing-box..."

  if [[ -f "${CONFIG_FILE_PATH}/config.json" ]]; then
    mv -f ${CONFIG_FILE_PATH}/config.json ${CONFIG_FILE_PATH}/config.json.bak
  fi

  echo ""
  ip=`curl -sL -4 ip.sb`
  if [[ "$?" != "0" ]]; then
    LOGE "Server IPv6 saat ini tidak didukung！"
    exit 1
  fi

  echo ""
  read -p " Apakah akan mengaktifkan TLS? [(y/n), default: y]：" tlsFlag
  [[ -z "${tlsFlag}" ]] && tlsFlag="y"
  LOGI " 开启tls：$tlsFlag"

  if [[ "${tlsFlag}" == "y" ]]; then
    echo ""
    echo " Silakan periksa apakah kondisi berikut terpenuhi:："
    echo -e " ${red}1. Nama domain palsu${plain}"
    echo -e " ${red}2. Resolusi DNS nama domain palsu menunjuk ke ip server saat ini（${ip}）${plain}"
    echo ""
    read -p " Ketik y konfirmasi, tekan lainnya untuk keluar dari skrip：" answer

    if [[ "${answer,,}" != "y" ]]; then
      exit 0
    fi

    echo ""
    while true
    do
      read -p " Silakan masukkan nama domain palsu：" domain
      if [[ -z "${domain}" ]]; then
        LOGE "Nama domain palsu yang dimasukkan salah, harap masukkan kembali！${plain}"
      else
        break
      fi
    done
    LOGI "nama domain palsu (host)：$domain"

    echo ""
    domain=${domain,,}
    resolve=`curl -sL https://lefu.men/hostip.php?d=${domain}`
    res=`echo -n ${resolve} | grep ${ip}`
    if [[ -z "${res}" ]]; then
      echo " ${domain} Hasil parsing：${resolve}"
      LOGE "Nama domain palsu tidak menuju ke IP server saat ini(${ip})!${plain}"
      exit 1
    fi
  fi

  echo ""
  read -p " Silakan masukkan port nginx [angka dari 100-65535, default 442]：" port
  [[ -z "${port}" ]] && port=442
  if [[ "${port:0:1}" = "0" ]]; then
    LOGE "Port tidak dapat dimulai dengan 0${plain}"
    exit 1
  fi
  LOGI " Port yang digunakan：$port"

  echo ""
  read -r -p "Apakah akan menyesuaikan UUID ？[y/n]:" customUUIDStatus
  if [[ "${customUUIDStatus}" == "y" ]]; then
		read -r -p "Harap masukkan UUID yang valid:" currentCustomUUID
		if [[ -n "${currentCustomUUID}" ]]; then
			uuid=${currentCustomUUID}
		fi
  else
    uuid=`cat /proc/sys/kernel/random/uuid`
	fi
  LOGI " UUID：$uuid"

  echo ""
  read -p " Silakan masukkan port Shadowsocks [nomor dari 30000-65535, default 34210]：" port_ss
  [[ -z "${port_ss}" ]] && port=34210
  if [[ "${port_ss:0:1}" = "0" ]]; then
    LOGE "Port tidak dapat dimulai dengan 0"
    exit 1
  fi
  LOGI " Port Shadowsocks：$port_ss"

  echo ""
  echo "Metode enkripsi data："
  echo -e " ${red}1. 2022-blake3-aes-128-gcm${plain}"
  echo -e " ${red}2. chacha20-ietf-poly1305${plain}"      
  echo ""
  read -p "Silakan pilih jenis enkripsi, defaultnya adalah 1：" method_type
  [[ -z "${method_type}" ]] && method_type=1

  case $method_type in
  1)
    method="2022-blake3-aes-128-gcm"
    password=`openssl rand -base64 16`
    ;;
  2)
    method="chacha20-ietf-poly1305"
    password=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1`
    ;;
  *)
    LOGE " Silakan masukkan opsi yang benar！"
    exit 1
  esac

  LOGI "Tipe enkripsi：$method"
  LOGI "Password：$password"

  if [[ "${tlsFlag}" == "y" ]]; then
    create_Cert
  fi

  install_Nginx
  config_Nginx

  LOGD "Mulai Konfigurasi config.json..."
  cat > /usr/local/etc/sing-box/config.json <<-EOF
{
  "log": {
    "disabled": false,
    "level": "info",
    "output": "/usr/local/sing-box/sing-box.log",
    "timestamp": true
  },
  "dns": {
    "servers": [
      {
        "tag": "google-tls",
        "address": "local",
        "address_strategy": "prefer_ipv4",
        "strategy": "ipv4_only",
        "detour": "direct"
      },
      {
        "tag": "google-udp",
        "address": "8.8.4.4",
        "address_strategy": "prefer_ipv4",
        "strategy": "prefer_ipv4",
        "detour": "direct"
      }
    ],
    "strategy": "prefer_ipv4",
    "disable_cache": false,
    "disable_expire": false
  },
  "inbounds": [
    {
      "type": "shadowsocks",
      "tag": "ss-in",
      "listen": "0.0.0.0",
      "listen_port": ${port_ss},
      "method": "${method}",
      "password": "${password}",
      "network": "tcp",
      "domain_strategy": "prefer_ipv4",
      "tcp_fast_open": true,
      "sniff": true,
      "proxy_protocol": false
    },
    {
      "type": "vmess",
      "tag": "vmess-in",
      "listen": "127.0.0.1",
      "listen_port": 443,
      "tcp_fast_open": false,
      "sniff": true,
      "sniff_override_destination": false,
      "domain_strategy": "prefer_ipv4",
      "proxy_protocol": false,
      "users": [
        {
          "name": "pew",
          "uuid": "${uuid}",
          "alterId": 0
        }
      ],
      "transport": {
        "type": "ws",
        "path": "/vmess"
      }
    },
    {
      "type": "trojan",
      "tag": "trojan-in",
      "listen": "127.0.0.1",
      "listen_port": 443,
      "domain_strategy": "prefer_ipv4",
      "users": [
        {
          "name": "truser",
          "password": "${uuid}"
        }
      ],
      "transport": {
        "type": "ws",
	      "path": "/trojan"
      }
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    },
    {
      "type": "block",
      "tag": "block"
    },
    {
      "type": "dns",
      "tag": "dns-out"
    }
  ],
  "route": {
    "rules": [
      {
        "protocol": "dns",
        "outbound": "dns-out"
      },
      {
        "inbound": ["ss-in","vmess-in","trojan-in"],
        "network": "tcp",
        "geosite": ["cn", "category-ads-all"],
        "geoip": ["cn"],
        "outbound": "block"
      },
      {
        "geosite": "category-ads-all",
        "outbound": "block"
      },
      {
        "geosite": "cn",
        "geoip": "cn",
        "outbound": "block"
      }
    ],
    "geoip": {
      "path": "geoip.db",
      "download_url": "https://github.com/SagerNet/sing-geoip/releases/latest/download/geoip.db",
      "download_detour": "direct"
    },
    "geosite": {
      "path": "geosite.db",
      "download_url": "https://github.com/SagerNet/sing-geosite/releases/latest/download/geosite.db",
      "download_detour": "direct"
    },
    "final": "direct",
    "auto_detect_interface": true
  }
}
EOF
}

setFirewall() {
  LOGD "Mulai mengonfigurasi firewall..."
  res=`which firewall-cmd 2>/dev/null`
  if [[ $? -eq 0 ]]; then
    systemctl status firewalld > /dev/null 2>&1
    if [[ $? -eq 0 ]];then
      firewall-cmd --permanent --add-service=http
      firewall-cmd --permanent --add-service=https
      firewall-cmd --permanent --add-port=${port_ss}/tcp
      if [[ "$port" != "443" ]]; then
        firewall-cmd --permanent --add-port=${port}/tcp
      fi
      firewall-cmd --reload
    else
      nl=`iptables -nL | nl | grep FORWARD | awk '{print $1}'`
      if [[ "$nl" != "3" ]]; then
        iptables -I INPUT -p tcp --dport 80 -j ACCEPT
        iptables -I INPUT -p tcp --dport 443 -j ACCEPT
        iptables -I INPUT -p tcp --dport ${port_ss} -j ACCEPT
        if [[ "$port" != "443" ]]; then
          iptables -I INPUT -p tcp --dport ${port} -j ACCEPT
        fi
      fi
    fi
  else
    res=`which iptables 2>/dev/null`
    if [[ $? -eq 0 ]]; then
      nl=`iptables -nL | nl | grep FORWARD | awk '{print $1}'`
      if [[ "$nl" != "3" ]]; then
        iptables -I INPUT -p tcp --dport 80 -j ACCEPT
        iptables -I INPUT -p tcp --dport 443 -j ACCEPT
        iptables -I INPUT -p tcp --dport ${port_ss} -j ACCEPT
        if [[ "$port" != "443" ]]; then
          iptables -I INPUT -p tcp --dport ${port} -j ACCEPT
        fi
      fi
    else
      res=`which ufw 2>/dev/null`
      if [[ $? -eq 0 ]]; then
        res=`ufw status | grep -i inactive`
        if [[ "$res" = "" ]]; then
          ufw allow http/tcp
          ufw allow https/tcp
          ufw allow ${port_ss}/tcp
          if [[ "$port" != "443" ]]; then
            ufw allow ${port}/tcp
          fi
        fi
      fi
    fi
  fi
  echo ""
}

showInfo() {
  if [[ -f ${CONFIG_FILE_PATH}/config.json && -f /etc/nginx/conf.d/alone.conf ]]; then
    line1=`grep -n 'server_name' /etc/nginx/conf.d/alone.conf | head -n1 | cut -d: -f1`
    domain=`sed -n "${line1}p" /etc/nginx/conf.d/alone.conf | cut -d: -f2 | sed s/[[:space:]]//g `
    domain=${domain/server_name/''}
    domain=${domain/;/''}

    port=`grep "listen.*ssl" /etc/nginx/conf.d/alone.conf | sed s/[[:space:]]//g `
    port=${port/listen/''}
    port=${port/ssl;/''}

    uuid=`grep password ${CONFIG_FILE_PATH}/config.json | cut -d\" -f4`
    
    base64Str=$(echo -n "{\"port\":${port},\"ps\":\"${domain}_vmess\",\"tls\":\"tls\",\"id\":\"${uuid}\",\"aid\":0,\"v\":2,\"host\":\"${domain}\",\"type\":\"none\",\"path\":\"/vmess\",\"net\":\"ws\",\"add\":\"${domain}\",\"allowInsecure\":0,\"peer\":\"${domain}\",\"sni\":\"\"}" | base64 -w 0)
    base64Str="${base64Str// /}"

    ss_ip=`curl -sL -4 ip.sb`
    line1=`grep -n 'shadowsocks' ${CONFIG_FILE_PATH}/config.json | head -n1 | cut -d: -f1`
    line11=`expr $line1 + 3`
    ss_port=`sed -n "${line11}p" ${CONFIG_FILE_PATH}/config.json | cut -d: -f2 | tr -d \",' '`
    line11=`expr $line1 + 4`
    ss_method=`sed -n "${line11}p" ${CONFIG_FILE_PATH}/config.json | cut -d: -f2 | tr -d \",' '`
    line11=`expr $line1 + 5`
    ss_password=`sed -n "${line11}p" ${CONFIG_FILE_PATH}/config.json | cut -d: -f2 | tr -d \",' '`

    ss_base64Str=$(echo -n "${ss_method}:${ss_password}" | base64 -w 0)
    ss_base64Str="${ss_base64Str// /}"

    echo ""
    echo -e "${blue}vmess+ws+tls：${plain}"
    echo -e "vmess://${base64Str}\n"
    echo -e ""
    echo -e "${blue}trojan+ws+tls：${plain}"
    echo -e "trojan://${uuid}@${domain}:${port}?security=tls&type=ws&host=${domain}&path=%2Ftrojan#${domain}_trojan\n"
    echo -e ""
    echo -e "${blue}Shadowsocks：${plain}"
    echo -e "ss://${ss_base64Str}@${ss_ip}:${ss_port}#ss\n"
    echo ""
  else
    LOGE "Gagal membaca file konfigurasi."
    exit 1    
  fi
}

show_menu() {
  echo -e "
  ${green}sing-box-onekey:v${SING_BOX_ONEKEY_VERSION} Kelola skrip${plain}
  ${green}0.${plain} Keluar Skrip
  ${green}1.${plain} Install sing-box
  ${green}2.${plain} Update sing-box
  ${green}3.${plain} Uninstall sing-box
  ${green}4.${plain} Start sing-box
  ${green}5.${plain} Stop sing-box
  ${green}6.${plain} Restart sing-box
  ${green}7.${plain} Check konfigurasi sing-box
  ${green}8.${plain} Lihat konfigurasi sing-box

 "
  show_status
  echo && read -p "Silakan masukkan pilihan[0-7]:" num

  case "${num}" in
  0)
    exit 0
    ;;
  1)
    install_sing-box && showInfo
    ;;
  2)
    update_sing-box && showInfo
    ;;  
  3)
    uninstall_sing-box && show_menu
    ;;
  4)
    start_sing-box && show_menu
    ;;
  5)
    stop_sing-box && show_menu
    ;;
  6)
    restart_sing-box && show_menu
    ;;
  7)
    config_check && show_menu
    ;;    
  8)
    showInfo
    ;;     
  *)
    LOGE "Silakan masukkan opsi yang benar [0-8]"
    ;;
  esac
}

start_to_run() {
  clear
  show_menu
}

start_to_run
