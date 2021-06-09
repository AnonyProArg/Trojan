#!/bin/bash
export LC_ALL=C
export LANG=en_US
export LANGUAGE=en_US.UTF-8
clear

branch="main"
VERSION="2.2.1"

ip4_api="--ipv4 https://v4.ident.me/"
ip6_api="--ipv6 https://v6.ident.me/"

raw_proxy="raw.staticdn.net"
api_proxy="gh-api.phlin.workers.dev"
gh_proxy="gh-proxy.phlin.workers.dev"

cf_node_default="icook.tw"

log_path="/var/log/xwall.log"

if [[ $(/usr/bin/id -u) -ne 0 ]]; then
  echo "¡No eres un usuario root! Ingrese sudo -i para cambiar al usuario root antes de ejecutar este script"
  exit
fi

colorStart="\033["
colorEnd="\033[0m"

RED="0;31m"      # Error message
GREEN="0;32m"    # Success message
LGREEN="1;32m"   # Success message 2
YELLOW="0;33m"   # Warning message
LYELLOW="1;33m"  # Info message 1
BLUE="0;36m"     # Info message 2

colorEcho(){
  # copied from v2ray official script
  echo -e "${colorStart}${1}${@:2}${colorEnd}" 1>& 2
}

colorEchoFlush(){
  echo -ne "${colorStart}${1}${@:2}${colorEnd}\r" 1>& 2
}

leerv (){
clear
echo " AL INSTALAR ESTE METODO, SE OCUPARAN LOS SIGUIENTES PUERTOS: 80,443."
echo ""
echo " DEBES TENER YA CONFIGURADO EL CLOUDFLARE"
echo ""
echo " SE OCUPA OTRA APK, PORQUE NO LO SOPORTA CUALQUIERA"
echo ""
echo " ES 3 EN 1. INSTALA VLESS, SHADOWSOCK Y TROJAN-GO"
echo ""
echo " ESTOS MISMOS CON Y SIN WEBSOCK (SE RECOMIENDA LOS DE WESOCK)"
echo ""
echo " NO SE PUEDE CREAR VARIAS CUENTAS"
echo ""
echo " EL APK NO BLEQUEA EL PERFIL PARA COMPARTIR, TAMPOCO LO ENCRIPTA"
echo ""
echo " LINK DEL APK COMPATIBLE: https://www.mediafire.com/folder/hmq5cstvcg9gk/TROJAN-GO "
echo ""
echo " FIN DEL CURSO. TECLEA 7 PARA VOLVER AL MENU"
}   

VPS-ARG (){
clear
sudo VPS-ARG
}

#copied & modified from v2fly fhs script
identify_the_operating_system_and_architecture() {
  if [[ "$(uname)" == 'Linux' ]]; then
    case "$(uname -m)" in
      'amd64' | 'x86_64')
        V2_MACHINE='64'
        TJ_MACHINE='amd64'
        ;;
      'armv8' | 'aarch64')
        V2_MACHINE='arm64-v8a'
        TJ_MACHINE='armv8'
        ;;
    esac
    if [[ ! -f '/etc/os-release' ]]; then
      echo "error: no utilice distribuciones de Linux obsoletas."
      exit 1
    fi
    if [[ -z "$(ls -l /sbin/init | grep systemd)" ]]; then
      echo "error: solo se admiten las distribuciones de Linux que utilizan systemd."
      exit 1
    fi
    if [[ "$(command -v apt)" ]]; then
      PACKAGE_MANAGEMENT_UPDATE='apt update'
      PACKAGE_MANAGEMENT_INSTALL='apt install'
      PACKAGE_MANAGEMENT_REMOVE='apt remove'
    elif [[ "$(command -v yum)" ]]; then
      PACKAGE_MANAGEMENT_UPDATE='yum update'
      PACKAGE_MANAGEMENT_INSTALL='yum install'
      PACKAGE_MANAGEMENT_REMOVE='yum remove'
    elif [[ "$(command -v dnf)" ]]; then
      PACKAGE_MANAGEMENT_UPDATE='dnf update'
      PACKAGE_MANAGEMENT_INSTALL='dnf install'
      PACKAGE_MANAGEMENT_REMOVE='dnf remove'
    elif [[ "$(command -v zypper)" ]]; then
      PACKAGE_MANAGEMENT_INSTALL='zypper install'
      PACKAGE_MANAGEMENT_REMOVE='zypper remove'
    elif [[ "$(command -v pacman)" ]]; then
      PACKAGE_MANAGEMENT_INSTALL='pacman -S'
      PACKAGE_MANAGEMENT_REMOVE='pacman -R'
    else
      echo "error: el script no es compatible con el administrador de paquetes en este sistema operativo."
      exit 1
    fi
  else
    echo "error: este sistema operativo no es compatible."
    exit 1
  fi
}

read_json() {
  # jq [key] [path-to-file]
  jq --raw-output $2 $1 2>/dev/null | tr -d '\n'
} ## read_json [path-to-file] [key]

write_json() {
  # jq [key = value] [path-to-file]
  jq -r "$2 = $3" $1 > /tmp/tmp.$$.json && mv /tmp/tmp.$$.json $1 && sleep 1
} ## write_json [path-to-file] [key] [value]

urlEncode() {
  printf %s "$1" | jq -s -R -r @uri
}

urlDecode() {
  printf "${_//%/\\x}"
}

writeLog() {
  while IFS= read -r line; do
    printf '[%s] %s\n' "$(date)" "$line";
  done
}

continue_prompt() {
  read -rp "¿Continuar con otras operaciones (Yes/no)? " choice
  case "${choice}" in
    [yY]|[yY][eE][sS] ) return 0 ;;
    * ) exit 0;;
  esac
}

build_web() {
  if [ ! -f "/var/www/html/index.html" ]; then
    # choose and copy a random  template for dummy web pages
    local template="$(curl -sL https://${raw_proxy}/phlinhng/web-templates/master/list.txt | shuf -n  1)"
    wget -q --show-progress https://${raw_proxy}/phlinhng/web-templates/master/${template} -O /tmp/template.zip
    mkdir -p /var/www/html
    unzip -q /tmp/template.zip -d /var/www/html
    echo -ne "User-agent: *\nDisallow: /\n" > /var/www/html/robots.txt
  else
    echo "Existía un sitio web ficticio. Saltar edificio."
  fi
}

checkIP() {
  local realIP4="$(curl -sL ${ip4_api} -m 5)"
  local resolvedIP4="$(curl -sSL https://cloudflare-dns.com/dns-query\?name\=$1\&type\=A -H 'accept: application/dns-json' | jq ".Answer | .[] | select(.type == 1) | .data" --raw-output)"

  [ ! -z "${realIP4}" ] && printf "%s %s\n" "dirección IPv4 detectada:" "${realIP4}" | writeLog >> $log_path
  ([ ! -z "${resolvedIP4}" ] && [ "${resolvedIP4}" != "null" ]) && printf "%s %s\n" "encontró un registro:" "${resolvedIP4}" | writeLog >> $log_path

  if [[ "${realIP4}" == "${resolvedIP4}" ]]; then
    echo "Un récord igualado." | writeLog >> $log_path
    return 0
  else
    local realIP6="$(curl -sL ${ip6_api} -m 5)"
    local resolvedIP6="$(curl -sSL https://cloudflare-dns.com/dns-query\?name\=$1\&type\=AAAA -H 'accept: application/dns-json' | jq ".Answer | .[] | select(.type == 28) | .data" --raw-output)"
    [ ! -z "${realIP6}" ] && printf "%s %s\n" "dirección IPv6 detectada:" "${realIP6}" | writeLog >> $log_path
    ([ ! -z "${resolvedIP6}" ] && [ "${resolvedIP6}" != "null" ]) && printf "%s %s\n" "encontrado registro AAAA:" "${resolvedIP6}" | writeLog >> $log_path
    if [[ "${realIP6}" == "${resolvedIP6}" ]]; then
      echo "Registro AAAA igualado." | writeLog >> $log_path
      return 0
    else
      echo "ni el registro A ni el registro AAAA coinciden, devuelve 1" | writeLog >> $log_path
      return 1
    fi
  fi
}

show_links() {
  if [ -f "/usr/local/bin/xray" ]; then
    local uuid="$(read_json /usr/local/etc/xray/05_inbounds_vless.json '.inbounds[0].settings.clients[0].id')"
    local path="$(read_json /usr/local/etc/xray/05_inbounds_ss.json '.inbounds[0].streamSettings.wsSettings.path')"
    local sni="$(read_json /usr/local/etc/xray/05_inbounds_vless.json '.inbounds[0].tag')"
    local cf_node="$(read_json /usr/local/etc/xray/05_inbounds_ss.json '.inbounds[0].tag')"
    # path ss+ws: /[base], path vless+ws: /[base]ws, path vmess+ws: /[base]wss, path trojan+ws: /[base]tj

    colorEcho ${YELLOW} "===============分 SIN WEBSOCK (conexión directa)==============="
    colorEcho ${BLUE} "VLESS XTLS"
    #https://github.com/XTLS/Xray-core/issues/91
    local uri_vless="${uuid}@${sni}:443?security=xtls&flow=rprx-xtls-direct#`urlEncode "${sni} (VLESS)"`"
    printf "%s\n" "vless://${uri_vless}"
    echo ""

    colorEcho ${BLUE} "Trojan TLS"
    local uri_trojan="${uuid}@${sni}:443?peer=${sni}&sni=${sni}#`urlEncode "${sni} (Trojan)"`"
    printf "%s\n" "trojan://${uri_trojan}"
    echo ""

    colorEcho ${BLUE} "Shadowsocks"
    local user_ss="$(printf %s "aes-128-gcm:${uuid}" | base64 --wrap=0)"
    local uri_ss="${user_ss}@${sni}:443/?plugin=`urlEncode "v2ray-plugin;tls;mode=websocket;host=${sni};path=${path};mux=0"`#`urlEncode "${sni} (SS)"`"
    printf "%s\n" "ss://${uri_ss}"
    echo ""

    colorEcho ${YELLOW} "=============== LINKS RECOMENDADOS-WEBSOCK(CDN)==============="
    colorEcho ${BLUE} "VLESS WSS"
    #https://github.com/XTLS/Xray-core/issues/91
    local uri_vless_wss="${uuid}@${cf_node}:443?type=ws&security=tls&host=${sni}&path=`urlEncode ${path}ws?ed=2048`&sni=${sni}#`urlEncode "${sni} (VLESS+WSS)"`"
    printf "%s\n" "vless://${uri_vless_wss}"
    echo ""

    colorEcho ${BLUE} "Trojan WSS"
    local uri_trojango="${uuid}@${sni}:443?sni=${sni}&type=ws&host=${sni}&path=`urlEncode "${path}tj"`#`urlEncode "${sni} (Trojan-Go)"`"
    local uri_trojango_cf="${uuid}@${cf_node}:443?sni=${sni}&type=ws&host=${sni}&path=`urlEncode "${path}tj"`#`urlEncode "${sni} (Trojan-Go)"`"
    printf "%s\n" "trojan-go://${uri_trojango_cf}" "trojan-go://${uri_trojango}"
    colorEcho ${YELLOW} "Trojan-Go El formato del enlace para compartir no se ha finalizado. Si su cliente no puede analizar este enlace, complete la información de conexión manualmente."
    printf "%s:443 %s %s\n" "${sni}" "${uuid}" "${path}tj"
    echo ""

    colorEcho ${BLUE} "Shadowsocks"
    local user_ss="$(printf %s "aes-128-gcm:${uuid}" | base64 --wrap=0)"
    local uri_ss="${user_ss}@${cf_node}:443/?plugin=`urlEncode "v2ray-plugin;tls;mode=websocket;host=${sni};path=${path};mux=0"`#`urlEncode "${sni} (SS)"`"
    printf "%s\n" "ss://${uri_ss}"
    echo ""
    colorEcho ${YELLOW} "========================================"
  fi
}

preinstall() {
  # turning off selinux
  setenforce 0
  echo "SELINUX=disable" > /etc/selinux/config

  # turning off firewall
  systemctl stop firewalld
  systemctl disable firewalld
  ufw disable

  # get dependencies
  ${PACKAGE_MANAGEMENT_INSTALL} epel-release -y # centos
  ${PACKAGE_MANAGEMENT_UPDATE} -y
  ${PACKAGE_MANAGEMENT_INSTALL} coreutils curl wget unzip jq certbot nginx -y
}

init_cert() {
  if [ ! -d "/var/www/acme" ]; then
    $(which mkdir) -p "/var/www/acme"
    printf "Cretated: %s\n" "/var/www/acme"
  fi
  certbot register -m "$RANDOM@$1" --agree-tos --no-eff-email -n
  # TODO: ecdsa cert will be available from cetbot 1.10+ with args "--key-type ecdsa"
  certbot certonly --webroot -w "/var/www/acme" -d $1 -n
  (crontab -l 2>/dev/null; echo "8 7 */4 * * certbot renew -n -q --post-hook \"systemctl restart xray\" >/dev/null 2>&1") | crontab -
}

get_trojan() {
  if [ ! -f "/usr/bin/trojan-go" ]; then
    echo "trojan-go is not installed. start installation"

    echo "Getting the latest version of trojan-go"
    local latest_version="$(curl -sL "https://${api_proxy}/repos/p4gefau1t/trojan-go/releases" | jq '.[0].tag_name' --raw-output)"
    echo "${latest_version}"
    local trojango_link="https://${gh_proxy}/github.com/p4gefau1t/trojan-go/releases/download/${latest_version}/trojan-go-linux-${TJ_MACHINE}.zip"

    mkdir -p "/etc/trojan-go"

    cd $(mktemp -d)
    wget -q --show-progress "${trojango_link}" -O trojan-go.zip
    unzip -q trojan-go.zip && rm -rf trojan-go.zip
    $(which mv) trojan-go /usr/bin/trojan-go && $(which chmod) +x /usr/bin/trojan-go
    $(which mv) geoip.dat /usr/bin/geoip.dat
    $(which mv) geosite.dat /usr/bin/geosite.dat

    echo "Building trojan-go.service"
    mv example/trojan-go.service /etc/systemd/system/trojan-go.service

    systemctl daemon-reload 2>&1 | writeLog >> $log_path
    systemctl enable trojan-go 2>&1 | writeLog >> $log_path

    echo "trojan-go is installed."
  else
    colorEcho ${BLUE} "Obtener la última versión de trojan-go"
    local latest_version="$(curl -sL "https://${api_proxy}/repos/p4gefau1t/trojan-go/releases" | jq '.[0].tag_name' --raw-output)"
    echo "${latest_version}"
    local trojango_link="https://${gh_proxy}/github.com/p4gefau1t/trojan-go/releases/download/${latest_version}/trojan-go-linux-${TJ_MACHINE}.zip"

    cd $(mktemp -d)
    wget -q --show-progress "${trojango_link}" -O trojan-go.zip
    unzip -q trojan-go.zip && rm -rf trojan-go.zip
    $(which mv) trojan-go /usr/bin/trojan-go && $(which chmod) +x /usr/bin/trojan-go
    colorEcho ${GREEN} "trojan-go ha sido actualizado."
  fi
}

set_xray_systemd() {
  cat > "/etc/systemd/system/xray.service" <<-EOF
[Unit]
Description=Xray - A unified platform for anti-censorship
Documentation=https://github.com/xtls
After=network.target nss-lookup.target
Wants=network-online.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=yes
Environment=XRAY_LOCATION_ASSET=/usr/local/share/xray
ExecStart=/usr/local/bin/xray run -confdir /usr/local/etc/xray
Restart=on-failure
RestartPreventExitStatus=23

[Install]
WantedBy=multi-user.target
EOF
}

get_xray() {
  if [ ! -f "/usr/local/bin/xray" ]; then
    echo "XRay-Core no está instalado. iniciar la instalación"

    echo "Obtener la última versión de xray-core"
    latest_version=`curl -sL "https://${api_proxy}/repos/XTLS/Xray-core/releases/latest" | jq '.tag_name' --raw-output`
    echo "${latest_version}"
    local xray_link="https://${gh_proxy}/github.com/XTLS/Xray-core/releases/download/${latest_version}/Xray-linux-${V2_MACHINE}.zip"

    $(which mkdir) -p "/usr/local/etc/xray"
    printf "Cretated: %s\n" "/usr/local/etc/xray"
    $(which mkdir) -p "/usr/local/share/xray"
    printf "Cretated: %s\n" "/usr/local/share/xray"

    cd $(mktemp -d)
    wget -q --show-progress "${xray_link}" -O xray-core.zip
    unzip -q xray-core.zip && $(which rm) -rf xray-core.zip
    $(which mv) xray /usr/local/bin/xray && $(which chmod) +x /usr/local/bin/xray
    printf "Installed: %s\n" "/usr/local/bin/xray"
    $(which mv) geoip.dat /usr/local/share/xray/geoip.dat
    printf "Installed: %s\n" "/usr/local/share/xray/geoip.dat"
    $(which mv) geosite.dat /usr/local/share/xray/geosite.dat
    printf "Installed: %s\n" "/usr/local/share/xray/geosite.dat"

    echo "Building xray.service"
    set_xray_systemd

    systemctl daemon-reload 2>&1 | writeLog >> $log_path
    systemctl enable xray 2>&1 | writeLog >> $log_path

    echo "XRay-Core ${latest_version} esta instalado."
  else
    echo "Getting the latest version of xray-core"
    latest_version=`curl -sL "https://${api_proxy}/repos/XTLS/Xray-core/releases/latest" | jq '.tag_name' --raw-output`
    echo "${latest_version}"
    local xray_link="https://${gh_proxy}/github.com/XTLS/Xray-core/releases/download/${latest_version}/Xray-linux-${V2_MACHINE}.zip"

    cd $(mktemp -d)
    wget -q --show-progress "${xray_link}" -O xray-core.zip
    unzip -q xray-core.zip && $(which rm) -rf xray-core.zip
    $(which mv) xray /usr/local/bin/xray && $(which chmod) +x /usr/local/bin/xray
    printf "Installed: %s\n" "/usr/local/bin/xray"

    systemctl restart xray
    colorEcho ${GREEN} "XRay-Core ${latest_version} Ha sido actualizado."
  fi
}

set_xray() {
  # $1: uuid for all except vless ws (in trojan and ss uuid == passowrd)
  # $2: base path
  # $3: sni
  # $4: url of cf node
  # 3564: trojan, 3565: ss, 3566: vless+wss
  cat > "/usr/local/etc/xray/05_inbounds_vless.json" <<-EOF
{
  "inbounds": [
    {
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$1",
            "flow": "xtls-rprx-direct"
          }
        ],
        "decryption": "none",
        "fallbacks": [
          {
            "dest": 3564
          },
          {
            "path": "$2tj",
            "dest": 3564
          },
          {
            "path": "$2",
            "dest": 3565,
            "xver": 1
          },
          {
            "path": "$2ws",
            "dest": 3566,
            "xver": 1
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "xtls",
        "xtlsSettings": {
          "alpn": [ "http/1.1" ],
          "certificates": [
            {
              "certificateFile": "/etc/letsencrypt/live/$3/fullchain.pem",
              "keyFile": "/etc/letsencrypt/live/$3/privkey.pem"
            }
          ]
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [ "http", "tls" ]
      },
      "tag": "$3"
    }
  ]
}
EOF
  cat > "/usr/local/etc/xray/05_inbounds_ss.json" <<-EOF
{
  "inbounds": [
    {
      "port": 3565,
      "listen": "127.0.0.1",
      "protocol": "shadowsocks",
      "settings": {
        "method": "aes-128-gcm",
        "password": "$1",
        "network": "tcp"
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": {
          "acceptProxyProtocol": true,
          "path": "$2"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [ "http", "tls" ]
      },
      "tag": "$4"
    }
  ]
}
EOF
  cat > "/usr/local/etc/xray/05_inbounds_vless_ws.json" <<-EOF
{
  "inbounds": [
    {
      "port": 3566,
      "listen": "127.0.0.1",
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$1"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": {
          "acceptProxyProtocol": true,
          "path": "$2ws"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [ "http", "tls" ]
      },
      "tag": "vless_ws"
    }
  ]
}
EOF
  wget -q https://${raw_proxy}/phlinhng/v2ray-tcp-tls-web/${branch}/config/03_routing.json -O /usr/local/etc/xray/03_routing.json
  wget -q https://${raw_proxy}/phlinhng/v2ray-tcp-tls-web/${branch}/config/06_outbounds.json -O /usr/local/etc/xray/06_outbounds.json
}

set_trojan() {
  # $1: password
  # $2: ws path
  # $3: sni
  cat > "/etc/trojan-go/config.json" <<-EOF
{
  "run_type": "server",
  "local_addr": "127.0.0.1",
  "local_port": 3564,
  "remote_addr": "127.0.0.1",
  "remote_port": 80,
  "log_level": 3,
  "password": [
    "$1"
  ],
  "transport_plugin": {
    "enabled": true,
    "type": "plaintext"
  },
  "websocket": {
    "enabled": true,
    "path": "$2",
    "host": "$3"
  },
  "router": {
    "enabled": false
  }
}
EOF
}

set_nginx_default() {
  cat > /etc/nginx/sites-available/default <<-EOF
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    location /.well-known {
      root /var/www/acme;
    }

    location / {
      return 301 https://\$host\$request_uri;
    }
}
EOF
}

set_nginx() {
  rm -f /etc/nginx/conf.d/vless_fallback.conf
  cat > /etc/nginx/conf.d/vless_fallback.conf <<-EOF
server {
    listen 127.0.0.1:80;
    server_name $1;
    root /var/www/html;
    index index.php index.html index.htm;
}
EOF
}

fix_cert() {
  if [ -f "/usr/local/bin/xray" ]; then
    while true; do
      read -rp "Resuelva el nombre de dominio de este VPS: " V2_DOMAIN
      if checkIP "${V2_DOMAIN}"; then
        colorEcho $LYELLOW "nombre de dominio${V2_DOMAIN}El análisis es correcto, el certificado se reparará pronto"
        break
      else
        colorEcho ${RED} "nombre de dominio ${V2_DOMAIN} Error de análisis (sí: forzar continuar, no: volver a ingresar, salir: salir)"
        read -rp "Si está seguro de que el nombre de dominio se ha resuelto correctamente, puede continuar con la operación de reparación. ¿Forzar continuar? (Sí / no / salir) " forceConfirm
        case "${forceConfirm}" in
          [yY]|[yY][eE][sS] ) break ;;
          [qQ]|[qQ][uU][iI][tT] ) return 0;;
        esac
      fi
    done

    [ -z "${V2_DOMAIN}" ] && return 0;

    local uuid="$(read_json /usr/local/etc/xray/05_inbounds_vless.json '.inbounds[0].settings.clients[0].id')"
    local path="$(read_json /usr/local/etc/xray/05_inbounds_ss.json '.inbounds[0].streamSettings.wsSettings.path')"
    local cf_node="$(read_json /usr/local/etc/xray/05_inbounds_ss.json '.inbounds[0].tag')"
    local old_domain="$(read_json /usr/local/etc/xray/05_inbounds_vless.json '.inbounds[0].tag')"

    certbot delete --cert-name ${old_domain} -n 2>&1 | writeLog >> $log_path
    certbot certonly --webroot -w "/var/www/acme" -d ${V2_DOMAIN} -n 2>&1 | writeLog >> $log_path

    set_xray "${uuid}" "${path}" "${V2_DOMAIN}" "${cf_node}"
    set_trojan "${uuid}" "${path}tj" "${V2_DOMAIN}"
    set_nginx "${V2_DOMAIN}"
    systemctl restart nginx 2>/dev/null
    systemctl restart trojan-go 2>/dev/null
    systemctl restart xray 2>/dev/null

    write_json /usr/local/etc/xray/05_inbounds_vless.json ".inbounds[0].tag" "\"${V2_DOMAIN}\""

    colorEcho $LGREEN "Reparación de certificado completada"
    show_links
  else
    colorEcho ${YELLOW} "Primero instale XRay"
  fi
}

install_xray() {
  colorEchoFlush $BLUE "Instalar el paquete de dependencia coreutils curl wget descomprimir jq certbot nginx"
  preinstall 2>&1 | writeLog >> $log_path
  colorEcho $LGREEN "Finalizar: instale el paquete de dependencia coreutils curl wget unzip jq certbot nginx"

  while true; do
    read -rp "Resuelva el nombre de dominio de este VPS: " V2_DOMAIN
    if checkIP "${V2_DOMAIN}"; then
      colorEcho $LYELLOW "nombre de dominio ${V2_DOMAIN} El análisis es correcto y la instalación comenzará pronto"
      break
    else
      colorEcho ${RED} "nombre de dominio ${V2_DOMAIN} Error de análisis (sí: forzar continuar, no: volver a ingresar, salir: salir)"
      read -rp "Si está seguro de que el nombre de dominio se ha resuelto correctamente, puede continuar con la operación de instalación. ¿Forzar continuar? (Sí / no / salir) " forceConfirm
      case "${forceConfirm}" in
        [yY]|[yY][eE][sS] ) break ;;
        [qQ]|[qQ][uU][iI][tT] ) return 0 ;;
      esac
    fi
  done

  echo "Start xray installation for domain ${V2_DOMAIN}" | writeLog >> $log_path

  colorEchoFlush $BLUE "Obtener xray-core\r"
  get_xray | writeLog >> $log_path
  colorEcho $LGREEN "Hecho: Obtener xray-core"

  colorEchoFlush $BLUE "Obtener trojan-go\r"
  get_trojan | writeLog >> $log_path
  colorEcho $LGREEN "Hecho: Obtener trojan-go"

  # set crontab to auto update geoip.dat and geosite.dat
  colorEchoFlush $BLUE "Configurar una tarea de actualización de geoip / geositio\r"
  (crontab -l 2>/dev/null; echo "0 7 * * * wget -q https://${raw_proxy}/Loyalsoldier/v2ray-rules-dat/release/geoip.dat -O /usr/local/share/xray/geoip.dat >/dev/null >/dev/null") | crontab -
  (crontab -l 2>/dev/null; echo "0 7 * * * wget -q https://${raw_proxy}/Loyalsoldier/v2ray-rules-dat/release/geosite.dat -O /usr/local/share/xray/geosite.dat >/dev/null >/dev/null") | crontab -
  echo "geoip/geosite crontab set" | writeLog >> $log_path
  colorEcho $LGREEN "Finalizar: configure la tarea de actualización de geoip / geositio"

  colorEchoFlush $BLUE "Descargue la plantilla del sitio web de disguise"
  build_web | writeLog >> $log_path
  colorEcho $LGREEN "Finalizar: descargue la plantilla del sitio web disguise"

  local uuid="$(cat '/proc/sys/kernel/random/uuid')"
  local path="/$(cat '/proc/sys/kernel/random/uuid' | sed -e 's/-//g' | tr '[:upper:]' '[:lower:]' | head -c $((10+$RANDOM%10)))"

  colorEchoFlush $BLUE "Configurar XRay"
  set_xray "${uuid}" "${path}" "${V2_DOMAIN}" "${cf_node_default}"
  colorEcho $LGREEN "realizar: Configuracion XRay"

  colorEchoFlush $BLUE "Configurar Trojan"
  set_trojan "${uuid}" "${path}tj" "${V2_DOMAIN}"
  colorEcho $LGREEN "realizar: Configuracion Trojan"

  colorEchoFlush $BLUE "Configurar Nginx"
  set_nginx_default | writeLog >> $log_path
  set_nginx "${V2_DOMAIN}"
  systemctl restart nginx | writeLog >> $log_path
  colorEcho $LGREEN "Finish: Setting Nginx"

  colorEchoFlush $BLUE "Solicita un certificado SSL"
  init_cert "${V2_DOMAIN}" 2>&1 | writeLog >> $log_path
  colorEcho $LGREEN "Finalizar: Solicite el certificado SSL"

  # activate services
  colorEchoFlush $BLUE "Iniciar el proceso systemd"
  systemctl daemon-reload | writeLog >> $log_path
  systemctl reset-failed | writeLog >> $log_path
  systemctl restart trojan-go 2>&1 | writeLog >> $log_path
  systemctl restart xray 2>&1 | writeLog >> $log_path

  colorEcho $LGREEN "XRay + Trojan-Go instalado con éxito!"
  show_links
}

edit_cf_node() {
  if [ -f "/usr/local/bin/xray" ]; then
    local cf_node_current="$(read_json /usr/local/etc/xray/05_inbounds_ss.json '.inbounds[0].tag')"
    printf "%s\n" "Ingrese el número para usar el valor recomendado"
    printf "1. %s\n" "icook.hk"
    printf "2. %s\n" "www.digitalocean.com"
    printf "3. %s\n" "www.garmin.com"
    printf "4. %s\n" "amp.cloudflare.com"
    read -p "Ingrese la nueva dirección del nodo CF(HOST) [Déjela en blanco para usar el valor existente] ${cf_node_current}]: " cf_node_new
    case "${cf_node_new}" in
      "1") cf_node_new="icook.hk" ;;
      "2") cf_node_new="www.digitalocean.com" ;;
      "3") cf_node_new="www.garmin.com" ;;
      "4") cf_node_new="amp.cloudflare.com" ;;
    esac
    if [ -z "${cf_node_new}" ]; then
      cf_node_new="${cf_node_current}"
    fi
    write_json /usr/local/etc/xray/05_inbounds_ss.json ".inbounds[0].tag" "\"${cf_node_new}\""
    sleep 1
    printf "%s\n" "El nodo CF (HOST) se ha cambiado a ${cf_node_new}"
    show_links
  fi
}

rm_xwall() {
  if [ -f "/usr/local/bin/xray" ]; then
    wget -q https://${raw_proxy}/phlinhng/v2ray-tcp-tls-web/${branch}/tools/rm_xwall.sh -O /tmp/rm_xwall.sh && bash /tmp/rm_xwall.sh
    exit 0
  fi
}

show_menu() {
  echo ""
  if [ -f "/usr/local/bin/xray" ]; then
  echo "             TROJAN-GO+   "
  echo ""
  echo "0) INSTALAR TROJAN + VLSS + SHADOWSOCK (WEBSOCK)"
  echo "----------Gestión de nombres de dominio----------"
  echo "1) Reparar certificado / cambiar nombre de dominio"
  echo "2) Nodo Cloudflare personalizado"
  echo "----------Configuración de pantalla----------"
  echo "3) Mostrar enlaces"
  echo "----------Gestión de actualizaciones----------"
  echo "4) Actualizar xray-core"
  echo "5) Actualizar trojan-go"
  echo "----------Desinstalar secuencia de comandos----------"
  echo "6)Desinstalar el script y todos los componentes"
  else
  echo "0) INSTALAR TROJAN + VLSS + SHADOWSOCK (WEBSOCK)"
  fi
  echo "100)ANTES DE INSTALAR, IMPORTANTE LEER"
  echo "7) VOLVER AL MENU"
  echo ""
}

menu() {
  colorEcho ${YELLOW} "Script automatizado de herramientas proxy v${VERSION}"
  colorEcho ${YELLOW} "AnonyProArg"

  #check_status

  COLUMNS=woof

  while true; do
    show_menu
    read -rp "Seleccione la operación [Ingrese cualquier valor para salir]: " opt
    case "${opt}" in
      "0") install_xray && continue_prompt ;;
      "1") fix_cert && continue_prompt ;;
      "2") edit_cf_node && continue_prompt ;;
      "3") show_links && continue_prompt ;;
      "4") get_xray && continue_prompt ;;
      "5") get_trojan && continue_prompt ;;
      "6") rm_xwall ;;
      "7") VPS-ARG ;;
       "100") leerv ;;
      *) break ;;
    esac
  done

}

identify_the_operating_system_and_architecture
menu
